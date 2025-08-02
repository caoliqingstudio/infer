(** SSRF (Server-Side Request Forgery) checker for detecting URL-based vulnerabilities *)

open! IStd
module F = Format
module L = Logging

module Domain = SsrfDomain

(** Check if a method is a user-controlled source *)
let is_user_controlled_source proc_name =
  match proc_name with
  | Procname.Java java_proc_name ->
    let class_name = Procname.Java.get_class_name java_proc_name in
    let method_name = Procname.Java.get_method java_proc_name in
    (* HTTP request parameters and headers *)
    (String.is_substring class_name ~substring:"HttpServletRequest" ||
     String.is_substring class_name ~substring:"ServletRequest") &&
    (String.equal method_name "getParameter" ||
     String.equal method_name "getParameterValues" ||
     String.equal method_name "getHeader" ||
     String.equal method_name "getHeaders" ||
     String.equal method_name "getQueryString" ||
     String.equal method_name "getPathInfo" ||
     String.equal method_name "getRequestURI" ||
     String.equal method_name "getRequestURL" ||
     String.equal method_name "getRemoteUser") ||
    (* File I/O operations that could contain URLs *)
    (String.is_substring class_name ~substring:"FileReader" ||
     String.is_substring class_name ~substring:"BufferedReader" ||
     String.is_substring class_name ~substring:"Scanner") &&
    (String.equal method_name "readLine" ||
     String.equal method_name "nextLine" ||
     String.equal method_name "next") ||
    (* Database results that could contain URLs *)
    (String.is_substring class_name ~substring:"ResultSet") &&
    (String.equal method_name "getString" ||
     String.equal method_name "getObject") ||
    (* Test mock methods *)
    String.equal method_name "getUserUrl" ||
    String.equal method_name "getTargetUrl" ||
    String.equal method_name "getRedirectUrl"
  | _ ->
    (* Generic user input methods *)
    let method_name = Procname.get_method proc_name in
    String.is_suffix method_name ~suffix:"getUserInput" ||
    String.is_suffix method_name ~suffix:"readLine" ||
    String.is_suffix method_name ~suffix:"nextLine"

(** Check if a method is an HTTP request sink *)
let is_http_request_sink proc_name =
  match proc_name with
  | Procname.Java java_proc_name ->
    let class_name = Procname.Java.get_class_name java_proc_name in
    let method_name = Procname.Java.get_method java_proc_name in
    (* Java standard library HTTP methods *)
    (String.is_substring class_name ~substring:"URLConnection" ||
     String.is_substring class_name ~substring:"HttpURLConnection") &&
    (String.equal method_name "connect" ||
     String.equal method_name "getInputStream" ||
     String.equal method_name "getOutputStream") ||
    (* URL constructor and methods *)
    String.is_substring class_name ~substring:"URL" &&
    (String.equal method_name "<init>" ||
     String.equal method_name "openConnection" ||
     String.equal method_name "openStream") ||
    (* URI methods *)
    String.is_substring class_name ~substring:"URI" &&
    String.equal method_name "<init>" ||
    (* Apache HttpClient methods *)
    (String.is_substring class_name ~substring:"HttpClient" ||
     String.is_substring class_name ~substring:"CloseableHttpClient") &&
    (String.equal method_name "execute" ||
     String.equal method_name "executeMethod") ||
    (* Apache HTTP request methods *)
    (String.is_substring class_name ~substring:"HttpGet" ||
     String.is_substring class_name ~substring:"HttpPost" ||
     String.is_substring class_name ~substring:"HttpPut" ||
     String.is_substring class_name ~substring:"HttpDelete" ||
     String.is_substring class_name ~substring:"HttpHead" ||
     String.is_substring class_name ~substring:"HttpOptions" ||
     String.is_substring class_name ~substring:"HttpPatch") &&
    String.equal method_name "<init>" ||
    (* OkHttp methods *)
    String.is_substring class_name ~substring:"OkHttpClient" &&
    (String.equal method_name "newCall" ||
     String.equal method_name "execute") ||
    (* Request.Builder methods *)
    (String.is_substring class_name ~substring:"Request" &&
     String.is_substring class_name ~substring:"Builder") &&
    String.equal method_name "url" ||
    (* Spring RestTemplate methods *)
    String.is_substring class_name ~substring:"RestTemplate" &&
    (String.equal method_name "getForObject" ||
     String.equal method_name "getForEntity" ||
     String.equal method_name "postForObject" ||
     String.equal method_name "postForEntity" ||
     String.equal method_name "exchange" ||
     String.equal method_name "execute") ||
    (* JAX-RS WebTarget methods *)
    String.is_substring class_name ~substring:"WebTarget" &&
    String.equal method_name "request" ||
    (* Socket connections *)
    String.is_substring class_name ~substring:"Socket" &&
    String.equal method_name "<init>" ||
    (* Test mock methods *)
    String.equal method_name "makeRequest" ||
    String.equal method_name "sendRequest" ||
    String.equal method_name "fetchUrl"
  | _ ->
    (* Generic HTTP request methods *)
    let method_name = Procname.get_method proc_name in
    String.is_suffix method_name ~suffix:"Request" ||
    String.is_suffix method_name ~suffix:"Fetch" ||
    String.equal method_name "connect"

(** Get variable from expression if possible *)
let get_var_from_exp exp =
  match exp with
  | Exp.Var id -> Some (Var.of_id id)
  | Exp.Lvar pvar -> Some (Var.of_pvar pvar)
  | _ -> None

(** Check if any of the actual arguments contains tainted data *)
let has_tainted_argument actuals astate =
  List.exists actuals ~f:(fun (exp, _) ->
    match get_var_from_exp exp with
    | Some var -> Domain.is_var_tainted var astate
    | None -> false
  )

(** TransferFunctions for the analysis *)
module TransferFunctions (CFG : ProcCfg.S) = struct
  module CFG = CFG
  module Domain = SsrfDomain

  type analysis_data = SsrfDomain.t InterproceduralAnalysis.t

  (** Main transfer function *)
  let exec_instr (astate : Domain.t) analysis_data _node _instr_index (instr : Sil.instr) =
    let {InterproceduralAnalysis.proc_desc; err_log; _} = analysis_data in
    let report_error loc message =
      Reporting.log_issue proc_desc err_log ~loc Ssrf IssueType.ssrf message
    in
    
    match instr with
    | Call ((return_id, _), Const (Cfun callee_proc_name), actuals, loc, _call_flags) ->
      (* Function call with return value *)
      if is_user_controlled_source callee_proc_name then (
        (* This is a call to a user-controlled source method - mark return variable as tainted *)
        let return_var = Var.of_id return_id in
        let updated_astate = Domain.add_tainted_var return_var astate in
        Domain.add_tainted_source (Procname.to_string callee_proc_name) updated_astate
      ) else if is_http_request_sink callee_proc_name then (
        (* This is an HTTP request operation - check if any argument is tainted *)
        if has_tainted_argument actuals astate then (
          let message = "Potential server-side request forgery due to user-provided value" in
          report_error loc message
        );
        astate
      ) else
        astate
        
    | Call (_, Const (Cfun callee_proc_name), actuals, loc, _call_flags) ->
      (* Function call without return value (void methods) *)
      if is_http_request_sink callee_proc_name then (
        (* This is an HTTP request operation - check if any argument is tainted *)
        if has_tainted_argument actuals astate then (
          let message = "Potential server-side request forgery due to user-provided value" in
          report_error loc message
        );
        astate
      ) else
        astate
        
    | Load {id= lhs; e= rhs; typ= _lhs_typ; loc= _loc} ->
      (* Load operation: lhs = *rhs *)
      (match get_var_from_exp rhs with
      | Some rhs_var when Domain.is_var_tainted rhs_var astate ->
        (* Propagate taint from rhs to lhs *)
        let lhs_var = Var.of_id lhs in
        Domain.add_tainted_var lhs_var astate
      | _ ->
        astate)
        
    | Store {e1= lhs; e2= rhs; typ= _rhs_typ; loc= _loc} ->
      (* Store operation: *lhs = rhs *)
      (* Propagate taint from rhs to lhs if rhs is tainted *)
      (match get_var_from_exp rhs with
      | Some rhs_var when Domain.is_var_tainted rhs_var astate ->
        (* If storing to a variable, propagate taint *)
        (match get_var_from_exp lhs with
        | Some lhs_var ->
          Domain.add_tainted_var lhs_var astate
        | None ->
          astate)
      | _ ->
        astate)
        
    | Prune (_assume_exp, _loc, _, _) ->
      (* Conditional assumption - could be used to detect sanitization *)
      (* For now, we don't implement sanitization detection *)
      astate
      
    | Call (_, call_exp, _actuals, loc, _) ->
      (* Indirect call - should not happen in Java *)
      L.die InternalError "Unexpected indirect call %a at %a" Exp.pp call_exp Location.pp loc
      
    | Metadata _ ->
      astate

  let pp_session_name _node fmt = F.pp_print_string fmt "ssrf checker"
end

(** Use normal CFG (without exceptional edges) *)
module CFG = ProcCfg.Normal

(** Create the abstract interpreter *)
module Analyzer = AbstractInterpreter.MakeRPO (TransferFunctions (CFG))

(** Main checker entry point *)
let checker ({InterproceduralAnalysis.proc_desc} as analysis_data) =
  let result = Analyzer.compute_post analysis_data ~initial:Domain.empty proc_desc in
  result