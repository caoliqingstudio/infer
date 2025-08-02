(**
 * URL Redirect detector for Infer
 * 
 * Detects when user-controlled data is used in URL redirection operations
 * without proper validation (CWE-601).
 * 
 * Sources: HTTP request parameters, headers, remote user input
 * Sinks: HTTP response redirection methods (sendRedirect, setHeader Location)
 * Sanitizers: URL validation methods, domain checks, path normalization
 *)

open! IStd
module F = Format

module Domain = UrlRedirectDomain

let is_user_input_source proc_name =
  match proc_name with
  | Procname.Java java_proc_name ->
    let class_name = Procname.Java.get_class_name java_proc_name in
    let method_name = Procname.Java.get_method java_proc_name in
    (* HTTP servlet request sources *)
    (String.is_substring class_name ~substring:"HttpServletRequest" ||
     String.is_substring class_name ~substring:"ServletRequest") &&
    (String.equal method_name "getParameter" ||
     String.equal method_name "getHeader" ||
     String.equal method_name "getQueryString" ||
     String.equal method_name "getPathInfo" ||
     String.equal method_name "getRequestURI" ||
     String.equal method_name "getRequestURL" ||
     String.equal method_name "getParameterValues" ||
     String.equal method_name "getAttribute")
  | _ -> false

let is_url_redirect_sink proc_name =
  match proc_name with
  | Procname.Java java_proc_name ->
    let class_name = Procname.Java.get_class_name java_proc_name in
    let method_name = Procname.Java.get_method java_proc_name in
    (* HTTP response redirection methods *)
    (String.is_substring class_name ~substring:"HttpServletResponse" ||
     String.is_substring class_name ~substring:"ServletResponse") &&
    (String.equal method_name "sendRedirect" ||
     String.equal method_name "setHeader" ||
     String.equal method_name "addHeader")
  | _ -> false

let is_url_sanitizer proc_name =
  match proc_name with
  | Procname.Java java_proc_name ->
    let class_name = Procname.Java.get_class_name java_proc_name in
    let method_name = Procname.Java.get_method java_proc_name in
    (* String validation methods *)
    (String.is_substring class_name ~substring:"String" &&
     (String.equal method_name "startsWith" ||
      String.equal method_name "contains" ||
      String.equal method_name "matches")) ||
    (* URL/URI validation *)
    (String.is_substring class_name ~substring:"URL" &&
     (String.equal method_name "getHost" ||
      String.equal method_name "getProtocol")) ||
    (* OWASP validation *)
    (String.is_substring class_name ~substring:"ESAPI" &&
     (String.equal method_name "isValidInput" ||
      String.equal method_name "getValidInput"))
  | _ -> false

let exec_instr (astate : Domain.t) ({InterproceduralAnalysis.proc_desc; err_log; _} : Domain.t InterproceduralAnalysis.t) _node _kind (instr : Sil.instr) =
  match instr with
  | Call ((return_id, _), Const (Cfun callee_proc_name), actuals, loc, _) ->
    if is_user_input_source callee_proc_name then
      (* Mark return value as tainted *)
      let dest_var = Var.of_id return_id in
      Domain.add_tainted_var dest_var astate
    else if is_url_redirect_sink callee_proc_name then
      (* Check if any argument is tainted *)
      let has_tainted_arg = List.exists actuals ~f:(fun (exp, _) ->
        match exp with
        | Exp.Var id -> 
          let var = Var.of_id id in
          Domain.is_var_tainted var astate
        | _ -> false) in
      if has_tainted_arg then (
        let message = "User-controlled data used in URL redirection without validation" in
        Reporting.log_issue proc_desc err_log UrlRedirect IssueType.url_redirection ~loc message
      );
      astate
    else if is_url_sanitizer callee_proc_name then
      (* Remove taint from sanitized arguments *)
      List.fold actuals ~init:astate ~f:(fun acc (exp, _) ->
        match exp with
        | Exp.Var id ->
          let var = Var.of_id id in
          Domain.remove_tainted_var var acc
        | _ -> acc)
    else
      astate
  | Store {e1= Lvar pvar; e2= Exp.Var id} ->
    (* Handle variable assignments *)
    let source_var = Var.of_id id in
    let dest_var = Var.of_pvar pvar in
    if Domain.is_var_tainted source_var astate then
      Domain.add_tainted_var dest_var astate
    else
      astate
  | Load {id; e= Exp.Lvar pvar} ->
    (* Handle loading from program variables *)
    let source_var = Var.of_pvar pvar in
    let dest_var = Var.of_id id in
    if Domain.is_var_tainted source_var astate then
      Domain.add_tainted_var dest_var astate
    else
      astate
  | Store {e1= Lvar pvar; e2= rhs_exp} ->
    (* Handle assignments with complex RHS *)
    (match rhs_exp with
    | Exp.Var id ->
      let source_var = Var.of_id id in
      if Domain.is_var_tainted source_var astate then
        let dest_var = Var.of_pvar pvar in
        Domain.add_tainted_var dest_var astate
      else
        astate
    | _ -> astate)
  | _ -> astate

let pp_session_name _node fmt = F.pp_print_string fmt "url_redirect"

module TransferFunctions = struct
  module CFG = ProcCfg.Normal
  module Domain = Domain

  type analysis_data = Domain.t InterproceduralAnalysis.t

  let exec_instr = exec_instr

  let pp_session_name = pp_session_name
end

module Analyzer = AbstractInterpreter.MakeRPO (TransferFunctions)

let checker ({InterproceduralAnalysis.proc_desc; _} as analysis_data) =
  let result = Analyzer.compute_post analysis_data ~initial:Domain.initial proc_desc in
  result