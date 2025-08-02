(**
 * Trust Boundary Violation detector for Infer
 * 
 * Detects when data from untrusted sources (HTTP requests) is stored
 * in trusted contexts (HTTP sessions) without proper validation.
 * 
 * Sources: HttpServletRequest.getParameter(), getHeader(), etc.
 * Sinks: HttpSession.setAttribute(), putValue()
 * Sanitizers: ESAPI validation methods
 *)

open! IStd
module F = Format

module Domain = TrustBoundaryViolationDomain

let is_http_request_source proc_name =
  match proc_name with
  | Procname.Java java_proc_name ->
    let class_name = Procname.Java.get_class_name java_proc_name in
    let method_name = Procname.Java.get_method java_proc_name in
    (* HTTP request parameters and headers *)
    (String.is_substring class_name ~substring:"HttpServletRequest" ||
     String.is_substring class_name ~substring:"ServletRequest") &&
    (String.equal method_name "getParameter" ||
     String.equal method_name "getParameterMap" ||
     String.equal method_name "getParameterNames" ||
     String.equal method_name "getParameterValues" ||
     String.equal method_name "getHeader" ||
     String.equal method_name "getHeaderNames" ||
     String.equal method_name "getHeaders" ||
     String.equal method_name "getPathInfo" ||
     String.equal method_name "getQueryString" ||
     String.equal method_name "getRemoteUser" ||
     String.equal method_name "getRequestURI" ||
     String.equal method_name "getRequestURL" ||
     String.equal method_name "getServletPath") ||
    (* HTTP cookies *)
    String.is_substring class_name ~substring:"Cookie" &&
    (String.equal method_name "getComment" ||
     String.equal method_name "getName" ||
     String.equal method_name "getValue")
  | _ -> false

let is_http_session_sink proc_name =
  match proc_name with
  | Procname.Java java_proc_name ->
    let class_name = Procname.Java.get_class_name java_proc_name in
    let method_name = Procname.Java.get_method java_proc_name in
    String.is_substring class_name ~substring:"HttpSession" &&
    (String.equal method_name "setAttribute" ||
     String.equal method_name "putValue")
  | _ -> false

let is_esapi_sanitizer proc_name =
  match proc_name with
  | Procname.Java java_proc_name ->
    let class_name = Procname.Java.get_class_name java_proc_name in
    let method_name = Procname.Java.get_method java_proc_name in
    String.is_substring class_name ~substring:"Validator" &&
    (String.equal method_name "isValidInput" ||
     String.equal method_name "getValidInput")
  | _ -> false

let get_var_from_exp exp =
  match exp with
  | Exp.Var id -> Some (Var.of_id id)
  | Exp.Lvar pvar -> Some (Var.of_pvar pvar)
  | _ -> None

let has_tainted_arg actuals astate =
  List.exists actuals ~f:(fun (actual_exp, _) ->
    match get_var_from_exp actual_exp with
    | Some var -> Domain.is_var_tainted var astate
    | None -> false)

module TransferFunctions (CFG : ProcCfg.S) = struct
  module CFG = CFG
  module Domain = Domain

  type analysis_data = Domain.t InterproceduralAnalysis.t

  let exec_instr (astate : Domain.t) ({InterproceduralAnalysis.proc_desc; err_log; _} : analysis_data) _ _ (instr : Sil.instr) =
    match instr with
    | Call ((return_id, _), Const (Cfun callee_proc_name), actuals, loc, _) -> (
      (* Source: HTTP request methods return tainted data *)
      if is_http_request_source callee_proc_name then (
        let ret_var = Var.of_id return_id in
        Domain.add_tainted_var ret_var astate
      )
      (* Sink: HTTP session methods with tainted arguments *)
      else if is_http_session_sink callee_proc_name then (
        if has_tainted_arg actuals astate then (
          let message = F.asprintf "Trust boundary violation: untrusted data stored in HTTP session" in
          Reporting.log_issue proc_desc err_log ~loc TrustBoundaryViolation IssueType.trust_boundary_violation message;
          astate
        ) else astate
      )
      (* Sanitizer: ESAPI validation methods remove taint *)
      else if is_esapi_sanitizer callee_proc_name then (
        let ret_var = Var.of_id return_id in
        Domain.remove_tainted_var ret_var astate
      )
      else astate
    )
    | Store {e1= Lvar pvar; e2; _} ->
      (* Assignment: propagate taint from source to destination *)
      (match get_var_from_exp e2 with
      | Some source_var when Domain.is_var_tainted source_var astate ->
        let dest_var = Var.of_pvar pvar in
        Domain.add_tainted_var dest_var astate
      | _ ->
        (* Assignment of non-tainted value: remove taint from destination *)
        let dest_var = Var.of_pvar pvar in
        Domain.remove_tainted_var dest_var astate)
    | Load {id; e; _} ->
      (* Load operation: id = *e *)
      (match get_var_from_exp e with
      | Some source_var when Domain.is_var_tainted source_var astate ->
        let dest_var = Var.of_id id in
        Domain.add_tainted_var dest_var astate
      | _ -> astate)
    | _ -> astate

  let pp_session_name _node fmt = F.pp_print_string fmt "trust_boundary_violation"
end

module NormalTransferFunctions = TransferFunctions (ProcCfg.Normal)
module Analyzer = AbstractInterpreter.MakeRPO (NormalTransferFunctions)

let checker ({InterproceduralAnalysis.proc_desc; _} as analysis_data) =
  let result = Analyzer.compute_post analysis_data ~initial:Domain.initial proc_desc in
  result