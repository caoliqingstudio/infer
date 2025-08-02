(**
 * Path Injection detector for Infer
 * 
 * Detects when user-controlled data is used in file path operations
 * without proper validation (CWE-022, CWE-023).
 * 
 * Sources: Network inputs, HTTP requests, user input streams
 * Sinks: File operations (File constructors, FileInputStream, etc.)
 * Sanitizers: Path validation methods (contains checks for dotdot, slash, backslash)
 *)

open! IStd
module F = Format

module Domain = PathInjectionDomain

let is_network_source proc_name =
  match proc_name with
  | Procname.Java java_proc_name ->
    let class_name = Procname.Java.get_class_name java_proc_name in
    let method_name = Procname.Java.get_method java_proc_name in
    (* Network and user input sources *)
    (String.is_substring class_name ~substring:"Socket" ||
     String.is_substring class_name ~substring:"InputStream" ||
     String.is_substring class_name ~substring:"Reader" ||
     String.is_substring class_name ~substring:"HttpServletRequest" ||
     String.is_substring class_name ~substring:"ServletRequest") &&
    (String.equal method_name "readLine" ||
     String.equal method_name "read" ||
     String.equal method_name "getParameter" ||
     String.equal method_name "getParameterMap" ||
     String.equal method_name "getParameterNames" ||
     String.equal method_name "getParameterValues" ||
     String.equal method_name "getHeader" ||
     String.equal method_name "getHeaders" ||
     String.equal method_name "getPathInfo" ||
     String.equal method_name "getQueryString" ||
     String.equal method_name "getRequestURI" ||
     String.equal method_name "getRequestURL")
  | _ -> false

let is_file_path_sink proc_name =
  match proc_name with
  | Procname.Java java_proc_name ->
    let class_name = Procname.Java.get_class_name java_proc_name in
    let method_name = Procname.Java.get_method java_proc_name in
    (* File operations that accept path arguments *)
    (String.equal class_name "java.io.File" ||
     String.equal class_name "java.io.FileInputStream" ||
     String.equal class_name "java.io.FileOutputStream" ||
     String.equal class_name "java.io.FileReader" ||
     String.equal class_name "java.io.FileWriter" ||
     String.equal class_name "java.io.RandomAccessFile" ||
     String.equal class_name "java.io.PrintWriter" ||
     String.equal class_name "java.io.PrintStream") &&
    (* Constructor calls or file operations *)
    (String.equal method_name "<init>" ||
     String.equal method_name "createNewFile" ||
     String.equal method_name "delete" ||
     String.equal method_name "exists" ||
     String.equal method_name "isDirectory" ||
     String.equal method_name "isFile" ||
     String.equal method_name "mkdir" ||
     String.equal method_name "mkdirs" ||
     String.equal method_name "canRead" ||
     String.equal method_name "canWrite" ||
     String.equal method_name "canExecute")
  | _ -> false

let is_path_sanitizer proc_name =
  match proc_name with
  | Procname.Java java_proc_name ->
    let class_name = Procname.Java.get_class_name java_proc_name in
    let method_name = Procname.Java.get_method java_proc_name in
    (* Path validation methods *)
    String.equal class_name "java.lang.String" &&
    (String.equal method_name "contains" ||
     String.equal method_name "startsWith" ||
     String.equal method_name "matches") ||
    (* Path normalization *)
    String.equal class_name "java.nio.file.Path" &&
    (String.equal method_name "normalize" ||
     String.equal method_name "toAbsolutePath")
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
      (* Source: Network and user input methods return tainted data *)
      if is_network_source callee_proc_name then (
        let ret_var = Var.of_id return_id in
        Domain.add_tainted_var ret_var astate
      )
      (* Sink: File path operations with tainted arguments *)
      else if is_file_path_sink callee_proc_name then (
        if has_tainted_arg actuals astate then (
          let message = F.asprintf "Path injection: user-controlled data used in file path operation" in
          Reporting.log_issue proc_desc err_log ~loc PathInjection IssueType.path_injection message;
          astate
        ) else astate
      )
      (* Sanitizer: Path validation methods remove taint from return value *)
      else if is_path_sanitizer callee_proc_name then (
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

  let pp_session_name _node fmt = F.pp_print_string fmt "path_injection"
end

module NormalTransferFunctions = TransferFunctions (ProcCfg.Normal)
module Analyzer = AbstractInterpreter.MakeRPO (NormalTransferFunctions)

let checker ({InterproceduralAnalysis.proc_desc; _} as analysis_data) =
  let result = Analyzer.compute_post analysis_data ~initial:Domain.initial proc_desc in
  result