(*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *)

open! IStd
module L = Logging

module TransferFunctions = struct
  module CFG = ProcCfg.Normal
  module Domain = LogInjectionDomain

  type analysis_data = LogInjectionDomain.t InterproceduralAnalysis.t

  (** Check if method call is a source of user-controlled data *)
  let is_user_input_source procname =
    match procname with
    | Procname.Java java_procname ->
        let method_name = Procname.Java.get_method java_procname in
        let class_name = Procname.Java.get_class_name java_procname in
        (* HTTP request parameter methods *)
        (String.is_substring class_name ~substring:"ServletRequest" && 
         (String.equal method_name "getParameter" || String.equal method_name "getHeader" ||
          String.equal method_name "getAttribute" || String.equal method_name "getQueryString")) ||
        (* Spring request parameter methods *)
        (String.is_substring class_name ~substring:"HttpServletRequest" && 
         (String.equal method_name "getParameter" || String.equal method_name "getHeader" ||
          String.equal method_name "getAttribute" || String.equal method_name "getQueryString")) ||
        (* Environment variables *)
        (String.equal class_name "java.lang.System" && String.equal method_name "getenv") ||
        (* System properties *)
        (String.equal class_name "java.lang.System" && String.equal method_name "getProperty") ||
        (* General user input patterns *)
        (String.equal method_name "getParameter" || String.equal method_name "getHeader" ||
         String.equal method_name "getAttribute" || String.equal method_name "getQueryString")
    | _ -> false

  (** Check if method call is a logging sink *)
  let is_logging_sink procname =
    match procname with
    | Procname.Java java_procname ->
        let method_name = Procname.Java.get_method java_procname in
        let class_name = Procname.Java.get_class_name java_procname in
        (* SLF4J Logger methods *)
        (String.is_substring class_name ~substring:"Logger" && 
         (String.equal method_name "debug" || String.equal method_name "info" ||
          String.equal method_name "warn" || String.equal method_name "error" ||
          String.equal method_name "trace")) ||
        (* Log4j Logger methods *)
        (String.is_substring class_name ~substring:"log4j" && 
         (String.equal method_name "debug" || String.equal method_name "info" ||
          String.equal method_name "warn" || String.equal method_name "error" ||
          String.equal method_name "fatal" || String.equal method_name "trace")) ||
        (* java.util.logging Logger methods *)
        (String.equal class_name "java.util.logging.Logger" && 
         (String.equal method_name "info" || String.equal method_name "warning" ||
          String.equal method_name "severe" || String.equal method_name "fine" ||
          String.equal method_name "finer" || String.equal method_name "finest" ||
          String.equal method_name "log")) ||
        (* Google Flogger *)
        (String.is_substring class_name ~substring:"flogger" && String.equal method_name "log") ||
        (* Generic logging patterns *)
        (String.equal method_name "log" || String.equal method_name "logp")
    | _ -> false

  (** Check if method call sanitizes log input by checking line breaks *)
  let is_log_sanitizer procname actuals =
    match procname with
    | Procname.Java java_procname ->
        let method_name = Procname.Java.get_method java_procname in
        let class_name = Procname.Java.get_class_name java_procname in
        (* String.replace or String.replaceAll methods that remove line breaks *)
        if String.equal class_name "java.lang.String" && 
           (String.equal method_name "replace" || String.equal method_name "replaceAll") then
          (* Check if replacing line break characters *)
          List.exists actuals ~f:(fun (exp, _) ->
            match exp with
            | Exp.Const (Cstr str) -> 
                String.is_substring str ~substring:"\n" || 
                String.is_substring str ~substring:"\r" ||
                String.is_substring str ~substring:"\\n" ||
                String.is_substring str ~substring:"\\r" ||
                String.is_substring str ~substring:"\\R"
            | Exp.Const (Cint n) ->
                (match IntLit.to_int n with
                | Some n_int -> Int.equal n_int 10 || Int.equal n_int 13  (* '\n' = 10, '\r' = 13 *)
                | None -> false)
            | _ -> false)
        (* String.matches method with regex that excludes line breaks *)
        else if String.equal class_name "java.lang.String" && String.equal method_name "matches" then
          List.exists actuals ~f:(fun (exp, _) ->
            match exp with
            | Exp.Const (Cstr str) ->
                (* Common patterns that exclude line breaks *)
                String.is_substring str ~substring:"\\w*" ||
                String.is_substring str ~substring:"[^\\n\\r]" ||
                String.is_substring str ~substring:"[a-zA-Z0-9]"
            | _ -> false)
        else false
    | _ -> false

  (** Extract variable from expression if possible *)
  let get_var_from_exp exp =
    match exp with
    | Exp.Var id -> Some (Var.of_id id)
    | Exp.Lvar pvar -> Some (Var.of_pvar pvar)
    | _ -> None

  (** Check if any argument in actuals contains tainted data *)
  let has_tainted_arg actuals astate =
    List.exists actuals ~f:(fun (exp, _typ) ->
      match get_var_from_exp exp with
      | Some var -> LogInjectionDomain.is_var_tainted var astate
      | None -> false
    )

  (** Main transfer function *)
  let exec_instr (astate : LogInjectionDomain.t)
      ({InterproceduralAnalysis.proc_desc; err_log; _} as _analysis_data) _node _instr_index (instr : Sil.instr) =
    match instr with
    | Call ((return_id, _return_typ), Const (Cfun callee_proc_name), actuals, loc, _) ->
        (* Function call - handle both with and without return values *)
        let new_astate = 
          if is_user_input_source callee_proc_name then
            (* This is a call to a user input source - mark return variable as tainted *)
            let return_var = Var.of_id return_id in
            LogInjectionDomain.add_tainted_var return_var astate
          else if is_log_sanitizer callee_proc_name actuals then
            (* This is a sanitizer call - remove taint from return value *)
            astate  (* Simplified: should track sanitization more precisely *)
          else
            astate
        in
        if is_logging_sink callee_proc_name then
          (* Function call for logging - check if any argument contains tainted data *)
          if has_tainted_arg actuals new_astate then
            (* Report log injection vulnerability *)
            let message = "Log entry depends on user-controlled data that may contain line breaks, allowing log injection attacks" in
            Reporting.log_issue proc_desc err_log ~loc LogInjection IssueType.log_injection message ;
            new_astate
          else
            new_astate
        else
          new_astate
    | Load {id= lhs; e= rhs; typ= _lhs_typ; loc= _loc} ->
        (* Load operation: lhs = *rhs *)
        (match get_var_from_exp rhs with
        | Some rhs_var when LogInjectionDomain.is_var_tainted rhs_var astate ->
            (* Propagate taint from rhs to lhs *)
            let lhs_var = Var.of_id lhs in
            LogInjectionDomain.add_tainted_var lhs_var astate
        | _ ->
            astate)
    | Store {e1= lhs; e2= rhs; typ= _rhs_typ; loc= _loc} ->
        (* Store operation: *lhs = rhs *)
        (* Propagate taint from rhs to lhs if rhs is tainted *)
        (match get_var_from_exp rhs with
        | Some rhs_var when LogInjectionDomain.is_var_tainted rhs_var astate ->
            (* If storing to a variable, propagate taint *)
            (match get_var_from_exp lhs with
            | Some lhs_var ->
                LogInjectionDomain.add_tainted_var lhs_var astate
            | None ->
                astate)
        | _ ->
            astate)
    | Prune (_assume_exp, _loc, _, _) ->
        (* Conditional assumption - could be used to detect sanitization *)
        (* For now, we don't implement sanitization detection via guards *)
        astate
    | Call (_, call_exp, _actuals, loc, _) ->
        (* Indirect call - should not happen in Java *)
        L.die InternalError "Unexpected indirect call %a at %a" Exp.pp call_exp Location.pp loc
    | Metadata _ ->
        astate

  let pp_session_name _node fmt = Format.pp_print_string fmt "LogInjection"
end

module Analyzer = AbstractInterpreter.MakeRPO (TransferFunctions)

let checker ({InterproceduralAnalysis.proc_desc; _} as analysis_data) =
  let initial = LogInjectionDomain.empty in
  let final_state = Analyzer.compute_post analysis_data ~initial proc_desc in
  final_state