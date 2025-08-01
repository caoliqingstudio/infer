(*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *)

open! IStd
module F = Format
module L = Logging

module TransferFunctions (CFG : ProcCfg.S) = struct
  module CFG = CFG
  module Domain = CsrfDomain

  type analysis_data = CsrfDomain.t InterproceduralAnalysis.t

  (** Check if a method has Spring Controller pattern and potentially unsafe name *)
  let is_unprotected_spring_method procname _tenv =
    match procname with
    | Procname.Java java_procname ->
        let class_name = Procname.Java.get_class_name java_procname in
        let method_name = Procname.Java.get_method java_procname in
        (* Look for Spring controller methods - simple pattern matching on class name and method names *)
        if String.is_substring class_name ~substring:"Controller" then
          (* Check for method names that suggest HTTP GET operations *)
          String.is_prefix (String.lowercase method_name) ~prefix:"get"
          || String.is_prefix (String.lowercase method_name) ~prefix:"show"
          || String.is_prefix (String.lowercase method_name) ~prefix:"view"
          || String.is_prefix (String.lowercase method_name) ~prefix:"list"
          || String.is_prefix (String.lowercase method_name) ~prefix:"find"
        else false
    | _ -> false

  (** Check if method name suggests state-changing operation *)
  let has_state_changing_name method_name =
    let state_change_keywords = [
      "post"; "put"; "patch"; "delete"; "remove"; "create"; "add"; "update"; 
      "edit"; "publish"; "unpublish"; "fill"; "move"; "transfer"; "logout"; 
      "login"; "access"; "connect"; "connection"; "register"; "submit"
    ] in
    let read_only_keywords = ["get"; "show"; "view"; "list"; "query"; "find"] in
    (* Check if method starts with read-only keywords *)
    let is_read_only = List.exists read_only_keywords ~f:(fun keyword ->
      String.is_prefix (String.lowercase method_name) ~prefix:(String.lowercase keyword)
    ) in
    if is_read_only then false
    else
      (* Check if method contains state-changing keywords *)
      List.exists state_change_keywords ~f:(fun keyword ->
        String.is_substring (String.lowercase method_name) ~substring:(String.lowercase keyword)
      )

  (** Check if a method call is a database update operation *)
  let is_database_update_method procname =
    match procname with
    | Procname.Java java_procname ->
        let class_name = Procname.Java.get_class_name java_procname in
        let method_name = Procname.Java.get_method java_procname in
        (* MyBatis operations *)
        (String.is_substring class_name ~substring:"Mapper" && 
         (String.equal method_name "insert" || String.equal method_name "update" || 
          String.equal method_name "delete"))
        (* JDBC PreparedStatement operations *)
        || (String.is_substring class_name ~substring:"PreparedStatement" && 
            (String.equal method_name "executeUpdate" || String.equal method_name "executeLargeUpdate"))
        (* General SQL operations *)
        || List.exists ["delete"; "insert"; "update"; "batchUpdate"; "executeUpdate"; "executeLargeUpdate"; "execute"] 
             ~f:(String.equal method_name)
    | _ -> false

  (** Main transfer function *)
  let exec_instr (astate : CsrfDomain.t)
      ({InterproceduralAnalysis.proc_desc; err_log; tenv; analyze_dependency= _; _} as _analysis_data) _node _instr_index
      (instr : Sil.instr) =
    match instr with
    | Call (_, Const (Cfun callee_proc_name), _actuals, loc, _) ->
        let current_procname = Procdesc.get_proc_name proc_desc in
        
        (* Check if we're in an unprotected request handler method *)
        let updated_astate = 
          if is_unprotected_spring_method current_procname tenv then
            CsrfDomain.mark_unprotected_request astate
          else astate
        in

        let final_astate = 
          (* Check if this is a state-changing operation *)
          if is_database_update_method callee_proc_name then
            CsrfDomain.mark_state_change updated_astate
          else
            let java_method_name = match callee_proc_name with
              | Procname.Java java_procname -> Procname.Java.get_method java_procname
              | _ -> ""
            in
            if has_state_changing_name java_method_name then
              CsrfDomain.mark_state_change updated_astate
            else updated_astate
        in

        (* Check for CSRF vulnerability *)
        if CsrfDomain.is_vulnerable final_astate then (
          let message = "Potential CSRF vulnerability: Unprotected HTTP request handler performs state-changing operation" in
          Reporting.log_issue proc_desc err_log ~loc Csrf IssueType.csrf_vulnerability message
        );
        
        final_astate

    | Load {id= _lhs; e= _rhs; typ= _lhs_typ; loc= _loc} ->
        astate
    | Store {e1= _lhs; e2= _rhs; typ= _rhs_typ; loc= _loc} ->
        astate
    | Prune (_assume_exp, _loc, _, _) ->
        astate
    | Call (_, call_exp, _actuals, loc, _) ->
        L.die InternalError "Unexpected indirect call %a at %a" Exp.pp call_exp Location.pp loc
    | Metadata _ ->
        astate

  let pp_session_name _node fmt = F.pp_print_string fmt "csrf"
end

(** Use normal CFG (without exceptional edges) *)
module CFG = ProcCfg.Normal

(** Create the abstract interpreter *)
module Analyzer = AbstractInterpreter.MakeRPO (TransferFunctions (CFG))

(** Main checker entry point *)
let checker ({InterproceduralAnalysis.proc_desc} as analysis_data) =
  let result = Analyzer.compute_post analysis_data ~initial:CsrfDomain.initial proc_desc in
  result