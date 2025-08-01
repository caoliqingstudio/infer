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
  module Domain = PartialPathTraversalDomain

  type analysis_data = PartialPathTraversalDomain.t InterproceduralAnalysis.t

  (** Check if this is a call to File.getCanonicalPath() *)
  let is_get_canonical_path_call procname =
    match procname with
    | Procname.Java java_procname ->
        let method_name = Procname.Java.get_method java_procname in
        let class_name = Procname.Java.get_class_name java_procname in
        String.equal method_name "getCanonicalPath" && 
        (String.equal class_name "java.io.File" ||
         String.is_suffix class_name ~suffix:".File")
    | _ -> false

  (** Check if this is a call to String.startsWith() *)
  let is_string_starts_with_call procname =
    match procname with
    | Procname.Java java_procname ->
        let method_name = Procname.Java.get_method java_procname in
        let class_name = Procname.Java.get_class_name java_procname in
        String.equal method_name "startsWith" && 
        (String.equal class_name "java.lang.String" ||
         String.is_suffix class_name ~suffix:".String")
    | _ -> false

  (** Check if expression is a safe separator (File.separator, File.separatorChar, "/", '\', etc.) *)
  let is_file_separator_expr exp =
    match exp with
    | Exp.Const (Cstr str) ->
        String.equal str "/" || String.equal str "\\" || String.equal str "\\\\"
    | Exp.Const (Cint n) ->
        (match IntLit.to_int n with
        | Some n_int -> Int.equal n_int 47 || Int.equal n_int 92  (* '/' = 47, '\' = 92 *)
        | None -> false)
    | _ -> false

  (** Check if expression is a field access to File.separator or File.separatorChar *)
  let is_file_separator_field_access exp =
    match exp with
    | Exp.Lfield (_, fieldname, _) ->
        let field_str = Fieldname.to_simplified_string fieldname in
        String.equal field_str "separator" || String.equal field_str "separatorChar"
    | _ -> false

  (** Check if expression represents a safe separator concatenation *)
  let is_safe_separator_concatenation exp =
    match exp with
    | Exp.BinOp (PlusA _, left_exp, right_exp) ->
        is_file_separator_expr right_exp || 
        is_file_separator_field_access right_exp ||
        is_file_separator_expr left_exp ||
        is_file_separator_field_access left_exp
    | _ -> false

  (** Check if the argument to startsWith is properly slash-terminated *)
  let is_argument_safe_for_startswith exp astate =
    match exp with
    | Exp.Var id ->
        let var = Var.of_id id in
        (* If it's a canonical path variable and not properly terminated, it's unsafe *)
        not (PartialPathTraversalDomain.is_canonical_path var astate)
    | Exp.Lvar pvar ->
        let var = Var.of_pvar pvar in
        not (PartialPathTraversalDomain.is_canonical_path var astate)
    | _ when is_safe_separator_concatenation exp ->
        true  (* Safe if it includes separator concatenation *)
    | _ -> 
        true  (* Conservative: assume other expressions are safe *)

  (** Extract variable from expression if possible *)
  let get_var_from_exp exp =
    match exp with
    | Exp.Var id -> Some (Var.of_id id)
    | Exp.Lvar pvar -> Some (Var.of_pvar pvar)
    | _ -> None

  (** Check if the qualifier (string being checked) is a canonical path *)
  let is_qualifier_canonical_path exp astate =
    match get_var_from_exp exp with
    | Some var -> PartialPathTraversalDomain.is_canonical_path var astate
    | None -> false

  (** Main transfer function *)
  let exec_instr (astate: PartialPathTraversalDomain.t)
      ({InterproceduralAnalysis.proc_desc; err_log; _} as _analysis_data) _node _instr_index (instr : Sil.instr) =
    match instr with
    | Call ((return_id, _return_typ), Const (Cfun callee_proc_name), actuals, loc, _) ->
        let new_astate = 
          if is_get_canonical_path_call callee_proc_name then
            (* This is a call to getCanonicalPath() - mark return variable as canonical path *)
            let return_var = Var.of_id return_id in
            PartialPathTraversalDomain.add_canonical_path return_var astate
          else
            astate
        in
        if is_string_starts_with_call callee_proc_name then
          (* This is a call to String.startsWith() - check for partial path traversal *)
          match actuals with
          | [(qualifier_exp, _); (prefix_exp, _)] ->
              (* Check if qualifier is a canonical path and prefix is not safe *)
              if is_qualifier_canonical_path qualifier_exp new_astate && 
                 not (is_argument_safe_for_startswith prefix_exp new_astate) then
                (* Report partial path traversal vulnerability *)
                let message = "Partial Path Traversal Vulnerability due to insufficient guard against path traversal. The prefix used to check that a canonicalised path falls within another must be slash-terminated." in
                Reporting.log_issue proc_desc err_log ~loc PartialPathTraversal IssueType.partial_path_traversal message ;
                new_astate
              else
                new_astate
          | _ ->
              new_astate
        else
          new_astate
    | Load {id= lhs; e= rhs; typ= _lhs_typ; loc= _loc} ->
        (* Load operation: lhs = *rhs *)
        (match get_var_from_exp rhs with
        | Some rhs_var when PartialPathTraversalDomain.is_canonical_path rhs_var astate ->
            (* Propagate canonical path from rhs to lhs *)
            let lhs_var = Var.of_id lhs in
            PartialPathTraversalDomain.add_canonical_path lhs_var astate
        | _ ->
            astate)
    | Store {e1= lhs; e2= rhs; typ= _rhs_typ; loc= _loc} ->
        (* Store operation: *lhs = rhs *)
        (* Propagate canonical path from rhs to lhs if rhs is canonical path *)
        (match get_var_from_exp rhs with
        | Some rhs_var when PartialPathTraversalDomain.is_canonical_path rhs_var astate ->
            (* If storing to a variable, propagate canonical path *)
            (match get_var_from_exp lhs with
            | Some lhs_var ->
                PartialPathTraversalDomain.add_canonical_path lhs_var astate
            | None ->
                astate)
        | _ ->
            astate)
    | Prune (_assume_exp, _loc, _, _) ->
        (* Conditional assumption - no specific handling needed *)
        astate
    | Call (_, call_exp, _actuals, loc, _) ->
        (* Indirect call - should not happen in Java *)
        L.die InternalError "Unexpected indirect call %a at %a" Exp.pp call_exp Location.pp loc
    | Metadata _ ->
        astate

  let pp_session_name _node fmt = Format.pp_print_string fmt "PartialPathTraversal"
end

module Analyzer = AbstractInterpreter.MakeRPO (TransferFunctions)

let checker ({InterproceduralAnalysis.proc_desc; _} as analysis_data) =
  let initial = PartialPathTraversalDomain.empty in
  let final_state = Analyzer.compute_post analysis_data ~initial proc_desc in
  final_state