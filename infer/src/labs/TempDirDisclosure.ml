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
  module Domain = TempDirDisclosureDomain

  type analysis_data = TempDirDisclosureDomain.t InterproceduralAnalysis.t

  (** Check if this is a call to System.getProperty("java.io.tmpdir") *)
  let is_temp_dir_system_property callee_proc_name actuals =
    String.is_suffix (Procname.get_method callee_proc_name) ~suffix:"getProperty" &&
    match actuals with
    | [(Exp.Const (Cstr property_name), _)] ->
        String.equal property_name "java.io.tmpdir"
    | _ -> false

  (** Extract variable from expression *)
  let get_var_from_exp = function
    | Exp.Var id -> Some (Var.of_id id)
    | Exp.Lvar pvar -> Some (Var.of_pvar pvar)
    | _ -> None

  (** Check if method is insecure file/directory creation in temp directory *)
  let is_insecure_temp_file_creation callee_proc_name =
    let method_name = Procname.get_method callee_proc_name in
    let class_name = Procname.get_class_type_name callee_proc_name in
    match class_name with
    | Some class_name when String.is_suffix (Typ.Name.to_string class_name) ~suffix:"File" ->
        String.equal method_name "createTempFile" ||
        String.equal method_name "mkdir" ||
        String.equal method_name "mkdirs" ||
        String.equal method_name "createNewFile"
    | Some class_name when String.is_suffix (Typ.Name.to_string class_name) ~suffix:"Files" ->
        String.equal method_name "createFile" ||
        String.equal method_name "createDirectory" ||
        String.equal method_name "createDirectories" ||
        String.equal method_name "write" ||
        String.equal method_name "newBufferedWriter" ||
        String.equal method_name "newOutputStream" ||
        String.equal method_name "newByteChannel"
    | _ -> 
        (* Google Guava Files.createTempDir *)
        String.is_suffix (Procname.to_string callee_proc_name) ~suffix:"Files.createTempDir"

  (** Check if any argument in actuals references a temp directory path *)
  let has_temp_dir_arg actuals astate =
    List.exists actuals ~f:(fun (exp, _) ->
      match get_var_from_exp exp with
      | Some var -> Domain.is_temp_dir_path var astate
      | None -> false
    )

  (** Check if method call has explicit FileAttribute permissions *)
  let has_explicit_file_attributes actuals =
    List.exists actuals ~f:(fun (exp, _) ->
      match exp with
      | Exp.Const _ -> false
      | _ -> 
          (* Look for calls that include FileAttribute parameters - simplified heuristic *)
          let exp_str = Exp.to_string exp in
          String.is_substring exp_str ~substring:"FileAttribute" ||
          String.is_substring exp_str ~substring:"PosixFilePermissions"
    )

  (** Check if this is File constructor with temp directory path *)
  let is_file_constructor_with_temp_dir callee_proc_name actuals astate =
    String.is_suffix (Procname.get_method callee_proc_name) ~suffix:"<init>" &&
    (match Procname.get_class_type_name callee_proc_name with
     | Some class_name when String.is_suffix (Typ.Name.to_string class_name) ~suffix:"File" ->
         has_temp_dir_arg actuals astate
     | _ -> false)

  (** Main transfer function *)
  let exec_instr (astate : Domain.t)
      ({InterproceduralAnalysis.proc_desc; err_log; _} as _analysis_data) _node _instr_index (instr : Sil.instr) =
    match instr with
    | Call ((return_id, _return_typ), Const (Cfun callee_proc_name), actuals, loc, _) ->
        (* Function call - handle both with and without return values *)
        let new_astate = 
          if is_temp_dir_system_property callee_proc_name actuals then
            (* This is a call to System.getProperty("java.io.tmpdir") - mark return variable as tainted *)
            let return_var = Var.of_id return_id in
            Domain.add_temp_dir_path return_var astate
          else if is_file_constructor_with_temp_dir callee_proc_name actuals astate then
            (* File constructor with temp directory path - mark return value as tainted *)
            let return_var = Var.of_id return_id in
            Domain.add_temp_dir_path return_var astate
          else
            astate
        in
        if is_insecure_temp_file_creation callee_proc_name then
          (* Check for insecure file/directory creation in temp directory *)
          if (has_temp_dir_arg actuals new_astate || 
              String.equal (Procname.get_method callee_proc_name) "createTempFile") && 
             not (has_explicit_file_attributes actuals) then
            (* Report temp directory information disclosure vulnerability *)
            let message = "Local information disclosure vulnerability due to file/directory creation in shared temporary directory without explicit permissions" in
            Reporting.log_issue proc_desc err_log ~loc TempDirDisclosure IssueType.temp_dir_local_information_disclosure message ;
            new_astate
          else
            new_astate
        else
          new_astate
    | Load {id= lhs; e= rhs; typ= _lhs_typ; loc= _loc} ->
        (* Load operation: lhs = *rhs *)
        (match get_var_from_exp rhs with
        | Some rhs_var when Domain.is_temp_dir_path rhs_var astate ->
            let lhs_var = Var.of_id lhs in
            Domain.add_temp_dir_path lhs_var astate
        | _ -> astate)
    | Store {e1= lhs; e2= rhs; typ= _; loc= _loc} ->
        (* Store operation: *lhs = rhs *)
        (match get_var_from_exp rhs, get_var_from_exp lhs with
        | Some rhs_var, Some lhs_var when Domain.is_temp_dir_path rhs_var astate ->
            Domain.add_temp_dir_path lhs_var astate
        | _ -> astate)
    | _ ->
        astate

  let pp_session_name _node fmt = Format.pp_print_string fmt "TempDirDisclosure"
end

module Analyzer = AbstractInterpreter.MakeRPO (TransferFunctions)

let checker ({InterproceduralAnalysis.proc_desc; _} as analysis_data) =
  let initial = TempDirDisclosureDomain.empty in
  let final_state = Analyzer.compute_post analysis_data ~initial proc_desc in
  final_state