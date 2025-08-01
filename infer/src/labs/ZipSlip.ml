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
  module Domain = ZipSlipDomain

  type analysis_data = ZipSlipDomain.t InterproceduralAnalysis.t

  (** Check if a method call is ZipEntry.getName() or similar archive entry name methods *)
  let is_archive_entry_name_method procname =
    match procname with
    | Procname.Java java_procname ->
        let class_name = Procname.Java.get_class_name java_procname in
        let method_name = Procname.Java.get_method java_procname in
        (* Check for ZipEntry or ArchiveEntry classes and getName method *)
        (String.is_substring class_name ~substring:"ZipEntry"
         || String.is_substring class_name ~substring:"ArchiveEntry") 
        && String.equal method_name "getName"
    | _ ->
        false

  (** Check if a method call is a file creation operation *)
  let is_file_creation_method procname =
    match procname with
    | Procname.Java java_procname ->
        let class_name = Procname.Java.get_class_name java_procname in
        let method_name = Procname.Java.get_method java_procname in
        (* File constructors and file I/O operations *)
        (String.is_substring class_name ~substring:"File" && String.equal method_name "<init>")
        || (String.is_substring class_name ~substring:"FileOutputStream" && String.equal method_name "<init>")
        || (String.is_substring class_name ~substring:"FileInputStream" && String.equal method_name "<init>")
        || (String.is_substring class_name ~substring:"FileWriter" && String.equal method_name "<init>")
        || (String.is_substring class_name ~substring:"FileReader" && String.equal method_name "<init>")
        || (String.is_substring class_name ~substring:"PrintWriter" && String.equal method_name "<init>")
        || (String.is_substring class_name ~substring:"RandomAccessFile" && String.equal method_name "<init>")
        (* File operation methods like Files.copy, Files.move, etc. *)
        || (String.is_substring class_name ~substring:"Files" && 
            (String.equal method_name "copy" || String.equal method_name "move" 
             || String.equal method_name "write" || String.equal method_name "createFile"))
    | _ ->
        false

  (** Check if a string contains path traversal patterns *)
  let is_potentially_malicious_path path =
    String.is_substring path ~substring:".." 
    || String.is_prefix path ~prefix:"/"
    || String.is_prefix path ~prefix:"\\"

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
      | Some var -> ZipSlipDomain.is_var_tainted var astate
      | None -> false
    )

  (** Main transfer function *)
  let exec_instr (astate : ZipSlipDomain.t)
      ({InterproceduralAnalysis.proc_desc; err_log; tenv= _; analyze_dependency= _; _} as analysis_data) _ _
      (instr : Sil.instr) =
    match instr with
    | Call ((return_id, _), Const (Cfun callee_proc_name), actuals, loc, _) ->
        (* Function call with return value - check if it's an archive entry getName method *)
        if is_archive_entry_name_method callee_proc_name then
          (* This is a call to getName() on an archive entry - mark return variable as tainted *)
          let return_var = Var.of_id return_id in
          ZipSlipDomain.add_tainted_var return_var astate
        else if is_file_creation_method callee_proc_name then
          (* Function call for file creation - check if any argument contains tainted data *)
          if has_tainted_arg actuals astate then
            (* Report zip slip vulnerability *)
            let message = "Potential Zip Slip vulnerability: Archive entry name used in file creation without validation" in
            Reporting.log_issue proc_desc err_log ~loc ZipSlip IssueType.zip_slip message ;
            astate
          else
            astate
        else
          astate
    | Call (_, Const (Cfun callee_proc_name), actuals, loc, _) ->
        (* Function call without return value (void methods) *)
        if is_file_creation_method callee_proc_name then
          (* Function call for file creation - check if any argument contains tainted data *)
          if has_tainted_arg actuals astate then
            (* Report zip slip vulnerability *)
            let message = "Potential Zip Slip vulnerability: Archive entry name used in file creation without validation" in
            Reporting.log_issue proc_desc err_log ~loc ZipSlip IssueType.zip_slip message ;
            astate
          else
            astate
        else
          astate
    | Load {id= lhs; e= rhs; typ= _lhs_typ; loc= _loc} ->
        (* Load operation: lhs = *rhs *)
        (match get_var_from_exp rhs with
        | Some rhs_var when ZipSlipDomain.is_var_tainted rhs_var astate ->
            (* Propagate taint from rhs to lhs *)
            let lhs_var = Var.of_id lhs in
            ZipSlipDomain.add_tainted_var lhs_var astate
        | _ ->
            astate)
    | Store {e1= lhs; e2= rhs; typ= _rhs_typ; loc= _loc} ->
        (* Store operation: *lhs = rhs *)
        (* Propagate taint from rhs to lhs if rhs is tainted *)
        (match get_var_from_exp rhs with
        | Some rhs_var when ZipSlipDomain.is_var_tainted rhs_var astate ->
            (* If storing to a variable, propagate taint *)
            (match get_var_from_exp lhs with
            | Some lhs_var ->
                ZipSlipDomain.add_tainted_var lhs_var astate
            | None ->
                astate)
        | _ ->
            astate)
    | Prune (_assume_exp, _loc, _, _) ->
        (* Conditional assumption - could be used to detect validation *)
        (* For now, we don't implement sanitization detection *)
        astate
    | Call (_, call_exp, _actuals, loc, _) ->
        (* Indirect call - should not happen in Java *)
        L.die InternalError "Unexpected indirect call %a at %a" Exp.pp call_exp Location.pp loc
    | Metadata _ ->
        astate

  let pp_session_name _node fmt = F.pp_print_string fmt "zip slip"
end

(** Use normal CFG (without exceptional edges) *)
module CFG = ProcCfg.Normal

(** Create the abstract interpreter *)
module Analyzer = AbstractInterpreter.MakeRPO (TransferFunctions (CFG))

(** Report zip slip vulnerability if tainted data is found *)
let report_if_zip_slip {InterproceduralAnalysis.proc_desc; err_log; _} post =
  if ZipSlipDomain.has_tainted_data post then
    let last_loc = Procdesc.Node.get_loc (Procdesc.get_exit_node proc_desc) in
    let message = "Potential Zip Slip vulnerability detected: Archive entry names may be used unsafely" in
    Reporting.log_issue proc_desc err_log ~loc:last_loc ZipSlip IssueType.zip_slip message

(** Main checker entry point *)
let checker ({InterproceduralAnalysis.proc_desc} as analysis_data) =
  let result = Analyzer.compute_post analysis_data ~initial:ZipSlipDomain.initial proc_desc in
  Option.iter result ~f:(fun post -> report_if_zip_slip analysis_data post) ;
  result