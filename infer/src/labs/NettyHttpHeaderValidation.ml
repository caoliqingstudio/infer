(*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *)

open! IStd
module F = Format

module TransferFunctions (CFG : ProcCfg.S) = struct
  module CFG = CFG
  module Domain = NettyHttpHeaderValidationDomain

  type analysis_data = NettyHttpHeaderValidationDomain.t InterproceduralAnalysis.t

  let vulnerable_netty_classes = [
    ("io.netty.handler.codec.http.DefaultHttpHeaders", [0]);
    ("io.netty.handler.codec.http.CombinedHttpHeaders", [0]);
    ("io.netty.handler.codec.http.DefaultHttpResponse", [2]);
    ("io.netty.handler.codec.http.DefaultHttpRequest", [3]);
    ("io.netty.handler.codec.http.DefaultFullHttpResponse", [2; 3]);
    ("io.netty.handler.codec.http.DefaultFullHttpRequest", [3; 4]);
  ]

  let is_vulnerable_netty_constructor proc_name =
    let class_name = Procname.get_class_type_name proc_name in
    match class_name with
    | Some typ_name ->
        let full_class_name = Typ.Name.name typ_name in
        (* Debug: Print the class name we found *)
        L.debug Analysis Verbose "NettyHttpHeaderValidation: Found class name: %s@." full_class_name ;
        List.find vulnerable_netty_classes ~f:(fun (class_str, _) -> String.equal full_class_name class_str)
    | None -> None

  let check_constructor_args args vulnerable_indices location proc_desc err_log =
    List.iter vulnerable_indices ~f:(fun index ->
      if index < List.length args then
        match List.nth args index with
        | Some (Exp.Const (Cint i), _) when IntLit.iszero i ->
            let message = F.asprintf "Netty HTTP header validation disabled (validateHeaders=false)" in
            let issue_type = IssueType.netty_http_header_validation_disabled in
            Reporting.log_issue proc_desc err_log ~loc:location NettyHttpHeaderValidation issue_type message
        | _ -> ()
      )

  let exec_instr (astate : Domain.t) 
      ({InterproceduralAnalysis.proc_desc; err_log; tenv= _; analyze_dependency= _; _}) _ _
      (instr : Sil.instr) =
    match instr with
    | Call (_, Const (Cfun proc_name), args, location, _) ->
        (match is_vulnerable_netty_constructor proc_name with
        | Some (_, vulnerable_indices) ->
            check_constructor_args args vulnerable_indices location proc_desc err_log;
            astate
        | None -> astate)
    | _ -> astate

  let pp_session_name _node fmt = F.pp_print_string fmt "NettyHttpHeaderValidation"
end

module CFG = ProcCfg.Normal
module Analyzer = AbstractInterpreter.MakeRPO (TransferFunctions (CFG))

let checker ({InterproceduralAnalysis.proc_desc; _} as analysis_data) =
  let initial_state = NettyHttpHeaderValidationDomain.bottom in
  Analyzer.compute_post analysis_data ~initial:initial_state proc_desc