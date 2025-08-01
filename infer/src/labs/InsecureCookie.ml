(*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *)

open! IStd
module F = Format
module L = Logging

module Domain = InsecureCookieDomain

let initial_state = {InsecureCookieDomain.secure_cookies = Var.Set.empty}

let is_cookie_constructor procname =
  match Procname.get_class_name procname with
  | Some class_name -> String.is_suffix class_name ~suffix:"Cookie" &&
                      String.equal (Procname.get_method procname) "<init>"
  | None -> false

let is_set_secure_method procname =
  match Procname.get_class_name procname with
  | Some class_name -> String.is_suffix class_name ~suffix:"Cookie" &&
                      String.equal (Procname.get_method procname) "setSecure"
  | None -> false

let is_add_cookie_method procname =
  match Procname.get_class_name procname with
  | Some class_name -> String.is_suffix class_name ~suffix:"HttpServletResponse" &&
                      String.equal (Procname.get_method procname) "addCookie"
  | None -> false

let is_secure_value_true exp =
  match exp with
  | Exp.Const (Const.Cint i) -> IntLit.isone i
  | _ -> false

let get_cookie_variable_from_call args =
  match args with
  | (Exp.Var id, _) :: _ -> Some (Var.of_id id)
  | _ -> None

let get_cookie_variable_from_receiver exp =
  match exp with
  | Exp.Lvar pvar -> Some (Var.of_pvar pvar)
  | Exp.Var id -> Some (Var.of_id id)
  | _ -> None

module TransferFunctions (CFG : ProcCfg.S) = struct
  module CFG = CFG
  module Domain = Domain

  type analysis_data = Domain.t InterproceduralAnalysis.t

  let exec_instr (astate : Domain.t) ({InterproceduralAnalysis.proc_desc; err_log; tenv= _; analyze_dependency= _; _} as analysis_data) (node : CFG.Node.t)
      (instr_index : int) (instr : Sil.instr) =
    let proc_name = Procdesc.get_proc_name proc_desc in
    
    match instr with
    | Call (ret_id_typ_opt, Const (Cfun callee_proc_name), args, loc, _) ->
        if is_set_secure_method callee_proc_name then (
          match (args, get_cookie_variable_from_receiver (List.hd_exn args |> fst)) with
          | (receiver_exp, _) :: (arg_exp, _) :: _, Some cookie_var ->
              if is_secure_value_true arg_exp then
                Domain.add_secure_cookie cookie_var astate
              else
                astate
          | _ -> astate
        )
        else if is_add_cookie_method callee_proc_name then (
          match args with
          | (cookie_exp, _) :: _ ->
              let cookie_var_opt = get_cookie_variable_from_receiver cookie_exp in
              (match cookie_var_opt with
              | Some cookie_var ->
                  if not (Domain.has_secure_cookie cookie_var astate) then (
                    let message = "Cookie added to HttpServletResponse without 'secure' flag set" in
                    Reporting.log_issue proc_desc err_log ~loc InsecureCookie IssueType.insecure_cookie message
                  );
                  astate
              | None -> astate)
          | _ -> astate
        )
        else astate
    | _ -> astate

  let pp_session_name node fmt =
    F.fprintf fmt "InsecureCookie %a" CFG.Node.pp_id (CFG.Node.id node)
end

module CFG = ProcCfg.Normal
module Analyzer = AbstractInterpreter.MakeRPO (TransferFunctions (CFG))

let checker ({InterproceduralAnalysis.proc_desc} as analysis_data) =
  let result = Analyzer.compute_post analysis_data ~initial:initial_state proc_desc in
  result