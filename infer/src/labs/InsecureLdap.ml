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
  module Domain = InsecureLdapDomain

  type analysis_data = InsecureLdapDomain.t InterproceduralAnalysis.t

  (** Check if a string literal contains insecure LDAP URL (ldap://) *)
  let is_insecure_ldap_url_literal str =
    String.is_prefix (String.lowercase str) ~prefix:"ldap://" &&
    (* Exclude localhost and private addresses to reduce false positives *)
    not (String.is_substring (String.lowercase str) ~substring:"localhost") &&
    not (String.is_substring (String.lowercase str) ~substring:"127.0.0.1") &&
    not (String.is_substring (String.lowercase str) ~substring:"::1")

  (** Check if string concatenation creates insecure LDAP URL *)
  let is_insecure_ldap_concatenation left_str =
    String.equal (String.lowercase left_str) "ldap://"

  (** Check if method call sets basic authentication (simple) *)
  let is_basic_auth_setter procname args =
    match procname with
    | Procname.Java java_procname ->
        let method_name = Procname.Java.get_method java_procname in
        let class_name = Procname.Java.get_class_name java_procname in
        if (String.equal method_name "put" || String.equal method_name "setProperty") &&
           String.is_substring class_name ~substring:"Hashtable" &&
           List.length args >= 2 then
          match List.nth args 0, List.nth args 1 with
          | Some (key_exp, _), Some (value_exp, _) ->
              (match key_exp, value_exp with
              | Exp.Const (Cstr key_str), Exp.Const (Cstr value_str) ->
                  (String.equal key_str "java.naming.security.authentication" ||
                   String.is_suffix key_str ~suffix:"SECURITY_AUTHENTICATION") &&
                  String.equal value_str "simple"
              | _ -> false)
          | _ -> false
        else false
    | _ -> false

  (** Check if method call enables SSL protocol *)
  let is_ssl_enabler procname args =
    match procname with
    | Procname.Java java_procname ->
        let method_name = Procname.Java.get_method java_procname in
        let class_name = Procname.Java.get_class_name java_procname in
        if (String.equal method_name "put" || String.equal method_name "setProperty") &&
           String.is_substring class_name ~substring:"Hashtable" &&
           List.length args >= 2 then
          match List.nth args 0, List.nth args 1 with
          | Some (key_exp, _), Some (value_exp, _) ->
              (match key_exp, value_exp with
              | Exp.Const (Cstr key_str), Exp.Const (Cstr value_str) ->
                  (String.equal key_str "java.naming.security.protocol" ||
                   String.is_suffix key_str ~suffix:"SECURITY_PROTOCOL") &&
                  String.equal value_str "ssl"
              | _ -> false)
          | _ -> false
        else false
    | _ -> false

  (** Check if method call is LDAP context constructor (sink) *)
  let is_ldap_context_constructor procname =
    match procname with
    | Procname.Java java_procname ->
        let class_name = Procname.Java.get_class_name java_procname in
        let method_name = Procname.Java.get_method java_procname in
        String.equal method_name "<init>" &&
        (String.equal class_name "javax.naming.directory.InitialDirContext" ||
         String.equal class_name "javax.naming.ldap.InitialLdapContext" ||
         String.is_suffix class_name ~suffix:"DirContext")
    | _ -> false

  (** Extract variable from expression if possible *)
  let get_var_from_exp exp =
    match exp with
    | Exp.Var id -> Some (Var.of_id id)
    | Exp.Lvar pvar -> Some (Var.of_pvar pvar)
    | _ -> None

  (** Main transfer function *)
  let exec_instr (astate : InsecureLdapDomain.t)
      ({InterproceduralAnalysis.proc_desc; err_log; tenv= _; analyze_dependency= _; _} as _analysis_data) _node _instr_index
      (instr : Sil.instr) =
    match instr with
    | Call (_, Const (Cfun callee_proc_name), actuals, loc, _) ->
        let updated_astate = ref astate in
        
        (* Check for insecure LDAP URL in string literals *)
        List.iter actuals ~f:(fun (exp, _typ) ->
          match exp with
          | Exp.Const (Cstr str) ->
              if is_insecure_ldap_url_literal str then
                updated_astate := InsecureLdapDomain.mark_insecure_ldap_url !updated_astate
          | _ -> ()
        );
        
        (* Check for basic authentication setter *) 
        if is_basic_auth_setter callee_proc_name actuals then
          updated_astate := InsecureLdapDomain.mark_basic_auth !updated_astate;
        
        (* Check for SSL enabler *)
        if is_ssl_enabler callee_proc_name actuals then
          updated_astate := InsecureLdapDomain.mark_ssl_enabled !updated_astate;

        (* Check if this is LDAP context constructor (sink) *)
        if is_ldap_context_constructor callee_proc_name then (
          if InsecureLdapDomain.is_vulnerable !updated_astate then (
            let message = "Insecure LDAP authentication: Using ldap:// URL with basic authentication without SSL" in
            Reporting.log_issue proc_desc err_log ~loc InsecureLdap IssueType.insecure_ldap_auth message
          )
        );
        
        !updated_astate

    | Load {id= _lhs; e= _rhs; typ= _lhs_typ; loc= _loc} ->
        astate
    | Store {e1= _lhs; e2= rhs; typ= _rhs_typ; loc= _loc} ->
        (* Check for insecure LDAP URL in store operations *)  
        (match rhs with
        | Exp.Const (Cstr str) ->
            if is_insecure_ldap_url_literal str then
              InsecureLdapDomain.mark_insecure_ldap_url astate
            else astate
        | _ -> astate)
    | Prune (_assume_exp, _loc, _, _) ->
        astate
    | Call (_, call_exp, _actuals, loc, _) ->
        L.die InternalError "Unexpected indirect call %a at %a" Exp.pp call_exp Location.pp loc
    | Metadata _ ->
        astate

  let pp_session_name _node fmt = F.pp_print_string fmt "insecure ldap"
end

(** Use normal CFG (without exceptional edges) *)
module CFG = ProcCfg.Normal

(** Create the abstract interpreter *)
module Analyzer = AbstractInterpreter.MakeRPO (TransferFunctions (CFG))

(** Main checker entry point *)
let checker ({InterproceduralAnalysis.proc_desc} as analysis_data) =
  let result = Analyzer.compute_post analysis_data ~initial:InsecureLdapDomain.initial proc_desc in
  result