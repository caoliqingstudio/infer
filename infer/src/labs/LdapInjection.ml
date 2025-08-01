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
  module Domain = LdapInjectionDomain

  type analysis_data = LdapInjectionDomain.t InterproceduralAnalysis.t

  (** Check if method call is a source of user-controlled data *)
  let is_user_input_source procname =
    match procname with
    | Procname.Java java_procname ->
        let method_name = Procname.Java.get_method java_procname in
        let class_name = Procname.Java.get_class_name java_procname in
        (* HTTP request parameter methods *)
        (String.is_substring class_name ~substring:"ServletRequest" && 
         (String.equal method_name "getParameter" || String.equal method_name "getHeader")) ||
        (* Spring request parameter methods *)
        (String.is_substring class_name ~substring:"RequestParam" || 
         String.is_substring class_name ~substring:"PathVariable") ||
        (* General web input methods *)
        (String.equal method_name "getParameter" || String.equal method_name "getHeader" ||
         String.equal method_name "getAttribute" || String.equal method_name "getQueryString")
    | _ -> false

  (** Check if method name suggests user input (for Spring @RequestParam methods) *)
  let is_user_input_method method_name =
    let user_input_patterns = [
      "getParameter"; "getHeader"; "getAttribute"; "getQueryString";
      "getRequestParam"; "getPathVariable"; "getUserInput"
    ] in
    List.exists user_input_patterns ~f:(String.equal method_name)

  (** Check if method call is an LDAP query execution sink *)
  let is_ldap_query_sink procname =
    match procname with
    | Procname.Java java_procname ->
        let method_name = Procname.Java.get_method java_procname in
        let class_name = Procname.Java.get_class_name java_procname in
        (* JNDI LDAP operations *)
        (String.is_substring class_name ~substring:"DirContext" && String.equal method_name "search") ||
        (String.is_substring class_name ~substring:"LdapContext" && String.equal method_name "search") ||
        (String.is_substring class_name ~substring:"InitialDirContext" && String.equal method_name "search") ||
        (String.is_substring class_name ~substring:"InitialLdapContext" && String.equal method_name "search") ||
        (* Spring LDAP operations *)
        (String.is_substring class_name ~substring:"LdapTemplate" && 
         (String.equal method_name "search" || String.equal method_name "searchForObject" ||
          String.equal method_name "searchForContext")) ||
        (* UnboundID LDAP operations *)
        (String.is_substring class_name ~substring:"LDAPConnection" && String.equal method_name "search") ||
        (String.is_substring class_name ~substring:"SearchRequest" && 
         (String.equal method_name "setFilter" || String.equal method_name "setBase")) ||
        (* Apache LDAP API operations *)
        (String.is_substring class_name ~substring:"LdapConnection" && String.equal method_name "search")
    | _ -> false

  (** Check if string concatenation could create LDAP query with user data *)
  let is_string_concatenation_with_ldap_pattern str =
    (* Look for LDAP filter patterns like (uid=, (cn=, etc. *)
    String.is_substring str ~substring:"(uid=" ||
    String.is_substring str ~substring:"(cn=" ||
    String.is_substring str ~substring:"(mail=" ||
    String.is_substring str ~substring:"(sn=" ||
    String.is_substring str ~substring:"(objectClass=" ||
    String.is_substring str ~substring:"ou=" ||
    String.is_substring str ~substring:"dc="

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
      | Some var -> LdapInjectionDomain.is_var_tainted var astate
      | None -> false
    )

  (** Check if expression contains string literal with LDAP pattern *)
  let has_ldap_pattern_in_args actuals =
    List.exists actuals ~f:(fun (exp, _typ) ->
      match exp with
      | Exp.Const (Cstr str) -> is_string_concatenation_with_ldap_pattern str
      | _ -> false
    )

  (** Main transfer function *)
  let exec_instr (astate : LdapInjectionDomain.t)
      ({InterproceduralAnalysis.proc_desc; err_log; tenv= _; analyze_dependency= _; _} as _analysis_data) _node _instr_index
      (instr : Sil.instr) =
    match instr with
    | Call ((return_id, return_typ), Const (Cfun callee_proc_name), actuals, loc, _) ->
        (* Function call - handle both with and without return values *)
        let new_astate = 
          if is_user_input_source callee_proc_name then
            (* This is a call to a user input source - mark return variable as tainted *)
            let return_var = Var.of_id return_id in
            LdapInjectionDomain.add_tainted_var return_var astate
          else
            astate
        in
        if is_ldap_query_sink callee_proc_name then
          (* Function call for LDAP query - check if any argument contains tainted data *)
          if (has_tainted_arg actuals new_astate || has_ldap_pattern_in_args actuals) && 
             has_tainted_arg actuals new_astate then
            (* Report LDAP injection vulnerability *)
            let message = "LDAP query built from user-controlled sources" in
            Reporting.log_issue proc_desc err_log ~loc LdapInjection IssueType.ldap_injection message ;
            new_astate
          else
            new_astate
        else
          new_astate
    | Load {id= lhs; e= rhs; typ= _lhs_typ; loc= _loc} ->
        (* Load operation: lhs = *rhs *)
        (match get_var_from_exp rhs with
        | Some rhs_var when LdapInjectionDomain.is_var_tainted rhs_var astate ->
            (* Propagate taint from rhs to lhs *)
            let lhs_var = Var.of_id lhs in
            LdapInjectionDomain.add_tainted_var lhs_var astate
        | _ ->
            astate)
    | Store {e1= lhs; e2= rhs; typ= _rhs_typ; loc= _loc} ->
        (* Store operation: *lhs = rhs *)
        (* Propagate taint from rhs to lhs if rhs is tainted *)
        (match get_var_from_exp rhs with
        | Some rhs_var when LdapInjectionDomain.is_var_tainted rhs_var astate ->
            (* If storing to a variable, propagate taint *)
            (match get_var_from_exp lhs with
            | Some lhs_var ->
                LdapInjectionDomain.add_tainted_var lhs_var astate
            | None ->
                astate)
        | _ ->
            astate)
    | Prune (_assume_exp, _loc, _, _) ->
        (* Conditional assumption - could be used to detect sanitization *)
        (* For now, we don't implement sanitization detection *)
        astate
    | Call (_, call_exp, _actuals, loc, _) ->
        (* Indirect call - should not happen in Java *)
        L.die InternalError "Unexpected indirect call %a at %a" Exp.pp call_exp Location.pp loc
    | Metadata _ ->
        astate

  let pp_session_name _node fmt = F.pp_print_string fmt "ldap injection"
end

(** Use normal CFG (without exceptional edges) *)
module CFG = ProcCfg.Normal

(** Create the abstract interpreter *)
module Analyzer = AbstractInterpreter.MakeRPO (TransferFunctions (CFG))

(** Main checker entry point *)
let checker ({InterproceduralAnalysis.proc_desc} as analysis_data) =
  let result = Analyzer.compute_post analysis_data ~initial:LdapInjectionDomain.initial proc_desc in
  result