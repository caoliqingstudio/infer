(**
 * Weak Cryptographic Algorithm detector for Infer
 * 
 * Detects when potentially weak or risky cryptographic algorithms are used
 * in Java cryptographic APIs (CWE-327, CWE-328).
 * 
 * Sources: String literals containing weak algorithm names
 * Sinks: Cryptographic API calls (Cipher.getInstance, KeyGenerator.getInstance, etc.)
 * 
 * Based on CodeQL rule: "Use of a potentially broken or risky cryptographic algorithm"
 *)

open! IStd
module F = Format

module Domain = WeakCryptoDomain

(** Check if method call is a source of weak algorithm strings *)
let is_crypto_algo_source proc_name =
  match proc_name with
  | Procname.Java java_proc_name ->
    let class_name = Procname.Java.get_class_name java_proc_name in
    let method_name = Procname.Java.get_method java_proc_name in
    (* Properties.getProperty calls that might return algorithm names *)
    (String.is_substring class_name ~substring:"Properties" &&
     String.equal method_name "getProperty") ||
    (* System.getProperty calls *)
    (String.equal class_name "java.lang.System" &&
     String.equal method_name "getProperty")
  | _ -> false

(** Check if method call is a cryptographic API sink *)
let is_crypto_api_sink proc_name =
  match proc_name with
  | Procname.Java java_proc_name ->
    let class_name = Procname.Java.get_class_name java_proc_name in
    let method_name = Procname.Java.get_method java_proc_name in
    (* javax.crypto.Cipher.getInstance *)
    (String.equal class_name "javax.crypto.Cipher" &&
     String.equal method_name "getInstance") ||
    (* javax.crypto.KeyGenerator.getInstance *)
    (String.equal class_name "javax.crypto.KeyGenerator" &&
     String.equal method_name "getInstance") ||
    (* javax.crypto.KeyAgreement.getInstance *)
    (String.equal class_name "javax.crypto.KeyAgreement" &&
     String.equal method_name "getInstance") ||
    (* javax.crypto.SecretKeyFactory.getInstance *)
    (String.equal class_name "javax.crypto.SecretKeyFactory" &&
     String.equal method_name "getInstance") ||
    (* java.security.MessageDigest.getInstance *)
    (String.equal class_name "java.security.MessageDigest" &&
     String.equal method_name "getInstance") ||
    (* java.security.KeyPairGenerator.getInstance *)
    (String.equal class_name "java.security.KeyPairGenerator" &&
     String.equal method_name "getInstance") ||
    (* java.security.AlgorithmParameterGenerator.getInstance *)
    (String.equal class_name "java.security.AlgorithmParameterGenerator" &&
     String.equal method_name "getInstance") ||
    (* javax.crypto.spec.SecretKeySpec constructor *)
    (String.equal class_name "javax.crypto.spec.SecretKeySpec" &&
     String.equal method_name "<init>")
  | _ -> false

(** Extract string literal value from expression *)
let get_string_literal_value exp =
  match exp with
  | Exp.Const (Const.Cstr s) -> Some s
  | _ -> None

(** Check if any argument is a weak algorithm string literal *)
let has_weak_algo_literal actuals =
  List.find_map actuals ~f:(fun (exp, _) ->
    match get_string_literal_value exp with
    | Some s when Domain.is_potentially_weak_algorithm s -> Some s
    | _ -> None)

(** Check if any argument is a tainted variable *)
let has_tainted_arg actuals astate =
  List.exists actuals ~f:(fun (exp, _) ->
    match exp with
    | Exp.Var id -> 
      let var = Var.of_id id in
      Domain.is_var_tainted var astate
    | _ -> false)

let exec_instr (astate : Domain.t) ({InterproceduralAnalysis.proc_desc; err_log; _} : Domain.t InterproceduralAnalysis.t) _node _kind (instr : Sil.instr) =
  match instr with
  | Call ((return_id, _), Const (Cfun callee_proc_name), actuals, loc, _) ->
    if is_crypto_algo_source callee_proc_name then
      (* Mark return value as potentially tainted *)
      let dest_var = Var.of_id return_id in
      Domain.add_tainted_var dest_var astate
    else if is_crypto_api_sink callee_proc_name then
      (* Check for weak algorithm usage *)
      let weak_algo_opt = has_weak_algo_literal actuals in
      let has_tainted = has_tainted_arg actuals astate in
      
      if Option.is_some weak_algo_opt || has_tainted then (
        let algo_name = 
          match weak_algo_opt with
          | Some s -> s
          | None -> "unknown algorithm"
        in
        let message = 
          F.asprintf "Cryptographic algorithm '%s' may not be secure. Consider using a different algorithm such as AES-256 or RSA-2048." algo_name
        in
        Reporting.log_issue proc_desc err_log WeakCrypto IssueType.weak_cryptographic_algorithm ~loc message
      );
      astate
    else
      astate
  | Store {e1= Lvar pvar; e2= Exp.Var id} ->
    (* Handle variable assignments - propagate taint *)
    let source_var = Var.of_id id in
    let dest_var = Var.of_pvar pvar in
    if Domain.is_var_tainted source_var astate then
      Domain.add_tainted_var dest_var astate
    else
      astate
  | Load {id; e= Exp.Lvar pvar} ->
    (* Handle loading from program variables *)
    let source_var = Var.of_pvar pvar in
    let dest_var = Var.of_id id in
    if Domain.is_var_tainted source_var astate then
      Domain.add_tainted_var dest_var astate
    else
      astate
  | Store {e1= Lvar pvar; e2= rhs_exp} ->
    (* Handle assignments with string literals *)
    (match rhs_exp with
    | Exp.Var id ->
      let source_var = Var.of_id id in
      if Domain.is_var_tainted source_var astate then
        let dest_var = Var.of_pvar pvar in
        Domain.add_tainted_var dest_var astate
      else
        astate
    | Exp.Const (Const.Cstr s) ->
      if Domain.is_potentially_weak_algorithm s then
        let dest_var = Var.of_pvar pvar in
        let updated_state = Domain.add_weak_algo s astate in
        Domain.add_tainted_var dest_var updated_state
      else
        astate
    | _ -> astate)
  | _ -> astate

let pp_session_name _node fmt = F.pp_print_string fmt "weak_crypto"

module TransferFunctions = struct
  module CFG = ProcCfg.Normal
  module Domain = Domain

  type analysis_data = Domain.t InterproceduralAnalysis.t

  let exec_instr = exec_instr

  let pp_session_name = pp_session_name
end

module Analyzer = AbstractInterpreter.MakeRPO (TransferFunctions)

let checker ({InterproceduralAnalysis.proc_desc; _} as analysis_data) =
  let result = Analyzer.compute_post analysis_data ~initial:Domain.initial proc_desc in
  result