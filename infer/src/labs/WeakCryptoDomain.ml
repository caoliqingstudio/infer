(**
 * Abstract domain for tracking potentially weak cryptographic algorithms
 * 
 * This domain tracks:
 * - Weak algorithm strings that may be insecure
 * - Variables that contain potentially weak cryptographic algorithm specifications
 *)

open! IStd
module F = Format

(** Set of weak algorithm strings *)
module WeakAlgoSet = AbstractDomain.FiniteSet (String)

(** Set of tainted variables *)
module TaintedVarSet = AbstractDomain.FiniteSet (Var)

type t = {
  weak_algorithms : WeakAlgoSet.t;
  tainted_vars : TaintedVarSet.t;
}

let initial = {
  weak_algorithms = WeakAlgoSet.empty;
  tainted_vars = TaintedVarSet.empty;
}

let pp fmt {weak_algorithms; tainted_vars} =
  F.fprintf fmt "{weak_algorithms=%a; tainted_vars=%a}"
    WeakAlgoSet.pp weak_algorithms
    TaintedVarSet.pp tainted_vars

let leq ~lhs ~rhs =
  WeakAlgoSet.leq ~lhs:lhs.weak_algorithms ~rhs:rhs.weak_algorithms &&
  TaintedVarSet.leq ~lhs:lhs.tainted_vars ~rhs:rhs.tainted_vars

let join lhs rhs = {
  weak_algorithms = WeakAlgoSet.join lhs.weak_algorithms rhs.weak_algorithms;
  tainted_vars = TaintedVarSet.join lhs.tainted_vars rhs.tainted_vars;
}

let widen ~prev ~next ~num_iters =
  {
    weak_algorithms = WeakAlgoSet.widen ~prev:prev.weak_algorithms ~next:next.weak_algorithms ~num_iters;
    tainted_vars = TaintedVarSet.widen ~prev:prev.tainted_vars ~next:next.tainted_vars ~num_iters;
  }

(** List of known secure algorithms - these should NOT be flagged *)
let secure_algorithms = [
  "AES"; "RSA"; "SHA-256"; "SHA-384"; "SHA-512"; "SHA3-256"; "SHA3-384"; "SHA3-512";
  "GCM"; "CCM"; "Blowfish"; "ECIES";
]

(** List of known weak algorithms that should definitely be flagged *)
let known_weak_algorithms = [
  "DES"; "RC2"; "RC4"; "ARCFOUR"; "RC5"; "MD5"; "SHA1"; "ECB";
]

(** Check if algorithm string contains any secure algorithm *)
let contains_secure_algorithm algo_str =
  List.exists secure_algorithms ~f:(fun secure ->
    String.is_substring_at algo_str ~pos:0 ~substring:secure ||
    String.is_substring algo_str ~substring:secure)

(** Check if algorithm string contains any known weak algorithm *)
let contains_weak_algorithm algo_str =
  List.exists known_weak_algorithms ~f:(fun weak ->
    String.is_substring_at algo_str ~pos:0 ~substring:weak ||
    String.is_substring algo_str ~substring:weak)

(** Check if an algorithm string is potentially weak *)
let is_potentially_weak_algorithm algo_str =
  (* Algorithm should be at least 2 characters *)
  String.length algo_str > 1 &&
  (* Not obviously secure *)
  not (contains_secure_algorithm algo_str) &&
  (* Either contains known weak algorithm or is suspicious (short, unknown) *)
  (contains_weak_algorithm algo_str ||
   (String.length algo_str <= 5 && not (String.contains algo_str '/')))

let add_weak_algo algo_str domain =
  if is_potentially_weak_algorithm algo_str then
    {domain with weak_algorithms = WeakAlgoSet.add algo_str domain.weak_algorithms}
  else
    domain

let add_tainted_var var domain =
  {domain with tainted_vars = TaintedVarSet.add var domain.tainted_vars}

let remove_tainted_var var domain =
  {domain with tainted_vars = TaintedVarSet.remove var domain.tainted_vars}

let is_var_tainted var domain =
  TaintedVarSet.mem var domain.tainted_vars