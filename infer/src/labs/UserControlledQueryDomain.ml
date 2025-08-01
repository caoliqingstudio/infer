(** Abstract domain for tracking user-controlled query vulnerabilities *)

module F = Format

(** Set of tainted variables *)
module TaintedVarSet = AbstractDomain.FiniteSet (Var)

(** Set of tainted strings/expressions *)
module TaintedStringSet = AbstractDomain.FiniteSet (String)

type t = {
  tainted_vars : TaintedVarSet.t;        (** Variables containing user-controlled data *)
  tainted_sources : TaintedStringSet.t;  (** Source methods that produce tainted data *)
}

let empty = {
  tainted_vars = TaintedVarSet.empty;
  tainted_sources = TaintedStringSet.empty;
}

let leq ~lhs ~rhs =
  TaintedVarSet.leq ~lhs:lhs.tainted_vars ~rhs:rhs.tainted_vars &&
  TaintedStringSet.leq ~lhs:lhs.tainted_sources ~rhs:rhs.tainted_sources

let join lhs rhs = {
  tainted_vars = TaintedVarSet.join lhs.tainted_vars rhs.tainted_vars;
  tainted_sources = TaintedStringSet.join lhs.tainted_sources rhs.tainted_sources;
}

let widen ~prev ~next ~num_iters =
  {
    tainted_vars = TaintedVarSet.widen ~prev:prev.tainted_vars ~next:next.tainted_vars ~num_iters;
    tainted_sources = TaintedStringSet.widen ~prev:prev.tainted_sources ~next:next.tainted_sources ~num_iters;
  }

let pp fmt {tainted_vars; tainted_sources} =
  F.fprintf fmt "TaintedVars: %a, TaintedSources: %a"
    TaintedVarSet.pp tainted_vars
    TaintedStringSet.pp tainted_sources

(** Add a tainted variable *)
let add_tainted_var var astate =
  {astate with tainted_vars = TaintedVarSet.add var astate.tainted_vars}

(** Add a tainted source *)
let add_tainted_source source astate =
  {astate with tainted_sources = TaintedStringSet.add source astate.tainted_sources}

(** Check if a variable is tainted *)
let is_var_tainted var astate =
  TaintedVarSet.mem var astate.tainted_vars

(** Check if any tainted data exists *)
let has_tainted_data astate =
  not (TaintedVarSet.is_empty astate.tainted_vars) || 
  not (TaintedStringSet.is_empty astate.tainted_sources)

(** Remove taint from a variable (for sanitization) *)
let remove_tainted_var var astate =
  {astate with tainted_vars = TaintedVarSet.remove var astate.tainted_vars}