(** Abstract domain for XXE (XML External Entity) checker *)

open! IStd
module F = Format

(** Set of tainted variables that may contain user-controlled XML data *)
module TaintedVarSet = AbstractDomain.FiniteSet (Var)

(** Set of tainted source method names *)
module TaintedStringSet = AbstractDomain.FiniteSet (String)

(** Abstract domain state for XXE detection *)
type t = {
  tainted_vars : TaintedVarSet.t;      (* Variables containing tainted XML data *)
  tainted_sources : TaintedStringSet.t; (* Source methods that introduced taint *)
}

let empty = {
  tainted_vars = TaintedVarSet.empty;
  tainted_sources = TaintedStringSet.empty;
}

let initial = empty

(** Add a tainted variable to the state *)
let add_tainted_var var astate =
  {astate with tainted_vars = TaintedVarSet.add var astate.tainted_vars}

(** Add a tainted source to the state *)
let add_tainted_source source astate =
  {astate with tainted_sources = TaintedStringSet.add source astate.tainted_sources}

(** Check if a variable is tainted *)
let is_var_tainted var astate =
  TaintedVarSet.mem var astate.tainted_vars

(** Check if any data is tainted *)
let has_tainted_data astate =
  not (TaintedVarSet.is_empty astate.tainted_vars)

(** Pretty print the abstract state *)
let pp fmt astate =
  F.fprintf fmt "XXE Domain: tainted_vars=%a, tainted_sources=%a"
    TaintedVarSet.pp astate.tainted_vars
    TaintedStringSet.pp astate.tainted_sources

(** Partial order for lattice *)
let leq ~lhs ~rhs =
  TaintedVarSet.leq ~lhs:lhs.tainted_vars ~rhs:rhs.tainted_vars &&
  TaintedStringSet.leq ~lhs:lhs.tainted_sources ~rhs:rhs.tainted_sources

(** Join operation for lattice *)
let join astate1 astate2 =
  {
    tainted_vars = TaintedVarSet.join astate1.tainted_vars astate2.tainted_vars;
    tainted_sources = TaintedStringSet.join astate1.tainted_sources astate2.tainted_sources;
  }

(** Widening operation *)
let widen ~prev ~next ~num_iters:_ = join prev next

(** Summary type for interprocedural analysis *)
type summary = t

let pp_summary = pp