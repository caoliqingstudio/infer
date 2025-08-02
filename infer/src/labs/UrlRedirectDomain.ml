(**
 * URL Redirect Domain implementation for Infer
 *
 * Tracks tainted variables that could be used in URL redirection attacks
 *)

open! IStd
module F = Format

module TaintedVarSet = AbstractDomain.FiniteSet (Var)

type t = TaintedVarSet.t

let initial = TaintedVarSet.empty

let is_empty = TaintedVarSet.is_empty

let join = TaintedVarSet.join

let widen ~prev ~next ~num_iters:_ = join prev next

let pp = TaintedVarSet.pp

let leq ~lhs ~rhs = TaintedVarSet.leq ~lhs ~rhs

let add_tainted_var var domain = TaintedVarSet.add var domain

let is_var_tainted var domain = TaintedVarSet.mem var domain

let remove_tainted_var var domain = TaintedVarSet.remove var domain