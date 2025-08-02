(**
 * Abstract domain for Path Injection detection
 * 
 * This domain tracks:
 * - Tainted data from user inputs (network, HTTP requests, etc.)
 * - Variables containing untrusted path data
 *)

open! IStd

module TaintedVarSet = AbstractDomain.FiniteSet (Var)

type t = {
  tainted_vars : TaintedVarSet.t;  (** Variables containing untrusted path data *)
}

let pp fmt {tainted_vars} =
  Format.fprintf fmt "@[<v>@[<hov 2>Tainted vars: {@ %a@]@ }@]" 
    TaintedVarSet.pp tainted_vars

let leq ~lhs ~rhs =
  TaintedVarSet.leq ~lhs:lhs.tainted_vars ~rhs:rhs.tainted_vars

let join astate1 astate2 = 
  {tainted_vars = TaintedVarSet.join astate1.tainted_vars astate2.tainted_vars}

let widen ~prev ~next ~num_iters:_ = join prev next

let initial = {tainted_vars = TaintedVarSet.empty}

let add_tainted_var var astate =
  {tainted_vars = TaintedVarSet.add var astate.tainted_vars}

let remove_tainted_var var astate =
  {tainted_vars = TaintedVarSet.remove var astate.tainted_vars}

let is_var_tainted var astate =
  TaintedVarSet.mem var astate.tainted_vars

let get_tainted_vars astate = astate.tainted_vars