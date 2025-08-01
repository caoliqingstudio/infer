(* Abstract domain implementation for tracking unsafe deserialization *)

open! IStd
module F = Format

type t = {
  tainted_vars : Var.Set.t;
}

let empty = {tainted_vars = Var.Set.empty}

let pp fmt {tainted_vars} =
  F.fprintf fmt "@[<v>tainted_vars: %a@]"
    Var.Set.pp tainted_vars

let leq ~lhs ~rhs =
  Var.Set.subset lhs.tainted_vars rhs.tainted_vars

let join lhs rhs =
  { tainted_vars = Var.Set.union lhs.tainted_vars rhs.tainted_vars }

let widen ~prev ~next ~num_iters:_ = join prev next

let add_tainted_var var state =
  {tainted_vars = Var.Set.add var state.tainted_vars}

let is_var_tainted var state =
  Var.Set.mem var state.tainted_vars

let remove_var var state =
  {tainted_vars = Var.Set.remove var state.tainted_vars}

let substitute old_var new_var state =
  if Var.Set.mem old_var state.tainted_vars then
    let new_tainted_vars = 
      state.tainted_vars |> Var.Set.remove old_var |> Var.Set.add new_var
    in
    {tainted_vars = new_tainted_vars}
  else
    state

type summary = t