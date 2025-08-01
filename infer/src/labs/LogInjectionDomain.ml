(*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *)

open! IStd
module F = Format

type t = {
  tainted_vars : Var.Set.t;  (* Variables containing user-controlled data *)
}

let empty = { tainted_vars = Var.Set.empty }

let add_tainted_var var { tainted_vars } =  
  { tainted_vars = Var.Set.add var tainted_vars }

let is_var_tainted var { tainted_vars } =
  Var.Set.mem var tainted_vars

let has_tainted_data { tainted_vars } = 
  not (Var.Set.is_empty tainted_vars)

let leq ~lhs ~rhs =
  Var.Set.subset lhs.tainted_vars rhs.tainted_vars

let join lhs rhs =
  { tainted_vars = Var.Set.union lhs.tainted_vars rhs.tainted_vars }

let widen ~prev ~next ~num_iters:_ = join prev next

let pp fmt { tainted_vars } =
  F.fprintf fmt "@[<hov 2>{ tainted_vars=@[<hov 2>%a@] }@]"
    (Pp.seq ~sep:", " Var.pp) (Var.Set.elements tainted_vars)

let summary = empty

type summary = t