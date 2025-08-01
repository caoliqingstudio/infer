(*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *)

open! IStd
module F = Format

(** Abstract domain to track tainted variables containing user-controlled data for LDAP injection *)

type t = {
  (* Set of variables containing tainted user-controlled data *)
  tainted_vars : Var.Set.t;
}

let initial = {tainted_vars= Var.Set.empty}

let leq ~lhs ~rhs =
  Var.Set.subset lhs.tainted_vars rhs.tainted_vars

let join astate1 astate2 =
  { tainted_vars= Var.Set.union astate1.tainted_vars astate2.tainted_vars }

let widen ~prev ~next ~num_iters:_ = join prev next

let pp fmt {tainted_vars} =
  F.fprintf fmt "@[<v>TaintedVars: %a@]" Var.Set.pp tainted_vars

(** Add a tainted variable *)
let add_tainted_var var astate =
  {tainted_vars= Var.Set.add var astate.tainted_vars}

(** Check if a variable is tainted *)
let is_var_tainted var astate = Var.Set.mem var astate.tainted_vars

(** Check if any tainted data exists *)
let has_tainted_data astate =
  not (Var.Set.is_empty astate.tainted_vars)

type summary = t