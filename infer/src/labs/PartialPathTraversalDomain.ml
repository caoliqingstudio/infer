(*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *)

open! IStd
module F = Format

type t = {
  canonical_paths : Var.Set.t;  (* Variables containing getCanonicalPath() results *)
}

let empty = { canonical_paths = Var.Set.empty }

let add_canonical_path var { canonical_paths } =  
  { canonical_paths = Var.Set.add var canonical_paths }

let is_canonical_path var { canonical_paths } =
  Var.Set.mem var canonical_paths

let has_canonical_paths { canonical_paths } = 
  not (Var.Set.is_empty canonical_paths)

let leq ~lhs ~rhs =
  Var.Set.subset lhs.canonical_paths rhs.canonical_paths

let join lhs rhs =
  { canonical_paths = Var.Set.union lhs.canonical_paths rhs.canonical_paths }

let widen ~prev ~next ~num_iters:_ = join prev next

let pp fmt { canonical_paths } =
  F.fprintf fmt "@[<hov 2>{ canonical_paths=@[<hov 2>%a@] }@]"
    (Pp.seq ~sep:", " Var.pp) (Var.Set.elements canonical_paths)

let summary = empty

type summary = t