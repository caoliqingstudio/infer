(*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *)

open! IStd
module F = Format

type t = {
  temp_dir_paths : Var.Set.t;  (* Variables tainted with temp directory paths *)
}

let empty = { temp_dir_paths = Var.Set.empty }

let add_temp_dir_path var { temp_dir_paths } =
  { temp_dir_paths = Var.Set.add var temp_dir_paths }

let is_temp_dir_path var { temp_dir_paths } =
  Var.Set.mem var temp_dir_paths

let has_temp_dir_data { temp_dir_paths } =
  not (Var.Set.is_empty temp_dir_paths)

let leq ~lhs ~rhs =
  Var.Set.subset lhs.temp_dir_paths rhs.temp_dir_paths

let join lhs rhs =
  { temp_dir_paths = Var.Set.union lhs.temp_dir_paths rhs.temp_dir_paths }

let widen ~prev ~next ~num_iters:_ = join prev next

let pp fmt { temp_dir_paths } =
  F.fprintf fmt "@[<hov 2>{ temp_dir_paths=@[<hov 2>%a@] }@]"
    (Pp.seq ~sep:", " Var.pp) (Var.Set.elements temp_dir_paths)

let summary = empty

type summary = t