(*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *)

open! IStd
module F = Format

type t = {
  secure_cookies : Var.Set.t;
}

let empty = {secure_cookies = Var.Set.empty}

let pp fmt {secure_cookies} =
  F.fprintf fmt "@[<v>secure_cookies: %a@]"
    Var.Set.pp secure_cookies

let leq ~lhs ~rhs =
  Var.Set.subset lhs.secure_cookies rhs.secure_cookies

let join astate1 astate2 =
  {secure_cookies = Var.Set.union astate1.secure_cookies astate2.secure_cookies}

let widen ~prev ~next ~num_iters:_ = join prev next

let add_secure_cookie cookie_var astate =
  {secure_cookies = Var.Set.add cookie_var astate.secure_cookies}

let has_secure_cookie cookie_var astate =
  Var.Set.mem cookie_var astate.secure_cookies