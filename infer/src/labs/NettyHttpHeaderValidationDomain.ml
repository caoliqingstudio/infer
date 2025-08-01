(*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *)

open! IStd

(** Abstract domain for tracking Netty HTTP header validation vulnerabilities *)

type t = Bottom

let bottom = Bottom

let is_bottom = function Bottom -> true

let pp fmt = function Bottom -> Format.fprintf fmt "⊥"

let leq ~lhs:_ ~rhs:_ = true

let join _ _ = Bottom

let widen ~prev:_ ~next ~num_iters:_ = next