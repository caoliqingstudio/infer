(*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *)

open! IStd

include AbstractDomain.S

val initial : t

val add_tainted_var : Var.t -> t -> t

val is_var_tainted : Var.t -> t -> bool

val has_tainted_data : t -> bool

type summary = t