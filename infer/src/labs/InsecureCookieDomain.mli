(*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *)

open! IStd

type t = {
  secure_cookies : Var.Set.t;
}

include AbstractDomain.S with type t := t

val add_secure_cookie : Var.t -> t -> t
val has_secure_cookie : Var.t -> t -> bool