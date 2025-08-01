(*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *)

open! IStd

(** Abstract domain for tracking Netty HTTP header validation vulnerabilities *)

type t

include AbstractDomain.S with type t := t

val bottom : t

val is_bottom : t -> bool

val pp : Format.formatter -> t -> unit