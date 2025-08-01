(*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *)

open! IStd

type t = {
  canonical_paths : Var.Set.t;  (* Variables containing getCanonicalPath() results *)
}

include AbstractDomain.S with type t := t

val empty : t

val add_canonical_path : Var.t -> t -> t

val is_canonical_path : Var.t -> t -> bool

val has_canonical_paths : t -> bool

val summary : t

type summary = t