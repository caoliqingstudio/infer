(*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *)

open! IStd

type t = {
  temp_dir_paths : Var.Set.t;  (* Variables tainted with temp directory paths *)
}

include AbstractDomain.S with type t := t

val empty : t

val add_temp_dir_path : Var.t -> t -> t

val is_temp_dir_path : Var.t -> t -> bool

val has_temp_dir_data : t -> bool

val summary : t

type summary = t