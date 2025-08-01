(*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *)

open! IStd

include AbstractDomain.S

val initial : t

val mark_unprotected_request : t -> t

val is_unprotected_request : t -> bool

val mark_state_change : t -> t

val has_state_change : t -> bool

val is_vulnerable : t -> bool

type summary = t