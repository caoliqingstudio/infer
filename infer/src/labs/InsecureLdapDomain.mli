(*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *)

open! IStd

include AbstractDomain.S

val initial : t

val mark_insecure_ldap_url : t -> t

val mark_basic_auth : t -> t

val mark_ssl_enabled : t -> t

val has_insecure_ldap_url : t -> bool

val has_basic_auth : t -> bool

val has_ssl_enabled : t -> bool

val is_vulnerable : t -> bool

type summary = t