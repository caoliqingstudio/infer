(*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *)

open! IStd
module F = Format

(** Abstract domain to track insecure LDAP authentication vulnerabilities *)

type t = {
  (* Whether we've seen insecure LDAP URL (ldap://) *)
  has_insecure_ldap_url : bool;
  (* Whether basic authentication ("simple") is configured *)
  has_basic_auth : bool;
  (* Whether SSL protocol is explicitly enabled *)
  has_ssl_enabled : bool;
}

let initial = {has_insecure_ldap_url= false; has_basic_auth= false; has_ssl_enabled= false}

let leq ~lhs ~rhs =
  Bool.equal lhs.has_insecure_ldap_url rhs.has_insecure_ldap_url
  && Bool.equal lhs.has_basic_auth rhs.has_basic_auth
  && Bool.equal lhs.has_ssl_enabled rhs.has_ssl_enabled

let join astate1 astate2 =
  { has_insecure_ldap_url= astate1.has_insecure_ldap_url || astate2.has_insecure_ldap_url;
    has_basic_auth= astate1.has_basic_auth || astate2.has_basic_auth;
    has_ssl_enabled= astate1.has_ssl_enabled || astate2.has_ssl_enabled }

let widen ~prev ~next ~num_iters:_ = join prev next

let pp fmt {has_insecure_ldap_url; has_basic_auth; has_ssl_enabled} =
  F.fprintf fmt "@[<v>InsecureLDAP: %b, BasicAuth: %b, SSL: %b@]" 
    has_insecure_ldap_url has_basic_auth has_ssl_enabled

(** Mark that we've seen an insecure LDAP URL *)
let mark_insecure_ldap_url astate =
  {astate with has_insecure_ldap_url= true}

(** Mark that we've seen basic authentication configuration *)
let mark_basic_auth astate =
  {astate with has_basic_auth= true}

(** Mark that SSL protocol is explicitly enabled *)
let mark_ssl_enabled astate =
  {astate with has_ssl_enabled= true}

(** Check if we've seen insecure LDAP URL *)
let has_insecure_ldap_url astate = astate.has_insecure_ldap_url

(** Check if we've seen basic authentication *)
let has_basic_auth astate = astate.has_basic_auth

(** Check if SSL is explicitly enabled *)
let has_ssl_enabled astate = astate.has_ssl_enabled

(** Check if we have insecure LDAP authentication (insecure URL + basic auth + no SSL) *)
let is_vulnerable astate = 
  astate.has_insecure_ldap_url && astate.has_basic_auth && not astate.has_ssl_enabled

type summary = t