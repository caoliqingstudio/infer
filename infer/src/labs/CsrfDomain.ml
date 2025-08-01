(*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *)

open! IStd
module F = Format

(** Abstract domain to track CSRF vulnerabilities in unprotected request handlers *)

type t = {
  (* Whether we're in an unprotected request handler *)
  is_unprotected_request : bool;
  (* Whether we've encountered state-changing operations *)
  has_state_change : bool;
}

let initial = {is_unprotected_request= false; has_state_change= false}

let leq ~lhs ~rhs =
  Bool.equal lhs.is_unprotected_request rhs.is_unprotected_request
  && Bool.equal lhs.has_state_change rhs.has_state_change

let join astate1 astate2 =
  { is_unprotected_request= astate1.is_unprotected_request || astate2.is_unprotected_request;
    has_state_change= astate1.has_state_change || astate2.has_state_change }

let widen ~prev ~next ~num_iters:_ = join prev next

let pp fmt {is_unprotected_request; has_state_change} =
  F.fprintf fmt "@[<v>UnprotectedRequest: %b, StateChange: %b@]" 
    is_unprotected_request has_state_change

(** Mark that we're in an unprotected request handler *)
let mark_unprotected_request astate =
  {astate with is_unprotected_request= true}

(** Check if we're in an unprotected request handler *)
let is_unprotected_request astate = astate.is_unprotected_request

(** Mark that we've encountered a state-changing operation *)
let mark_state_change astate =
  {astate with has_state_change= true}

(** Check if we've encountered state-changing operations *)
let has_state_change astate = astate.has_state_change

(** Check if we have a CSRF vulnerability (unprotected request + state change) *)
let is_vulnerable astate = 
  astate.is_unprotected_request && astate.has_state_change

type summary = t