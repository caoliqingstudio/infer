(**
 * Abstract domain for Trust Boundary Violation detection
 * 
 * This domain tracks:
 * - Tainted data from HTTP request sources
 * - Variables containing untrusted data
 *)

open! IStd

module TaintedVarSet : AbstractDomain.S with type t = AbstractDomain.FiniteSet(Var).t

type t = {
  tainted_vars : TaintedVarSet.t;  (** Variables containing untrusted data *)
}

include AbstractDomain.S with type t := t

val initial : t
(** Initial empty state *)

val add_tainted_var : Var.t -> t -> t
(** Mark a variable as containing tainted data *)

val remove_tainted_var : Var.t -> t -> t
(** Remove taint from a variable *)

val is_var_tainted : Var.t -> t -> bool
(** Check if a variable contains tainted data *)

val get_tainted_vars : t -> TaintedVarSet.t
(** Get all tainted variables *)