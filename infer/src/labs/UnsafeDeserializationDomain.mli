(* Interface for the abstract domain tracking unsafe deserialization *)

open! IStd

include AbstractDomain.S

val empty : t
(** Empty domain state *)

val add_tainted_var : Var.t -> t -> t
(** Add a tainted variable to the domain *)

val is_var_tainted : Var.t -> t -> bool
(** Check if a variable is tainted *)

val remove_var : Var.t -> t -> t
(** Remove a variable from the domain *)

val substitute : Var.t -> Var.t -> t -> t
(** Substitute one variable for another *)

type summary = t