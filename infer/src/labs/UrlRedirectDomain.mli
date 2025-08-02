(**
 * Domain interface for URL redirect taint tracking
 *)

open! IStd

(** Abstract domain for tracking tainted data in URL redirections *)
type t

include AbstractDomain.S with type t := t

(** Initial empty domain *)
val initial : t

(** Add a tainted variable to the domain *)
val add_tainted_var : Var.t -> t -> t

(** Check if a variable is tainted *)
val is_var_tainted : Var.t -> t -> bool

(** Remove a variable from tainted set (for sanitization) *)
val remove_tainted_var : Var.t -> t -> t