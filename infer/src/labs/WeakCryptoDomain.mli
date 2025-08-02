(**
 * Abstract domain for tracking potentially weak cryptographic algorithms
 *)

open! IStd

type t

include AbstractDomain.S with type t := t

(** Empty domain *)
val initial : t

(** Add a potentially weak algorithm string *)
val add_weak_algo : string -> t -> t

(** Add a tainted variable (containing weak algorithm) *)
val add_tainted_var : Var.t -> t -> t

(** Remove taint from a variable *)
val remove_tainted_var : Var.t -> t -> t

(** Check if a variable is tainted *)
val is_var_tainted : Var.t -> t -> bool

(** Check if an algorithm string is potentially weak *)
val is_potentially_weak_algorithm : string -> bool