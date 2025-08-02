(** Abstract domain interface for XXE checker *)

open! IStd

type t = {
  tainted_vars : AbstractDomain.FiniteSet(Var).t;
  tainted_sources : AbstractDomain.FiniteSet(String).t;
}

include AbstractDomain.S with type t := t

type summary = t

val empty : t
val initial : t
val add_tainted_var : Var.t -> t -> t
val add_tainted_source : string -> t -> t
val is_var_tainted : Var.t -> t -> bool
val has_tainted_data : t -> bool
val pp_summary : Format.formatter -> summary -> unit