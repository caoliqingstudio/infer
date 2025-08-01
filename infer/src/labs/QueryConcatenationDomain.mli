(** Abstract domain for tracking query concatenation vulnerabilities *)

module StringConcatSet : module type of AbstractDomain.FiniteSet (String)

module VarSet : module type of AbstractDomain.FiniteSet (Var)

type t = {
  tainted_strings : StringConcatSet.t;  (** Track expressions that contain potentially untrusted strings *)
  sql_query_vars : VarSet.t;            (** Track variables that hold SQL query strings *)
  sb_vars : VarSet.t;                   (** Track StringBuilder variables used for query construction *)
}

include AbstractDomain.S with type t := t

val empty : t

val add_tainted_string : string -> t -> t

val add_sql_query_var : Var.t -> t -> t

val add_sb_var : Var.t -> t -> t

val is_tainted_string : string -> t -> bool

val is_sql_query_var : Var.t -> t -> bool

val is_sb_var : Var.t -> t -> bool