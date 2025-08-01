(** Abstract domain for tracking user-controlled query vulnerabilities *)

module TaintedVarSet : module type of AbstractDomain.FiniteSet (Var)

module TaintedStringSet : module type of AbstractDomain.FiniteSet (String)

type t = {
  tainted_vars : TaintedVarSet.t;        (** Variables containing user-controlled data *)
  tainted_sources : TaintedStringSet.t;  (** Source methods that produce tainted data *)
}

include AbstractDomain.S with type t := t

val empty : t

val add_tainted_var : Var.t -> t -> t

val add_tainted_source : string -> t -> t

val is_var_tainted : Var.t -> t -> bool

val has_tainted_data : t -> bool

val remove_tainted_var : Var.t -> t -> t