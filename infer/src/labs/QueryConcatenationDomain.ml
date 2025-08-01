(** Abstract domain for tracking query concatenation vulnerabilities *)

module F = Format
module StringConcatSet = AbstractDomain.FiniteSet (String)
module VarSet = AbstractDomain.FiniteSet (Var)

type t = {
  tainted_strings : StringConcatSet.t;  (** Track expressions that contain potentially untrusted strings *)
  sql_query_vars : VarSet.t;            (** Track variables that hold SQL query strings *)
  sb_vars : VarSet.t;                   (** Track StringBuilder variables used for query construction *)
}

let empty = {
  tainted_strings = StringConcatSet.empty;
  sql_query_vars = VarSet.empty;
  sb_vars = VarSet.empty;
}

let leq ~lhs ~rhs =
  StringConcatSet.leq ~lhs:lhs.tainted_strings ~rhs:rhs.tainted_strings &&
  VarSet.leq ~lhs:lhs.sql_query_vars ~rhs:rhs.sql_query_vars &&
  VarSet.leq ~lhs:lhs.sb_vars ~rhs:rhs.sb_vars

let join lhs rhs = {
  tainted_strings = StringConcatSet.join lhs.tainted_strings rhs.tainted_strings;
  sql_query_vars = VarSet.join lhs.sql_query_vars rhs.sql_query_vars;
  sb_vars = VarSet.join lhs.sb_vars rhs.sb_vars;
}

let widen ~prev ~next ~num_iters =
  {
    tainted_strings = StringConcatSet.widen ~prev:prev.tainted_strings ~next:next.tainted_strings ~num_iters;
    sql_query_vars = VarSet.widen ~prev:prev.sql_query_vars ~next:next.sql_query_vars ~num_iters;
    sb_vars = VarSet.widen ~prev:prev.sb_vars ~next:next.sb_vars ~num_iters;
  }

let pp fmt {tainted_strings; sql_query_vars; sb_vars} =
  F.fprintf fmt "TaintedStrings: %a, SQLVars: %a, SBVars: %a"
    StringConcatSet.pp tainted_strings
    VarSet.pp sql_query_vars
    VarSet.pp sb_vars

let add_tainted_string str astate =
  {astate with tainted_strings = StringConcatSet.add str astate.tainted_strings}

let add_sql_query_var var astate =
  {astate with sql_query_vars = VarSet.add var astate.sql_query_vars}

let add_sb_var var astate =
  {astate with sb_vars = VarSet.add var astate.sb_vars}

let is_tainted_string str astate =
  StringConcatSet.mem str astate.tainted_strings

let is_sql_query_var var astate =
  VarSet.mem var astate.sql_query_vars

let is_sb_var var astate =
  VarSet.mem var astate.sb_vars