(** QueryConcatenation checker for detecting SQL injection through string concatenation *)

open! IStd
module F = Format

module Domain = QueryConcatenationDomain

let is_source_method proc_name =
  let method_name = Procname.get_method proc_name in
  String.is_suffix method_name ~suffix:"getCategory" ||
  String.is_suffix method_name ~suffix:"getParameter" ||
  String.is_suffix method_name ~suffix:"getHeader" ||
  String.is_suffix method_name ~suffix:"getUserInput" ||
  String.is_suffix method_name ~suffix:"readLine" ||
  String.is_suffix method_name ~suffix:"nextLine"

let is_sql_method proc_name =
  let method_name = Procname.get_method proc_name in
  String.is_suffix method_name ~suffix:"executeQuery" ||
  String.is_suffix method_name ~suffix:"executeUpdate" ||
  String.is_suffix method_name ~suffix:"execute" ||
  String.is_suffix method_name ~suffix:"createQuery" ||
  String.is_suffix method_name ~suffix:"createStatement"

let is_string_concat_op = function
  | Binop.PlusA _ -> true
  | _ -> false

let is_stringbuilder_append proc_name =
  let method_name = Procname.get_method proc_name in
  String.equal method_name "append" &&
  match Procname.get_class_type_name proc_name with
  | Some class_name -> 
    String.is_substring (Typ.Name.name class_name) ~substring:"StringBuilder" ||
    String.is_substring (Typ.Name.name class_name) ~substring:"StringBuffer"
  | None -> false

let is_stringbuilder_tostring proc_name =
  let method_name = Procname.get_method proc_name in
  String.equal method_name "toString" &&
  match Procname.get_class_type_name proc_name with
  | Some class_name ->
    String.is_substring (Typ.Name.name class_name) ~substring:"StringBuilder" ||
    String.is_substring (Typ.Name.name class_name) ~substring:"StringBuffer"
  | None -> false

(** TransferFunctions for the analysis *)
module TransferFunctions (CFG : ProcCfg.S) = struct
  module CFG = CFG
  module Domain = QueryConcatenationDomain

  type analysis_data = QueryConcatenationDomain.t InterproceduralAnalysis.t

  (** Main transfer function *)
  let exec_instr (astate : Domain.t) analysis_data node instr_index (instr : Sil.instr) =
    let {InterproceduralAnalysis.proc_desc; err_log; _} = analysis_data in
    let report_error loc message =
      Reporting.log_issue proc_desc err_log ~loc QueryConcatenation IssueType.query_concatenation message
    in
    
    match instr with
    | Call (_ret_id, Const (Cfun callee_proc_name), actuals, loc, _call_flags) ->
      (* Detect source methods that return potentially untrusted strings *)
      if is_source_method callee_proc_name then
        Domain.add_tainted_string (Procname.to_string callee_proc_name) astate
      (* Detect SQL execution methods - check if any arguments are tainted *)
      else if is_sql_method callee_proc_name then (
        let message = 
          "SQL query built by concatenation with potentially untrusted string"
        in
        report_error loc message;
        astate
      )
      (* Track StringBuilder.append() calls *)
      else if is_stringbuilder_append callee_proc_name then (
        match actuals with
        | (receiver_exp, _) :: _ ->
          (match receiver_exp with
          | Lvar pvar ->
            let var = Var.of_pvar pvar in
            let updated_astate = Domain.add_sb_var var astate in
            let message = 
              "StringBuilder append detected for potential SQL query"
            in
            report_error loc message;
            updated_astate
          | _ -> astate)
        | [] -> astate
      )
      (* Track StringBuilder.toString() calls *)
      else if is_stringbuilder_tostring callee_proc_name then (
        match actuals with
        | (receiver_exp, _) :: _ ->
          (match receiver_exp with
          | Lvar pvar ->
            let var = Var.of_pvar pvar in
            if Domain.is_sb_var var astate then (
              let message = 
                "StringBuilder toString() called on query builder"
              in
              report_error loc message
            );
            astate
          | _ -> astate)
        | [] -> astate
      )
      else astate
      
    | Store {e1= Lvar pvar; e2= BinOp (op, e1, e2); loc} when is_string_concat_op op ->
      (* Track string concatenation assignments *)
      let var = Var.of_pvar pvar in
      let updated_astate = Domain.add_sql_query_var var astate in
      let message = 
        "String concatenation detected for SQL query construction"
      in
      report_error loc message;
      updated_astate
      
    | _ -> astate

  let pp_session_name _node fmt = F.pp_print_string fmt "query concatenation"
end

(** Use normal CFG (without exceptional edges) *)
module CFG = ProcCfg.Normal

(** Create the abstract interpreter *)
module Analyzer = AbstractInterpreter.MakeRPO (TransferFunctions (CFG))

(** Main checker entry point *)
let checker ({InterproceduralAnalysis.proc_desc} as analysis_data) =
  let result = Analyzer.compute_post analysis_data ~initial:Domain.empty proc_desc in
  result