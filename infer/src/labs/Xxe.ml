(** XXE (XML External Entity) checker for detecting XML parsing vulnerabilities *)

open! IStd
module F = Format
module L = Logging

module Domain = XxeDomain

(** Check if a method is a user-controlled source *)
let is_user_controlled_source proc_name =
  match proc_name with
  | Procname.Java java_proc_name ->
    let class_name = Procname.Java.get_class_name java_proc_name in
    let method_name = Procname.Java.get_method java_proc_name in
    (* HTTP request parameters and headers *)
    (String.is_substring class_name ~substring:"HttpServletRequest" ||
     String.is_substring class_name ~substring:"ServletRequest") &&
    (String.equal method_name "getParameter" ||
     String.equal method_name "getParameterValues" ||
     String.equal method_name "getHeader" ||
     String.equal method_name "getHeaders" ||
     String.equal method_name "getQueryString" ||
     String.equal method_name "getPathInfo" ||
     String.equal method_name "getRequestURI" ||
     String.equal method_name "getRemoteUser") ||
    (* File I/O operations *)
    (String.is_substring class_name ~substring:"FileInputStream" ||
     String.is_substring class_name ~substring:"FileReader" ||
     String.is_substring class_name ~substring:"BufferedReader") &&
    (String.equal method_name "read" ||
     String.equal method_name "readLine") ||
    (* Network I/O operations *)
    (String.is_substring class_name ~substring:"InputStream" ||
     String.is_substring class_name ~substring:"Reader") &&
    (String.equal method_name "read" ||
     String.equal method_name "readLine") ||
    (* Test mock methods *)
    String.equal method_name "getUserInput" ||
    String.equal method_name "getXmlData" ||
    String.equal method_name "readXmlFile"
  | _ ->
    (* Generic user input methods *)
    let method_name = Procname.get_method proc_name in
    String.is_suffix method_name ~suffix:"getUserInput" ||
    String.is_suffix method_name ~suffix:"readLine" ||
    String.is_suffix method_name ~suffix:"nextLine"

(** Check if a method is a vulnerable XML parsing sink *)
let is_xml_parsing_sink proc_name =
  match proc_name with
  | Procname.Java java_proc_name ->
    let class_name = Procname.Java.get_class_name java_proc_name in
    let method_name = Procname.Java.get_method java_proc_name in
    (* DocumentBuilder parsing methods *)
    (String.is_substring class_name ~substring:"DocumentBuilder") &&
    String.equal method_name "parse" ||
    (* SAX parser methods *)
    (String.is_substring class_name ~substring:"SAXParser" ||
     String.is_substring class_name ~substring:"SAXBuilder" ||
     String.is_substring class_name ~substring:"SAXReader") &&
    (String.equal method_name "parse" ||
     String.equal method_name "build" ||
     String.equal method_name "read") ||
    (* XMLReader methods *)
    String.is_substring class_name ~substring:"XMLReader" &&
    String.equal method_name "parse" ||
    (* XMLInputFactory methods *)
    String.is_substring class_name ~substring:"XMLInputFactory" &&
    (String.equal method_name "createXMLStreamReader" ||
     String.equal method_name "createXMLEventReader") ||
    (* Transformer methods *)
    String.is_substring class_name ~substring:"Transformer" &&
    String.equal method_name "transform" ||
    (* JAXB Unmarshaller methods *)
    String.is_substring class_name ~substring:"Unmarshaller" &&
    String.equal method_name "unmarshal" ||
    (* XPath evaluation methods *)
    (String.is_substring class_name ~substring:"XPathExpression" ||
     String.is_substring class_name ~substring:"XPath") &&
    String.equal method_name "evaluate" ||
    (* SchemaFactory methods *)
    String.is_substring class_name ~substring:"SchemaFactory" &&
    String.equal method_name "newSchema" ||
    (* SimpleXML framework methods *)
    String.is_substring class_name ~substring:"Persister" &&
    (String.equal method_name "read" ||
     String.equal method_name "validate") ||
    (* Test mock methods *)
    String.equal method_name "parseXml" ||
    String.equal method_name "processXml"
  | _ ->
    (* Generic XML parsing methods *)
    let method_name = Procname.get_method proc_name in
    String.is_suffix method_name ~suffix:"parseXml" ||
    String.is_suffix method_name ~suffix:"processXml" ||
    String.equal method_name "parse"

(** Get variable from expression if possible *)
let get_var_from_exp exp =
  match exp with
  | Exp.Var id -> Some (Var.of_id id)
  | Exp.Lvar pvar -> Some (Var.of_pvar pvar)
  | _ -> None

(** Check if any of the actual arguments contains tainted data *)
let has_tainted_argument actuals astate =
  List.exists actuals ~f:(fun (exp, _) ->
    match get_var_from_exp exp with
    | Some var -> Domain.is_var_tainted var astate
    | None -> false
  )

(** TransferFunctions for the analysis *)
module TransferFunctions (CFG : ProcCfg.S) = struct
  module CFG = CFG
  module Domain = XxeDomain

  type analysis_data = XxeDomain.t InterproceduralAnalysis.t

  (** Main transfer function *)
  let exec_instr (astate : Domain.t) analysis_data _node _instr_index (instr : Sil.instr) =
    let {InterproceduralAnalysis.proc_desc; err_log; _} = analysis_data in
    let report_error loc message =
      Reporting.log_issue proc_desc err_log ~loc Xxe IssueType.xxe message
    in
    
    match instr with
    | Call ((return_id, _), Const (Cfun callee_proc_name), actuals, loc, _call_flags) ->
      (* Function call with return value *)
      if is_user_controlled_source callee_proc_name then (
        (* This is a call to a user-controlled source method - mark return variable as tainted *)
        let return_var = Var.of_id return_id in
        let updated_astate = Domain.add_tainted_var return_var astate in
        Domain.add_tainted_source (Procname.to_string callee_proc_name) updated_astate
      ) else if is_xml_parsing_sink callee_proc_name then (
        (* This is an XML parsing operation - check if any argument is tainted *)
        if has_tainted_argument actuals astate then (
          let message = "XML parsing depends on user-controlled data without guarding against external entity expansion" in
          report_error loc message
        );
        astate
      ) else
        astate
        
    | Call (_, Const (Cfun callee_proc_name), actuals, loc, _call_flags) ->
      (* Function call without return value (void methods) *)
      if is_xml_parsing_sink callee_proc_name then (
        (* This is an XML parsing operation - check if any argument is tainted *)
        if has_tainted_argument actuals astate then (
          let message = "XML parsing depends on user-controlled data without guarding against external entity expansion" in
          report_error loc message
        );
        astate
      ) else
        astate
        
    | Load {id= lhs; e= rhs; typ= _lhs_typ; loc= _loc} ->
      (* Load operation: lhs = *rhs *)
      (match get_var_from_exp rhs with
      | Some rhs_var when Domain.is_var_tainted rhs_var astate ->
        (* Propagate taint from rhs to lhs *)
        let lhs_var = Var.of_id lhs in
        Domain.add_tainted_var lhs_var astate
      | _ ->
        astate)
        
    | Store {e1= lhs; e2= rhs; typ= _rhs_typ; loc= _loc} ->
      (* Store operation: *lhs = rhs *)
      (* Propagate taint from rhs to lhs if rhs is tainted *)
      (match get_var_from_exp rhs with
      | Some rhs_var when Domain.is_var_tainted rhs_var astate ->
        (* If storing to a variable, propagate taint *)
        (match get_var_from_exp lhs with
        | Some lhs_var ->
          Domain.add_tainted_var lhs_var astate
        | None ->
          astate)
      | _ ->
        astate)
        
    | Prune (_assume_exp, _loc, _, _) ->
      (* Conditional assumption - could be used to detect sanitization *)
      (* For now, we don't implement sanitization detection *)
      astate
      
    | Call (_, call_exp, _actuals, loc, _) ->
      (* Indirect call - should not happen in Java *)
      L.die InternalError "Unexpected indirect call %a at %a" Exp.pp call_exp Location.pp loc
      
    | Metadata _ ->
      astate

  let pp_session_name _node fmt = F.pp_print_string fmt "xxe checker"
end

(** Use normal CFG (without exceptional edges) *)
module CFG = ProcCfg.Normal

(** Create the abstract interpreter *)
module Analyzer = AbstractInterpreter.MakeRPO (TransferFunctions (CFG))

(** Main checker entry point *)
let checker ({InterproceduralAnalysis.proc_desc} as analysis_data) =
  let result = Analyzer.compute_post analysis_data ~initial:Domain.empty proc_desc in
  result