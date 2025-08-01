(* Infer checker for detecting unsafe deserialization vulnerabilities *)
(* Based on CodeQL's UnsafeDeserialization.ql rule *)

open! IStd
module F = Format
module L = Logging

module TransferFunctions (CFG : ProcCfg.S) = struct
  module CFG = CFG
  module Domain = UnsafeDeserializationDomain

  type analysis_data = UnsafeDeserializationDomain.t InterproceduralAnalysis.t

  let pp_session_name _node fmt = F.pp_print_string fmt "UnsafeDeserialization"

  (* Check if a method call is a taint source (remote user input) *)
  let is_remote_source proc_name =
    match proc_name with
    | Procname.Java java_proc_name ->
        let class_name = Procname.Java.get_class_name java_proc_name in
        let method_name = Procname.Java.get_method java_proc_name in
        (* Socket I/O *)
        (String.is_substring class_name ~substring:"Socket" &&
         String.equal method_name "getInputStream") ||
        (* URL connections *)
        (String.is_substring class_name ~substring:"URL" &&
         (String.equal method_name "openStream" ||
          String.equal method_name "openConnection")) ||
        (* URLConnection streams *)
        (String.is_substring class_name ~substring:"URLConnection" &&
         (String.equal method_name "getInputStream" ||
          String.equal method_name "getContent")) ||
        (* HTTP Request sources *)
        (String.is_substring class_name ~substring:"HttpServletRequest" &&
         (String.equal method_name "getParameter" ||
          String.equal method_name "getHeader" ||
          String.equal method_name "getInputStream" ||
          String.equal method_name "getReader")) ||
        (* File uploads *)
        (String.is_substring class_name ~substring:"MultipartFile" &&
         String.equal method_name "getInputStream") ||
        (* Message queues and similar *)
        (String.is_substring class_name ~substring:"Message" &&
         (String.equal method_name "getBody" ||
          String.equal method_name "getPayload"))
    | _ -> false

  (* Check if a method call is an unsafe deserialization sink based on CodeQL's comprehensive list *)
  let is_unsafe_deserialization_sink proc_name =
    match proc_name with
    | Procname.Java java_proc_name ->
        let class_name = Procname.Java.get_class_name java_proc_name in
        let method_name = Procname.Java.get_method java_proc_name in
        (
          (* ObjectInputStream.readObject/readUnshared - exclude safe variants *)
          (String.is_substring class_name ~substring:"ObjectInputStream" &&
           not (String.is_substring class_name ~substring:"ValidatingObjectInputStream" ||
                String.is_substring class_name ~substring:"SerialKiller") &&
           (String.equal method_name "readObject" ||
            String.equal method_name "readUnshared")) ||
          (* XMLDecoder.readObject *)
          (String.is_substring class_name ~substring:"XMLDecoder" &&
           String.equal method_name "readObject") ||
          (* XStream deserialization *)
          (String.is_substring class_name ~substring:"XStream" &&
           (String.equal method_name "fromXML" ||
            String.equal method_name "fromJSON")) ||
          (* Kryo deserialization *)
          (String.is_substring class_name ~substring:"Kryo" &&
           String.equal method_name "readObject") ||
          (* Apache Commons Lang SerializationUtils *)
          (String.is_substring class_name ~substring:"SerializationUtils" &&
           String.equal method_name "deserialize") ||
          (* SnakeYAML unsafe parsing *)
          (String.is_substring class_name ~substring:"Yaml" &&
           (String.equal method_name "load" ||
            String.equal method_name "loadAll")) ||
          (* FastJSON *)
          (String.is_substring class_name ~substring:"JSON" &&
           (String.equal method_name "parseObject" ||
            String.equal method_name "parse")) ||
          (* Jackson ObjectMapper with potential unsafe configurations *)
          (String.is_substring class_name ~substring:"ObjectMapper" &&
           (String.equal method_name "readValue" ||
            String.equal method_name "readTree")) ||
          (* Gson deserialization *)
          (String.is_substring class_name ~substring:"Gson" &&
           String.equal method_name "fromJson") ||
          (* JsonIo *)
          (String.is_substring class_name ~substring:"JsonReader" &&
           String.equal method_name "jsonToJava") ||
          (* YamlBeans *)
          (String.is_substring class_name ~substring:"YamlReader" &&
           String.equal method_name "read") ||
          (* Hessian/Burlap *)
          ((String.is_substring class_name ~substring:"HessianInput" ||
            String.is_substring class_name ~substring:"BurlapInput") &&
           String.equal method_name "readObject") ||
          (* Castor *)
          (String.is_substring class_name ~substring:"Unmarshaller" &&
           String.equal method_name "unmarshal") ||
          (* Jabsorb *)
          (String.is_substring class_name ~substring:"JSONRPCBridge" &&
           (String.equal method_name "unmarshall" ||
            String.equal method_name "fromJSON")) ||
          (* JoddJson *)
          (String.is_substring class_name ~substring:"JsonParser" &&
           String.equal method_name "parse") ||
          (* Flexjson *)
          (String.is_substring class_name ~substring:"JSONDeserializer" &&
           String.equal method_name "deserialize")
        )
    | _ -> false

  (* Extract variable from expression if possible *)
  let get_var_from_exp exp =
    match exp with
    | Exp.Var id -> Some (Var.of_id id)
    | Exp.Lvar pvar -> Some (Var.of_pvar pvar)
    | _ -> None

  (* Check if any argument is tainted *)
  let has_tainted_args args state =
    List.exists args ~f:(fun (exp, _) ->
      match get_var_from_exp exp with
      | Some var -> Domain.is_var_tainted var state
      | None -> false
    )

  (* Check if the qualifier (receiver) is tainted *)
  let is_qualifier_tainted qualifier state =
    match qualifier with
    | Some exp -> 
        (match get_var_from_exp exp with
        | Some var -> Domain.is_var_tainted var state
        | None -> false)
    | None -> false

  (* Add taint to return value *)
  let add_taint_to_return ret state =
    match ret with
    | Some (id, _) -> Domain.add_tainted_var (Var.of_id id) state
    | None -> state

  (** Main transfer function *)
  let exec_instr (astate : UnsafeDeserializationDomain.t)
      ({InterproceduralAnalysis.proc_desc; err_log; tenv= _; analyze_dependency= _; _} as analysis_data) _ _
      (instr : Sil.instr) =
    match instr with
    | Call ((id, _), Const (Cfun callee_proc_name), actuals, loc, _) ->
        (* Function call with return value *)
        if is_remote_source callee_proc_name then (
          (* Taint the return value for remote source methods *)
          L.progress "UnsafeDeserialization: Found source %a at %a@." Procname.pp callee_proc_name Location.pp loc ;
          UnsafeDeserializationDomain.add_tainted_var (Var.of_id id) astate
        ) else if is_unsafe_deserialization_sink callee_proc_name then (
          (* Check if arguments are tainted for deserialization sinks *)
          let has_tainted_input = 
            List.exists actuals ~f:(fun (exp, _) ->
              match get_var_from_exp exp with
              | Some var -> UnsafeDeserializationDomain.is_var_tainted var astate
              | None -> false
            )
          in
          if has_tainted_input then (
            (* Report unsafe deserialization vulnerability *)
            let message = "Unsafe deserialization of user-controlled data may allow arbitrary code execution" in
            Reporting.log_issue proc_desc err_log ~loc UnsafeDeserialization IssueType.unsafe_deserialization message ;
            astate
          ) else
            astate
        ) else
          astate
    | Call (_, Const (Cfun callee_proc_name), actuals, loc, _) ->
        (* Function call without return value *)
        if is_unsafe_deserialization_sink callee_proc_name then
          (* Check if arguments are tainted for deserialization sinks *)
          let has_tainted_input = 
            List.exists actuals ~f:(fun (exp, _) ->
              match get_var_from_exp exp with
              | Some var -> UnsafeDeserializationDomain.is_var_tainted var astate
              | None -> false
            )
          in
          if has_tainted_input then (
            (* Report unsafe deserialization vulnerability *)
            let message = "Unsafe deserialization of user-controlled data may allow arbitrary code execution" in
            Reporting.log_issue proc_desc err_log ~loc UnsafeDeserialization IssueType.unsafe_deserialization message ;
            astate
          ) else
            astate
        else
          astate
    | Store {e1= lhs; e2= rhs; typ= _; loc= _} ->
        (* Store operation: *lhs = rhs - propagate taint *)
        (match get_var_from_exp rhs with
        | Some rhs_var when UnsafeDeserializationDomain.is_var_tainted rhs_var astate ->
            (* If storing to a variable, propagate taint *)
            (match get_var_from_exp lhs with
            | Some lhs_var ->
                UnsafeDeserializationDomain.add_tainted_var lhs_var astate
            | None ->
                astate)
        | _ ->
            astate)
    | Load {id= lhs; e= rhs; typ= _; loc= _} ->
        (* Load operation: lhs = *rhs - propagate taint *)
        (match get_var_from_exp rhs with
        | Some rhs_var when UnsafeDeserializationDomain.is_var_tainted rhs_var astate ->
            let lhs_var = Var.of_id lhs in
            UnsafeDeserializationDomain.add_tainted_var lhs_var astate
        | _ ->
            astate)
    | Prune (_assume_exp, _loc, _, _) ->
        (* Conditional assumption - no taint propagation for now *)
        astate
    | Call (_, call_exp, _actuals, loc, _) ->
        (* Indirect call - should not happen in Java *)
        L.die InternalError "Unexpected indirect call %a at %a" Exp.pp call_exp Location.pp loc
    | Metadata _ ->
        astate

  let pp_session_name _node fmt = F.pp_print_string fmt "unsafe deserialization"
end

(** Use normal CFG (without exceptional edges) *)
module CFG = ProcCfg.Normal

(** Create the abstract interpreter *)
module Analyzer = AbstractInterpreter.MakeRPO (TransferFunctions (CFG))

(** Main checker entry point *)
let checker ({InterproceduralAnalysis.proc_desc} as analysis_data) =
  let result = Analyzer.compute_post analysis_data ~initial:UnsafeDeserializationDomain.empty proc_desc in
  result