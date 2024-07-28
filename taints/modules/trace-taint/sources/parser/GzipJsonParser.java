package parser;

import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.Optional;

import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;

import com.google.gson.stream.MalformedJsonException;
import taintengine.handlers.helperclasses.StructureMapper;
import taintengine.helperclasses.ProgramInputInformation;
import utils.LineInformation;
import utils.Operand;
import utils.Utils;
import utils.Effect;

public class GzipJsonParser implements ITraceParser {
    // Constants to generate arrays from collections
    private static final ProgramInputInformation[] PROGRAM_INPUT_INFORMATION = new ProgramInputInformation[0];
    private static final ProgramInputInformation[][] PROGRAM_INPUT_INFORMATIONS = new ProgramInputInformation[0][0];
    private static final String[] STRINGS = new String[0];
    // end constants

    private final JsonReader jsReader;

    /**
     * @param trace Gzip file containing the trace.
     */
    public GzipJsonParser(Reader trace) {
        jsReader = new JsonReader(trace);
        jsReader.setLenient(true);
    }

    @Override
    public ProgramInputInformation[][] parseArguments() throws IOException {
        LinkedList<ProgramInputInformation> tmpList = new LinkedList<>();
        LinkedList<ProgramInputInformation[]> leafList = new LinkedList<>();

        while (JsonToken.END_DOCUMENT != jsReader.peek()) {
            jsReader.beginObject();
            // check whether it really starts with argv, else skip the first object
            if ("av".equals(jsReader.nextName())) {
                // leave loop if the argv content is found
                break;
            }

            while (JsonToken.END_OBJECT != jsReader.peek()) {
                jsReader.skipValue();
            }
            jsReader.endObject();
        }
        jsReader.beginArray();
        // start of json object which represents the argv array
        while (jsReader.hasNext()) {
            jsReader.beginObject();
            // names are irrelevant here
            jsReader.nextName();
            jsReader.beginArray();
            // start of an element of the argv array
            long taintValue = 0;
            while (jsReader.hasNext()) {
                jsReader.beginObject();
                // names are irrelevant here
                jsReader.nextName();
                taintValue = Long.decode(jsReader.nextString());

                // names are irrelevant here
                jsReader.nextName();
                char correspondingChar = jsReader.nextString().charAt(0);
                ProgramInputInformation addNode = new ProgramInputInformation(taintValue, correspondingChar);
                tmpList.add(addNode);
                jsReader.endObject();
            }
            // add the \0 character which shows the end of a c string
            ProgramInputInformation addNode = new ProgramInputInformation(taintValue + 1, '\0');
            tmpList.add(addNode);
            leafList.add(tmpList.toArray(PROGRAM_INPUT_INFORMATION));
            tmpList.clear();
            jsReader.endArray();
            jsReader.endObject();
        }
        jsReader.endArray();
        jsReader.endObject();
        return leafList.toArray(PROGRAM_INPUT_INFORMATIONS);
    }

    private static void parseFunctionDefinition(Map<String, String[]> functions, JsonReader mdataReader) throws IOException {
        mdataReader.setLenient(true);
        LinkedList<String> args = new LinkedList<>();

        // names are irrelevant here
        String fname = mdataReader.nextString(); // no checkstyle, not solvable otherwise

        // the name is irrelevant, its always the start of the array
        mdataReader.nextName();

        // parse array
        mdataReader.beginArray();
        // start of the array containing the operands
        while (mdataReader.hasNext()) {
            mdataReader.beginObject();

            // names are irrelevant here
            mdataReader.nextName();
            // the operand name
            args.add(mdataReader.nextString());

            // read type, which is not relevant here, but later for the JFlow information
            // names are irrelevant here
            mdataReader.nextName();
            // the operand name
            mdataReader.nextString();

            mdataReader.endObject();
        }
        mdataReader.endArray();

        if ("main".equals(fname)) {
            fname = "_real_program_main";
        }

        functions.put(fname, args.toArray(STRINGS));
        args.clear();
        mdataReader.endObject();
    }

    private static void parseGVar(List<Operand> operands, JsonReader mdataReader) throws IOException {
        // at start the global variables have no meaning, i.e. no taints, so a taint vector of size 1 is created
        String name = mdataReader.nextString();

        mdataReader.nextName();

        String type = mdataReader.nextString();

        mdataReader.nextName();

        String value = mdataReader.nextString();
        operands.add(new Operand(name, value, type)); // no tainted value at start, so the value is not logged

        mdataReader.endObject();
    }

    @Override
    public void parseMetadata(File metadata, StructureMapper structureMapper, Map<String, String[]> functions, List<Operand> gvars) throws IOException {
        InputStreamReader mreader = new InputStreamReader(new BufferedInputStream(new FileInputStream(metadata)), StandardCharsets.UTF_8);
        JsonReader mdataReader = new JsonReader(mreader);
        mdataReader.setLenient(true);

        // eof exception has to be catched if file is empty: https://github.com/google/gson/issues/330
        try {
            mdataReader.peek();
        } catch (EOFException e) {
            mdataReader.close();
            return;
        }

        while (JsonToken.END_DOCUMENT != mdataReader.peek()) {
            mdataReader.beginObject();

            // check if the next element is a structure, if not do no use this element
            String typeDefinition = mdataReader.nextName();
            if ("sn".equals(typeDefinition)) {
                extractStructureInformation(structureMapper, mdataReader);
                continue;
            }
            if ("un".equals(typeDefinition)) {
                extractUnionInformation(mdataReader);
                continue;
            }
            if ("f".equals(typeDefinition)) {
                parseFunctionDefinition(functions, mdataReader);
                continue;
            }
            if ("gv".equals(typeDefinition)) {
                parseGVar(gvars, mdataReader);
                continue;
            }
            // skip everything that is not useful for now
            while (JsonToken.END_OBJECT != mdataReader.peek()) {
                mdataReader.skipValue();
            }
            mdataReader.endObject();
        }

        mdataReader.close();
    }

    private static List<String>[] parseFunctionStaticInfo(JsonReader mdataReader) throws IOException {
        mdataReader.setLenient(true);

        LinkedList<String>[] fnameAndArgs;
        fnameAndArgs = new LinkedList[] {new LinkedList<String>(), new LinkedList<String>()};

        // functionName
        fnameAndArgs[0].add(mdataReader.nextString());

        // the name is irrelevant, its always the start of the array
        mdataReader.nextName();

        // parse array
        mdataReader.beginArray();
        // start of the array containing the operands
        while (mdataReader.hasNext()) {
            mdataReader.beginObject();

            // names are irrelevant here
            mdataReader.nextName();
            // the operand name
            fnameAndArgs[1].add(mdataReader.nextString());

            // read type and report
            // names are irrelevant here
            mdataReader.nextName();
            // the operand name
            fnameAndArgs[0].add(mdataReader.nextString());

            mdataReader.endObject();
        }
        mdataReader.endArray();

        mdataReader.endObject();

        return fnameAndArgs;
    }

    private static List<String> parseStructureNames(JsonReader mdataReader) throws IOException {
        LinkedList<String> snames = new LinkedList<>();
        while (mdataReader.hasNext()) {
            mdataReader.beginObject();

            // names are irrelevant here
            mdataReader.nextName();
            // the operand name
            snames.add(mdataReader.nextString());

            mdataReader.endObject();
        }
        return snames;
    }

    @Override
    public void extractStaticInfo(File metadata, ObjectOutputStream oos) throws IOException {
        InputStreamReader mreader = new InputStreamReader(new BufferedInputStream(new FileInputStream(metadata)), StandardCharsets.UTF_8);
        JsonReader mdataReader = new JsonReader(mreader);
        mdataReader.setLenient(true);

        // eof exception has to be catched if file is empty: https://github.com/google/gson/issues/330
        try {
            mdataReader.peek();
        } catch (EOFException e) {
            mdataReader.close();
            return;
        }
        LinkedList<String> functionNames = new LinkedList<>();
        LinkedList<String> paramList = new LinkedList<>();
        LinkedList<List<String>> funParameterNames = new LinkedList<>();

        LinkedList<String> structureNames = new LinkedList<>();
        LinkedList<List<String>> structureFields = new LinkedList<>();
        while (JsonToken.END_DOCUMENT != mdataReader.peek()) {
            mdataReader.beginObject();

            // take the next function
            String typeDefinition = mdataReader.nextName();
            if ("f".equals(typeDefinition)) {
                List<String>[] funNamesAndParams = parseFunctionStaticInfo(mdataReader);
                functionNames.add(funNamesAndParams[0].remove(0));
                paramList.add(createMethodDescription(funNamesAndParams[0]));
                funParameterNames.add(funNamesAndParams[1]);
                continue;
            }

            // take the next structure or union
            if ("sn".equals(typeDefinition)) { // || typeDefinition.equals("un")) {
                structureNames.add(mdataReader.nextString());
                mdataReader.nextName();
                mdataReader.nextInt();
                mdataReader.nextName();
                mdataReader.beginArray();
                structureFields.addLast(parseStructureNames(mdataReader));
                mdataReader.endArray();
                mdataReader.endObject();
                continue;
            }

            // skip everything that is not useful for now
            while (JsonToken.END_OBJECT != mdataReader.peek()) {
                mdataReader.skipValue();
            }
            mdataReader.endObject();
        }
        // write out data for jflow

        // print out static info about classes. since they do not exist, static data has to be printed out
        oos.writeInt(structureNames.size() + 1);
        // main class with methods
        oos.writeUTF("MainClass");
        // membercount
        oos.writeInt(functionNames.size());
        for (String fname : functionNames) {
            // membertype (function = 0)
            oos.writeInt(0);
            // ID
            oos.writeInt(fname.hashCode());
            // Name
            oos.writeUTF(fname);
            // memberDesc
            oos.writeUTF(paramList.remove(0));
            // methodparameternames
            List<String> funParamNames = funParameterNames.remove(0);
            oos.writeInt(funParamNames.size());
            for (String paramName : funParamNames) {
                oos.writeUTF(paramName);
            }
            // isStatic
            oos.writeBoolean(true);
            //#branches
            oos.writeInt(0);
        }

        // structs which count as classes which have fields
        for (String sname : structureNames) {
            // main class with methods
            oos.writeUTF(sname);

            List<String> fieldNames = structureFields.remove(0);
            // membercount
            oos.writeInt(fieldNames.size());
            for (String fieldName : fieldNames) {
                // membertype, field has value 2
                oos.writeInt(2);
                // id
                oos.writeInt(fieldName.hashCode());
                // name
                oos.writeUTF(fieldName);
                // type
                oos.writeUTF("Ljava/lang/Object;");
                // is not static
                oos.writeBoolean(false);
            }
        }

        //#nativeMethods
        oos.writeInt(0);

        mdataReader.close();
    }

    private static String createMethodDescription(List<String> params) {
        StringBuilder methodDesc = new StringBuilder();
        methodDesc.append('(');
        for (String param : params) {
            methodDesc.append(convertToJavaType(param));
        }
        methodDesc.append(")V");
        return methodDesc.toString();
    }

    private static String convertToJavaType(String type) {
        switch (type) {
        case "i8": return "C";
        case "i8*": return "Ljava/lang/String;";
        case "float": return "F";
        case "double": return "D";
        case "i1": return "Z";
        default:
            break;
            // do nothing
        }

        if (!type.isEmpty() && 'i' == type.charAt(0) && !(!type.isEmpty() && '*' == type.charAt(type.length() - 1))) {
            return "I";
        }

        return "Ljava/lang/Object;";
    }

    private static void extractUnionInformation(JsonReader mdataReader) throws IOException {
        String name = mdataReader.nextString();

        // name irrelevant here, array starts next
        mdataReader.nextName();

        int unionSize = mdataReader.nextInt();
        Utils.SIZEMAP.put(name, unionSize);

        mdataReader.endObject();
    }

    private static void extractStructureInformation(StructureMapper structureMapper, JsonReader mdataReader) throws IOException {
        String name = mdataReader.nextString();

        // name irrelevant here, array starts next
        mdataReader.nextName();

        int structSize = mdataReader.nextInt();
        Utils.SIZEMAP.put(name, structSize);

        // name irrelevant here, array starts next
        mdataReader.nextName();

        LinkedList<String> elements = new LinkedList<>();

        mdataReader.beginArray();
        // start of the array containing the elements
        while (mdataReader.hasNext()) {
            mdataReader.beginObject();

            // names are irrelevant here
            mdataReader.nextName();
            // the element name
            elements.add(mdataReader.nextString());

            mdataReader.endObject();
        }
        mdataReader.endArray();

        mdataReader.endObject();

        structureMapper.addStructure(name, elements.toArray(STRINGS));
    }

    @Override
    public Optional<LineInformation> parseNextInstruction() throws IOException {
        try {
            if (JsonToken.END_DOCUMENT == jsReader.peek()) {
                jsReader.close();
                return Optional.empty();
            }
            jsReader.beginObject();
            boolean isFunction = Utils.CALLOBJECTSTARTER.equals(jsReader.nextName());
            if (isFunction) {
                return Optional.ofNullable(parseFunctionLine());
            } else {
                return Optional.ofNullable(parseStandardLine());
            }
        } catch (EOFException | MalformedJsonException eofException) {
            System.err.println("Input was truncated. Using the information up until then.");
            eofException.printStackTrace();
            return Optional.empty();
        }
    }

    /**
     * Parse a json object containing a call instruction.
     * @return The info for the line.
     * @throws IOException if file cannot be read
     */
    private LineInformation parseFunctionLine() throws IOException {
        LineInformation info = new LineInformation();

        info.setInstruction(jsReader.nextString());

        // names are irrelevant here
        jsReader.nextName();
        // get Name of surrounding function
        info.setFunction(jsReader.nextString());

        // names for data are irrelevant here
        jsReader.nextName();
        // read name of assigned register
        String name = jsReader.nextString();

        // names for data are irrelevant here
        jsReader.nextName();
        // read type for assigned register
        String type = jsReader.nextString();

        info.setAssignedRegister(name, type);

        // names are irrelevant here
        jsReader.nextName();
        List<Map<String, String>> operands = parseObjectsArray();
        info.setOperands(operands);

        // parse opts
        jsReader.nextName();
        List<Map<String, String>> opts = parseObjectsArray();
        info.setOpts(opts);

        jsReader.endObject();

        for (Effect e : info.getOpts()) {
            if ("opcode".equals(e.get("type"))) {
                info.setOpcode(Integer.parseInt(e.get("value")));
                return info;
            }
        }

        info.setOpcode(Utils.CALLINSTRUCTIONOPCODE);
        return info;
    }

    /**
     * Parse a json object containing a default instruction.
     * @return The info for the line.
     * @throws IOException if file cannot be read
     */
    private LineInformation parseStandardLine() throws IOException {
        LineInformation info = new LineInformation();

        info.setOpcode(jsReader.nextInt());

        // names for data are irrelevant here
        jsReader.nextName();
        info.setFunction(jsReader.nextString());

        // names for data are irrelevant here
        jsReader.nextName();
        // read name of assigned register
        String name = jsReader.nextString();

        // names for data are irrelevant here
        jsReader.nextName();
        // read type for assigned register
        String type = jsReader.nextString();

        info.setAssignedRegister(name, type);

        // parse array of operands
        jsReader.nextName();
        List<Map<String, String>> operands = parseObjectsArray();
        info.setOperands(operands);

        jsReader.endObject();

        return info;
    }

    /**
     * Parse the operands of an instruction.
     * @throws IOException if file cannot be read
     */
    private List<Map<String, String>> parseObjectsArray() throws IOException {
        List<Map<String, String>> result = new ArrayList<>(5);

        // iterate through the content of the array
        jsReader.beginArray();
        while (jsReader.hasNext()) {
            jsReader.beginObject();

            // read one object
            Map<String, String> object = new HashMap<>(5);
            while (jsReader.hasNext()) {
                object.put(jsReader.nextName(), jsReader.nextString());
            }
            result.add(object);

            jsReader.endObject();
        }
        jsReader.endArray();

        return result;
    }
}
