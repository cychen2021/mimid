package main;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Optional;
import java.util.zip.GZIPInputStream;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import parser.GzipJsonParser;
import parser.ITraceParser;
import taintengine.TaintEngine;
import taintengine.handlers.ArrayAccessHandler;
import taintengine.handlers.MethodCallHandler;
import taintengine.handlers.MethodEnterExitHandler;
import taintengine.handlers.StructureHandler;
import taintengine.handlers.TaintGenerationHandler;
import taintengine.handlers.TaintPropagationHandler;
import taintengine.handlers.BinOperationHandler;
import taintengine.handlers.TokenHandler;
import taintengine.handlers.VaListHandler;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import taintengine.handlers.helperclasses.PygmalionEventSender;
import taintengine.handlers.helperclasses.ResourceManager;
import taintengine.handlers.helperclasses.StructureMapper;
import taintengine.helperclasses.ProgramInputInformation;
import utils.LineInformation;
import utils.Operand;
import utils.Utils;

public class TaintTracker {
    private static final String programName = "TaintTracker";

    /**
     * Main which initiates the parsing and let the TaintEngine build the shadow memory.
     * @param args The arguments to the program
     * @throws ParseException if parsing of command line is not possible
     * @throws IOException if one of the input files cannot be read
     */
    public static void main(String[] args) throws ParseException, IOException {
        Options option = new Options();
        option.addOption("t", "trace", true, "The input trace file");
        option.addOption("p", "pipe", true, "The input pipe which delivers the trace information from the program with its name as argument.");
        option.addOption("me", "metadata", true, "The file containing metadata for the program (e.g. structs).");
        option.addOption("h", "help", false, "print this message");
        option.addOption("po", "output_file", true, "The file where the output for pygmalion is written to.");
        option.addOption("ai", "array_index_tracking", false, "If the index of an array is tainted, the taint is also propagated to the read value.");
        option.addOption("i", "input_source", true, "If set, the given string will be used to define the input source. Filename for files, \"argv\" for command line inputs. Can be left out to use stdin as input source.");

        HelpFormatter helpFormatter = new HelpFormatter();

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(option, args);

        if (cmd.hasOption("h")) {
            helpFormatter.printHelp(programName, option);
            return;
        }

        if (cmd.hasOption("ai")) {
            Utils.setArrayIndexTaintPropagation(true);
        }

        File metadata;
        if (cmd.hasOption("me")) {
            metadata = new File(cmd.getOptionValue("me"));
        } else {
            helpFormatter.printHelp(programName, option);
            throw new ParseException("The metdata option is missing but required.");
        }

        String eventOutput;
        if (cmd.hasOption("po")) {
            eventOutput = cmd.getOptionValue("po");
        } else {
            helpFormatter.printHelp(programName, option);
            throw new ParseException("Missing event output file (use either '-mo' or '-po')");
        }

        ResourceManager resourceManager = new ResourceManager();

        // create AutoGram or Pygmalion event writer, this has to be given to all handlers that write out events
        EventSender eventSender = new PygmalionEventSender(eventOutput, resourceManager);

        ITraceParser traceParser;
        if (cmd.hasOption("t")) {
            String trace = cmd.getOptionValue("t");
            GZIPInputStream gzReader = new GZIPInputStream(Files.newInputStream(Paths.get(trace)));
            Reader reader = new InputStreamReader(gzReader, StandardCharsets.UTF_8);
            traceParser = new GzipJsonParser(reader);
        } else {
            if (cmd.hasOption("p")) {
                String trace = cmd.getOptionValue("p");
                InputStreamReader isr = new InputStreamReader(Files.newInputStream(Paths.get(trace)), StandardCharsets.UTF_8);
                traceParser = new GzipJsonParser(isr);
            } else {
                helpFormatter.printHelp(programName, option);
                throw new ParseException("The trace option is missing but required. You need to define an"
                                         + " input file or an input pipe.");
            }
        }

        if (cmd.hasOption("i")) {
            Utils.setobservedInputSource(cmd.getOptionValue("i"));
        }

        ProgramInputInformation[][] argvInformation = traceParser.parseArguments();
        StructureMapper structureMapper = new StructureMapper();
        HashMap<String, String[]> functionDefinitions = new HashMap<>(100);
        LinkedList<Operand> gvarDefinitions = new LinkedList<>();
        traceParser.parseMetadata(metadata, structureMapper, functionDefinitions, gvarDefinitions);
        TaintEngine taintEngine = new TaintEngine(argvInformation, functionDefinitions, gvarDefinitions, resourceManager);

        // register handlers
        taintEngine.registerHandler(new MethodCallHandler(eventSender));
        taintEngine.registerHandler(new TaintGenerationHandler(eventSender, resourceManager));
        taintEngine.registerHandler(new TaintPropagationHandler());
        taintEngine.registerHandler(new VaListHandler());

        // StructureHandler, has to be added after taintPropagationHandler
        taintEngine.registerHandler(new StructureHandler(structureMapper, eventSender));

        // giving the arMapper to the nodeMapper is optional, array sizes will not be known if the arMapper is not given
        // this will reduce precision of the taint propagation
        ArrayIndexMapper arMapper = new ArrayIndexMapper(argvInformation);
        taintEngine.addArrayIndexMapperToNodeMapper(arMapper);

        taintEngine.registerHandler(new MethodEnterExitHandler(eventSender, arMapper));
        taintEngine.registerHandler(new ArrayAccessHandler(eventSender, arMapper));
        taintEngine.registerHandler(new BinOperationHandler(eventSender));
        taintEngine.registerHandler(new TokenHandler(eventSender));

        Optional<LineInformation> info = traceParser.parseNextInstruction();
        while (info.isPresent()) {
            taintEngine.handleLine(info.get());
            info = traceParser.parseNextInstruction();
        }

        // close open outputs
        eventSender.close();
    }
}
