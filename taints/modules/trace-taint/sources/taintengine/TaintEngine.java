package taintengine;

import java.util.BitSet;
import java.util.Map;
import java.util.List;
import java.util.LinkedList;

import taintengine.handlers.OperationHandler;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.ResourceManager;
import taintengine.helperclasses.ProgramInputInformation;
import taintengine.operations.ConcreteOperationFactory;
import taintengine.operations.Operation;
import taintengine.operations.interfaces.OperationFactory;
import utils.LineInformation;
import utils.Operand;
import utils.Utils;

public class TaintEngine {
    private final OperationFactory opFactory = new ConcreteOperationFactory();
    private final NodeMapper nodeMapper;
    private final List<OperationHandler> operationHandlers = new LinkedList<>();

    /**
     * Create the initial datastructure which will then be used to track the taint information.
     * Initialize the taint for the command line arguments.
     *
     * @param argv the input characters from the command line
     * @param funDefMap the mapping from function names to their definitions (the used arguments)
     * @param gvarMap the map of global variables to their operands
     * @param resourceManager the resourcemanager monitoring at which file position each input source is
     */
    public TaintEngine(ProgramInputInformation[][] argv, Map<String, String[]> funDefMap, List<Operand> gvarMap, ResourceManager resourceManager) {
        nodeMapper = new NodeMapper(funDefMap, gvarMap, resourceManager);

        int index = 0;
        if ("argv".equals(Utils.getobservedInputSource())) {
            for (ProgramInputInformation[] leafArray : argv) {
                for (ProgramInputInformation taintedInput : leafArray) {
                    BitSet forTaint = new BitSet(8);
                    resourceManager.setCharacter(Utils.ARGVSOURCEID, index, taintedInput.getCorrespondingCharacter());
                    forTaint.set(index++);

                    nodeMapper.addAddressTaint(taintedInput.getAddress(), new Taint(Utils.ARGVSOURCEID, forTaint, 1));
                }
            }
            resourceManager.saveFilePosition(Utils.ARGVSOURCEID, index);
        }
        String[] operands = {"argc", "argv"};
        nodeMapper.functionCall("_real_program_main", operands, "MainReturnDummy");
    }

    /**
     * Gets the information of a line and generates a node out of this.
     * @param info The lineinformation
     */
    public void handleLine(LineInformation info) {
        Operation operation = opFactory.getOperation(info);

        for (OperationHandler opHandler : this.operationHandlers) {
            opHandler.handleOperation(operation, nodeMapper);
        }
        // after each operation replace the last LineInformation
        nodeMapper.replacePrevLineInformation(info);
    }

    /**
     * Adds an OperationHandler to the taint engine. This handler will be executed after all other handlers.
     * @param opHandler the specific operation handle to attach
     */
    public void registerHandler(OperationHandler opHandler) { this.operationHandlers.add(opHandler); }

    /**
     * Sets the arrayindexMapper in the node mapper.
     * @param arMapper the arraymapper to attach to the nodemapper
     */
    public void addArrayIndexMapperToNodeMapper(ArrayIndexMapper arMapper) { nodeMapper.addArrayIndexMapper(arMapper); }
}
