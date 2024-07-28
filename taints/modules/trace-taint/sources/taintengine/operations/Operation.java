package taintengine.operations;

import java.io.IOException;
import java.util.LinkedList;

import taintengine.NodeMapper;
import taintengine.TaintVector;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import taintengine.handlers.helperclasses.MethodCallHelper;
import taintengine.handlers.helperclasses.ResourceManager;
import taintengine.handlers.helperclasses.StructureMapper;
import taintengine.handlers.helperclasses.TokenManager;
import taintengine.handlers.helperclasses.VaListMapper;
import utils.LineInformation;
import utils.Operand;

public abstract class Operation {

    private static final String[] STRING_ZERO_ARRAY = new String[0];
    private static final Integer[] INVALID_INTEGER_EXTRACTION = new Integer[0];
    protected final LineInformation info;
    protected String newNode;

    /**
     * Creates an Operation object based on the given line information. This is the abstract constructor.
     * @param info the line information used for this instruction
     */
    protected Operation(LineInformation info) {
        this.info = info;
    }

    /**
     * @return Returns the unfiltered operand List. Also contains values etc. To get only the names of the operands call getOperandNames.
     */
    public Operand[] getOperands() { return info.getOperands(); }

    /**
     * @return Returns only the names of the operands. These are the wished SSA registers.
     */
    public String[] getOperandNames() {
        LinkedList<String> ret = new LinkedList<>();
        for (Operand o : this.getOperands()) {
            ret.add(o.getName());
        }
        return ret.toArray(STRING_ZERO_ARRAY);
    }

    /**
     * Returns the name of the node generated in the propagateTaint operation.
     * This method has to be run beforehand.
     * @return the name of the new node.
     */
    public String getNewNodeName() {
        if (null == newNode) {
            throw new IllegalStateException("The propagateTaint method was not run beforehand or a new Node was not set.");
        }
        return newNode;
    }

    /**
     * Creates a new Node based on the operation. May be overwritten in a concrete class if necessary.
     * @param nodeMapper Maps the name of a ssa-register to a node.
     */
    public void propagateTaint(NodeMapper nodeMapper) {
        Operand result = info.getAssignedRegister();
        nodeMapper.addLocal(result.getName(),
                            this.getOperandNames(),
                            result.getVectorLength(),
                            result.getByteSizeUnderlyingType(),
                            TaintVector::unionIntoFull);

        this.newNode = result.getName();
    }

    /**
     * Returns an array of values. For scalars the array has size 1, for vectors the length of the vector.
     * @return the array of values
     */
    public static Integer[] extractValues(String value) {
        var values = value.split(" ");
        var ret = new Integer[values.length];
        int index = 0;
        for (String v : values) {
            try {
                ret[index] = Integer.parseInt(v);
            } catch (NumberFormatException nfe) {
                return INVALID_INTEGER_EXTRACTION;
            }
            index++;
        }

        return ret;
    }

    /**
     * Works on the StructureMapper to track field accesses and sends events regarding field accesses.
     * @param structureMapper the given structure mapper
     * @param nodeMapper the given node mapper
     */
    public void handleStructureSendFieldAccess(StructureMapper structureMapper, NodeMapper nodeMapper, EventSender eventSender) {
        // Intentionally left blank
    }

    /**
     * Sends events regarding method enter and exit.
     * @param nodeMapper  the given node mapper
     */
    public void handleMethodEnterExit(NodeMapper nodeMapper, EventSender eventSender , ArrayIndexMapper arMapper) throws IOException {
        // Intentionally left blank
    }

    /**
     * Sends events regarding array accesses and stores information regarding array accesses in the arMapper.
     * @param nodeMapper the given node mapper
     */
    public void handleArrayAccess(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) throws IOException {
        // check whether we need for some variable information about the size for an index
        for (Operand op : this.getOperands()) {
            if (op.getType().contains("*")) {
                arMapper.setIndexSize(op.getName(), Long.parseUnsignedLong(op.getValue()));
            }
        }
    }

    /**
     * Generically handles the call to a method. For mostly all operations this is just a return.
     * @param nodeMapper the given node mapper
     * @param mch the given method call handler
     * @throws IOException if messages were not be send-able
     */
    public void handleMethodCall(NodeMapper nodeMapper, MethodCallHelper mch) throws IOException {
        // Intentionally left blank
    }

    /**
     * Generically handles the taint generation. For mostly all operations this is just a return.
     * @param eventSender the eventSender to send messages
     * @param resourceManager the resource manager
     */
    public void handleTaintGeneration(NodeMapper nodeMapper, EventSender eventSender, ResourceManager resourceManager) {
        // Intentionally left blank
    }

    /**
     * Generically handles a binary operation
     * @param nodeMapper the given node mapper
     * @param eventSender the eventSender to send messages
     */
    public void handleBinOperation(NodeMapper nodeMapper, EventSender eventSender) {
        // Intentionally left blank
    }

    /***
     * Handles the generation of token taints. Those taints appear if an enum constant is assigned or returned.
     * @param nodeMapper the given node mapper
     * @param tokenManager the given token manager
     */
    public void handleToken(NodeMapper nodeMapper, TokenManager tokenManager, EventSender eventSender) {
        //Intentionally left blank
    }

    @Override
    public String toString() {
        return "Operation [info=" + info + ", newNode=" + newNode + ']';
    }


    public void handleVaList(NodeMapper nodeMapper, VaListMapper vaMapper) {
        // intentionally left blank
    }
}
