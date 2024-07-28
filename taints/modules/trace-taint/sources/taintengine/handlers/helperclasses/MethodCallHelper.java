package taintengine.handlers.helperclasses;

import taintengine.NodeMapper;
import taintengine.TaintVector;
import utils.Operand;

import java.io.IOException;
import java.util.LinkedList;

public class MethodCallHelper {
    private static final TaintVector[] TAINT_VECTOR_ARRAY_CONSTANT = new TaintVector[0];
    private Operand[] operands;
    private String returnVariable;
    private final EventSender eventSender;

    /**
     * Generates a new MethodCallHelper with an {@link EventSender} s.t. later MethodEntryEvents can be send.
     * @param eventSender the sender for tainting events
     */
    public MethodCallHelper(EventSender eventSender) { this.eventSender = eventSender; }

    /**
     * Initializes the call instruction, which might be executed next
     * @param operands the operands of the function that is called
     * @param returnVariable the return variable which is filled by the return value of the function
     */
    public void handleCallMethod(Operand[] operands, String returnVariable) {
        this.operands = operands.clone();
        this.returnVariable = returnVariable;
    }

    /**
     * Actually performs the function call on the nodeMapper with the collected information if necessary
     * @param functionName Name of the method surrounding the instruction.
     * @param nodeMapper the nodeMapper
     */
    public void flushCallMethod(String functionName, NodeMapper nodeMapper) {
        // if there was a call instruction beforehand, now execute it and empty the operands and returnVariable
        String[] opNames = new String[operands.length];
        int counter = 0;
        for (Operand op : operands) {
            opNames[counter] = op.getName();
            counter++;
        }
        nodeMapper.functionCall(functionName, opNames, returnVariable);

        LinkedList<TaintVector> arguments = new LinkedList<>();
        for (Operand op : operands) {
            // the last argument ist a pointer to the function, so its not reasonable to print this as well
            // therefore it is skipped here
            if (arguments.size() == operands.length - 1) {
                break;
            }

            TaintVector argumentTaint;

            // if its a pointer dereference and try to extract as many tainted consecutive bits as possible
            if (op.getType().contains("*")) {
                argumentTaint = createTaintVectorForAddress(Long.parseUnsignedLong(op.getValue()), nodeMapper);
            } else {
                // since the new stack was already created one has to take the old stack here to determine which values
                // were tainted when the function was called
                // above for addresses there is no function stack, addresses are global, so no need to do this there
                argumentTaint = nodeMapper.getTaintForNameOldStack(op.getName(), 1);
            }
            if (null == argumentTaint || argumentTaint.isEmpty()) {
                argumentTaint = new TaintVector(0, 0);
            }
            arguments.add(argumentTaint);
        }

        eventSender.methodEnter(functionName, arguments.toArray(TAINT_VECTOR_ARRAY_CONSTANT));

        this.operands = null;
        this.returnVariable = null;
    }

    private static TaintVector createTaintVectorForAddress(long address, NodeMapper nodeMapper) {
        int remBytes = nodeMapper.getRemainingBytesForAddress(address);

        return nodeMapper.getTaintsForAddress(address, 1, remBytes);
    }
}
