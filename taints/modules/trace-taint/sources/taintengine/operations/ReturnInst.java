package taintengine.operations;

import java.io.IOException;

import taintengine.NodeMapper;
import taintengine.TaintVector;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import taintengine.handlers.helperclasses.StructureMapper;
import taintengine.handlers.helperclasses.TokenManager;
import taintengine.handlers.helperclasses.VaListMapper;
import utils.LineInformation;

public class ReturnInst extends Operation {
    /**
     * Creates a return instruction with the given line information
     * @param info the line information
     */
    public ReturnInst(LineInformation info) { super(info); }

    @Override
    public void propagateTaint(NodeMapper nodeMapper) {
        if (0 == getOperands().length) {
            newNode = nodeMapper.returnCall("", 0, 0);
            return;
        }

        // return the register it returns to
        // the first operator defines the vector length
        newNode = nodeMapper.returnCall(getOperandNames()[0], info.getOperands()[0].getVectorLength(), info.getOperands()[0].getByteSizeUnderlyingType());
    }

    @Override
    public void handleStructureSendFieldAccess(StructureMapper structureMapper, NodeMapper nodeMapper, EventSender eventSender) {
        structureMapper.returnCall();
    }

    @Override
    public void handleMethodEnterExit(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) throws IOException {
        super.handleArrayAccess(nodeMapper, eventSender, arMapper);
        // at this point the function stack is already reduced, so we have to look at the taints of the returned node
        TaintVector taintForName = nodeMapper.getTaintForName(newNode);
        // if there is no taint for the return value, then print no taint but create event anyway
        if (null == taintForName) {
            taintForName = new TaintVector(0, 0);
        }
        eventSender.methodExit(info.getFunction(), taintForName);
    }

    @Override
    public void handleArrayAccess(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) {
        arMapper.returnCall();
    }

    @Override
    public void handleToken(NodeMapper nodeMapper, TokenManager tokenManager, EventSender eventSender) {
        // specifically only taint returned constants, otw. the value was stored in a variable or memory section beforehand and was already tainted
        // && "Constant".equals(getOperands()[0].getName())
        if (0 < getOperands().length  && "i32".equals(getOperands()[0].getType())) {
            tokenManager.getValue().flatMap(val -> tokenManager.getTnt()).ifPresent(tnt -> nodeMapper.addTaintForLocal(newNode, tnt));
        }
        tokenManager.clean();
    }

    @Override
    public void handleVaList(NodeMapper nodeMapper, VaListMapper vaMapper) {
        vaMapper.methodReturn();
    }
}
