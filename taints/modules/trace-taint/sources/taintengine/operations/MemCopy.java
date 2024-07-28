package taintengine.operations;

import java.io.IOException;

import taintengine.NodeMapper;
import taintengine.Taint;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import utils.LineInformation;

public class MemCopy extends Operation {
    /**
     * Create MemCopy operation. This is a llvm intrinsic operation.
     * I.e. its an intrinsic call to an llvm internal function.
     * The function always has the same semantics.
     * @param info
     */
    public MemCopy(LineInformation info) { super(info); }

    @Override
    public void propagateTaint(NodeMapper nodeMapper) {
        int byteSize = Integer.parseInt(getOperands()[2].getValue());
        long src = Long.parseLong(getOperands()[1].getValue());
        long dest = Long.parseLong(getOperands()[0].getValue());

        Taint[] taint = nodeMapper.getTaintForAddress(src, byteSize);
        nodeMapper.addTaintForAddress(dest, taint);

        newNode = getOperands()[0].getName();
    }

    @Override
    public void handleArrayAccess(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) {
        // for memcpy the memory is already allocated
    }
}
