package taintengine.operations;

import java.io.IOException;

import taintengine.NodeMapper;
import taintengine.Taint;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import taintengine.handlers.helperclasses.StructureMapper;
import taintengine.handlers.helperclasses.VaListMapper;
import utils.LineInformation;
import utils.TaintType;

public class GetElementPointer extends Operation {
    /**
     * Creates an getElementPoitner operation with the given line information.
     * @param info the given line information
     */
    public GetElementPointer(LineInformation info) { super(info); }

    @Override
    public void propagateTaint(NodeMapper nodeMapper) {
        super.propagateTaint(nodeMapper);

        var address = Long.parseUnsignedLong(getOperands()[0].getValue());
        for (var op : getOperandNames()) {
            var tntVec = nodeMapper.getTaintForName(op);
            if (null != tntVec && !tntVec.getTaint(0).isEmpty()) {
                var tnt = tntVec.getTaint(0);
                // for the moment we only taint tables with strconst taints (assuming those are the writes to a lookup table)
                // later we might also want to use this for semantic checks where we will also have to taint
                if (tnt.hasTaintType(TaintType.STRCONST)) {
                    nodeMapper.taintTablePointer(address, tntVec.getTaint(0));
                }
            }
        }
    }

    // for a GEP the structure mapper has to save the name of the variable together with the name of the accesses field element.
    @Override
    public void handleStructureSendFieldAccess(StructureMapper structureMapper, NodeMapper nodeMapper, EventSender eventSender) {
        // a pointer to a structure
        if (3 > getOperands().length) {
            return;
        }
        // TODO it might be the case, that multi dereferencing leads to a cascade of dereferencings
        Integer[] extractedValues = extractValues(getOperands()[2].getValue());
        // if the integer extraction was not successful this is not a structure field access
        if (0 < extractedValues.length) {
            structureMapper.mapLocalToElement(getNewNodeName(), getOperands()[0].getType(), extractedValues[0]);
        }
    }

    @Override
    public void handleArrayAccess(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) throws IOException {
        super.handleArrayAccess(nodeMapper, eventSender, arMapper);
        // if "[" is contained, then an element from an array is taken
        if (getOperands()[0].getType().contains("[")) {
            // the third operand defines the index
            arMapper.setArrayIndex(info.getAssignedRegisterName(), Long.parseUnsignedLong(getOperands()[2].getValue()));
            arMapper.setAccessedArray(info.getAssignedRegisterName(), getOperands()[0].getValue());
        }
        for (var op : getOperands()) {
            var tnt = nodeMapper.getTaintForName(op.getName());
            if (null != tnt && !tnt.isEmpty() && tnt.getTaint(0).hasOnlyTaintType(TaintType.DEFAULT)) {
                eventSender.cmimid("mem_access", tnt.getTaint(0));
            }
        }
    }

    @Override
    public void handleBinOperation(NodeMapper nodeMapper, EventSender eventSender) {
        var address = Long.parseUnsignedLong(getOperands()[0].getValue());
        for (var op : getOperandNames()) {
            var opTaint = nodeMapper.getTaintForName(op);
            // if a tainted value is used for a loookup and the lookup is not done by a strconstant, then we need to check if we have taints attached to the address
            if (null != opTaint && !opTaint.isEmpty() && !opTaint.getTaint(0).hasTaintType(TaintType.STRCONST)) {
                var tnts = nodeMapper.getTablePointerTaints(address);
                if (0 != tnts.length) {
                    eventSender.tableLookup(opTaint.getTaint(0), tnts);
                }
            }
        }
    }

    @Override
    public void handleVaList(NodeMapper nodeMapper, VaListMapper vaMapper) {
        long vaListAddress = Long.parseUnsignedLong(getOperands()[0].getValue());
        if (vaMapper.isVaList(vaListAddress)) {
            if ("2".equals(getOperands()[2].getValue()) || "3".equals(getOperands()[2].getValue())) {
                vaMapper.stageElement(vaListAddress);
            }
        }
    }
}
