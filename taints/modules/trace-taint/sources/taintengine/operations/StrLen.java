package taintengine.operations;

import taintengine.NodeMapper;
import taintengine.Taint;
import taintengine.TaintVector;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import utils.LineInformation;
import utils.TaintType;

import java.io.IOException;

public class StrLen extends Operation {
    /**
     * Creates a strto operation which performs the taint propagation over
     * strto calls, like strtol, strtod, ...
     * @param info
     */
    public StrLen(LineInformation info) { super(info); }

    @Override
    public void propagateTaint(NodeMapper nodeMapper) {
        newNode = info.getAssignedRegisterName();
        long address = Long.parseLong(info.getOperands()[0].getValue());
        var strLen = nodeMapper.getRemainingBytesForAddress(address);
        if (0 >= strLen) {
            return;
        }
        var taints = nodeMapper.getTaintsForAddress(address, 1, strLen);

        // od not create strlen taints for string constants
        if (taints.isEmpty() || taints.getTaint(0).hasTaintType(TaintType.STRCONST)) {
            return;
        }

        int byteSizeUnderlyingTypeAssignedRegister = info.getAssignedRegister().getByteSizeUnderlyingType();
        taints.forEach(tnt -> tnt.addTaintType(TaintType.STRLEN));
        taints = TaintVector.unionIntoFull(new TaintVector(1, byteSizeUnderlyingTypeAssignedRegister), taints);
        Taint[] tnts = {taints.getTaint(0)};
        nodeMapper.addLocalVector(info.getAssignedRegisterName(), tnts, byteSizeUnderlyingTypeAssignedRegister, TaintVector::unionIntoFull);

    }

    @Override
    public void handleArrayAccess(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) {
        // Intentionally left blank
    }
}
