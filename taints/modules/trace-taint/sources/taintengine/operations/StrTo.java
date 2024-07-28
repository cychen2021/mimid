package taintengine.operations;

import taintengine.NodeMapper;
import taintengine.Taint;
import taintengine.TaintVector;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import utils.LineInformation;

public class StrTo extends Operation {
    /**
     * Creates a strto operation which performs the taint propagation over
     * strto calls, like strtol, strtod, ...
     * @param info the line information
     */
    public StrTo(LineInformation info) { super(info); }

    @Override
    public void propagateTaint(NodeMapper nodeMapper) {
        var value = info.getOpts()[1].get("result");
        newNode = info.getAssignedRegisterName();
        if (2 > value.length()) {
            // nothing was converted, the function got an empty string
            return;
        }
        long address = Long.parseLong(info.getOpts()[1].get("source"));
        int strLength;
        if (2 < info.getOpts().length) {
            strLength = (int) (Long.parseLong(info.getOpts()[2].get("source")) - address);
        } else {
            strLength = value.length();
        }

        TaintVector taintedMemory = nodeMapper.getTaintsForAddress(address, 1, strLength);
        LineInformation prevLineInformation = nodeMapper.getPrevLineInformation();
        int byteSizeUnderlyingType = prevLineInformation.getAssignedRegister().getByteSizeUnderlyingType();
        taintedMemory = TaintVector.unionIntoFull(new TaintVector(1, byteSizeUnderlyingType), taintedMemory);
        Taint[] tnts = {taintedMemory.getTaint(0)};
        nodeMapper.addLocalVector(prevLineInformation.getAssignedRegisterName(), tnts, byteSizeUnderlyingType, TaintVector::unionIntoFull);
    }

    @Override
    public void handleBinOperation(NodeMapper nodeMapper, EventSender eventSender) {
        var value = info.getOpts()[1].get("result");
        newNode = info.getAssignedRegisterName();
        if (2 > value.length()) {
            // nothing was converted, the function got an empty string
            return;
        }
        long address = Long.parseLong(info.getOpts()[1].get("source"));
        int strLength;
        if (2 < info.getOpts().length) {
            strLength = (int) (Long.parseLong(info.getOpts()[2].get("source")) - address);
        } else {
            strLength = value.length();
        }
        TaintVector taintedMemory = nodeMapper.getTaintsForAddress(address, 1, strLength);
        LineInformation prevLineInformation = nodeMapper.getPrevLineInformation();
        int byteSizeUnderlyingType = prevLineInformation.getAssignedRegister().getByteSizeUnderlyingType();
        taintedMemory = TaintVector.unionIntoFull(new TaintVector(1, byteSizeUnderlyingType), taintedMemory);
        Taint tnts = taintedMemory.getTaint(0);
        if (!tnts.isEmpty()) {
            eventSender.conversion(value, prevLineInformation.getOperands()[prevLineInformation.getOperands().length - 1].getName(), tnts);
        }
    }

    @Override
    public void handleArrayAccess(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) {
        // Intentionally left blank
    }
}
