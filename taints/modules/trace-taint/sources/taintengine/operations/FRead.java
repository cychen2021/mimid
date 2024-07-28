package taintengine.operations;

import taintengine.NodeMapper;
import taintengine.Taint;
import taintengine.TaintVector;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import taintengine.handlers.helperclasses.ResourceManager;
import utils.LineInformation;
import utils.Utils;

public class FRead extends Operation {
    private int initialFilePosition;

    /**
     * Creates a fread operation which reflects the stdlibc method.
     * @param info the line information
     */
    public FRead(LineInformation info) { super(info); }

    @Override
    public void propagateTaint(NodeMapper nodeMapper) {
        // Intentionally left blank
    }

    @Override
    public void handleArrayAccess(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) {
        // the memory the values are written to must already be allocated, so the size is known to the tainting engine


//        long sourceID = Long.parseLong(info.getOpts()[1].get("source"));
//        // number of read bytes is the return value of fread
//        // number and size as defined by the documentation of fread
//        LineInformation prevLineInformation = nodeMapper.getPrevLineInformation();
//        int size = info.getOpts()[1].get("result").length();
//
//        arMapper.setNameSize(prevLineInformation.getOperands()[0].getName(), size);
//        arMapper.setIndexSize(prevLineInformation.getOperands()[0].getName(), Long.parseUnsignedLong(nodeMapper.getPrevLineInformation().getOperands()[0].getValue()));
    }

    @Override
    public void handleTaintGeneration(NodeMapper nodeMapper, EventSender eventSender, ResourceManager resourceManager) {
        // read string
        String value = info.getOpts()[1].get("result");

        // address of the file and therefore the sourceID
        long sourceID = Long.parseLong(info.getOpts()[1].get("source"));
        sourceID = nodeMapper.getFDUniqueID(sourceID);
        if (Utils.INVALIDSOURCEID == sourceID) {
            // if the source is not considered, do not use it
            return;
        }
        initialFilePosition = resourceManager.getFilePosition(sourceID);
        int counter = 0;
        Taint[] newTaint = new Taint[value.length()];
        var ungotc = resourceManager.popUngotC(sourceID, value.length());
        var ungotcSize = ungotc.size();
        for (char c : value.toCharArray()) {
            if (ungotc.isEmpty()) {
                resourceManager.setCharacter(sourceID, initialFilePosition + counter, c);
                // TODO this operation is quite expensive, better set all bits in the end..
                newTaint[counter] = Taint.setBit(new Taint(1), sourceID, initialFilePosition + counter - ungotcSize);
            } else {
                newTaint[counter] = ungotc.remove(0).getTaint(0);
            }

            counter++;
        }

        nodeMapper.addAddressTaint(Long.parseUnsignedLong(nodeMapper.getPrevLineInformation().getOperands()[0].getValue()), new TaintVector(newTaint), 1);
        newNode = info.getAssignedRegisterName();
        resourceManager.saveFilePosition(sourceID, initialFilePosition + value.length() - ungotcSize);
    }
}
