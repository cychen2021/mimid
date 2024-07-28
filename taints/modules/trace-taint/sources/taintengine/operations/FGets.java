package taintengine.operations;

import taintengine.NodeMapper;
import taintengine.Taint;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import taintengine.handlers.helperclasses.ResourceManager;
import utils.LineInformation;
import utils.Utils;

import java.io.IOException;

public class FGets extends Operation {

    /**
     * Creates a fgets operation which reflects the stdlibc method.
     * @param info the line information of this instruction call
     */
    public FGets(LineInformation info) { super(info); }

    @Override
    public void propagateTaint(NodeMapper nodeMapper) {
        // Intentionally left blank
    }

    @Override
    public void handleArrayAccess(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) {
        //nothing was read, nothing to do
        if (2 > info.getOpts().length) {
            return;
        }
        var prevInfo = nodeMapper.getPrevLineInformation();
        long address = Long.parseLong(prevInfo.getOperands()[1].getValue().split(" ")[0]);
        int size = info.getOpts()[1].get("result").length();

        arMapper.setNameSize(prevInfo.getAssignedRegisterName(), size);
        arMapper.setIndexSize(prevInfo.getAssignedRegisterName(), address);
    }

    @Override
    public void handleTaintGeneration(NodeMapper nodeMapper, EventSender eventSender, ResourceManager resourceManager) {
        var prevInfo = nodeMapper.getPrevLineInformation();
        //nothing was read, nothing to do
        if (2 > info.getOpts().length) {
            newNode = prevInfo.getAssignedRegisterName();
            return;
        }
        // get address and read string
        long address = Long.parseLong(prevInfo.getOperands()[0].getValue());
        long sourceID = Long.parseLong(info.getOpts()[1].get("source"));
        String value = info.getOpts()[1].get("result");
        sourceID = nodeMapper.getFDUniqueID(sourceID);
        if (Utils.INVALIDSOURCEID == sourceID) {
            // if the source is not considered, do not use it
            return;
        }
        // stores temporarily the fileposition at the point when this operation was called
        int initialFilePosition = resourceManager.getFilePosition(sourceID);
        int counter = 0;

        var ungotc = resourceManager.popUngotC(sourceID, value.length());
        var ungotcSize = ungotc.size();
        for (char c : value.toCharArray()) {
            Taint newTaint;
            if (ungotc.isEmpty()) {
                resourceManager.setCharacter(sourceID, initialFilePosition + counter, c);
                // TODO this operation is quite expensive, better set all bits in the end..
                newTaint = Taint.setBit(new Taint(1), sourceID, initialFilePosition + counter);
            } else {
                newTaint = ungotc.remove(0).getTaint(0);
            }
            nodeMapper.addAddressTaint(address + counter, newTaint);

            counter++;
        }

        // get the size of the read string and advance the stream position
        int size = value.length();

        resourceManager.saveFilePosition(sourceID, initialFilePosition + size - ungotcSize);
    }
}
