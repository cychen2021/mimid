package taintengine.operations;

import taintengine.NodeMapper;
import taintengine.Taint;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import taintengine.handlers.helperclasses.ResourceManager;
import utils.LineInformation;
import utils.Utils;

import java.io.IOException;

public class Read extends Operation {
    /**
     * Creates a read operation with the given line information.
     * @param info
     */
    public Read(LineInformation info) { super(info); }

    @Override
    public void propagateTaint(NodeMapper nodeMapper) {
        // Intentionally left blank
    }

    @Override
    public void handleTaintGeneration(NodeMapper nodeMapper, EventSender eventSender, ResourceManager resourceManager) {
        // for read ungetc does not have an effect
        var prevInfo = nodeMapper.getPrevLineInformation();
        //nothing was read, nothing to do
        if (2 > info.getOpts().length) {
            newNode = prevInfo.getAssignedRegisterName();
            return;
        }
        var value = info.getOpts()[1].get("result");
        int size = value.length();
        long sourceID = Long.parseLong(info.getOpts()[1].get("source"));
        sourceID = nodeMapper.getFDUniqueID(sourceID);
        if (Utils.INVALIDSOURCEID == sourceID) {
            return;
        }
        int offset = resourceManager.getFilePosition(sourceID);

        var address = Long.parseLong(prevInfo.getOperands()[1].getValue());

        char[] strArray = value.toCharArray();
        for (int x = 0; x < size; ++x) {
            resourceManager.setCharacter(sourceID, offset + x, strArray[x]);
            Taint newTaint = Taint.setBit(new Taint(1), sourceID, offset + x);
            nodeMapper.addAddressTaint(address + x, newTaint);
        }

        resourceManager.saveFilePosition(sourceID, offset + size);
        newNode = prevInfo.getAssignedRegisterName();
    }

    @Override
    public void handleArrayAccess(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) {
        var prevInfo = nodeMapper.getPrevLineInformation();
        if (2 > info.getOpts().length) {
            return;
        }
        String value = info.getOpts()[1].get("result");
        long width = value.length();
        // reads larger than maxint are too large and skipped, likely nothing was read then.
        if (Integer.MAX_VALUE < width) {
            newNode = prevInfo.getAssignedRegisterName();
            return;
        }
        var address = Long.parseLong(prevInfo.getOperands()[1].getValue());
        arMapper.setIndexSize(address, (int)width);
    }
}
