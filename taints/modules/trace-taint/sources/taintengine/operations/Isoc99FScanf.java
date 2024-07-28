package taintengine.operations;

import taintengine.NodeMapper;
import taintengine.Taint;
import taintengine.TaintVector;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import taintengine.handlers.helperclasses.ResourceManager;
import utils.LineInformation;
import utils.Utils;

import java.io.IOException;
import java.util.Map;

public class Isoc99FScanf extends Scanf {
    /**
     * Creates a isoc99_fscanf operation which reflects the stdlibc method.
     * @param info
     */
    public Isoc99FScanf(LineInformation info) { super(info); }

    @Override
    public void handleArrayAccess(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) {
        for (Map.Entry<Long, Integer> entry : addressSizeMapping.entrySet()) {
            arMapper.setIndexSize(entry.getKey(), entry.getValue());
        }
    }

    @Override
    public void handleTaintGeneration(NodeMapper nodeMapper, EventSender eventSender, ResourceManager resourceManager) {
        long filePointer = Long.parseLong(info.getOpts()[1].get("source"));
        filePointer = nodeMapper.getFDUniqueID(filePointer);
        if (Utils.INVALIDSOURCEID == filePointer) {
            // if the source is not considered, do not use it
            return;
        }
        String formatString = info.getOpts()[1].get("result");
        String readChars = info.getOpts()[2].get("result");

        char[] format = formatString.toCharArray();
        // The 6th chraracter is the first to assign a value to.
        var filepos = resourceManager.getFilePosition(filePointer);
        parseFormatSpecifier(resourceManager, readChars.toCharArray(), format, nodeMapper, filePointer, 6);
        resourceManager.saveFilePosition(filePointer, filepos + readChars.length());
    }

    @Override
    protected void storeAtPosition(ResourceManager resourceManager, char[] characters, int startingPoint, long address, int numberToStore, NodeMapper nodeMapper, int typeSize, boolean arraySpecifier, long sourceID) {
        // create a new taint at the beginning, this is either filled if the read information is not stored in an
        // array, otherwise each byte in the memory gets the respective taint
        Taint tnt = new Taint(typeSize);
        for (int i = startingPoint; i < startingPoint + numberToStore; i++) {
            resourceManager.setCharacter(sourceID, i, characters[i]);
            tnt = Taint.setBit(tnt, sourceID, i);
            if (arraySpecifier) {
                // store a taint to bytes in the memory wrt. the typeSize
                nodeMapper.addAddressTaint(address + (i - startingPoint) * (long)typeSize, new TaintVector(tnt), typeSize);
                tnt = new Taint(typeSize);
            }
        }

        if (!arraySpecifier) {
            // store the assigned taints to the memory, e.g. for a i32* which is not an array
            nodeMapper.addAddressTaint(address, new TaintVector(tnt), typeSize);
        }
    }
}
