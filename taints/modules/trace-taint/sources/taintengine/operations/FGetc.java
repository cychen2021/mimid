package taintengine.operations;

import taintengine.NodeMapper;
import taintengine.Taint;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import taintengine.handlers.helperclasses.ResourceManager;
import utils.LineInformation;
import utils.Utils;

import java.io.IOException;

public class FGetc extends Operation {
    /**
     * Creates a fgetc operation which reflects the stdlibc method.
     * @param info
     */
    public FGetc(LineInformation info) { super(info); }

    @Override
    public void handleArrayAccess(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) {
        // Intentionally left blank
    }

    @Override
    public void handleTaintGeneration(NodeMapper nodeMapper, EventSender eventSender, ResourceManager resourceManager) {
        if (2 > info.getOpts().length) {
            // in this case no new input was read, the read input was EOF
            return;
        }
        long sourceID = Long.parseLong(info.getOpts()[1].get("source"));
        sourceID = nodeMapper.getFDUniqueID(sourceID);
        if (Utils.INVALIDSOURCEID == sourceID) {
            // if the source is not considered, do not use it
            return;
        }
        var ungotc = resourceManager.popUngotC(sourceID, 1);
        if (1 == ungotc.size()) {
            // in this case we read a character that was previously put back to the input queue
            String name = nodeMapper.getPrevLineInformation().getAssignedRegisterName();
            nodeMapper.addTaintForLocal(name, ungotc.get(0));
            return;
        }
        char assignedCharacter = info.getOpts()[1].get("result").charAt(0);
        int resourcePosition = resourceManager.getFilePosition(sourceID);
        resourceManager.setCharacter(sourceID, resourcePosition, assignedCharacter);

        Taint newTaint = new Taint(4);
        newTaint = Taint.setBit(newTaint, sourceID, resourcePosition);
        String name = nodeMapper.getPrevLineInformation().getAssignedRegisterName();
        nodeMapper.addTaintForLocal(name, newTaint);

        resourceManager.saveFilePosition(sourceID, resourcePosition + 1);
    }

    @Override
    public void propagateTaint(NodeMapper nodeMapper) {
        // the taint "propagation" already happens in the taint generation, since here the variable is initially assigned
        this.newNode = nodeMapper.getPrevLineInformation().getAssignedRegisterName();
    }
}
