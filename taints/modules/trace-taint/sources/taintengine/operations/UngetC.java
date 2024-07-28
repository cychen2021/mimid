package taintengine.operations;

import taintengine.NodeMapper;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import taintengine.handlers.helperclasses.ResourceManager;
import utils.LineInformation;
import utils.Utils;


public class UngetC extends Operation {
    public UngetC(LineInformation info) {
        super(info);
    }

    @Override
    public void propagateTaint(NodeMapper nodeMapper) {
        // the taint "propagation" already happens in the taint generation, since here the variable is initially assigned
        this.newNode = nodeMapper.getPrevLineInformation().getAssignedRegisterName();
    }

    @Override
    public void handleTaintGeneration(NodeMapper nodeMapper, EventSender eventSender, ResourceManager resourceManager) {
        long sourceID = Long.parseLong(info.getOpts()[1].get("source"));
        sourceID = nodeMapper.getFDUniqueID(sourceID);
        if (Utils.INVALIDSOURCEID == sourceID) {
            // if the source is not considered, do not use it
            return;
        }
        var prevInfo = nodeMapper.getPrevLineInformation();
        var charTaint = nodeMapper.getTaintForName(prevInfo.getOperands()[0].getName());
        var chr = info.getOpts()[1].get("result");
        resourceManager.ungetc(sourceID, charTaint);
    }

    @Override
    public void handleArrayAccess(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) {
        // intentionally left blank
    }
}
