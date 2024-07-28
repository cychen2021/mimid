package taintengine.operations;

import java.io.IOException;
import java.util.Optional;

import taintengine.NodeMapper;
import taintengine.Taint;
import taintengine.TaintVector;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import taintengine.handlers.helperclasses.StructureMapper;
import taintengine.handlers.helperclasses.TokenManager;
import utils.Operand;
import utils.LineInformation;
import utils.Utils;

public class Load extends Operation {
    /**
     * Creates a Load operation with the given line information.
     * @param info The line information of the load instruction
     */
    public Load(LineInformation info) { super(info); }

    @Override
    public void propagateTaint(NodeMapper nodeMapper) {
        long    loadFrom = Long.parseUnsignedLong(this.getOperands()[0].getValue());
        Operand loadInto = info.getAssignedRegister();


        // iterate over the vector length, since this is the number of loaded values
        // TODO this is likely type dependant, i8 means add 1 to the long, i32 would add 4

        String targetRegisterName = loadInto.getName();
        nodeMapper.addLocalForAddress(loadFrom, targetRegisterName,
                loadInto.getVectorLength(),
                loadInto.getByteSizeUnderlyingType() / loadInto.getVectorLength());

        if (Utils.isArrayIndexTaintPropagation()) {
            //also add taints of index that is used for loading
            var names = new String[]{this.getOperands()[0].getName(), targetRegisterName};
            nodeMapper.addLocal(targetRegisterName, names, loadInto.getVectorLength(),
                    loadInto.getByteSizeUnderlyingType(), TaintVector::unionIntoFull);
        }

        this.newNode = targetRegisterName;
    }

    @Override
    public void handleBinOperation(NodeMapper nodeMapper, EventSender eventSender) {
        Operand loadInto = info.getAssignedRegister();
        long    loadFrom = Long.parseUnsignedLong(this.getOperands()[0].getValue());
        var tnt = nodeMapper.getTaintForAddress(loadFrom, loadInto.getByteSizeUnderlyingType());
        eventSender.cmimid("load", new Taint(tnt));
    }

    @Override
    public void handleArrayAccess(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) throws IOException {
        super.handleArrayAccess(nodeMapper, eventSender, arMapper);

        Long index = arMapper.getIndexForName(getOperands()[0].getName());
        if (null == index) {
            // if it was not mapped there was no array access for this variable
            if (info.getAssignedRegisterType().contains("[")) {
                arMapper.setArrayIndex(info.getAssignedRegisterName(), Long.parseLong(getOperands()[0].getValue()));
            }
            return;
        }
    }
}
