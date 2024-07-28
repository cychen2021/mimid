package taintengine.operations;

import taintengine.NodeMapper;
import taintengine.TaintVector;
import taintengine.handlers.helperclasses.VaListMapper;
import utils.LineInformation;
import utils.Operand;

public class TypeChange extends Operation {
    /**
     * Creates an bitcast operation with the given line information.
     * @param info
     */
    public TypeChange(LineInformation info) { super(info); }

    @Override
    public void propagateTaint(NodeMapper nodeMapper) {
        Operand result = info.getAssignedRegister();
        nodeMapper.addLocal(result.getName(),
                            getOperandNames(),
                            result.getVectorLength(),
                            result.getByteSizeUnderlyingType(),
                            TaintVector::unionIntoByteWise);

        this.newNode = result.getName();
    }

    @Override
    public void handleVaList(NodeMapper nodeMapper, VaListMapper vaMapper) {
        vaMapper.retrieveStaged().ifPresent(staged -> {
            if (null != staged.taint) {
                var byteSize = Operand.getByteSizeForType(info.getAssignedRegisterType().substring(0, info.getAssignedRegisterType().length() -1)); //get size of memory that is pointed to
                nodeMapper.addAddressTaint(Long.parseUnsignedLong(getOperands()[0].getValue()), staged.taint, byteSize);
            }
        });
    }
}
