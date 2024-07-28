package taintengine.operations;

import taintengine.NodeMapper;
import taintengine.Taint;
import taintengine.TaintVector;
import utils.LineInformation;

import java.util.regex.Pattern;

public class InsertElement extends Operation {
    private static final Pattern XPATTERNCONSTANT = Pattern.compile(" x ");

    /**
     * Creates a new insertElement operation with the given line information.
     * @param info
     */
    public InsertElement(LineInformation info) { super(info); }

    @Override
    public void propagateTaint(NodeMapper nodeMapper) {
        TaintVector vector = nodeMapper.getTaintForName(getOperandNames()[0]);
        TaintVector insert = nodeMapper.getTaintForName(getOperandNames()[1]);
        int index = Integer.parseInt(getOperands()[2].getValue());

        int elementSize = getOperands()[1].getByteSizeUnderlyingType();

        // the insert is a scalar, so the first taint is the taint we want to have
        Taint insertTaint;
        if (null == insert) {
            insertTaint = new Taint(elementSize);
        } else {
            insertTaint = insert.getTaint(0);
        }

        if (null == vector) {
            // create new taintvector, the size of the vector is given by the type of the assigned register, the size of the
            // elements is given by the type of the inserted element
            String replacedVector = XPATTERNCONSTANT.split(info.getAssignedRegisterType())[0].replace("<", "");
            vector = new TaintVector(Integer.parseInt(replacedVector), elementSize);
        }

        Taint[] newTv = new Taint[vector.getLength()];

        int loopCounter = 0;
        for (Taint t : vector) {
            newTv[loopCounter++] = t;
        }
        newTv[index] = insertTaint;

        nodeMapper.addLocalVector(info.getAssignedRegisterName(), newTv, elementSize, TaintVector::unionIntoByteWise);
    }
}
