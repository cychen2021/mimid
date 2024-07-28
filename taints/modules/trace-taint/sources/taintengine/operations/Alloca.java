package taintengine.operations;

import java.io.IOException;
import java.util.regex.Pattern;

import taintengine.NodeMapper;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import utils.LineInformation;
import utils.Operand;
import utils.Utils;

public class Alloca extends Operation {
    private static final Pattern REPLACECONSTANT = Pattern.compile("\\*");

    /**
     * Creates a malloc operation with the given line information.
     * @param info
     */
    public Alloca(LineInformation info) { super(info); }

    @Override
    public void propagateTaint(NodeMapper nodeMapper) {
        newNode = info.getAssignedRegisterName();
    }

    @Override
    public void handleArrayAccess(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) {
        arMapper.setNameSize(newNode, getTypeSizeInBytes(info.getAssignedRegister()));
    }

    /**
     * Returns the number of bytes that are used to store the operand.
     * @return
     */
    private static int getTypeSizeInBytes(Operand operand) {
        // if its a pointer to a pointer it only allocates space for a pointer
        if (operand.getType().endsWith("**")) {
            return Utils.POINTERBYTESIZE;
        }

        // use one reference less to determine type size

        // if there is no " x " the type is basic or a struct, so we already got the size we want
        return Operand.getByteSizeForType(REPLACECONSTANT.matcher(operand.getType()).replaceFirst(""));
    }
}
