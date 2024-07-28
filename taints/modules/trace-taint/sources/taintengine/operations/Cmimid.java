package taintengine.operations;

import taintengine.NodeMapper;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import utils.LineInformation;
import utils.Operand;

import java.io.IOException;
import java.util.LinkedList;

public class Cmimid extends Operation {

    /**
     * Creates a Cmimid opteration to print the cmimid specific data.
     * @param info the line information
     */
    public Cmimid(LineInformation info) {
        super(info);
    }

    @Override
    public void handleBinOperation(NodeMapper nodeMapper, EventSender eventSender) {
        Operand[] operands = info.getOperands();
        var name = operands[operands.length - 1].getName();
        var information = new LinkedList<String>();
        for (int i = 1; i < operands.length - 1; i++) {
            String value = operands[i].getValue();
            String[] valueSplit = value.split(" ", 2);
            if (1 < valueSplit.length) {
                information.add(valueSplit[1]);
            } else {
                information.add(value);
            }
        }
        eventSender.cmimid(name, information);
    }

    @Override
    public void handleArrayAccess(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) throws IOException {
        // Intentionally left blank
    }
}
