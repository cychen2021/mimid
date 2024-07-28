package taintengine.operations;

import taintengine.NodeMapper;
import taintengine.Taint;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import taintengine.handlers.helperclasses.TokenManager;
import utils.LineInformation;
import utils.Operand;
import utils.TaintType;

import java.io.IOException;

public class Strcmp extends Operation {

    private final long addressOp1;
    private final long addressOp2;
    private final String stringOp1;
    private final String stringOp2;
    /**
     * Create a string comparison operation which represents the standard lib strncmp/strcmp
     * @param info
     */
    public Strcmp(LineInformation info) {
        super(info);
        Operand operand1 = info.getOperands()[1];
        Operand operand2 = info.getOperands()[2];
        addressOp1 = Long.parseLong(operand1.getValue().split(" ", 2)[0]);
        addressOp2 = Long.parseLong(operand2.getValue().split(" ", 2)[0]);
        stringOp1 = operand1.getValue().split(" ", 2)[1];
        stringOp2 = operand2.getValue().split(" ", 2)[1];
    }

    @Override
    public void propagateTaint(NodeMapper nodeMapper) {
//        System.out.println("Strcmp:");
//        System.out.println("  " + this.getOperands()[0]);
//        System.out.println("  " + this.getOperands()[1]);
//        System.out.println("  " + this.getOperands()[2]);
        newNode = getOperands()[0].getName();
    }

    @Override
    public void handleArrayAccess(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) {
        Taint taintOp1 = nodeMapper.getTaintForAddress(addressOp1, stringOp1.isEmpty() ? 1 : stringOp1.length())[0];
        Taint taintOp2 = nodeMapper.getTaintForAddress(addressOp2, stringOp2.isEmpty() ? 1 : stringOp2.length())[0];

        if (3 < info.getOperands().length) {
            var strlenTaint = nodeMapper.getTaintForName(getOperands()[3].getName());
            if ((null != strlenTaint && strlenTaint.getTaint(0).hasTaintType(TaintType.STRLEN)) && (taintOp1.hasTaintType(TaintType.STRCONST) || taintOp2.hasTaintType(TaintType.STRCONST))) {
                eventSender.strlen(taintOp1, taintOp2, arMapper.getRemainingBytesForAddress(addressOp1), arMapper.getRemainingBytesForAddress(addressOp2));
            }
        }
    }

    public void handleBinOperation(NodeMapper nodeMapper, EventSender eventSender) {
        Taint[] taintOp1Array = nodeMapper.getTaintForAddress(addressOp1, stringOp1.isEmpty() ? 1 : stringOp1.length());
        Taint[] taintOp2Array = nodeMapper.getTaintForAddress(addressOp2, stringOp2.isEmpty() ? 1 : stringOp2.length());
        var taintOp1 = new Taint(taintOp1Array);
        var taintOp2 = new Taint(taintOp2Array);

        eventSender.strcmp(stringOp1, stringOp2, taintOp1, taintOp2);
    }

    @Override
    public void handleToken(NodeMapper nodeMapper, TokenManager tokenManager, EventSender eventSender) {
        Taint[] taintOp1Array = nodeMapper.getTaintForAddress(addressOp1, stringOp1.isEmpty() ? 1 : stringOp1.length());
        Taint[] taintOp2Array = nodeMapper.getTaintForAddress(addressOp2, stringOp2.isEmpty() ? 1 : stringOp2.length());
        var taintOp1 = new Taint(taintOp1Array);
        var taintOp2 = new Taint(taintOp2Array);
        if (null != taintOp1 && !taintOp1.isEmpty()) {
            if (stringOp1.equals(stringOp2)) {
                tokenManager.markLexing(info.getFunction());
                tokenManager.setTaint(stringOp1, taintOp1, taintOp2);
            } else {
                // clean token if the comparison was not successful but contained taints
                tokenManager.clean();
            }
        } else {
            if (stringOp1.equals(stringOp2)) {
                tokenManager.markLexing(info.getFunction());
                tokenManager.setTaint(stringOp2, taintOp1, taintOp2);
            } else {
                // clean token if the comparison was not successful but contained taints
                tokenManager.clean();
            }
        }
    }
}
