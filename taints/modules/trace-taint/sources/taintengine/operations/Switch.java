package taintengine.operations;

import taintengine.NodeMapper;
import taintengine.Taint;
import taintengine.TaintVector;
import taintengine.handlers.helperclasses.EventSender;
import taintengine.handlers.helperclasses.TokenManager;
import utils.LineInformation;
import utils.Operand;
import utils.TaintType;

import java.io.IOException;
import java.util.LinkedList;
import java.util.Optional;

public class Switch extends Operation {

    private static final String[] ZERO_LENGTH_STRING_ARRAY = new String[0];

    /**
     * Creates a switch operation with the given line information.
     * @param info the line information for this instruction call
     */
    public Switch(LineInformation info) { super(info); }

    @Override
    public void handleBinOperation(NodeMapper nodeMapper, EventSender eventSender) {
        Operand[] operands = getOperands();
        Operand switchRegister = operands[0];
        var taintSwitchRegister = getTaintVector(nodeMapper, switchRegister);
        if (taintSwitchRegister.isEmpty()) return;

        LinkedList<String> values = getValues(operands);
        eventSender.swtch(switchRegister.getValue(), values.toArray(ZERO_LENGTH_STRING_ARRAY), taintSwitchRegister.get().getTaint(0));
        //TODO add token read here later
    }

    private static LinkedList<String> getValues(Operand[] operands) {
        var values = new LinkedList<String>();
        for (int i = 1; i < operands.length ; i++) {
            Operand operand = operands[i];
            if ("label".equals(operand.getType())) {
                continue;
            }

            values.add(operand.getValue());
        }
        return values;
    }

    private static Optional<TaintVector> getTaintVector(NodeMapper nodeMapper, Operand switchRegister) {
        TaintVector taintSwitchRegister = nodeMapper.getTaintForName(switchRegister.getName());

        if (null == taintSwitchRegister || taintSwitchRegister.isEmpty()) {
            // at this point the character that is used for comparison is not tainted and therefore of no interest for us
            return Optional.empty();
        }
        return Optional.of(taintSwitchRegister);
    }

    @Override
    public void handleToken(NodeMapper nodeMapper, TokenManager tokenManager, EventSender eventSender) {
        var taintVector = getTaintVector(nodeMapper, getOperands()[0]);
        if (taintVector.isPresent()) {
            Taint switchTaint = taintVector.get().getTaint(0);
            tokenManager.setTaint(getOperands()[0].getValue(), switchTaint);
            // check if tokentaint is present, otw. there is nothing to send
            if (switchTaint.hasTaintType(TaintType.TOKEN)) {
                LinkedList<String> values = getValues(getOperands());
                for (var value : values) {
                    eventSender.tokenCompare(getOperands()[0].getValue(), value, switchTaint, null, tokenManager);
                }
            } else {
                if (null != switchTaint && !switchTaint.isEmpty()) {
                    //TODO test
                    tokenManager.markLexing(info.getFunction());
                }
            }
        }
    }
}
