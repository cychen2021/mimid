package taintengine.operations;

import taintengine.NodeMapper;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import taintengine.handlers.helperclasses.MethodCallHelper;
import taintengine.handlers.helperclasses.TokenManager;
import taintengine.handlers.helperclasses.VaListMapper;
import taintengine.helperclasses.VaEntry;
import utils.LineInformation;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.LinkedList;

public class MethodEntry extends Operation {
    /**
     * Creates a MethodEntry operation with the given line information.
     * @param info
     */
    public MethodEntry(LineInformation info) { super(info); }

    @Override
    public void handleMethodCall(NodeMapper nodeMapper, MethodCallHelper mch) throws IOException {
        super.handleMethodCall(nodeMapper, mch);
        mch.flushCallMethod(info.getFunction(), nodeMapper);
    }

    @Override
    public void handleArrayAccess(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) throws IOException {
        arMapper.methodCall();
        super.handleArrayAccess(nodeMapper, eventSender, arMapper);
    }

    @Override
    public void handleToken(NodeMapper nodeMapper, TokenManager tokenManager, EventSender eventSender) {
        tokenManager.clean();
    }

    @Override
    public void handleVaList(NodeMapper nodeMapper, VaListMapper vaMapper) {
        var inf = nodeMapper.getPrevLineInformation();
        if (inf.getInstruction().contains(", ...) @")) {
            // in this case we call a function with variable number of arguments, this could be converted to a va_list which we want to know its contents later
            //calc number of operands first:
            var carved = inf.getInstruction().split("\\(", 2)[1].split(",\\s\\.\\.\\.\\)\\s@", 2)[0];
            var bracketCounter = 0;
            var operandCounter = 0;
            for (var el : carved.split(",")) {
                if (el.contains("(")) {
                    bracketCounter++;
                } else {
                    if (el.contains(")")) {
                        bracketCounter--;
                    }
                }
                if (0 >= bracketCounter) {
                    operandCounter++;
                }
            }
            var entries = new LinkedList<VaEntry>();
            for (var i = operandCounter; i < inf.getOperands().length - 1; i++) {
                var op = inf.getOperands()[i];
                entries.add(new VaEntry(Long.parseUnsignedLong(op.getValue()), nodeMapper.getTaintForNameOldStack(op.getName(), 1)));
            }
            vaMapper.methodCall(entries);
        } else {
            // in the case this is not a variable argument function we still need to create an entry on the stack
            vaMapper.methodCall(new LinkedList<>());
        }
    }
}
