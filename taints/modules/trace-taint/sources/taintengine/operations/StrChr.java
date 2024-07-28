package taintengine.operations;

import taintengine.NodeMapper;
import taintengine.Taint;
import taintengine.TaintVector;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import taintengine.handlers.helperclasses.TokenManager;
import utils.LineInformation;
import utils.Operand;
import utils.TaintType;

import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;

public class StrChr extends Operation {
    public StrChr(LineInformation info) {
        super(info);
    }

    @Override
    public void handleBinOperation(NodeMapper nodeMapper, EventSender eventSender) {
        Operand[] operands = getOperands();
        Operand chr = operands[2];
        TaintVector taintSwitchRegister = nodeMapper.getTaintForName(chr.getName());
        String[] splittedSearchinStr = operands[1].getValue().split(" ", 2);
        String searchIn = splittedSearchinStr[1];

        if (null == taintSwitchRegister || taintSwitchRegister.isEmpty()) {
            // at this point the character that is used for comparison is not tainted now check if the searched string is tainted
            Long searchInAddress = Long.parseUnsignedLong(splittedSearchinStr[0]);
            var searchInTaint = nodeMapper.getTaintForAddress(searchInAddress, searchIn.length());
            if (null != searchInTaint && 0 < searchInTaint.length && !searchInTaint[0].isEmpty() && !searchInTaint[0].hasTaintType(TaintType.STRCONST)) {
                // the searched string is tainted but is no string constant, we analyze the string and report the index of the found value
                var searched = (char) Integer.parseUnsignedInt(getOperands()[2].getValue());
                // the actual parts of the string that were accessed by strchr
                var analyzed = searchIn.split(String.format("(?<=\\Q%c\\E)", searched))[0];
                Taint[] analyzedTaint;
                // contains the taints of the chars that were accessed until the searched char was found
                analyzedTaint = Arrays.copyOf(searchInTaint, analyzed.length());
                //TODO check correctness of this, changed from giving a character to giving the respective string of the char
                var charlist = new LinkedList<String>();
                charlist.add(Character.toString(searched));
                eventSender.strsearch(charlist, analyzed, new Taint(analyzedTaint));
            }
        } else {
            eventSender.strchr(chr.getValue(), searchIn, taintSwitchRegister.getTaint(0));
        }
    }

    public void handleArrayAccess(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) {
        //Intentionally left blank
    }

    @Override
    public void handleToken(NodeMapper nodeMapper, TokenManager tokenManager, EventSender eventSender) {
        //TODO not tested yet
        var taint = nodeMapper.getTaintForName(getOperands()[2].getName());
        if (null != taint && !taint.isEmpty() && !taint.getTaint(0).hasTaintType(TaintType.TOKEN)) {
            tokenManager.markLexing(info.getFunction());
        }
    }
}
