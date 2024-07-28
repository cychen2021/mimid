package taintengine.operations;

import taintengine.NodeMapper;
import taintengine.Taint;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import utils.LineInformation;
import utils.TaintType;

import java.io.IOException;
import java.util.LinkedList;

public class StrToK extends Operation {

    public StrToK(LineInformation info) {
        super(info);
    }

    @Override
    public void propagateTaint(NodeMapper nodeMapper) {
        // intentionally left blank
    }

    @Override
    public void handleBinOperation(NodeMapper nodeMapper, EventSender eventSender) {
        //get the taints of the value that was searched
        var searchSplit = getOperands()[0].getValue().split(" ", 2);
        if (1 < searchSplit.length) {
            var returnAddress = Long.parseUnsignedLong(searchSplit[0]);
            var remainingStringBytes = nodeMapper.getRemainingBytesForAddress(returnAddress);
            var returnTaints = nodeMapper.getTaintForAddress(returnAddress, remainingStringBytes);

            // get the string that was used for searching
            var splitString = getOperands()[2].getValue().split(" ", 2);
            if (1 < splitString.length) {
                if (null != returnTaints && 0 < returnTaints.length && !returnTaints[0].isEmpty() && !returnTaints[0].hasTaintType(TaintType.STRCONST)) {
                    var charlist = new LinkedList<String>();
                    for (var c : splitString[1].toCharArray()) {
                        charlist.add(Character.toString(c));
                    }
                    eventSender.strsearch(charlist, searchSplit[1], new Taint(returnTaints));
                }
            }
        }
    }

    @Override
    public void handleArrayAccess(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) {
        // intentionally left blank
    }
}
