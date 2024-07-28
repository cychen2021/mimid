package taintengine.operations;

import taintengine.NodeMapper;
import taintengine.Taint;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import taintengine.handlers.helperclasses.VaListMapper;
import taintengine.helperclasses.VaEntry;
import utils.LineInformation;
import utils.Operand;

import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Stream;

public class VsnPrintf extends Operation {

    private static final Pattern FORMATSTRINGSPLITTER = Pattern.compile("%[^%diufFeEgGxXaAoscpn]*[%diufFeEgGxXaAoscpn]");

    public VsnPrintf(LineInformation info) {
        super(info);
    }

    @Override
    public void propagateTaint(NodeMapper nodeMapper) {
        // intentionally left blank
    }

    @Override
    public void handleArrayAccess(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) throws IOException {
        // intentionally left blank
    }

    @Override
    public void handleVaList(NodeMapper nodeMapper, VaListMapper vaMapper) {
        Operand[] prevOperands = nodeMapper.getPrevLineInformation().getOperands();
        var vaList = vaMapper.getVaList(Long.parseUnsignedLong(prevOperands[prevOperands.length - 2].getValue()));

        // get information about the format string (the constant string values and the format specifiers in between)
        var formatString = info.getOpts()[1].get("result");
        var formatStringaddress = Long.parseUnsignedLong(info.getOpts()[1].get("source"));
        var formatStringSplit = FORMATSTRINGSPLITTER.split(formatString);
        var formatStrings = FORMATSTRINGSPLITTER.matcher(formatString);
        var formatStringList = new LinkedList<String>();
        while (formatStrings.find()) {
            formatStringList.add(formatStrings.group());
        }
        formatStringList.addLast("");

        // assemble the taint for the string that was created by vsnprintf from the values and their taints it is composed of
        var formatStringPosition = 0;
        var resultStringPosition = 0;
        var optPosition = 3; // index of the next element from the opt list to retrieve
        Taint[] taints = new Taint[info.getOpts()[2].get("result").length()];
        Arrays.parallelSetAll(taints, i -> new Taint(0));
        for (var val : formatStringSplit) {
            String formatStringUsed = formatStringList.remove(0);
            // add the taints of the string constant values from the format string
            for (var tnt : nodeMapper.getTaintForAddress(formatStringaddress + formatStringPosition, val.length())) {
                taints[resultStringPosition++] = tnt;
                formatStringPosition++;
            }

            // add the taints from the
            if (!formatStringUsed.isEmpty() && 's' == formatStringUsed.charAt(formatStringUsed.length() - 1)) {
                var optString = info.getOpts()[optPosition].get("result");
                var vaEntry = vaList.remove(0);
                // taints attached to the string that is included into the resulting string of vsnprintf
                for (var tnt : nodeMapper.getTaintForAddress(vaEntry.value, optString.length())) {
                    taints[resultStringPosition++] = tnt;
                }
            } else {
                // if the formatStringUsed is empty we are at the tail of the format string and just added the last constant values, no more argument values are added
                if (!formatStringUsed.isEmpty()) {
                    var optString = info.getOpts()[optPosition].get("result");
                    var vaEntry = vaList.remove(0);
                    // taints of basic types that are included in the resulting string
                    for (var i = 0; i < optString.length(); i ++) {
                        taints[resultStringPosition++] = vaEntry.taint.getTaint(0);
                    }
                }
            }
            optPosition++;
            formatStringPosition += formatStringUsed.length();
        }

        long storedTo = Long.parseUnsignedLong(info.getOpts()[2].get("source"));
        nodeMapper.addTaintForAddress(storedTo, taints);
    }
}
