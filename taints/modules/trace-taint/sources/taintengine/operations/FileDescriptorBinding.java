package taintengine.operations;

import taintengine.NodeMapper;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import utils.LineInformation;
import utils.Utils;

import java.io.IOException;

public class FileDescriptorBinding extends Operation {

    public FileDescriptorBinding(LineInformation info) {
        super(info);
    }

    private static boolean checkSource(String source, long id) {
        if (Utils.getobservedInputSource().isEmpty()) {
            return "0".equals(source) || "1".equals(source) || "2".equals(source) || (Utils.INVALIDSOURCEID != id && 3 > id);
        } else {
            return source.endsWith(Utils.getobservedInputSource());
        }
    }

    @Override
    public void propagateTaint(NodeMapper nodeMapper) {
        if (info.getOpts().length > 1) {
            var id = Long.parseUnsignedLong(info.getOpts()[1].get("source"));
            var name = info.getOpts()[1].get("result");
            if (checkSource(name, nodeMapper.getFDUniqueID(id))) {
                var filename = info.getOpts()[1].get("result");
                if (Utils.isNumeric(filename)) {
                    var oldfd = Long.parseUnsignedLong(filename);
                    nodeMapper.setFDUniqueID(oldfd, id);
                } else {
                    nodeMapper.setFDUniqueID(id);
                }
            }
        }
    }

    @Override
    public void handleArrayAccess(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) {
        // intentionally left blank
    }
}
