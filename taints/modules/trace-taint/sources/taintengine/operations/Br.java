package taintengine.operations;

import java.io.IOException;

import taintengine.NodeMapper;
import taintengine.handlers.helperclasses.EventSender;
import utils.LineInformation;

public class Br extends Operation {
    /**
     * Creates an br operation with the given line information.
     * @param info
     */
    public Br(LineInformation info) { super(info); }

}
