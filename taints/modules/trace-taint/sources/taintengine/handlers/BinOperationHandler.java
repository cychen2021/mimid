package taintengine.handlers;

import taintengine.NodeMapper;
import taintengine.handlers.helperclasses.EventSender;
import taintengine.operations.Operation;

import java.io.IOException;

public class BinOperationHandler extends OperationHandler {
    private final EventSender eventSender;

    /**
     * @param eventSender
     */
    public BinOperationHandler(EventSender eventSender) {
        this.eventSender = eventSender;
    }

    @Override
    public void handleOperation(Operation operation, NodeMapper nodeMapper) {
        operation.handleBinOperation(nodeMapper, eventSender);
    }
}
