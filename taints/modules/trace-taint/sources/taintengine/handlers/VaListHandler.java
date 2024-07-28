package taintengine.handlers;

import taintengine.NodeMapper;
import taintengine.handlers.helperclasses.VaListMapper;
import taintengine.operations.Operation;

import java.io.IOException;

public class VaListHandler extends OperationHandler {

    private final VaListMapper vaMapper = new VaListMapper();

    @Override
    public void handleOperation(Operation operation, NodeMapper nodeMapper) {
        operation.handleVaList(nodeMapper, vaMapper);
    }
}
