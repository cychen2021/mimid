package taintengine.operations;

import java.io.IOException;
import java.util.Set;
import java.util.HashSet;
import java.util.Arrays;

import taintengine.NodeMapper;
import taintengine.Taint;
import taintengine.TaintVector;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import taintengine.handlers.helperclasses.MethodCallHelper;
import taintengine.handlers.helperclasses.StructureMapper;
import taintengine.handlers.helperclasses.VaListMapper;
import utils.LineInformation;
import utils.Operand;

public class Call extends Operation {
    private static final Set<String> undefFunctions = new HashSet<>(20);

    /**
     * Creates a call instruction with the given line information.
     * @param info
     */
    public Call(LineInformation info) { super(info); }

    @Override
    public String[] getOperandNames() {
        // length -2 since the last operand defines the name and position of the instruction
        int length = this.getOperands().length - 1;

        // number of names is exactly half of the number of all elements in the operands array
        String[] names = new String[length];

        for (int x = 0; x < length; x++) {
            names[x] = this.getOperands()[x].getName();
        }
        return names;
    }

    @Override
    public void propagateTaint(NodeMapper nodeMapper) {
        // nodeMapper.functionCall(functionName(), this.getOperandNames(), info.getAssignedRegisterName());
        if (!nodeMapper.isFunctionInstrumented(functionName()) && !undefFunctions.contains(functionName())) {
            undefFunctions.add(functionName());
            System.out.println("info: taint engine skipping call to uninstrumented function: " + functionName());
        }
        this.newNode = info.getAssignedRegisterName();
    }

    /**
     * Returns the name of the function represented by this object.
     * @return
     */
    private String functionName() {
        // the last operand is the name of the function
        return this.getOperands()[this.getOperands().length - 1].getName();
    }

    @Override
    public void handleStructureSendFieldAccess(StructureMapper structureMapper, NodeMapper nodeMapper, EventSender eventSender) {
        structureMapper.methodCall();
    }

    @Override
    public void handleMethodEnterExit(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) {
//        if (info.getInstruction().contains("fwrite")) {
//            long address = Long.parseLong(getOperands()[0].getValue());
//            int totalSize = Integer.parseInt(getOperands()[1].getValue()) * Integer.parseInt(getOperands()[2].getValue());
//            Taint[] taints = nodeMapper.getTaintForAddress(address, totalSize);
//
//
//            System.out.println("TaintVector [taints=" + Arrays.toString(taints) + ", length=" + taints.length + ']');
//        }
//
//        if (info.getInstruction().contains("fputc")) {
//            System.out.println(nodeMapper.getTaintForName(getOperandNames()[0]));
//            System.out.println(Character.toChars(Integer.parseInt(getOperands()[0].getValue())));
//        }
//
//        if (info.getInstruction().contains("printf") || info.getInstruction().contains("puts")) {
//            for (Operand op : this.getOperands()) {
//                TaintVector operandTaint;
//
//                // if its a pointer dereference and try to extract as many tainted consecutive bits as possible
//                if (op.getType().contains("*")) {
//                    long address = Long.parseUnsignedLong(op.getValue());
//                    int remBytes = arMapper.getRemainingBytesForAddress(address);
//
//                    operandTaint = new TaintVector(nodeMapper.getTaintForAddress(address, remBytes));
//                } else {
//                    operandTaint = nodeMapper.getTaintForName(op.getName());
//                }
//                System.out.println(operandTaint);
////                if (null == operandTaint || operandTaint.isEmpty()) {
////                    operandTaint = new TaintVector(0, 0);
////                }
//            }
//        }
    }

    @Override
    public void handleArrayAccess(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) {
        // This is done by the methodEntry operation
    }

    @Override
    public void handleMethodCall(NodeMapper nodeMapper, MethodCallHelper mch) {
        mch.handleCallMethod(this.getOperands(), info.getAssignedRegisterName());
    }

    @Override
    public void handleVaList(NodeMapper nodeMapper, VaListMapper vaMapper) {
        if ("llvm.va_start".equals(functionName())) {
//            System.out.println(info);
            vaMapper.vaStart(Long.parseUnsignedLong(info.getOperands()[0].getValue()));
        }
        if ("llvm.va_copy".equals(functionName())) {
//            System.out.println(info);
            vaMapper.vaCopy(Long.parseUnsignedLong(info.getOperands()[0].getValue()), Long.parseUnsignedLong(info.getOperands()[1].getValue()));
        }
        if ("llvm.va_end".equals(functionName())) {
//            System.out.println(info);
            vaMapper.vaEnd(Long.parseUnsignedLong(info.getOperands()[0].getValue()));
        }
    }
}
