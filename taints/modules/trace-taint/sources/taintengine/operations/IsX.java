package taintengine.operations;

import taintengine.NodeMapper;
import taintengine.TaintVector;
import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.EventSender;
import taintengine.handlers.helperclasses.TokenManager;
import utils.LineInformation;
import utils.Operand;
import utils.TaintType;

public class IsX extends Operation {

    private enum IsXEnum{
        ISUPPER,
        ISLOWER,
        ISALPHA,
        ISDIGIT,
        ISXDIGIT,
        ISSPACE,
        ISPRINT,
        ISGRAPH,
        ISBLANK,
        ISCNTRL,
        ISPUNCT,
        ISALNUM
    }

    public IsX(LineInformation info) {
        super(info);
    }

    @Override
    public void propagateTaint(NodeMapper nodeMapper) {
        var oldInfo = nodeMapper.getPrevLineInformation();
        Operand result = oldInfo.getAssignedRegister();
        nodeMapper.addLocal(result.getName(),
                this.getOperandNames(),
                result.getVectorLength(),
                result.getByteSizeUnderlyingType(),
                TaintVector::unionIntoFull);

        this.newNode = result.getName();
    }

    @Override
    public void handleBinOperation(NodeMapper nodeMapper, EventSender eventSender) {
        var oldInfo = nodeMapper.getPrevLineInformation();
        Operand value = oldInfo.getOperands()[0];
        var taint = nodeMapper.getTaintForName(value.getName());
        if (null != taint && !taint.isEmpty()) {
            var searchString = "";
            switch (IsXEnum.values()[Integer.parseInt(info.getOpts()[1].get("source"))]) {
                case ISUPPER:
                    searchString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                    break;
                case ISLOWER:
                    searchString = "abcdefghijklmnopqrstuvwxyz";
                    break;
                case ISALPHA:
                    searchString = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
                    break;
                case ISDIGIT:
                    searchString = "0123456789";
                    break;
                case ISXDIGIT:
                    searchString = "0123456789abcdefABCDEF";
                    break;
                case ISSPACE:
                    searchString = " \t\n\f\r";
                    break;
                case ISPRINT:
                    searchString = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 \t\n\f\n";
                    break;
                case ISGRAPH:
                    searchString = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\t\n\f\n";
                    break;
                case ISBLANK:
                    searchString = " \t";
                    break;
                case ISCNTRL:
                    searchString = "\t\n\b\r\f"; //control characters are not fully captured yet
                    break;
                case ISPUNCT:
                    searchString = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~\t\n\f\n";
                    break;
                case ISALNUM:
                    searchString = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                    break;
                default:
                    throw new IllegalStateException(String.format("isX enum value not known: %d", Integer.parseInt(info.getOpts()[0].get("enum"))));
            }
            if (!searchString.isEmpty()){
                eventSender.strchr(value.getValue(), searchString, taint.getTaint(0));
            }
        }
    }

    @Override
    public void handleArrayAccess(NodeMapper nodeMapper, EventSender eventSender, ArrayIndexMapper arMapper) {
        // Intentionally left blank
    }

    @Override
    public void handleToken(NodeMapper nodeMapper, TokenManager tokenManager, EventSender eventSender) {
        var oldInfo = nodeMapper.getPrevLineInformation();
        var taint = nodeMapper.getTaintForName(oldInfo.getOperands()[0].getName());
        if (null != taint && !taint.isEmpty() && !taint.getTaint(0).hasTaintType(TaintType.TOKEN)) {
            tokenManager.markLexing(info.getFunction());
            var character = (char) Integer.parseInt(oldInfo.getOperands()[0].getValue());
            tokenManager.setTaint(Character.toString(character), taint.getTaint(0));
        }
    }
}
