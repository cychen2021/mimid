package taintengine.handlers.helperclasses;

import taintengine.Taint;
import taintengine.TaintVector;
import utils.Predicate;
import utils.TaintType;
import utils.Utils;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.IOException;
import java.io.BufferedWriter;
import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObjectBuilder;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public class PygmalionEventSender implements EventSender {
    public static final int MAXASCIIVALUE = 128;
    public static final int MINASCIIVALUE = 32;
    private final ResourceManager resourceManager;
    private final String outputFilename;
    private final List<PygmalionEvent> events;
    private Long taintSource = -1L;
    private final Set<CoverageEvent> coveredBasicBlocks = new HashSet<>(30);
    private int lastBB = -1;
    private InputComparisonEvent lastInputComparison;
    private final List<String> stack = new LinkedList<>();

    private enum PygmalionEventType {
        INPUT_COMPARISON,
        COVERAGE_EVENT,
        STACK_EVENT,
        CMIMID_EVENT,
        CMIMID_ACCESS
    }

    private interface PygmalionEvent {
        String toString(int inputLength);
        PygmalionEventType getPygType();
    }

    private static final class StackEvent implements PygmalionEvent{
        private final LinkedList<String> stack;

        private StackEvent(List<String> stack) {
            this.stack = new LinkedList<>(stack);
        }

        @Override
        public String toString(int inputLength) {
            JsonObjectBuilder event  = Json.createObjectBuilder();
            event.add("type", PygmalionEventType.STACK_EVENT.toString());
            var stackArray = Json.createArrayBuilder();
            stack.forEach(stackArray::add);
            event.add("stack", stackArray);
            return event.build().toString();
        }

        @Override
        public PygmalionEventType getPygType() {
            return PygmalionEventType.STACK_EVENT;
        }
    }

    private static final class CoverageEvent implements PygmalionEvent {

        private final int lastBasicBlock;
        private final int currentBasicBlock;

        private CoverageEvent(int lastBasicBlock, int currentBasicBlock) {

            this.lastBasicBlock = lastBasicBlock;
            this.currentBasicBlock = currentBasicBlock;
        }

        @Override
        public String toString(int inputLength) {
            JsonObjectBuilder event  = Json.createObjectBuilder();
            event.add("type", PygmalionEventType.COVERAGE_EVENT.toString());
            event.add("old", lastBasicBlock);
            event.add("new", currentBasicBlock);
            return event.build().toString();
        }

        @Override
        public PygmalionEventType getPygType() {
            return PygmalionEventType.COVERAGE_EVENT;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) return true;
            if (null == obj || getClass() != obj.getClass()) return false;
            CoverageEvent covEvent = (CoverageEvent) obj;
            return lastBasicBlock == covEvent.lastBasicBlock &&
                    currentBasicBlock == covEvent.currentBasicBlock;
        }

        @Override
        public int hashCode() {
            return lastBasicBlock * 31 + currentBasicBlock;
        }
    }

    private static final class CmimidEvent implements PygmalionEvent {

        private final String name;
        private final List<String> information;
        private final PygmalionEventType pygType;

        private CmimidEvent(PygmalionEventType type, String name, List<String> information) {
            this.pygType = type;
            this.name = name;
            this.information = information;
        }

        @Override
        public String toString(int inputLength) {
            JsonObjectBuilder result = Json.createObjectBuilder();
            result.add("type", pygType.toString());
            result.add("fun", name);
            var infoArray = Json.createArrayBuilder();
            for (var info : information) {
                infoArray.add(info);
            }
            result.add(PygmalionEventType.CMIMID_EVENT == pygType ? "info" : "index", infoArray);
            return result.build().toString();
        }

        @Override
        public PygmalionEventType getPygType() {
            return pygType;
        }
    }

    private static final class InputComparisonEvent implements PygmalionEvent {
        private final List<Integer> index;
        private final String predicate;
        private final PygmalionEventType pygType;
        private final String lhs;
        private final List<String> rhs;
        private Character nextEventRhs;
        private final List<String> callStack;
        // as id take the id of the basic block
        private final int id;

        private InputComparisonEvent(List<Integer> index, String predicate, List<String> lhs, List<String> rhs, boolean lhsTainted, InputComparisonEvent lastComp, List<String> callStack, int id)
        {
            this.index = index;
            this.predicate = predicate;
            pygType = PygmalionEventType.INPUT_COMPARISON;
            // the lhs is always the tainted side
            if (lhs.isEmpty() || rhs.isEmpty()) {
                throw new IllegalStateException("Nothing to compare when generating a Comparisonevent.");
            }
            this.lhs = lhsTainted ? lhs.get(0) : rhs.get(0);
            this.rhs = lhsTainted ? rhs : lhs;
            this.callStack = new LinkedList<>(callStack);
            this.id = id;

            if (null != lastComp &&
                    !lastComp.index.isEmpty() && !this.index.isEmpty() &&
                    lastComp.index.get(0).equals(this.index.get(0)) &&
                    isIncludingPredicate(lastComp.predicate, this.predicate, lastComp.rhs.get(0).charAt(0), this.rhs.get(0).charAt(0))) {
                // if the events are including we take both into account for one operation and do not consider the
                // upcoming event anymore
                lastComp.nextEventRhs = this.rhs.get(0).charAt(0);
            }
        }

        /**
         * Checks if the two predicates are including, i.e. form a set. Example: x>='a' and x<='z' is the set from 'a' to 'z'
         * Therefore also a range must be defined by the values, if x >= 'z' and x <= 'a' is found, the this is not an including predicate.
         * @param pr1: the first predicate in the comparison list
         * @param pr2: the second predicate in the comparison list
         * @return true if the predicates are including
         */
        private static boolean isIncludingPredicate(String pr1, String pr2, char rhs1, char rhs2) {
            return (">=".equals(pr1) || ">".equals(pr1)) && ("<=".equals(pr2) || "<".equals(pr2))
                    && rhs1 <= rhs2 ||
                    ("<=".equals(pr1) || "<".equals(pr1)) && (">=".equals(pr2) || ">".equals(pr2))
                            && rhs2 <= rhs1 ;

        }

        public String toString(int inputLength) {
            if ("eof".equals(predicate)) {
                if (!index.isEmpty() && index.get(0) < inputLength - 1) {
                    // EOF should have the index of the last char read, if not the event is not an EOF comparison
                    // and therefore we should not print anything
                    return "# no EOF";
                }
            }

            JsonArrayBuilder taints = Json.createArrayBuilder();
            for (int taint : index) {
                taints.add(taint);
            }

            JsonObjectBuilder event  = Json.createObjectBuilder();
            event.add("type", pygType.toString());
            event.add("index", taints);
            event.add("length", inputLength);
            event.add("value", lhs);
            event.add("operator", null == nextEventRhs ? predicate : "in");

            JsonArrayBuilder operand = Json.createArrayBuilder();
            List<String> chars = getComparisonChars(rhs, nextEventRhs);
            for (var chr : chars) {
                operand.add(chr);
            }

            event.add("operand", operand);
            event.add("id", id);
            var stack = Json.createArrayBuilder();
            callStack.forEach(stack::add);
            event.add("stack", stack);
            return event.build().toString();
        }

        @Override
        public PygmalionEventType getPygType() {
            return pygType;
        }

        private List<String> getComparisonChars(List<String> rhs, Character nextEvent) {
            LinkedList<String> chars = new LinkedList<>();

            //handling of "in" operator
            char firstChar = rhs.isEmpty() || rhs.get(0).isEmpty() ? '\0': rhs.get(0).charAt(0);
            if (null != nextEvent) {
                addChars(firstChar, nextEvent, chars);
                return chars;
            }

            switch (predicate) {
            case "==":
            case "!=":
            case "switch":
            case "eof": rhs.get(0).chars().forEach(chr -> chars.add(String.valueOf((char) chr))); break;
            case ">": addChars(firstChar + 1, MAXASCIIVALUE, chars); break;
            case ">=": addChars(firstChar, MAXASCIIVALUE, chars); break;
            case "<": addChars(MINASCIIVALUE, firstChar - 1, chars); break;
            case "<=": addChars(MINASCIIVALUE, firstChar, chars); break;
            case "tokenstore":
            case "tokencomp":
            case "strcmp":
            case "strconstcmp":
            case "conversion":
            case "strsearch":
            case "intcmp":
            case "strlen": chars.add(rhs.get(0)); break;
            case "scanf": chars.addAll(rhs);
            case "assert": break;
            default:
                throw new UnsupportedOperationException(String.format("invalid comparison predicate %s", predicate));
            }

            return chars;
        }

        /**
         * Creates a char list from val1 to val2 if val1 < val2, else from val2 to val1.
         * @param val1: First character.
         * @param val2: Second character.
         * @param chars: List of characters to fill.
         */
        private static void addChars(int val1, int val2, List<String> chars) {
            var minValue = Math.min(val1, val2);
            var maxValue = Math.max(val1, val2);
            for (var value = minValue; value <= maxValue; ++value) {
                chars.add(String.valueOf((char) value));
            }
        }
    }

    /**
     * Generates a EventSender which writes to the given {@link FileOutputStream} in a format appropriate for Pygmalion
     */
    public PygmalionEventSender(String outputFilename, ResourceManager resourceManager) {
        this.resourceManager = resourceManager;
        this.outputFilename = outputFilename;
        events = new ArrayList<>(30);
    }

    public void close() throws IOException {
        // TODO Using getFilePosition() is not ideal to get input length because it could be changed by the program.
        //      There is also the question of stdin and other non-file inputs where the position is not simple
        //      to get.
        int inputLength = 0;
        if (!taintSource.equals(-1L)) {
            inputLength = resourceManager.getFilePosition(taintSource);
        }

        try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(outputFilename))) {

            for (PygmalionEvent ev : events) {
                writer.write(String.format("%s%n", ev.toString(inputLength)));
            }
        }
    }

    @Override
    public void methodEnter(String methodName, TaintVector[] argumentTaints) {
        stack.add(methodName);
        events.add(new StackEvent(stack));
    }

    @Override
    public void methodExit(String methodName, TaintVector returnTaint) {
        stack.remove(stack.size() - 1);
        events.add(new StackEvent(stack));
    }

    public void numberComparison(String op1Val, String op2Val, TaintVector op1Taint, TaintVector op2Taint) {
        if (isEmptyOrNull(op1Taint)) {
            // get the indeces of the first byte (as all bytes have the same taints for numbers)
            var idx = taintToIndex(op2Taint.getTaint(0), 1);
            var val = createStringFromTaint(op1Taint.getTaint(0), idx);
            // only print an intcompare if the string representation of the integer is equal to the string it stems from
            if (val.equals(op2Val)) {
                addInputComparisonEvent(false, idx, "intcmp", op1Val, op2Val);
            }
        } else {
            var idx = taintToIndex(op1Taint.getTaint(0), 1);
            var val = createStringFromTaint(op1Taint.getTaint(0), idx);
            // only print an intcompare if the string representation of the integer is equal to the string it stems from
            if (val.equals(op1Val)) {
                addInputComparisonEvent(true, idx, "intcmp", op1Val, op2Val);
            }
        }
    }

    @Override
    public void binOperation(Integer operatorVal, String op1Val, String op2Val, TaintVector resTaint, TaintVector op1Taint, TaintVector op2Taint) {
        // TODO We assume values are non-vector for now. Extend to vectors.
        Taint lhsTaint = (null == op1Taint) ? null : op1Taint.getTaint(0);
        Taint rhsTaint = (null == op2Taint) ? null : op2Taint.getTaint(0);
        boolean lhsTainted = null != lhsTaint && !lhsTaint.isEmpty() && !lhsTaint.hasTaintType(TaintType.STRCONST);

        //if both sides are empty or only strconst taints, return
        if ((isEmptyOrNull(op1Taint) || op1Taint.getTaint(0).hasTaintType(TaintType.STRCONST))
                && (isEmptyOrNull(op2Taint) || op2Taint.getTaint(0).hasTaintType(TaintType.STRCONST))) {
            return;
        } else {
            // check and perform strconst comparison if possible
            var wasStrConst = handleStrConstComparison(lhsTaint, rhsTaint);
            if (wasStrConst) {
                return;
            }
        }

        long char1 = Long.parseUnsignedLong(op1Val);
        long char2 = Long.parseUnsignedLong(op2Val);

        if (!isEmptyOrNull(op1Taint) && op1Taint.getTaint(0).hasTaintType(TaintType.CONVERTEDNUMBER) ||
                !isEmptyOrNull(op2Taint) && op2Taint.getTaint(0).hasTaintType(TaintType.CONVERTEDNUMBER)) {
            numberComparison(op1Val, op2Val, op1Taint, op2Taint);
        }

        if (!isEmptyOrNull(op1Taint) && op1Taint.getTaint(0).hasTaintType(TaintType.TOKEN) ||
                !isEmptyOrNull(op2Taint) && op2Taint.getTaint(0).hasTaintType(TaintType.TOKEN)) {
            return;
        }

        if ((!isEmptyOrNull(op1Taint) && op1Taint.getTaint(0).hasTaintType(TaintType.STRLEN) ||
                !isEmptyOrNull(op2Taint) && op2Taint.getTaint(0).hasTaintType(TaintType.STRLEN))
                && 1 <= char1 && 1 <= char2 && char1 != char2 &&
                Utils.KEYWORDLENGTH > char1 && Utils.KEYWORDLENGTH > char2) {
            List<Integer> index = taintToIndex(lhsTainted ? lhsTaint : rhsTaint, 1);
            addInputComparisonEvent(lhsTainted, index, "strlen", Long.toString(char1), Long.toString(char2));
            return;
        } else {
            // in case this is an uninteresting strlen comparison, do not report it except there is a comparison against a string constant
            if (!isEmptyOrNull(op1Taint) && op1Taint.getTaint(0).hasTaintType(TaintType.STRLEN)||
                    !isEmptyOrNull(op2Taint) && op2Taint.getTaint(0).hasTaintType(TaintType.STRLEN)) {
                return;
            }
        }

        if (!(isPrintableCharacter(char1) && isPrintableCharacter(char2))) {
            // not usual ascii -> not characters comparison
            // check for eof: check if one side is tainted and also if the comparison is successful -> we assume this as a
            // check against eof
            if ((!isEmptyOrNull(op1Taint) || !isEmptyOrNull(op2Taint)) && char1 == char2) {
                List<Integer> index = taintToIndex(lhsTainted ? lhsTaint : rhsTaint, 1);
                addInputComparisonEvent(lhsTainted, index, "eof", "-1", "-1");
                return;
            }
            return;
        }

        String predicate;
        Predicate operatorEnum = Predicate.getICMPpredicate(operatorVal);
        switch (operatorEnum) {
        case ICMP_EQ: predicate = "=="; break;
        case ICMP_NE: predicate = "!="; break;
        case ICMP_UGT:
        case ICMP_SGT:
            predicate = ">"; break;
        case ICMP_UGE:
        case ICMP_SGE:
            predicate = ">="; break;
        case ICMP_ULT:
        case ICMP_SLT:
            predicate = "<"; break;
        case ICMP_ULE:
        case ICMP_SLE:
            predicate = "<="; break;
        default:
            throw new UnsupportedOperationException(String.format("error: invalid comparison in event.\nOperator%s", operatorVal));
        }


        if (isEmptyOrNull(lhsTaint) && isEmptyOrNull(rhsTaint)) {
            // neither side of this comparison is tainted -> nothing to do
            return;
        }

        List<Integer> index = taintToIndex((lhsTainted) ? lhsTaint : rhsTaint, 1);
        char lhs = (char)Integer.parseInt(op1Val);
        char rhs = (char)Integer.parseInt(op2Val);


        addInputComparisonEvent(lhsTainted, index, predicate, Character.toString(lhs), Character.toString(rhs));
    }

    public void strlen(Taint op1Taint, Taint op2Taint, long len1, long len2) {
        boolean lhsTainted = null != op1Taint && !op1Taint.isEmpty() && !op1Taint.hasTaintType(TaintType.STRCONST);

        if (len1 != len2) {
            List<Integer> index = taintToIndex(lhsTainted ? op1Taint : op2Taint, 1);
            addInputComparisonEvent(lhsTainted, index, "strlen", Long.toString(len1), Long.toString(len2));
            return;
        }
    }

    private boolean handleStrConstComparison(Taint lhsTaint, Taint rhsTaint) {
        if (!(isEmptyOrNull(lhsTaint) || isEmptyOrNull(rhsTaint))  && (lhsTaint.hasTaintType(TaintType.STRCONST) || rhsTaint.hasTaintType(TaintType.STRCONST))) {
            // union taints to get all taints
            var lhsUnion = Taint.unionIntoFull(lhsTaint, lhsTaint);
            var rhsUnion = Taint.unionIntoFull(rhsTaint, rhsTaint);
            var lhsIndex = taintToIndex(lhsUnion,1);
            var rhsIndex = taintToIndex(rhsUnion,1);

            var lhsValue = createStringFromTaint(lhsUnion, lhsIndex);
            var rhsValue = createStringFromTaint(rhsUnion, rhsIndex);
            var lhsTainted = rhsTaint.hasTaintType(TaintType.STRCONST);
            addInputComparisonEvent(lhsTainted, lhsTainted ? lhsIndex : rhsIndex, "strconstcmp", lhsValue, rhsValue);
            return true;
        }
        return false;
    }

    private String createStringFromTaint(Taint taint, List<Integer> indices) {
        String value = "";
        for (var tnt : taint) {
            for (var key : tnt.keySet()) {
                value = createStringFromTaint(key, indices);
                break;
            }
            break;
        }
        return value;
    }

    private String createStringFromTaint(long source, List<Integer> indices) {
        var sBuilder = new StringBuilder();
        for (var idx : indices) {
            resourceManager.getChar(source, idx).ifPresent(sBuilder::append);
        }
        return sBuilder.toString();
    }

    private static boolean isEmptyOrNull(TaintVector tnt) {
        return null == tnt || tnt.isEmpty();
    }

    private static boolean isEmptyOrNull(Taint tnt) {
        return null == tnt || tnt.isEmpty();
    }

    private void addInputComparisonEvent(boolean lhsTainted, List<Integer> index, String predicate, String lhs, String rhs) {
        var inputComparisonEvent = new InputComparisonEvent(index, predicate, List.of(lhs), List.of(rhs), lhsTainted, lastInputComparison, stack, lastBB);
        // now check if with the previous event an "in" operation is formed, if so do not add the newly generated input comparison
        if (null != lastInputComparison && null != lastInputComparison.nextEventRhs) {
            lastInputComparison = null;
            return;
        } else {
            events.add(inputComparisonEvent);
            lastInputComparison = inputComparisonEvent;
        }
    }

    @Override
    public void strcmp(String str1, String str2, Taint str1Taint, Taint str2Taint) {
        if (!isExactlyOneTainted(str1Taint, str2Taint)) return;

        boolean lhsTainted = (null != str1Taint && !str1Taint.isEmpty() && !str1Taint.hasTaintType(TaintType.STRCONST));
        List<Integer> index = taintToIndex((lhsTainted) ? str1Taint : str2Taint, (lhsTainted) ? str1.length() : str2.length());
        addInputComparisonEvent(lhsTainted, index, "strcmp", str1, str2);
    }

    @Override
    public void swtch(String str1, String[] str2, Taint str1Taint) {
        //if both sides are empty or only strconst taints, return
        if (null == str1Taint || str1Taint.isEmpty() || str1Taint.hasTaintType(TaintType.STRCONST)) {
            return;
        }

        List<Integer> index = taintToIndex(str1Taint, 1);
        var str2Values = new StringBuilder();
        Arrays.stream(str2).forEach(val -> convertToChar(val).ifPresent(str2Values::append));
        if (null != str2Values.toString() && str2Values.toString().isEmpty()) {
            // in this case the right hand side of switch contained no valid char, so we ignore it
            return;
        }
        convertToChar(str1).ifPresent(str1chr -> addInputComparisonEvent(true, index, "switch", str1chr.toString(), str2Values.toString()));
    }

    @Override
    public void strchr(String str1, String str2, Taint str1Taint) {
        //if both sides are empty or only strconst taints, return
        if (null == str1Taint || str1Taint.isEmpty() || str1Taint.hasTaintType(TaintType.STRCONST)) {
            return;
        }
        List<Integer> index = taintToIndex(str1Taint, 1);
        convertToChar(str1).ifPresent(str1chr -> addInputComparisonEvent(true, index, "switch", str1chr.toString(), str2));
    }

    @Override
    public void strsearch(List<String> searched, String str2, Taint str2Taint) {
        //TODO searches can be in two directions, so either the searched string or the characters that are searched in the string can be tainted
        //if both sides are empty or only strconst taints, return
        if (null == str2Taint || str2Taint.isEmpty() || str2Taint.hasTaintType(TaintType.STRCONST)) {
            return;
        }
        List<Integer> index = taintToIndex(str2Taint, str2Taint.getSize());
        searched.forEach(valueSearched -> addInputComparisonEvent(true, index, "strsearch", str2, valueSearched));
    }

    @Override
    public void scanf(String formatString, List<String> givenString, Taint givenStringTaints) {
        //TODO searches can be in two directions, so either the searched string or the characters that are searched in the string can be tainted
        //if both sides are empty or only strconst taints, return
        if (null == givenString || givenStringTaints.isEmpty() || givenStringTaints.hasTaintType(TaintType.STRCONST)) {
            return;
        }
        List<Integer> index = taintToIndex(givenStringTaints, givenStringTaints.getSize());
        events.add(new InputComparisonEvent(index, "scanf", List.of(formatString), givenString, true, lastInputComparison, stack, lastBB));
    }

    @Override
    public void tokenStore(String op1Val, String op2Val, Taint op1Taint){
        if (null == op1Taint || op1Taint.isEmpty()) {
            return;
        }
        // just get the taint of the first byte as for tokens all four bytes have the same taint
        var index = taintToIndex(op1Taint, 1);

        var chr = convertToChar(op1Val);
        addInputComparisonEvent(true, index, "tokenstore", chr.isPresent() ? String.valueOf(chr.get()) : op1Val, op2Val);
    }

    @Override
    public void tokenCompare(String op1Val, String op2Val, Taint op1Taint, Taint op2Taint, TokenManager tokenManager) {

        // omit lexing functions, this also includes functions that are called by lexing functions as we assume those as lexing functions as well
        for (var function : stack) {
            if (tokenManager.isLexing(function)) {
                return;
            }
        }

        if (!isExactlyOneTainted(op1Taint, op2Taint)) return;

        boolean lhsTainted = (null != op1Taint && !op1Taint.isEmpty());

        // check if token taint is present, only then report tokencomp
        if (lhsTainted ? !op1Taint.hasTaintType(TaintType.TOKEN) : (null == op2Taint || !op2Taint.hasTaintType(TaintType.TOKEN))) {
            return;
        }

        var index = taintToIndex(lhsTainted ? op1Taint : op2Taint, 1);

        addInputComparisonEvent(lhsTainted, index, "tokencomp", op1Val, op2Val);

        // if a tokencompare was done, the taint stored in the TokenManager should be marked as used
        tokenManager.setUsed(true);
    }

    @Override
    public void tableLookup(Taint opTaint, Taint[] tnts) {
        if (null == tnts || 0 == tnts.length) {
            return;
        }

        List<Integer> opIndeces = taintToIndex(opTaint, 1);
        String opString = createStringFromTaint(opTaint, opIndeces);
        Arrays.stream(tnts).forEach(tnt -> addInputComparisonEvent(true, opIndeces, "strcmp", opString, createStringFromTaint(tnt, taintToIndex(tnt, 1))));
    }

    private static boolean isExactlyOneTainted(Taint op1Taint, Taint op2Taint) {
        return (null == op1Taint || op1Taint.isEmpty() || op1Taint.hasTaintType(TaintType.STRCONST)) ^ (null == op2Taint || op2Taint.isEmpty() || op2Taint.hasTaintType(TaintType.STRCONST));
    }

    @Override
    public void bbEnter(int id) {
        if (-1 == lastBB) {
            lastBB = id;
            return;
        }
        var covBB = new CoverageEvent(lastBB, id);
        lastBB = id;
        if (!coveredBasicBlocks.contains(covBB)) {
            events.add(covBB);
        }
        coveredBasicBlocks.add(covBB);
    }

    private static Optional<Character> convertToChar(String val) {
        long v1;
        try {
            v1 = Long.parseUnsignedLong(val);
        } catch (NumberFormatException nfe) {
            return Optional.empty();
        }

        if (!isPrintableCharacter(v1)) {
            // not usual ascii -> not characters comparison
            return Optional.empty();
        }

        return Optional.of((char)Integer.parseInt(val));
    }

    private static boolean isPrintableCharacter(long v1) {
        return !((MINASCIIVALUE > v1 &&
				'\n' != v1 &&
				'\r' != v1 &&
				'\013' != v1 &&
				'\f' != v1 &&
				'\t' != v1
				) || MAXASCIIVALUE <= v1);
    }

    /**
     * Extracts from a taint the indices defining the position of the characters of the taint source.
     * @param taint The taint from which the indices should be extracted.
     * @param size the number of bytes that are used for extraction.
     * @return a list of indices used in the taint.
     */
    private List<Integer> taintToIndex(Taint taint, int size) {
        var result = new LinkedList<Integer>();

        if (null == taint || taint.isEmpty()) {
            return result;
        }

        int bytesCounter = 0;
        for (HashMap<Long, BitSet> map : taint) {
            if (bytesCounter >= size) {
                return result;
            }

            if (map.entrySet().isEmpty()) {
                continue;
            }
            Entry<Long, BitSet> entry = map.entrySet().iterator().next();

            taintSource = entry.getKey();
            int i = entry.getValue().nextSetBit(0);

            while (-1 != i) {
                result.add(i);
                i = entry.getValue().nextSetBit(i + 1);
            }
            ++bytesCounter;
        }

        return result;
    }

    @Override
    public void cmimid(String name, List<String> information) {
        events.add(new CmimidEvent(PygmalionEventType.CMIMID_EVENT, name, information));
    }

    @Override
    public void cmimid(String name, Taint information) {
        if (!information.isEmpty() && information.hasOnlyTaintType(TaintType.DEFAULT)) {
            List<Integer> indexList = taintToIndex(information, 1);
            var strList = new ArrayList<String>(indexList.size());
            indexList.forEach(el -> strList.add(Integer.toString(el)));
            events.add(new CmimidEvent(PygmalionEventType.CMIMID_ACCESS, name, strList));
        }
    }

    @Override
    public void conversion(String str1, String conversionFunction, Taint str1Taint) {
        if ((null == str1Taint || str1Taint.isEmpty())) {
            // not tainted -> nothing to do
            return;
        }
        List<Integer> index = taintToIndex(str1Taint, 1);
        addInputComparisonEvent(true, index, "conversion", str1, conversionFunction);
    }

    @Override
    public void assertCall() {
        LinkedList<Integer> index = new LinkedList<>();
        index.add(-1);
        addInputComparisonEvent(true, index, "assert", "", "");
    }
}
