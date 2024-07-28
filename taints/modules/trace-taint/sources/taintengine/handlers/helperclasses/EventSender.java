package taintengine.handlers.helperclasses;

import java.io.IOException;
import java.util.List;

import taintengine.Taint;
import taintengine.TaintVector;

public interface EventSender {
    /**
     * Close the EventSender output stream
     */
    void close() throws IOException;
    /**
     * Sends a MethodEnterEvent: EventCode, MethodName, NumOperands, [NumTaintElements, [NumBytes, [SourceID, NumBits, [Bits]*]*]*]*
     */
    void methodEnter(String methodName, TaintVector[] argumentTaints);

    /**
     * Sends a MethodExitEvent: EventCode, MethodName, NumTaintElements, [NumBytes, [SourceID, NumBits, [Bits]*]*]*
     */
    void methodExit(String methodName, TaintVector returnTaint);
    /**
     * Sends a BinOperationEvent
     */
    void binOperation(Integer operatorVal, String op1Val, String op2Val, TaintVector resTaint, TaintVector op1Taint, TaintVector op2Taint);

    /**
     * Sends a StrcmpEvent
     */
    void strcmp(String str1, String str2, Taint str1Taint, Taint str2Taint);

    /**
     * Sends switch
     */
    void swtch(String str1, String[] str2, Taint str1Taint);

    /**
     * Sends cmimid information
     */
    void cmimid(String functionName, List<String> information);

    void cmimid(String name, Taint information);

    /**
     * Sends strchr
     * @param str1 the ordinal value of the char that is searched in string representation
     * @param str2 the string in which is searched
     * @param str1Taint the taint of str1
     */
    void strchr(String str1, String str2, Taint str1Taint);

    /**
     * Sends strsearch
     * @param searched the list of values which are searched in the string
     * @param str2 the string in which is searched
     * @param str2Taint the taint of str2
     */
    void strsearch(List<String> searched, String str2, Taint str2Taint);

    /**
     * Sends scanf
     * @param formatString the format string used in scanf
     * @param givenString the string that was given and is parsed
     * @param givenStringTaints the taint of the given string
     */
    void scanf(String formatString, List<String> givenString, Taint givenStringTaints);


    /**
     * Sends conversion operation (like strto*)
     * @param str1 the string or char used in the conversion operation
     * @param conversionFunction function used for conversion
     * @param str1Taint the taint of str1
     */
    void conversion(String str1, String conversionFunction, Taint str1Taint);

    /**
     * Sends basic block entering event
     * @param id id of basic block
     */
    void bbEnter(int id);

    /**
     * @param op1Val The value of the first operator, i.e. the string from the input which is converted to a token
     * @param op2Val The value of the token that is stored, the token itself has no taint as it is a constant
     * @param op1Taint The taint of the string that is converted
     */
    void tokenStore(String op1Val, String op2Val, Taint op1Taint);

    /**
     * @param op1Val The value of the left hand side token
     * @param op2Val The value of the right hand side token
     * @param op1Taint The taint of the lhs token
     * @param op2Taint The taint of the rhs token
     * @param tokenManager
     */
    void tokenCompare(String op1Val, String op2Val, Taint op1Taint, Taint op2Taint, TokenManager tokenManager);

    /**
     * @param op1Taint The taint of the first
     * @param op2Taint
     */
    void strlen(Taint op1Taint, Taint op2Taint, long len1, long len2);

    /**
     * Sends taints for table lookups.
     * @param opTaint the taint of the value that is looked up
     * @param tnts the taints of the values that are already present in the table
     */
    void tableLookup(Taint opTaint, Taint[] tnts);

    /**
     * Sends information that an assert call happened.
     */
    void assertCall();
}
