package utils;

import java.util.Map;
import java.util.HashMap;

public class Utils {
    // call objects start with this string as name
    public static final String CALLOBJECTSTARTER = "i";

    // call instruction opcode
    public static final int CALLINSTRUCTIONOPCODE = 54;

    // Byte size of a double
    public static final int DOUBLEBYTESIZE = 8;

    // Byte size of a float
    public static final int FLOATBYTESIZE = 4;

    // byte size of a half
    public static final int HALFBYTESIZE = 2;

    // byte size of a void
    public static final int VOIDBYTESIZE = 0;

    // size of a pointer
    // the size may be system dependant. May later be read from metadata which is generated for each program.
    public static final int POINTERBYTESIZE = 4;

    // size of x85_fp80
    public static final int I86_FP80SIZE = 10;

    // Map from structname to size in bits
    public static final Map<String, Integer> SIZEMAP = new HashMap<>(50);

    public static final int STDINFILEMAPPER = 0;

    //this constant is used to define how long a keyword could be
    public static final int KEYWORDLENGTH = 20;

    // the source ID for String Constants
    public static final long STRINGCONSTANTSOURCEID = -1L;

    // the source ID of argv (the command line input given in main)
    public static final long ARGVSOURCEID = -2L;

    // defines a source ID that tells the engine to not generate taints that use that source
    public static final int INVALIDSOURCEID = -1337;

    // the name of the input file that should be observed
    private static String observedInputSource = "";

    // Flag for taint propagation over array indices: If on and the index of a load operation is tainted,
    // the read value is also tainted
    private static boolean arrayIndexTaintPropagation;

    public static boolean isArrayIndexTaintPropagation() {
        return arrayIndexTaintPropagation;
    }

    public static void setArrayIndexTaintPropagation(boolean arrayTaintProp) {
        Utils.arrayIndexTaintPropagation = arrayTaintProp;
    }

    public static boolean isNumeric(String str)
    {
        for (char c : str.toCharArray())
        {
            if (!Character.isDigit(c)) return false;
        }
        return true;
    }

    public static String getobservedInputSource() {
        return observedInputSource;
    }

    public static void setobservedInputSource(String observedInputSource) {
        Utils.observedInputSource = observedInputSource;
    }
}
