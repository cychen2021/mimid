package utils;

import java.util.Arrays;
import java.util.Iterator;
import java.util.Deque;
import java.util.LinkedList;
import java.util.Objects;
import java.util.regex.Pattern;

public class Operand {
    private static final Pattern TYPEENDPATTERN = Pattern.compile(".*\\)\\*\\]*");
    private static final Pattern STRUCTPATTERNCONSTANT = Pattern.compile("%struct.");
    private static final Pattern UNIONPATTERNCONSTANT = Pattern.compile("%union.");
    private static final Pattern XPATTERNCONSTANT = Pattern.compile(" x ");
    private static final Pattern IPATTERNCONSTANT = Pattern.compile("i");
    private final String name;
    private final String value;
    private final String type;
    private final int vectorLength;

    /**
     * Create an operand with the given information.
     * @param name
     * @param value
     * @param type
     */
    public Operand(String name, String value, String type) {
        this.name = name;
        this.value = value;
        this.type = type;

        // if its a pointer to a vector the actual vector length is 1
        if (!type.contains("<") || type.endsWith("*")) {
            this.vectorLength = 1;
        } else {
            // a vector type looks like "<4 x i8>", so the second member is the length
            this.vectorLength = Integer.parseInt(type.replace("<", "").split(" ")[0]);
        }
    }

    /**
     * Return the name of the operand.
     * @return
     */
    public String getName() { return name; }

    /**
     * Return the value of the operand.
     * @return
     */
    public String getValue() { return value; }

    /**
     * Return the type of the operand.
     * @return
     */
    public String getType() { return type; }

    /**
     * Return the vector length of the operand. If it is not a vector this returns 0.
     * @return
     */
    public int getVectorLength() { return vectorLength; }

    /**
     * Returns the number of bytes denoted by the type.
     * For pointer the size of the pointsTo is returned, for vectors and arrays the size of the element.
     * @return
     */
    public int getByteSizeUnderlyingType() { return getByteSizeForType(this.type); }

    /**
     * Returns the size in bytes which is consumed by an element of
     * the given type.
     * @param type
     * @return
     */
    public static int getByteSizeForType(String type) {
        String[] splitted = type.split(" ");
        LinkedList<Integer> addStack = new LinkedList<>();
        LinkedList<Integer> mulStack = new LinkedList<>();

        // initialize with nothing for standard types
        addStack.addFirst(0);
        // for types like "void (i32, %struct.siginfo_t*, i8*)*" or "ioid ()*"
        // one has to wait until ")*" and skip all inbetween
        boolean waitForPointer = false;
        Iterator<String> stIterator = Arrays.asList(splitted).iterator();
        while (stIterator.hasNext()) {
            String str = stIterator.next();
            if (waitForPointer) {
                if (str.endsWith(")*") || str.endsWith(")*,")) {
                    waitForPointer = false;
                    addStack.addFirst(addStack.pollFirst() + Utils.POINTERBYTESIZE);
                    continue;
                }

                if (TYPEENDPATTERN.matcher(str).matches()) {
                    waitForPointer = false;
                    endArrayByteSizeCalculation(addStack, mulStack, str);
                    continue;
                }
                // skip everything until the void pointer is resolved
                continue;
            }
            if ("void".equals(str) || "ioid".equals(str)) {
                waitForPointer = true;
                continue;
            }
            if (!str.isEmpty() && '(' == str.charAt(0) && !waitForPointer) {
                waitForPointer = true;
                // remove last element from addstack as this is a function pointer and the return type of the function
                // lies on the addstack now
                addStack.removeLast();
                if (addStack.isEmpty()) {
                    addStack.add(0);
                }
                continue;
            }
            if (!str.isEmpty() && '<' == str.charAt(0)) {
                // skip "x"
                stIterator.next();

                // extract type
                String endOfVector = stIterator.next();
                if (!endOfVector.isEmpty() && '*' == endOfVector.charAt(endOfVector.length() - 1)) {
                    addStack.addFirst(Utils.POINTERBYTESIZE);
                    continue;
                }
                int size = getByteSizeForStandardTypeStructAndUnion(endOfVector.replace(">", ""));
                addStack.addFirst(size * Integer.parseInt(str.replace("<", "")));
                continue;
            }
            str = str.replace(",", "");
            if (!str.isEmpty() && '{' == str.charAt(0)) {
                addStack.addFirst(0);
                continue;
            }

            if (!str.isEmpty() && '[' == str.charAt(0)) {
                mulStack.addFirst(Integer.parseInt(str.replace("[", "")));
                continue;
            }

            // if this happens, an anonymous struct is the second part of an array
            // so the top of the addstack has to be put onto the mulstack
            if (str.startsWith("}]")) {
                mulStack.addFirst(addStack.pollFirst());
                str = str.substring(1);
            }

            if (!str.isEmpty() && ']' == str.charAt(str.length() - 1)) {
                endArrayByteSizeCalculation(addStack, mulStack, str);
                continue;
            }

            if (!str.isEmpty() && '}' == str.charAt(str.length() - 1)) {
                addStack.addFirst(addStack.pollFirst() + addStack.pollFirst());
                continue;
            }

            if (!str.isEmpty() && 'i' == str.charAt(0) || !str.isEmpty() && '%' == str.charAt(0)) {
                addStack.addFirst(addStack.pollFirst() + getByteSizeForStandardTypeStructAndUnion(str));
                continue;
            }

            // skip unnecessary syntax symbols
            if ("x".equals(str) || "=".equals(str) || "type".equals(str) || "null".equals(str)) {
                continue;
            }

            addStack.addFirst(getByteSizeForStandardTypeStructAndUnion(str));
        }

        return addStack.getFirst();
    }

    private static void endArrayByteSizeCalculation(Deque<Integer> addStack, Deque<Integer> mulStack, String str) {
        // count number of closing parenthesis
        String typeNoParenthesis = str.replace("]", "");
        int parenCount = str.length() - typeNoParenthesis.length();
        // if the type is empty is was calculated before (e.g. an anonymous struct was part of it)
        if (!typeNoParenthesis.isEmpty()) {
            mulStack.addFirst(getByteSizeForStandardTypeStructAndUnion(typeNoParenthesis));
        }

        for (int x = 0; x < parenCount; x++) {
            mulStack.addFirst(mulStack.pollFirst() * mulStack.pollFirst());
        }

        addStack.addFirst(addStack.pollFirst() + mulStack.pollFirst());
    }

    private static int getByteSizeForStandardTypeStructAndUnion(String type) {
        if (type.startsWith("@")) {
            // this was a function pointer, so the size does not matter esentially, just return pointer size
            return Utils.POINTERBYTESIZE;
        }
        if (type.endsWith("*")) {
            return Utils.POINTERBYTESIZE;
        }
        if (type.startsWith("double")) {
            return Utils.DOUBLEBYTESIZE;
        }

        if (type.startsWith("float")) {
            return Utils.FLOATBYTESIZE;
        }

        if (type.startsWith("half")) {
            return Utils.HALFBYTESIZE;
        }

        if (type.startsWith("void")) {
            return Utils.VOIDBYTESIZE;
        }

        if (type.startsWith("i86_fp80") || type.startsWith("x86_fp80")) {
            return Utils.I86_FP80SIZE;
        }

        // if its a structure we will recognize this here and write out the correct size
        Integer structSize = Utils.SIZEMAP.get(UNIONPATTERNCONSTANT.matcher(STRUCTPATTERNCONSTANT.matcher(type).replaceAll("")).replaceAll(""));
        // if the size is not dividable by 8 the bytes still have to loaded, therefore the result has to be ceiled.
        // i is removed in order to get the bitsize denoted by llvm base type
        return (int) Math.ceil((double) Objects.requireNonNullElseGet(structSize, () -> Integer.parseInt(IPATTERNCONSTANT.matcher(type).replaceAll(""))) / 8); // size is stored in bits, has to be converted in bytes

    }

    private static int byteSizeArray(String type) {
        type = type.replace("{ ", "").replace(" }", "");
        String[] types = XPATTERNCONSTANT.split(type);
        int byteSizeType = getByteSizeForType(types[types.length - 1].replace("]", ""));

        int finalSize = 0;
        // the last element of the splitted type is the base type
        for (int x = 0; x < types.length - 1; x++) {
            finalSize += byteSizeType * Integer.parseInt(types[x].replace("[", ""));
        }

        return finalSize;
    }

    @Override
    public int hashCode() {
        int prime = 31;
        int result = 1;
        result = prime * result + ((null == name) ? 0 : name.hashCode());
        result = prime * result + ((null == type) ? 0 : type.hashCode());
        result = prime * result + ((null == value) ? 0 : value.hashCode());
        result = prime * result + vectorLength;
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (null == obj) {
            return false;
        }

        if (getClass() != obj.getClass()) {
            return false;
        }

        Operand other = (Operand)obj;
        if (null == name) {
            if (null != other.name) {
                return false;
            }
        } else if (!name.equals(other.name)) {
            return false;
        }

        if (null == type) {
            if (null != other.type) {
                return false;
            }
        } else if (!type.equals(other.type)) {
            return false;
        }

        if (null == value) {
            if (null != other.value) {
                return false;
            }
        } else if (!value.equals(other.value)) {
            return false;
        }

        return (vectorLength == other.vectorLength);
    }

    @Override
    public String toString() {
        return "Operand [name=" + name + ", value=" + value + ", type=" + type + ']';
    }
}
