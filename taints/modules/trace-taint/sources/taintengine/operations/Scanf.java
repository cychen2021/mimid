package taintengine.operations;

import taintengine.NodeMapper;
import taintengine.handlers.helperclasses.ResourceManager;
import utils.LineInformation;
import utils.Operand;

import java.util.Map;
import java.util.HashMap;
import java.util.HashSet;
import java.util.regex.Pattern;

public abstract class Scanf extends Operation {
    private static final Pattern STARPATTERNCONSTANT = Pattern.compile("\\*");
    // stores temporarily the fileposition at the point when this operation was called
    protected final Map<Long, Integer> addressSizeMapping = new HashMap<>(20);

    /**
     * Creates an abstract scanf operation which reflects the stdlibc method.
     * @param info
     */
    public Scanf(LineInformation info) { super(info); }

    /**
     * Creates taints for each character and stores them at the respective position.
     * @param characters the characters for which the taints shall be generated
     * @param startingPoint the position of the char to start with
     * @param address the address in memory to store it to
     * @param numberToStore the number of chars to store
     * @param typeSize the size of the type of the operand, to which this will be stored
     * @param arraySpecifier the specifier defines if something is stored in an array or just in one cell
     */
    protected abstract void storeAtPosition(ResourceManager resourceManager, char[] characters, int startingPoint, long address, int numberToStore, NodeMapper nodeMapper, int typeSize, boolean arraySpecifier, long sourceID);

    /**
     * TODO this needs to be refactored at some point..
     * @param readChars The input string that is parsed as character array.
     * @param format The format string as character array.
     * @param nodeMapper
     * @param filePointer The pointer to the file, will be used as sourceID if necessary.
     * @param opCounter The first operand a value is assigned to.
     * */
    protected void parseFormatSpecifier(ResourceManager resourceManager, char[] readChars, char[] format, NodeMapper nodeMapper, long filePointer, int opCounter) {
        int stringCounter = 0;

        // indicates if the next read value is assigned or not
        boolean assign = true;

        int formatCounter = 0;
        while (formatCounter < format.length) {
            //%% is just a read % and nothing is assigned
            char character = format[formatCounter];
            //%% is just a read of % in the original string
            if ('%' == character && '%' == format[formatCounter + 1]) {
                formatCounter++;
                stringCounter++;
                continue;
            }

            if ('%' == character) {
                formatCounter++;
                character = format[formatCounter];
                //%n does not consume anything, does not return tainted data
                if ('n' == character) {
                    formatCounter++;
                    opCounter++;
                    continue;
                }

                // the next read value is not assigned, now it has to be checked which characters have to be skipped
                if ('*' == character) {
                    formatCounter++;
                    character = format[formatCounter];
                    assign = false;
                }

                // now get how many character should be read at most
                StringBuilder sbuilder = new StringBuilder();
                while (Character.isDigit(character)) {
                    sbuilder.append(character);
                    formatCounter++;
                    character = format[formatCounter];
                }
                int readlengthSpecifier = -1;

                String maxLengthRead = sbuilder.toString();
                if (!maxLengthRead.isEmpty()) {
                    readlengthSpecifier = Integer.parseInt(maxLengthRead);
                }

                formatCounter = skipLengthSpecifier(format, formatCounter);

                Operand operand = info.getOperands()[opCounter];
                String opType = operand.getType();
                int typeSize = Operand.getByteSizeForType(STARPATTERNCONSTANT.matcher(opType).replaceFirst(""));
                long storeToAddress = Long.parseLong(operand.getValue().split(" ")[0]);
                // string, character and numbers is missing
                if (isFloatingPointSpecifier(character) || isIntegerSpecifier(character) || 's' == character) {
                    int startingPoint = stringCounter;
                    while (stringCounter < readChars.length && !Character.isWhitespace(readChars[stringCounter]) && 0 != readlengthSpecifier) {
                        // check for consecutive character which might not be a whitespace
                        // if this one appears, the input read has to end
                        if (formatCounter + 1 < format.length && readChars[stringCounter] == format[formatCounter + 1] && stringCounter != startingPoint) {
                            break;
                        }
                        stringCounter++;
                        readlengthSpecifier--;
                    }
                    if (assign) {
                        storeAtPosition(resourceManager, readChars, startingPoint, storeToAddress, stringCounter - startingPoint, nodeMapper, typeSize, 's' == character, filePointer);
                        // save the size of the written array
                        if ('s' == character) {
                            addressSizeMapping.put(storeToAddress, stringCounter - startingPoint);
                        }
                        opCounter++;
                    } else {
                        assign = true; // value was read, the next one might be assigned again
                    }
                    formatCounter++;
                    continue;
                }

                if ('c' == character) {
                    // check if length was defined
                    if (assign) {
                        storeAtPosition(resourceManager, readChars, stringCounter, storeToAddress, -1 == readlengthSpecifier ? 1 : readlengthSpecifier, nodeMapper, typeSize, -1 != readlengthSpecifier, filePointer);
                        opCounter++;
                    } else {
                        assign = true; // value was read, the next one might be assigned again
                    }
                    // if more than one char is read, also consume more than one char from the input
                    stringCounter += -1 == readlengthSpecifier ? 1 : readlengthSpecifier;
                    formatCounter++;
                    continue;
                }

                if ('[' == character) {
                    formatCounter++;
                    boolean neg = false;
                    int startingPoint = stringCounter;
                    if ('^' == format[formatCounter]) {
                        neg = true;
                        formatCounter++;
                    }

                    HashSet<Character> charsToCheck = new HashSet<>(20);

                    character = format[formatCounter];
                    while (']' != character) {
                        charsToCheck.add(character);
                        character = format[++formatCounter];
                    }

                    // while the character is not part of the scanset (or is part of the scanset, depending
                    // on the scanning mode defined by the optional '^' at the beginning) look for such a char
                    while (stringCounter < readChars.length && charsToCheck.contains(readChars[stringCounter]) != neg && 0 != readlengthSpecifier) {
                        // check for consecutive character which might not be a whitespace
                        // if this one appears, the input read has to end
                        if (formatCounter + 1 < format.length && readChars[stringCounter] == format[formatCounter + 1]) {
                            break;
                        }
                        stringCounter++;
                        readlengthSpecifier--;
                    }

                    // assign values if necessary
                    if (assign) {
                        storeAtPosition(resourceManager, readChars, startingPoint, storeToAddress, stringCounter - startingPoint, nodeMapper, typeSize, true, filePointer);
                        // save the size of the written array
                        addressSizeMapping.put(storeToAddress, stringCounter - startingPoint);
                        opCounter++;
                    } else {
                        assign = true; // value was read, the next one might be assigned again
                    }
                    formatCounter++;
                    continue;
                }
            }

            if (Character.isWhitespace(character)) {
                while (formatCounter < format.length && Character.isWhitespace(format[formatCounter])) {
                    formatCounter++;
                }
                while (formatCounter < format.length && Character.isWhitespace(readChars[stringCounter])) {
                    stringCounter++;
                }
            } else {
                stringCounter++;
                formatCounter++;
            }
        }
    }

    private static boolean isFloatingPointSpecifier(char character) { return 'f' == character || 'e' == character || 'g' == character || 'a' == character; }

    private static boolean isIntegerSpecifier(char character) { return 'i' == character || 'u' == character || 'd' == character || 'o' == character || 'x' == character; }

    /**
     * Returns the size of the optional length specifier. Is 0 if there is none.
     * @param format
     * @param currentPosition
     * @return
     */
    private static int skipLengthSpecifier(char[] format, int currentPosition) {
        if (currentPosition + 1 >= format.length) {
            // end of format, so this cannot be a length specifier
            return currentPosition;
        }

        char currChar = format[currentPosition];
        char nextChar = format[currentPosition + 1];
        if ('h' == currChar && 'h' == nextChar || 'l' == currChar && 'l' == nextChar) {
            return currentPosition + 2;
        }

        if (-1 != "hljztL".indexOf(currChar)) {
            return currentPosition + 1;
        }

        return currentPosition;
    }
}
