package taintengine;

import taintengine.handlers.helperclasses.ArrayIndexMapper;
import taintengine.handlers.helperclasses.ResourceManager;
import taintengine.helperclasses.VaEntry;
import utils.LineInformation;
import utils.Operand;
import utils.TaintType;
import utils.Utils;

import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;

public class NodeMapper {
    // contains the name of the function mapped to its arguments in correct order
    private final Map<String, String[]> instrumentedFunctions;

    // This node mapping can be used to find a node again by name. It also represents the function functionNameStack.
    private final LinkedList<Map<String, TaintVector>> nodeMapping = new LinkedList<>();

    // contains the return functionNameStack, so if a return statement happens the value is saved to the node on top
    private final Deque<String> returnStack = new LinkedList<>();

    // Maps an address to a taint.
    private final Map<Long, Taint> addressMapping = new HashMap<>(100);

    // helps to find out sizes for arrays if needed, is optional
    private ArrayIndexMapper arMapper;

    //the global variables already tainted
    private final Set<String> taintedGlobals = new HashSet<>(30);

    // handles the lookups of values in tables
    private final Map<Long, Set<Taint>> tableEntryTaints = new HashMap<>(5);

    // stores the last LineInformation that was processed for instructions that are composed of several LineInformations
    private LineInformation prev_info;

    // stores the mapping from a file descriptor to its current unique ID
    private final Map<Long, Long> fdIdMapping= new HashMap<>(10);
    private long fdIdCounter = 3L; // start with fd id counter 4 as 0-2 are reserved for stdin/-out/-error

    // constant of zero length taint array to convert lists to arrays
    private static final Taint[] ZEROLENGTHTAINTARRAY = new Taint[0];

    /**
     * Creates a nodeMapper object. This contains the node Network as well as the function functionNameStack.
     * @param funDefMap A map containing function definitions.
     * @param gvars A map containing the global variables.
     */
    public NodeMapper(Map<String, String[]> funDefMap, List<Operand> gvars, ResourceManager resourceManager) {
        instrumentedFunctions = funDefMap;
        nodeMapping.add(parseGVars(gvars, resourceManager));
        // map the standard filedescriptors to themselves
        fdIdMapping.put(Utils.ARGVSOURCEID, Utils.ARGVSOURCEID);
        fdIdMapping.put(0L, 0L);
        fdIdMapping.put(1L, 1L);
        fdIdMapping.put(2L, 2L);
    }

    /**
     * Creates the map for the nodeMapping functionNameStack to store the global variables.
     * @param gvars global variables
     * @return Initially empty mapping of global vars to {@link TaintVector}
     */
    private static Map<String, TaintVector> parseGVars(List<Operand> gvars, ResourceManager resourceManager) {
        Map<String, TaintVector> tvMap = new HashMap<>(10);
        var stringIndexCounter = 0;
        for (Operand op : gvars) {
            TaintVector taintedGlobal;
            int byteSize = op.getByteSizeUnderlyingType();
            String value = op.getValue();
            if ("-42".equals(value)) {
                taintedGlobal = new TaintVector(op.getVectorLength(), byteSize);
            } else {
                // assign taints to all string constant values
                var taints = new Taint[Math.min(byteSize, value.length())];
                for (var i = 0; i < byteSize && i < value.length(); i++) {
                    taints[i] = Taint.setBit(new Taint(1), Utils.STRINGCONSTANTSOURCEID, stringIndexCounter);
                    taints[i].setTaintType(TaintType.STRCONST);
                    resourceManager.setCharacter(Utils.STRINGCONSTANTSOURCEID, stringIndexCounter++, value.charAt(i));
                }
                taintedGlobal = new TaintVector(taints);
            }
            tvMap.put(op.getName(), taintedGlobal);
        }

        return tvMap;
    }

    /**
     * Creates a new function functionNameStack if the function is listed in the functionDefintionMap.
     * @param functionName Name of the function that is called.
     * @param operands Name of the arguments of the function.
     * @param returnNode The node where the result of the function call is save to.
     */
    public void functionCall(String functionName, String[] operands, String returnNode) {
        String[] args = instrumentedFunctions.get(functionName);
        if (null == args) {
            // callee is not instrumented -> no need to change functionNameStack frame
            return;
        }

        Map<String, TaintVector> curFunctionFrame = nodeMapping.getFirst();
        Map<String, TaintVector> newFunctionFrame = new HashMap<>(5);

        for (int x = 0; x < args.length; ++x) {
            // get the existing taints and put them under the parameter names in the new function frame as copies
            TaintVector argNodeTaint = curFunctionFrame.get(operands[x]);
            if (null == argNodeTaint) {
                // if no taint is assigned for the var argNodeTaint will be null and we can skip this
                continue;
            }

            newFunctionFrame.put(args[x], argNodeTaint.copy());
        }
        nodeMapping.addFirst(newFunctionFrame);
        returnStack.addFirst(returnNode);
    }

    /**
     * Adds a local to the current function functionNameStack.
     * @param name of the variable
     * @param operands the operands that will be used to calculate the union of taints for the new local
     */
    public void addLocal(String name, String[] operands, int vectorLength, int numberOfBytes, BiFunction<TaintVector, TaintVector, TaintVector> method) {
        // union the taints of all operands
        TaintVector contained = new TaintVector(vectorLength, numberOfBytes);
        for (String operand : operands) {
            TaintVector toUnion = getTaintForName(operand);
            // if null there is nothing to do for this operand
            if (null == toUnion) {
                continue;
            }
            contained = method.apply(contained, toUnion);
        }

        nodeMapping.getFirst().put(name, contained);
    }

    /**
     * Adds a local to the function functionNameStack with the given taint information.
     * If the local was already set with a taint, the taint will be overwritten.
     * @param name the name of the variable the taint is attached to.
     * @param tnt the taint to attach.
     */
    public void addTaintForLocal(String name, Taint tnt) {
        Taint[] tntArray = {tnt};
        addTaintForLocal(name, tntArray);
    }

    /**
     * Adds a local to the function functionNameStack with the given taint information.
     * If the local was already set with a taint, the taint will be overwritten.
     * @param name the variable the taint is attached to.
     * @param tnt the taint-array to attach.
     */
    public void addTaintForLocal(String name, Taint[] tnt) {
        // TODO likely add here a taintarray, s.t. taintvectors can be added
        TaintVector taint = new TaintVector(tnt);
        Map<String, TaintVector> map = nodeMapping.getFirst();
        map.put(name, taint);
    }

    /**
     * Add a local variable taint
     */
    public void addTaintForLocal(String name, TaintVector taint) {
        nodeMapping.getFirst().put(name, taint);
    }

    /**
     * Removes the local with the given name from the current scope.
     * @param name the variable to delete from the current scope.
     */
    public void removeLocal(String name) {
        nodeMapping.getFirst().remove(name);
    }

    /**
     * Adds a local vector to the current function functionNameStack.
     * This method is intended to be used for adding vectors after specific vector operations (shuffle,extract...)
     * Or after specific byte level operations (e.g. shifts).
     * @param name of the variable
     * @param elementTaints the taints of the operands in the correct order [0..n]
     */
    public void addLocalVector(String name, Taint[] elementTaints, int numberOfBytes, BiFunction<TaintVector, TaintVector, TaintVector> method) {
        TaintVector contained = new TaintVector(elementTaints.length, numberOfBytes);
        TaintVector newVector = new TaintVector(elementTaints);
        contained = method.apply(contained, newVector);

        nodeMapping.getFirst().put(name, contained);
    }

    /**
     * Adds a new local with a copy of the taints attached to the address to the given name.
     * @param address the address the taint is loaded from.
     * @param name the name of the variable the taint is attached to.
     * @param vectorLength the length of the vector that is loaded.
     * @param numberOfBytes the number of bytes of each vector element.
     */
    public void addLocalForAddress(long address, String name, int vectorLength, int numberOfBytes) {
        TaintVector taint = getTaintsForAddress(address, vectorLength, numberOfBytes);

        nodeMapping.getFirst().put(name, taint);
    }

    /**
     * For a return call the function functionNameStack will be removed and the variable the function returns to gets the pointers assigned.
     */
    public String returnCall(String returnedValueName, int vectorLength, int numberOfBytes) {
        // get the name of the destination register
        String returnIntoNode = returnStack.removeFirst();

        // get the taint of the returned value
        TaintVector returnedTaint = getTaintForName(returnedValueName);
        if (null == returnedTaint) {
            returnedTaint = new TaintVector(vectorLength, numberOfBytes);
        }

        // pop the functionNameStack
        nodeMapping.removeFirst();

        nodeMapping.getFirst().put(returnIntoNode, returnedTaint);
        return returnIntoNode;
    }

    /**
     * Add a mapping from an address to a taint. This taints only 1 byte.
     * @param address the address the taint is stored to.
     * @param taint the taint that is stored.
     */
    public void addAddressTaint(Long address, Taint taint) {
        if (taint.isEmpty()) {
            addressMapping.remove(address);
        } else {
            addressMapping.put(address, taint.copy());
        }
    }

    /**
     * Add a mapping from an address to a taint defined by the name.
     * @param storeTo the address to store to.
     * @param name the name of the variable the taint comes from.
     */
    public void addAddressTaint(Long storeTo, String name, int byteSize) {
        TaintVector taint = getTaintForName(name);
        if (null == taint) {
            // TODO likely the taintvector has to be sized depending on the underlying type?
            taint = new TaintVector(1, byteSize);
        }
        addAddressTaintForVector(storeTo, taint, byteSize);
    }

    /**
     * Add a mapping from an address to a taint defined by the name. Thereby each byte gets all taints of the register the taint comes from.
     * @param storeTo the address to store to.
     * @param name the name of the variable the taint comes from.
     * @param byteSize the number of bytes that are stored
     */
    public void addAddressTaints(Long storeTo, String name, int byteSize) {
        TaintVector taint = getTaintForName(name);
        if (null == taint) {
            // TODO likely the taintvector has to be sized depending on the underlying type?
            taint = new TaintVector(1, byteSize);
        }
        for (var i = 0; i < byteSize; i++) {
            addAddressTaintForVector(storeTo + i, taint, 1);
        }
    }

    /**
     * Goes through the vector element for element, takes the taint and adds for each tainted byte a respective taint to the memory map.
     * @param storeTo the address to store the taint to.
     * @param taint the taint to store.
     * @param byteSize the number of bytes that are stored in the original execution.
     */
    public void addAddressTaint(Long storeTo, TaintVector taint, int byteSize) {
        addAddressTaintForVector(storeTo, taint, byteSize);
    }

    public void addAddressTaintForVector(Long storeTo, TaintVector taint, int byteSize) {
        if (taint.isEmpty()) {
            for (int vectorSize = 0; vectorSize < taint.getLength(); ++vectorSize) {
                for (int typeSize = 0; typeSize < byteSize; typeSize++) {
                    // store for each value of the vector a new taintvector of size 1 to the memory
                    addressMapping.remove(storeTo + ((long) vectorSize * byteSize) + typeSize);
                }
            }
        } else {
            for (int vectorSize = 0; vectorSize < taint.getLength(); ++vectorSize) {
                for (int typeSize = 0; typeSize < byteSize; typeSize++) {
                    // store for each value of the vector a new taintvector of size 1 to the memory
                    addressMapping.put(storeTo + ((long)vectorSize * byteSize) + typeSize, taint.getTaintForByte(vectorSize, typeSize));
                }
            }
        }
    }

    /**
     * @param name of the LLVM register.
     * @return copy of the taint related to the name of the register in the current function frame. Returns null if the taint does not exist.
     */
    public TaintVector getTaintForName(String name) { return getTaintForNameOldStack(name, 0); }

    /**
     * @param name of the LLVM register.
     * @param goUpCounter the number of frames to go up before looking for the variable (0 for currently active frame, 1 for the caller, 2 for the caller of the caller, ...)
     * @return copy of the taint related to the name of the register in the current function frame. Returns null if the taint does not exist.
     */
    public TaintVector getTaintForNameOldStack(String name, int goUpCounter) {
        return nodeMapping.get(goUpCounter).get(name);
    }

    /**
     * @param address that is queried.
     * @param vectorLength the length of the vector that is queried.
     * @return copy of a taint if the given address is tainted, otherwise it returns a new Taint.
     */
    public TaintVector getTaintsForAddress(long address, int vectorLength, int numberOfBytes) {
        Taint[] taints = new Taint[vectorLength];
        for (int vectorSize = 0; vectorSize < vectorLength; ++vectorSize) {
            Taint[] tmpTaint = new Taint[numberOfBytes];
            for (int byteSize = 0; byteSize < numberOfBytes; ++byteSize) {
                // iterate over addresses and take taints
                Taint byteTaint = addressMapping.get(address + ((long)vectorSize * numberOfBytes) + byteSize);
                if (null == byteTaint || byteTaint.isEmpty()) {
                    continue;
                }
                // store the taints of the addresses in the new vector
                tmpTaint[byteSize] = byteTaint;
            }

            taints[vectorSize] = new Taint(tmpTaint);
        }
        return new TaintVector(taints);
    }

    /**
     * Get the taints for numberOfBytes-bytes starting at address
     */
    public Taint[] getTaintForAddress(long address, int numberOfBytes) {
        TaintVector taintedMemory = getTaintsForAddress(address, numberOfBytes, 1);

        Taint[] taints = new Taint[taintedMemory.getLength()];
        int index = 0;
        for (Taint taint : taintedMemory) {
            taints[index] = taint;
            ++index;
        }

        return taints;
    }

    /**
     * Set the taints in bytesTaints to memory starting at address.
     */
    public void addTaintForAddress(long address, Taint[] bytesTaints) {
        for (int i = 0; i < bytesTaints.length; ++i) {
            addAddressTaint(address + i, bytesTaints[i]);
        }
    }

    /**
     * Checks if the function was instrumented. When it is the case, the taint propagation is done inside this
     * function.
     * @param name of the function.
     * @return true if function is instrumented, false if not.
     */
    public boolean isFunctionInstrumented(String name) { return instrumentedFunctions.containsKey(name); }

    /**
     * Sets the arrayIndexMapper to the given object.
     * @param arMapper the given {@link ArrayIndexMapper}
     */
    public void addArrayIndexMapper(ArrayIndexMapper arMapper) { this.arMapper = arMapper; }

    /**
     * @param index the index of the address that is queried.
     * @return the remaining bytes of an array for a given address.
     */
    public int getRemainingBytesForAddress(Long index) { return null == arMapper ? 0 : arMapper.getRemainingBytesForAddress(index); }

    /**
     * Handles the tainting of global values.
     */
    public void taintGlobal(String name, long addr) {
        if (!taintedGlobals.contains(name)) {
            // get from the topmost stack the global taints
            var tnt = nodeMapping.getLast().get(name);
            if (null != tnt && !tnt.isEmpty()) {
                addAddressTaint(addr, tnt, 1);
            }
            // store the size of the address we just wrote
            arMapper.setIndexSize(addr, tnt.getLength());
            // remember that we set the taints for this specific index
            taintedGlobals.add(name);
        }
    }

    /**
     * Handles the tainting of table pointers. Can be used to store information which tainted values are stored in a table, e.g. a hash table.
     * @param address The base address of the table.
     * @param tnt The taint of the value that is looked up in the table.
     */
    public void taintTablePointer(long address, Taint tnt) {
        tableEntryTaints.computeIfAbsent(address, value -> new HashSet<>(30)).add(tnt.copy());
    }

    public Taint[] getTablePointerTaints(long address) {
        var tnts = tableEntryTaints.get(address);
        if (null == tnts) {
            return ZEROLENGTHTAINTARRAY;
        } else {
            return tnts.toArray(ZEROLENGTHTAINTARRAY);
        }
    }

    /**
     * Replaces the old {@link LineInformation} with the new one.
     * @param info the new {@link LineInformation} to store
     */
    public void replacePrevLineInformation(LineInformation info) {
        this.prev_info = info;
    }

    public LineInformation getPrevLineInformation() {
        return this.prev_info;
    }

    /**
     * For the given filedescriptor return the internal unique id.
     * @param fd the filedescriptor from the program execution
     * @return the mapped filedescriptor
     */
    public long getFDUniqueID(long fd) {
        Long result = fdIdMapping.get(fd);
        if (null == result) {
            return Utils.INVALIDSOURCEID;
        } else {
//            System.err.println(String.format("Result is %d.", fd));
            return result;
        }
    }

    /**
     * For the given filedescriptor give it a new internal id
     * @param fd  the filedescriptor from the program execution
     */
    public void setFDUniqueID(long fd) {
        if (2L < fd) {
            fdIdMapping.put(fd, fdIdCounter++);
        }
    }

    /**
     * Bind the internal unique ID of the old filedescriptor to the id of the new filedescriptor (in case of filedescriptor duplication).
     * @param oldfd the filedescriptor from the program execution representing the old fd
     * @param newfd the filedescriptor from the program execution representing the new fd
     */
    public void setFDUniqueID(long oldfd, long newfd) {
        var uid = fdIdMapping.get(oldfd);
        if (null == uid) {
            //TODO introduce some more robust logging in future
            System.err.println(String.format("Filedescriptor %d is not known by now.", oldfd));
        }
        fdIdMapping.put(newfd, uid);
    }
}
