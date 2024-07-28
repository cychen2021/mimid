package taintengine.handlers.helperclasses;

import taintengine.helperclasses.VaEntry;
import utils.Utils;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class VaListMapper {

    private final Map<Long, List<VaEntry>> vaListTaints = new HashMap<>(5);
    private final LinkedList<List<VaEntry>> vaStack = new LinkedList<>();
    // a va_list has 2 positions at which it remembers the next element: the first element of the structure and the third element, we observe both
    private final Set<Long> monitoredAddresses = new HashSet<>(10);

    private VaEntry staged;

    /**
     * Creates a VaListMapper and initializes it.
     */
    public VaListMapper(){
        // init for handling program main
        vaStack.add(new LinkedList<>());
    }

    /**
     * Handles the call to va_start by binding the address to the va_entries stored for the current function call
     * @param address the address to be bound
     */
    public void vaStart(long address){
        vaListTaints.put(address, vaStack.getLast());
        monitoredAddresses.add(address + 8); // address of the third structure element containing the linkedlist to remaining elements of the va_list
        monitoredAddresses.add(address + 8 + 2 * Utils.POINTERBYTESIZE); // address of the array storing the first 5 pointers to values
    }


    /**
     * Makes a copy from the va_list from source to destination.
     * @param dest destination
     * @param src source
     */
    public void vaCopy(long dest, long src) {
        vaListTaints.put(dest, new LinkedList<>(vaListTaints.get(src)));
        monitoredAddresses.add(dest + 8); // address of the third structure element containing the linkedlist to remaining elements of the va_list
        monitoredAddresses.add(dest + 8 + 2 * Utils.POINTERBYTESIZE); // address of the array storing the first 5 pointers to values
    }

    /**
     * Gets and deletes the first element from the va_list bound to the given address.
     * @param address the address which is bound to the va_list
     * @return the entry which was read by va_arg
     */
    public void stageElement(long address) {
        staged = vaListTaints.get(address).remove(0);
    }

    public Optional<VaEntry> retrieveStaged() {
        var tmpStaged = staged;
        staged = null;
        return Optional.ofNullable(tmpStaged);
    }

    /**
     * Adds the given function arguments to the stack for later usage if va_start is called
     * @param vaEntries the function arguments
     */
    public void methodCall(List<VaEntry> vaEntries) {
        vaStack.add(vaEntries);
    }

    /**
     * Deletes the top of the stack.
     */
    public void methodReturn() {
        vaStack.removeLast();
    }

    /**
     * Checks if the given address is a known va_list.
     * @param address the address to check
     * @return true if the address points to a va_list, false otw.
     */
    public boolean isVaList(long address) {
        return vaListTaints.containsKey(address);
    }

    public List<VaEntry> getVaList(long address) {
        return vaListTaints.getOrDefault(address, new LinkedList<>());
    }

    public void vaEnd(long address) {
        vaListTaints.remove(address);
    }
}
