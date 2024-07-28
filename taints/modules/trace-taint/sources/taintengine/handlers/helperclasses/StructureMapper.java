package taintengine.handlers.helperclasses;

import java.util.Deque;
import java.util.Map;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Optional;
import java.util.regex.Pattern;

public class StructureMapper {
    private static final Pattern STRUCTPATTERNCONSTANT = Pattern.compile("struct.");
    private static final Pattern STARPATTERNCONSTANT = Pattern.compile("\\*");
    private static final Pattern PERCENTAGEPATTERNCONSTANT = Pattern.compile("%");
    private final Map<String, String[]> structureMap = new HashMap<>(50);

    // local name mapping must survive function calls, so a list of maps is needed
    // Localname -> {StructureName, FieldName}
    private final Deque<HashMap<String, String[]>> accessMap = new LinkedList<>();

    /**
     * Create a new Structure mapper which maps names of variables to structures.
     */
    public StructureMapper() { accessMap.addLast(new HashMap<>(20)); }

    /**
     * Add a structure definition to the mapper.
     * @param name
     * @param elements
     */
    public void addStructure(String name, String[] elements) { structureMap.put(name, elements); }

    /**
     * Maps the name of a local to the accessed field of it.
     * @param localName
     * @param elementNumber
     */
    public void mapLocalToElement(String localName, String structureName, int elementNumber) {
        // if its a pointer to a pointer to a structure, then ignore
        if (structureName.contains("**")) {
            return;
        }

        String actualStructureName = extractStructureName(structureName);

        // replace all additional characters, that do not define the structure name
        String[] names = structureMap.get(actualStructureName);

        // if not found, the structure is not known to us and will be ignored
        // or the gep does not access a structure
        if (null == names) {
            return;
        }
        String[] pair = {actualStructureName, names[elementNumber]};
        accessMap.getLast().put(localName, pair);
    }

    /**
     * On method call a new scope has to be created.
     */
    public void methodCall() { accessMap.addLast(new HashMap<>(20)); }

    /**
     * On return the scope has to be removed and the old scope is taken again.
     */
    public void returnCall() { accessMap.removeLast(); }

    /**
     * Returns the field name for a local.
     * @param local name of the local
     * @return null if the local does not contain values of a field.
     */
    public Optional<String> getFieldForLocal(String local) {
        String[] pair = accessMap.getLast().get(local);
        return null != pair ? Optional.ofNullable(pair[1]) : Optional.empty();
    }

    /**
     * Returns the structure name for the field the local points to.
     * @param local name of the local
     * @return null if the local does not contain values of a field.
     */
    public Optional<String> getStructureNameForLocal(String local) {
        String[] pair = accessMap.getLast().get(local);
        return null != pair ? Optional.ofNullable(pair[0]) : Optional.empty();
    }

    @Override
    public String toString() {
        return "StructureMapper [structureMap=" + structureMap + ']';
    }

    /**
     * Extracts the actual structure name from the llvm representation of the structure name.
     * @param origName
     * @return
     */
    public static String extractStructureName(String origName) { return PERCENTAGEPATTERNCONSTANT.matcher(STARPATTERNCONSTANT.matcher(STRUCTPATTERNCONSTANT.matcher(origName).replaceAll("")).replaceAll("")).replaceAll(""); }

    /**
     * Returns for a given structure name and an index the name of the field at this index.
     * @param structureName
     * @param index
     * @return
     */
    public String getFieldNameForStructureAndIndex(String structureName, int index) { return structureMap.get(structureName)[index]; }

    /**
     * Returns if a structure with the given name exists in the map.
     * @param struct
     */
    public boolean structExists(String struct) { return this.structureMap.containsKey(struct); }
}
