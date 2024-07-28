package taintengine.handlers.helperclasses;

import taintengine.Taint;
import taintengine.TaintVector;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Optional;

/**
 * Creates a new ResourceManager which handles the calls to files and other inputs.
 * It manages the information on how much of the resource was already read (i.e. which bytes were already read).
 */
public class ResourceManager {

    private final Map<Long, Resource> resources = new HashMap<>(20);
    private final Map<Long, List<TaintVector>> ungotc = new HashMap<>(20);

//    private static final class CharTaintPair {
//
//        public final TaintVector taint;
//
//        public final char chr;
//
//        private CharTaintPair(TaintVector taint, char chr) {
//            this.taint = taint;
//            this.chr = chr;
//        }
//    }

    private static class Resource {
        // current position in the resource
        public Integer currPosition = 0;

        // view of the resource as an array of (ASCII) characters
        public final Map<Integer, Character> charAtPosition = new HashMap<>(50);
    }



    /**
     * @param source the id of the source the value should be retrieved
     * @param idx the index in the source the value should be retrieved
     * @return an optional, with the character or empty
     */
    public Optional<Character> getChar(long source, int idx) {
          return Optional.ofNullable(resources.get(source).charAtPosition.get(idx));
    }

    /**
     * Stores the fileposition given by the parameter.
     *
     * @param sourceID
     * @param position
     */
    public void saveFilePosition(long sourceID, int position) {
        if (!resources.containsKey(sourceID)) {
            resources.put(sourceID, new Resource());
            if (-1 == position) {
                resources.get(sourceID).currPosition = 0;
            }
        }

        if (0 <= position) {
            resources.get(sourceID).currPosition = position;
        }
    }

    /**
     * Returns the stored position of the file.
     *
     * @param sourceID
     * @return
     */
    public int getFilePosition(long sourceID) {
        if (!resources.containsKey(sourceID)) {
            return 0;
        }

        return resources.get(sourceID).currPosition;
    }

    /**
     * Associate a given character to a resource location
     */
    public void setCharacter(long sourceID, Integer position, Character value) {
        if (!resources.containsKey(sourceID)) {
            resources.put(sourceID, new Resource());
        }

        resources.get(sourceID).charAtPosition.put(position, value);
    }

    public String sourceToString(long sourceID) {
        if (!resources.containsKey(sourceID)) {
            return "";
        }

        Map<Integer, Character> indexToChar = resources.get(sourceID).charAtPosition;
        StringBuilder sbuilder = new StringBuilder();
        for (int i = 0; i < indexToChar.size(); ++i) {
            sbuilder.append(indexToChar.getOrDefault(i, '?'));
        }

        return sbuilder.toString();
    }

    public void ungetc(long sourceID, TaintVector tnt) {
        var charList = ungotc.getOrDefault(sourceID, new LinkedList<>());
        charList.add(0, tnt);
        ungotc.put(sourceID, charList);
    }

    public List<TaintVector> popUngotC(long sourceID, int size) {
        var charList = ungotc.getOrDefault(sourceID, new LinkedList<>());
        var sublist = charList.subList(0, Math.min(size, charList.size()));
        var resultList = new LinkedList<>(sublist);
        sublist.clear();
        return resultList;
    }
}
