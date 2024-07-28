package taintengine;

import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.stream.Stream;
import java.util.stream.Collectors;

public final class TaintVector implements Iterable<Taint> {
    // TODO immutability is not fully implemented, at least the TaintVector cannot be changed from the outside

    private final List<Taint> elements = new ArrayList<>(10);

    public TaintVector() {
        // Intentionally left blank
    }

    /**Creates a new TaintVector with the given length. This vector gets initialized with empty taints.
     * @param length
     */
    public TaintVector(int length, int numberOfBytes) {
        while (elements.size() < length) {
            elements.add(new Taint(numberOfBytes));
        }
    }

    /**
     * Creates a new taint vector from the given taint array. It copies the array with its content to create the new vector.
     * @param taintedElements the given taint array
     */
    public TaintVector(Taint[] taintedElements) {
        for (Taint taintedElement : taintedElements) {
            elements.add(taintedElement.copy());
        }
    }

    /**
     * Create a new taint vector from a list of taints
     */
    public TaintVector(List<Taint> taintedVector) {
        elements.addAll(taintedVector);
    }

    /**
     * Creates a new taint vector with the given taint. This method is equivalent to creating a taint vector with one element.
     * It can be used for the common case that the vector size is 1.
     * @param elementTaint the given taint
     */
    public TaintVector(Taint elementTaint) {
        add(elementTaint);
    }

    public void add(Taint elementTaint) {
        elements.add(elementTaint.copy());
    }

    /**
     * Creates a new taint array which contains copies of the taints of the parameter.
     * @return new taint array with copied taints
     */
    public TaintVector copy() {
        return new TaintVector(elements);
    }

    /**
     *
     * @return The length of the taint vector.
     */
    public int getLength() {
        return elements.size();
    }

    /**
     * Unions the taints of the toUnion TaintVector into the source TaintVector. They should have the same size.
     * The taints of each byte are unioned into the taints of the respective other byte.
     * @param toUnion
     */
    public static TaintVector unionIntoByteWise(TaintVector source, TaintVector toUnion) {
        TaintVector newTv = new TaintVector();
        Iterator<Taint> sourceIterator = source.elements().iterator();
        Iterator<Taint> toUnionIterator = toUnion.elements().iterator();
        while (sourceIterator.hasNext() && toUnionIterator.hasNext()) {
            newTv.elements.add(Taint.unionIntoByteWise(sourceIterator.next(), toUnionIterator.next()));
        }

        return newTv;
    }

    /**
     * Unions the taints of the toUnion TaintVector into the source TaintVector. They should have the same size.
     * The taints of each byte are unioned into the taints of all other bytes.
     * @param toUnion
     */
    public static TaintVector unionIntoFull(TaintVector source, TaintVector toUnion) {
        TaintVector newTv = new TaintVector();
        Iterator<Taint> sourceIterator = source.elements().iterator();
        Iterator<Taint> toUnionIterator = toUnion.elements().iterator();
        while (sourceIterator.hasNext() && toUnionIterator.hasNext()) {
            newTv.elements.add(Taint.unionIntoFull(sourceIterator.next(), toUnionIterator.next()));
        }

        return newTv;
    }

    /**
     * Union the taint of one byte into the taint of one vector element.
     * The byte position defines where the first byte of the given taint is unioned into.
     * @param taint
     * @param vectorPosition
     * @param bytePosition
     */
    public static TaintVector unionByteTaintInto(TaintVector source, Taint taint, int vectorPosition, int bytePosition) {
        TaintVector newTv = source.copy();
        newTv.elements.set(vectorPosition, Taint.unionIntoByte(newTv.elements.get(vectorPosition), taint, bytePosition, 0));

        return newTv;
    }

    /**
     *
     * @return returns if all taints of the vector are empty.
     */
    public boolean isEmpty() {
        return elements().allMatch(Taint::isEmpty);
    }

    /**
     * Returns copy of taint at position.
     * @param position
     */
    public Taint getTaint(int position) {
        return elements.get(position);
    }

    /**
     * Returns a new Taint of size 1 which contains the copy of the taint of the byte at the specified position.
     * @param position
     * @param bytePos
     */
    public Taint getTaintForByte(int position, int bytePos) {
        return Taint.unionIntoByte(new Taint(1), elements.get(position), 0, bytePos);
    }

    public Stream<Taint> elements() {
        return elements.stream();
    }

    @Override
    /**
     * Returns an iterator over the copy of the taints in the taint vector.
     */
    public Iterator<Taint> iterator() {
        return elements.iterator();
    }

    @Override
    public String toString() {
        String elementsString = elements.stream()
                                        .map(Taint::toString)
                                        .collect(Collectors.joining(", "));

        return "TaintVector [taints=[" + elementsString + "], length=" + elements.size() + ']';
    }
}
