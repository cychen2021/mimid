package taintengine.helperclasses;

import taintengine.TaintVector;

public class VaEntry {

    public final long value;
    public final TaintVector taint; //taints are immutable

    public VaEntry(long value, TaintVector taint) {
        this.value = value;
        this.taint = taint;
    }
}
