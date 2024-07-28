package taintengine.handlers.helperclasses;

import taintengine.Taint;
import utils.TaintType;

import java.util.HashSet;
import java.util.Optional;

public class TokenManager {
    /**
     * Stores information about the last taint used in a comparison. This is needed if an enum assignment happens as
     * the taint stored in here needs to be attached to the enum.
     */

    private final HashSet<String> lexingFunctions = new HashSet<>(10);
    private String value;
    private Taint tnt;

    // defines if the stored values were used by now, if not they should not be removed
    private boolean used;

    /**
     * Stores the combination of taints in the manager as an enum taint that can later be used to taint enums.
     * @param tnt1 taint of left hand side of operation
     * @param tnt2 taint of right hand side of operation
     */
    public void setTaint(String value, Taint tnt1, Taint tnt2) {
        // for the moment do not use string constants for token taint generation
        if (tnt1.hasTaintType(TaintType.STRCONST) || tnt2.hasTaintType(TaintType.STRCONST)) {
            return;
        }
        tnt = Taint.unionIntoFull(tnt1, tnt2);
        // we need to ensure a taint of size 4 here as the token has size 4
        tnt = Taint.unionIntoFull(new Taint(4), tnt);
        tnt.addTaintType(TaintType.TOKEN);
        this.value = value;
        used = false;
    }

    /**
     * Stores the combination of taints in the manager as an enum taint that can later be used to taint enums.
     * @param tnt taint of operation
     */
    public void setTaint(String value, Taint tnt) {
        // for the moment do not use string constants for token taint generation
        if (tnt.hasTaintType(TaintType.STRCONST)) {
            return;
        }
        // taint each byte of the stored taint with all taint of all other bytes as a token is just one value
        if (null != this.tnt) {
            // check if the index of the taint we want to add is smaller than what we already have, if so we restarted
            // the tokenparsing and should also reset the taint info for the token we want to store
            if (this.tnt.getMaxTaint() > tnt.getMaxTaint()) {
                this.tnt = tnt.copy();
            } else {
                this.tnt = Taint.unionIntoFull(this.tnt, tnt);
            }
        } else {
            this.tnt = Taint.unionIntoFull(new Taint(4), tnt);
        }
        this.tnt.addTaintType(TaintType.TOKEN);
        this.value = value;
        used = false;
    }

    /**
     * Returns the taint stored in the taint manager. The invariant holds that this is the last taint used in a comparison.
     * @return a copy of the taint stored in this object
     */
    public Optional<Taint> getTnt() {
//        used = true;
        return Optional.ofNullable(tnt);
    }

    public Optional<String> getValue() {
//        used = true;
        return Optional.ofNullable(value);
    }

    public void clean() {
        if (used) {
            tnt = null;
            value = null;
        }
    }

    public void setUsed(boolean used) {
        this.used = used;
    }

    public boolean getUsed() {
        return used;
    }

    /**
     * Marks functions that process raw characters (as those are lexing functions).
     * @param functionName
     */
    public void markLexing(String functionName) {
        // we exclude the program main from lexing functions as input might be read in here
        // TODO might be interesting to exclude all input reading functions from the lexing functions
        if (!"_real_program_main".equals(functionName)) {
            lexingFunctions.add(functionName);
        }
    }

    public boolean isLexing(String functionName) {
        return lexingFunctions.contains(functionName);
    }
}
