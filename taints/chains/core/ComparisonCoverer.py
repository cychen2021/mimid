import core.Utils as Utils
import os
import core.ConversionHandler as ConversionHandler
from typing import Dict, Tuple, List, Set, Iterable, Any

# id -> (satisfied in any input, satisfied in valid input, unsat in any input, unsat in valid input, set of valid comparisons seen, set of possible comparison values, comparison object)
covered:Dict[int, Tuple[bool, bool, bool, bool, Set[str], Set[str], Any]] = dict() # collects information for comparisons, i.e. for each comparison id if it was already covered in both directions or not by any input

# defines which comparisons are already finished, on each change of this set the Prioqueue needs to be re-evaluated
finished_ids = set()

def collect_comparison_coverage_information(inpt: str, comparisons: Any, was_valid: bool):
    import core.PriorityHandling as PrioHandling
    # TODO check what needs to be done for conversions
    # TODO check which comparisons to consider, maybe only those for valid inputs? Also maybe just do not consider the last compared character or last comparison as they might have lead to the error handling code and are therefore no successful comparisons

    for comp in comparisons:
        if comp["operator"] in {"tokenstore", "eof"}:
            continue
        id_ = comp["id"]
        cov = covered.get(id_)
        if not cov:
            cov = (False, False, False, False, set(), set())
        # for the index of the last compared character only remember the comparisons done but do not set them to false
        # elif comp["value"] not in comp["operand"]:
        rhs = calc_rhs(comp)
        cov[5].update(rhs)
        if comp["value"] not in rhs:
            covered[id_] = (cov[0], cov[1], True, cov[3] or was_valid, cov[4], cov[5], comp)
        else: #if comp["index"][0] <= Utils.max_index_comparison:
            if was_valid:
                cov[4].add(comp["value"])
            covered[id_] = (True, cov[1] or was_valid, cov[2], cov[3], cov[4], cov[5], comp)

    with open(os.path.join("coverage_info.json"), "w") as cov_file:
        re_eval = True
        for el in covered.items():
            if el[1][6]["operator"] != "!=" and (not (el[1][0] and el[1][1] and el[1][2] and el[1][3]) or not el[1][4].issuperset(el[1][5])):
                cov_file.write(str(el[0]) + "\n")
                for val in el[1]:
                    cov_file.write(f"\t{val}\n")
                cov_file.write("\n")
                if el[0] in finished_ids:
                    # it may happen that a new comparison value is discovered which may bring the comparison back to the interesting ones, thus the PrioQueue needs to be re-evaluated again
                    if re_eval:
                        # only re-evaluate once
                        re_eval = False
                        PrioHandling.re_evaluate_queue()
                    finished_ids.remove(el[0])
            elif el[0] not in finished_ids:
                # re-evaluate the prioqueue as the interesting comparisons has changed
                if re_eval:
                    # only re-evaluate once
                    re_eval = False
                    PrioHandling.re_evaluate_queue()
                finished_ids.add(el[0])

def calc_rhs(comp: Any) -> Iterable[str]:
    """
    Checks if the tainted value in the given comparison is equal to at least one value it was tested for in the given comparison.
    :param comp: the comparisons to test
    :return:
    """
    # can be expanded to other operators that need special handling regarding their comparison
    if comp["operator"] == "conversion":
        return ConversionHandler.val_in_conversions(comp["operand"][0])
    return comp["operand"]


def is_interesting_comparison(id:int, correction:str, index:List[int], notcovered:bool):
    """
    Checks if the given comparison was already true and false in a valid value
    :param id: the id of the comparison
    :param inp_cmp: the compared input
    :param index: the indeces of the characters that were compared
    :param notcovered: a flag if the input covered new code or not
    :return: 0 if the comparison is not interesting according to the definition above, a value greater 0 if it is
    """
    cmp = covered.get(id)
    if notcovered and cmp and not (cmp[0] and cmp[1] and cmp[2] and cmp[3]):
        # if the condition is not fulfilled by the given comparison, we return a higher value
        #TODO the untainted value could be anything, so we might want to cover all untainted values (at least in prefixes, not necessarily in valid inputs)?
        if cmp[6]["operator"] != "!=" and (not(cmp[0] and cmp[1]) or not cmp[4].issuperset(cmp[5])) and correction not in cmp[4]:
            if (cmp[6]["operator"] == "tokencomp"):
                return 10 - (index[-1] + 1) * 2
            else:
                return - (index[-1] + 1) * 2
        else:
            return 0
    else:
        return 0
