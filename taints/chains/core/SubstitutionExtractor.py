# coding=utf-8
"""
Contains the code which extracts the next substitutions based on an execution log.
"""
import json
import string
import random
from typing import Set, Tuple, Any, List, Dict, Iterable

from core.TokenHandler import TokenHandler
from core.TokenLearningHandler import TokenLearningHandler
from core.HeuristicValue import HeuristicValue
from core.InputValue import InputValue
import sys
import core.Utils as Utils
from core.KnowledgeHandling import KnowledgeHandling
import core.ConversionHandler as ConversionHandler
from core.ParsingStageExtractor import ParsingStageExtractor
import core.HandleScanf as ScanfHandler
import core.IndexComparisonMapping as CmpMapping
import core.ComparisonCoverer as CmpCoverer


def get_substitution(taints: str, inpt: str, parent_stack: List[str], was_valid:bool, dfs: bool = True) -> \
Tuple[HeuristicValue, Set[Tuple[Any, Any]], List[InputValue], KnowledgeHandling, Set[Tuple[Any, Any]], bool, bool]:
    """
    Returns the next position to substitute and the possible substitutions.
    :param covered_branches_parent:
    :param taints: the taints as json string
    :param inpt: the used input
    :param h_value_parent: the heuristic value of the current input
    :param was_valid: indicates if the given input was a valid input
    :param dfs: the flag to show if dfs or bfs is used
    :return:
    """
    objs = []
    with open(taints, 'r+') as f:
        for i in f.readlines():
            if i.strip()[0] == '#':
                continue
            if i.strip() == '':
                continue
            v = json.loads(i)
            objs.append(v)
    nxt, last_assert, stop_function_found = _process(objs, inpt, was_valid, dfs)
    knowledgehandler = KnowledgeHandling(objs)
    new_h_value, new_covered, all_covered = HeuristicValue.calc_cov_heuristic(objs, parent_stack, inpt, knowledgehandler)
    return new_h_value, new_covered, nxt, knowledgehandler, all_covered, last_assert, stop_function_found


def _construct_correction_list(corrections, dfs, inpt, last_index):
    """
    Creates the correction list based on if dfs or bfs is used
    :param corrections: All possible subsitutions
    :param dfs: dfs or bfs? True for dfs
    :param inpt: The input that was used to generate the comparisons
    :param last_char_idx: the index of the character that needs to be substituted
    :return:
    """
    # if a flag is used the position of the index shifts, the min_index is not correct anymore and needs to be fixed
    # i.e. the flag is also checked at some point, so the min_index is the value point the flag starts rather than the point
    # at which the actual input starts, this is corrected here
    if not(Utils.g_flag == "") and Utils.as_arg:
        Utils.min_index += len(Utils.g_flag) + 1
    if dfs:
        choice = random.choice(corrections)
        return [InputValue(choice[2], Utils.min_index, choice[0], choice[1], inpt, True)]
    else:
        # add a random char and a random number to corrections as it often happens that there is no concrete check for those (i.e. everything except the chars that were found is accepted)
        if "tokencomp" in [cor[1] for cor in corrections] or not ParsingStageExtractor.has_parsing_functions():
            corrections.append(('H', 'random', (last_index,), sys.maxsize, 0, True))
            corrections.append(('5', 'random', (last_index,), sys.maxsize, 0, True))
        else:
            # if there is no tokencomp in the set emulate some random tokencomps, likely the token value of the last char
            # was ignored
            corrections.append(('H', 'tokencomp', (last_index,), sys.maxsize, 0, True))  # use artificial stacksize that is larger than any real staacksize
            corrections.append(('5', 'tokencomp', (last_index,), sys.maxsize, 0, True))
        return [InputValue(cor[2], Utils.min_index, cor[0], cor[1], inpt, cor[3], cor[4], cor[5]) for cor in corrections]


def _get_comparisons_on_idx(objs: List[Dict[str, Any]]):
    """
    Returns the comparisons made on the character with the given index.
    :param objs: The list of comparisons made during the execution.
    :param char_idx: The character index for which the comparisons should be extracted.
    :return:
    """
    Utils.min_index = min([idx["index"][0] for idx in objs])
    Utils.max_index_comparison = max([idx["index"][-1] for idx in objs if Utils.is_real_input_comparison(idx, idx["index"][-1])])
    result = []
    found_max = False # indicates if we still collect lookbacks, i.e. if we have comparisons on characters with index lower than maxindex that appear after the last comparison against a character with index equals maxindex
    for c in reversed(objs):
            # strlen and strcmp may have a lower index as the first index of the comparison is the one of the first compared character
            # tokencomp may have a lookahead, so we just use the compares of the next chars as well
        if (not found_max) or \
            (Utils.max_index_comparison in c['index']) or \
            (c['operator'] == "strlen" and c['index'] and c['index'][0] + int(c['operand'][0]) >= Utils.max_index_comparison) or \
            (c['operator'] == "tokencomp" and (c['index'][0] >= Utils.max_index_comparison or Utils.max_index_comparison in c["index"])):
                result.append(c)
        if c['index'][-1] >= Utils.max_index_comparison and Utils.is_real_input_comparison(c, Utils.max_index_comparison):
            found_max = True

    return result


def _construct_continuation_set(corrections: Iterable[str], val: Dict[Any, Any], do_append_random: bool = True) -> Set[Tuple[str, str, Tuple[int], int, int, bool]]:
    """
    Constructs from the given list of values a set of corrections.
    :param corrections: List of possible substitutions. Must be iterable.
    :param do_append_random: defines if a random append is done when trying out this input
    :return: The set of correction tuples.
    """
    #TODO improve to also handle lookbacks correctly
    return set((el, val["operator"], tuple(val["index"]), len(val["stack"]), val["id"], do_append_random) for el in corrections)


def _get_corrections(cmp_stack: List[Any]):
    """
    Returns the possible substitutions for the character at index at_idx
    :param cmp_stack: The comparisons made on the last character.
    :param local_continuations: The possible characters to insert if there is no useful continuation
    :return:
    """
    chars = set()
    tok_comp_values = set()
    # the index at which the same token occurred
    # in general the value to substitute should not be correct because we might have missed some comparisons
    # TODO maybe we should remember the last set of found tokcomp values, if the last set was the same, we ignore the flag
    found_token_same_index = None
    for char in cmp_stack:
        if char["operator"] == "switch":
            chars |= _construct_continuation_set(char["operand"], char)
            TokenLearningHandler.add_rhs(char["operand"])

        elif char["operator"] == "strlen":
            length = int(char["operand"][0])
            TokenLearningHandler.add_rhs(["".join(["a" for _ in range(0, length)])])
            chars |= _construct_continuation_set(["".join(["a" for _ in range(0, length)])], char)

        elif char["operator"] == "conversion":
            pos_subst = ConversionHandler.get_possible_substitutions(char["operand"][0])
            TokenLearningHandler.add_rhs(pos_subst)
            chars |= _construct_continuation_set(pos_subst, char)

        elif char["operator"] == "tokencomp":
            # check if really the largest tokencomparison is used for calculating a substitution
            # if TokenHandler.is_largest_token(char["index"][0]):
            tok_comp_values.add(int(char["operand"][0]))
            pos_subst = set()
            if TokenHandler.get_majority_token(char["index"][0]) == int(char["operand"][0]):
                found_token_same_index = char
            # only use tokencomps for which the majority vote and the lhs value are the same (so those which are likely the actual token comparisons)
            if TokenHandler.get_majority_token(char["index"][0]) == int(char["value"]):
                pos_subst = TokenHandler.get_possible_substitutions(char["operand"][0], char["stack"])
            # for tokencomp we might need to correct lookaheads, thus the index of char is corrected to Utils.max_index
            if char["index"][0] > Utils.last_comparison_index:
                char["index"][0] = Utils.last_comparison_index
            if pos_subst:
                chars |= _construct_continuation_set(pos_subst, char)

        elif char["operator"] == "tokenstore" or char["operator"] == "assert":
            pass

        elif char["operator"] == "strsearch":
            # check if the string is found in the searched string, if not append it to what was searched
            if char["value"] not in char["operand"][0]:
                chars.add((char["operand"][0], char["operator"], (char["index"][-1] + 1,), len(char["stack"]), char["id"], True))
        elif char["operator"] == "scanf":
            chars |= _construct_continuation_set([ScanfHandler.calc_scanf_value(char["value"], char["operand"], char["id"], char["index"])], char)
        else:
            # for smaller and greater the exact range is not defined, so we better learn only the first value in the range
            if ">" in char["operator"]:
                TokenLearningHandler.add_rhs(char["operand"][0])
            elif "<" in char["operator"]:
                TokenLearningHandler.add_rhs(char["operand"][-1])
            else:
                TokenLearningHandler.add_rhs(char["operand"])

            chars |= _construct_continuation_set([random.choice(char["operand"])], char)
    if not chars:
        # for cont in local_continuations:
        #     chars.add(("random"))
        return list()
    if found_token_same_index is not None:
        diff_token = TokenHandler.get_different_correct_token(tok_comp_values)
        if diff_token:
            found_token_same_index["stack"] = ["re-eval"]  # reduce stack size to rank re-calculation higher
            return list(_construct_continuation_set(diff_token, found_token_same_index, False))
        else:
            return list(chars)
    return list(chars)


def _get_last_comparison(objs):
    """
    Get the last comparison from the object list.
    :param objs:
    :return:
    """
    for val in reversed(objs):
        if val["type"] == "INPUT_COMPARISON" and val["operator"] not in ["eof", "strlen", "strconstcmp", "tokenstore", "tokencomp", "assert"]:
            return val


def _process(objs: List[Dict[str, Any]], inpt: str, was_valid:bool, dfs: bool = False) -> Tuple[List[InputValue], bool, bool]:
    """
    Returns the next position to substitute and the possible substitutions based on a list of comparisons
    :param dfs:
    :param objs: The list of comparisons made during the execution.
    :param inpt: The input used for the execution.
    :return: the list of possible replacements and a flag if the last comparison was an assert
    """
    # the sole input comparisons for those functions that need it
    input_comparisons = [obj for obj in objs if obj["type"] == "INPUT_COMPARISON"]

    if not objs:
        # FIXME return proper list of corrections
        return [], False, False  # [InputValue(0, 0, random.choice(string.printable), "undef", inpt)]

    # get the last comparison made, then extract the character index.
    last_comparison = _get_last_comparison(objs)
    if not last_comparison:
        # raise ValueError("The extraction of the last made comparison returned incorrectly.")
        return [], False, False
        # return _construct_correction_list([random.choice(Utils.continuations)], dfs, inpt, Utils.min_index + len(inpt) - 1)
    # input_len = last_comparison["length"]
    Utils.last_comparison_index = last_comparison['index'][-1]
    # if we can prune this branch of the search space, we do so
    # if Pruning.is_pruned(objs, input_comparisons, Utils.max_index):
    #    return []
    # if input_len <= Utils.max_index:  # EOF -- generate more data
    #     # FIXME return proper list of corrections
    #     return [InputValue(Utils.max_index, Utils.min_index, random.choice(string.printable), "undef", inpt)]

    # First, get all token links, then get all the comparisons on the index of last character comparison
    for cmp in input_comparisons:
        CmpMapping.add_comparison(cmp)
    cmps = _get_comparisons_on_idx(input_comparisons)
    ParsingStageExtractor.extract_stages(objs)
    TokenLearningHandler.find_learning_patterns(objs)
    TokenHandler.iterate_objs(input_comparisons, inpt)

    CmpCoverer.collect_comparison_coverage_information(inpt, input_comparisons, was_valid)
    corrections = _get_corrections(cmps)


    last_obj_entry = objs[-1]

    stop_function_found = False
    if Utils.stop_function:
        for obj in objs:
            if obj["type"] == "STACK_EVENT" and Utils.stop_function in obj["stack"]:
                stop_function_found = True
                break


    return _construct_correction_list(corrections, dfs, inpt, Utils.last_comparison_index), last_obj_entry["type"] == "INPUT_COMPARISON" and last_obj_entry["operator"] == "assert", stop_function_found
