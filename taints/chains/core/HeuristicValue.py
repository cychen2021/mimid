# coding=utf-8
"""
Contains the heuristic value code.
"""
from typing import Set, Tuple, Any, List

import core.Utils as Utils
from core.KnowledgeHandling import KnowledgeHandling
import sys
from core.ParsingStageExtractor import ParsingStageExtractor, Stage


class HeuristicValue:
    """
    Wraps the heuristic value of an input which consists of several sub-values.
    """

    # general heuristic value to start with
    value: int = 0

    # counter of how many new branches were covered
    cover_counter: Tuple[int, int] = (0, 0)

    # stack of this input
    stack: List[str] = []

    # stack of parent input
    parent_stack: List[str] = []

    # size of the diff stack calculated by _calc_diff_to_parent_stack
    diff_stack_size: int

    # input used in the execution which produced this h-value
    inp: str

    # counter of how often a path with this input was taken
    same_path_taken: float = 0

    # the stackchanges over the execution
    knowledge: KnowledgeHandling

    # the number of inputs generated before on this search branch
    input_counter: int

    # an individual heuristic correction that can be set before adding the value to the prio queue
    # this value is used as first instance for deciding where the value is placed in the Queue
    individual_correction: Tuple[Tuple[int]]

    def __init__(self, cover_counter, stack, parent_stack, inp, same_path_taken, knowledge: KnowledgeHandling):
        self.cover_counter = cover_counter
        self.stack = stack
        self.parent_stack = parent_stack
        self.diff_stack_size = self._calc_diff_to_parent_stack()
        if cover_counter[0] > 0:
            self.value = len(inp) - cover_counter[0]  # + knowledge.last_tokencomp_stack * 100
        else:
            self.value = 100.0

        # self.value = int(-1000 * cover_counter) + ((inp_len + self.diff_stack_size) ** 2)
        self.inp = inp
        # TODO the path taken value has a strong impact and needs to be treated carefully, sometimes a path needs to be taken several times before the algorithm can proceed
        self.same_path_taken = same_path_taken if len(inp) > 2 and (same_path_taken > 5 or same_path_taken <= 0) else 0 # leave some room for small lookaheads, only if a path was taken several times it is not interesting anymore
        self.knowledge = knowledge
        self.input_counter = 0
        self.individual_correction = ((sys.maxsize,),)

    def _calc_diff_to_parent_stack(self) -> int:
        for i in range(len(self.stack)):
            if i > len(self.parent_stack) - 1:
                return len(self.stack)
            elif self.stack[i] != self.parent_stack[i]:
                return i
        return len(self.parent_stack) - len(self.stack)

    def adjust_value(self, to_subst):
        """
        Set the intern value by substituting "to_subst". Can be used to fine adjust the position in the prio queue.
        :param to_subst: The value which is used for substitution.
        """
        self.value -= to_subst

    def set_individual_correction(self, correction: Tuple[Tuple[int]]):
        self.individual_correction = correction

    def __lt__(self, other):
        return (self.individual_correction, self.same_path_taken, self.value, len(self.inp)) < (other.individual_correction, other.same_path_taken, other.value, len(other.inp))

    def __str__(self):
        return "value: %f\n\tinp_len: %d\n\tsame_path_taken: %f\n\tcover_counter: %s\n\tdiff_stack_size: %s\n\tKnowledge: %s\n\tInput Counter: %s\n\tIndividual Correction: %s" % \
               (self.value, len(self.inp), self.same_path_taken, str(self.cover_counter), str(self.diff_stack_size), repr(self.knowledge), str(self.input_counter), str(self.individual_correction))

    def __repr__(self):
        return str(self)

    @staticmethod
    def calc_cov_heuristic(objs, parent_stack: List[str], inpt: str, knowledge: KnowledgeHandling) -> Tuple["HeuristicValue", Set[Tuple[Any, Any]], Set[Tuple[Any, Any]]]:
        """
        Calculates based on the covered lines and the heuristic value of the parent the heurisitic value for the children.
        New heuristic value is: #newly covered lines + 1 - heuristic value of parent. -1 as if no new line is covered the
        heuristic value decreases over time
        :param inpt: The string used in the execution
        :param objs: the covered lines and comparisons
        :param parent_stack: the smallest stack occurred for the parent input
        """
        # Todo also take stackdepth into account (maybe in combination with input length s.t. for longer inputs a small stack is preferred
        # Todo this obviously only works for recursive parsers, but for all others this is more or less a nop
        tmp_events = []
        coverage_events = []
        stack = HeuristicValue.calc_stack(objs)
        all_covered = set()
        # we need to consider the taken branches between the last comparison and the eof comparison
        last_was_real = False
        # cur_idx = -1
        curr_fun = ""
        for obj in objs:
            # consider only basic block jumps up until the last "real" comparison
            if Utils.is_real_input_comparison(obj, Utils.last_comparison_index - 1):  # and cur_idx != int(obj["index"][0]):
                # last_was_eof = False
                coverage_events += tmp_events
                tmp_events = []
                last_was_real = True
                # cur_idx = int(obj["index"][0])
            elif Utils.is_real_input_comparison(obj, Utils.last_comparison_index) and last_was_real:
                last_was_real = False
                coverage_events += tmp_events
                tmp_events = []
            # elif obj["type"] == "INPUT_COMPARISON" and obj["operator"] == "eof" and not last_was_eof:
            #     last_was_eof = True
            #     coverage_events += tmp_events
            #     tmp_events = []

            # only consider Parsing stage function
            #TODO if there are no parsing function, fallback to all functions
            elif obj["type"] == "COVERAGE_EVENT" and (ParsingStageExtractor.stages.get(curr_fun) == Stage.PARSING or not ParsingStageExtractor.has_parsing_functions()):
                tmp_events.append(obj)
                all_covered.add((obj["old"], obj["new"]))
            elif obj["type"] == "STACK_EVENT":
                if obj["stack"]:
                    curr_fun = obj["stack"][-1]

        cover_counter = 0
        new_covered = 0
        covered = set()
        for event in coverage_events:
            value = (event["old"], event["new"])
            if value not in Utils.valid_covered:
                cover_counter += 2
                new_covered += 1
            else:
                cover_counter += 1 / Utils.valid_covered[value]
            covered.add(value)
        same_path_taken = HeuristicValue.check_same_path_taken(coverage_events)
        return HeuristicValue((new_covered, cover_counter), stack, parent_stack, inpt, same_path_taken, knowledge), covered, all_covered

    def set_input_counter_adapt_value(self, input_counter):
        """
        Set the number of inputs generated before on this search branch. The heuristic value will get worse for inputs that are later generated.
        :param inpt_counter:
        """
        self.input_counter = input_counter
        self.value += input_counter // 5

    @staticmethod
    def check_same_path_taken(cov_events):
        """
        Check if the path was already covered by any input beforehand, if so report how often
        :param cov_events:
        :return:
        """
        covered_bb = tuple([el["old"] for el in cov_events])
        if covered_bb in Utils.covered_paths:
            Utils.covered_paths[covered_bb] = Utils.covered_paths.get(covered_bb) + 1
            return Utils.covered_paths.get(covered_bb)
        else:
            Utils.covered_paths[covered_bb] = 1
            return 1

    @staticmethod
    def calc_stack(objs) -> List[str]:
        """
        Returns the smallest stack in which a comparison with the last character was done
        :param objs:
        :return:
        """
        robjs = reversed(objs)
        stack = []
        ident = -1
        for obj in robjs:
            real_input_comparison = Utils.is_real_input_comparison(obj, Utils.max_index_comparison)
            if ident == -1 and real_input_comparison:
                ident = int(obj["index"][0])
            if ident != -1 and real_input_comparison:
                if ident in obj["index"]:
                    stack = stack if stack and len(stack) < len(obj["stack"]) else obj["stack"]
                else:
                    return stack
        return stack

    def clone(self):
        """
        Creates a copy of self.
        :return: The copy of self.
        """
        new_value = HeuristicValue((0, 0), [], [], "", 1, self.knowledge)
        new_value.value = self.value
        new_value.cover_counter = self.cover_counter
        new_value.stack = self.stack
        new_value.same_path_taken = self.same_path_taken
        new_value.inp = self.inp
        new_value.parent_stack = self.parent_stack
        new_value.diff_stack_size = self.diff_stack_size
        new_value.diff_stack_size = self.diff_stack_size
        new_value.knowledge = self.knowledge
        new_value.input_counter = self.input_counter
        new_value.individual_correction = self.individual_correction
        return new_value
