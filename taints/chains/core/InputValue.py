# coding=utf-8
"""
Contains the code that generates from an input and a given correction a new input.
"""
import random
import core.Utils as Utils
from core.TokenHandler import TokenHandler
from typing import List


class InputValue:
    """
    Generates from a given input based on operator, correcting string and the parent input a new input.
    """
    # the position at which the char subst starts
    at: List[int] = [0]
    # the start of the subst
    min: int = 0
    # the string to subst the char with
    correction: str = ""
    # the operator that caused the subst. strategy
    operator: str = ""
    # the input that was used in the execution
    inp: str = ""
    # the size of the stack at the comparison
    stack_size: int = 0
    # the id of the comparison which resulted in this input value
    id: int
    # defines if a random appending is done when the corrections are requested
    do_append: bool
    # defines if the comparison was a lookback or a real comparison
    lookback: bool
    # stores the maximal compared index for the given input
    max_index_comparison: int

    def __init__(self, at: List[int], min_pos: int, correction: str, operator: str, inp: str, stack_size: int, id: int, do_append: bool):
        self.at = at
        self.min = min_pos
        self.correction = correction
        self.operator = operator
        self.inp = inp
        self.stack_size = stack_size
        self.id = id
        self.do_append = do_append
        self.lookback = at[-1] < Utils.max_index_comparison
        self.max_index_comparison = Utils.max_index_comparison

    def __str__(self):
        return "inp: %s, at: %s, min: %d, correction: %s, operator: %s, stacksize: %d, id: %d" % (repr(self.inp), str(self.at), self.min, repr(self.correction), self.operator, self.stack_size, self.id)

    def __repr__(self):
        return self.__str__()

    def get_corrections(self):
        """
        Returns the new input string based on parent and other encapsulated parameters.
        :return:
        """
        new_char = self.correction
        subst_index_min = self.at[0] - self.min # the first char to substitute
        subst_index_max = self.at[-1] - self.min # the last char to substitute
        subst_str_end = self.max_index_comparison - self.min # the last char that was compared in the string
        inp = self.inp
        # replace char of last comparison with new continuation
        if self.lookback:
            # for lookbacks replace the characters that were compared in the lookback and keep also the remainder of the
            # string but leave out all remaining charactes that were not compared
            inp = inp[:subst_index_min] + new_char + inp[subst_index_max + 1: subst_str_end + 1]
        else:
            inp = inp[:subst_index_min] + new_char
        # append a new char, it might be that the program expects additional input
        # also if the newchar is not a char but a string it is likely a keyword, so we better add a whitespace
        if self.operator == "strcmp":
            inp_rand_new = inp + " " + random.choice(Utils.continuations)
        # for token compares the "random" next char has to be a token itself, otw. a lexing error might occur
        # and we will not see a token comparison. Also between two tokens a whitespace should be allowed.
        elif self.operator == "tokencomp":
            # for token substitutions add a whitespace as this is in general used to separate tokens
            inp = self.inp[:subst_index_min] + " " + new_char if not self.inp[:subst_index_min].endswith(" ") else self.inp[:subst_index_min] + new_char
            inp_rand_new = inp + " " + TokenHandler.random_token() if not inp.endswith(" ") else inp + new_char
        elif self.operator == "strlen":
            inp_rand_new = inp
        else:
            inp_rand_new = inp + random.choice(Utils.continuations)
        if self.do_append and not self.lookback:
            return inp, inp_rand_new
        else:
            return inp, inp
