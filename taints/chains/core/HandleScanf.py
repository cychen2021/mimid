"""
Handling a scanf format string by generating a random string that can be parsed by the given format string.
"""

import random
from typing import Tuple, List, Union, Dict
import string
import core.IndexComparisonMapping as IdxMapping

string_char_set: List[str] = list(string.ascii_letters + string.digits)

scanf_memory: Dict[Tuple[str, int], str] = dict()


def calc_scanf_value(scanf_string: str, orig_string_list: List[str], id: int, taints: List[int]) -> str:
    """
    Creates for the given format string a random string that can be parsed by it.
    :param scanf_string: the format string which was used for parsing
    :return: a string that matches the specified format
    """
    final_result = []
    tmp_result = ""
    i = 0
    taint_position = 0
    memory_position = -1
    orig_string_list.pop(0)
    while i < len(scanf_string):
        c = scanf_string[i]
        if c == "%":
            # memposition + 2 because there is a constant string between two format specifiers (could be a zero length string, but this would be saved as well)
            memory_position += 2
            extracted_string = ""
            if len(orig_string_list) > 0:
                extracted_string = orig_string_list.pop(0)
            final_result.append([tmp_result])
            tmp_result = ""
            actual_width, tp, i = _get_width_and_type(i + 1, scanf_string)
            width = actual_width
            if actual_width == -1:
                width = random.randint(1,9)
            print(actual_width, width, repr(tp), i)

            # check if we have actual values with which we can substitute, if so we use those
            if extracted_string:
                possible_subst = get_cmp(taints[taint_position: taint_position + len(extracted_string)], extracted_string)
                if possible_subst:
                    final_result.append(possible_subst)
                    i += 1
                    taint_position += len(extracted_string)
                    continue
                else:
                    # if possible, use a memorized string to avoid too many different generations for the same comparisons
                    # which might result in generating many different inputs that all cover the same code and lead to a generation loop
                    memorized = scanf_memory.get((scanf_string, id))
                    if memorized:
                        final_result.append(memorized[memory_position])
                        i += 1
                        taint_position += len(extracted_string)
                        continue
            if tp == "d":
                tmp_result += random.choice(["", "-", "+"]) + _rand_uint(width - 1) if width > 1 else _rand_uint(width)
            elif tp == "u":
                tmp_result += _rand_uint(width)
            elif tp in "eEfgG":
                tmp_result += _rand_float(width)
            elif tp == "o":
                tmp_result += _rand_octal(width)
            elif tp in "xX":
                tmp_result += _rand_hexa(width)
            elif tp.startswith("["):
                pos_chars = string_char_set
                if tp[1] == "^":
                    for not_allowed in tp[2:-1]:
                        try:
                            pos_chars.remove(not_allowed)
                        except ValueError:
                            pass
                else:
                    pos_chars = tp[1:-1]
                tmp_result += _rand_string(pos_chars, width)
            elif tp == "c":
                tmp_result += _rand_string(string_char_set, 1 if actual_width == -1 else width)
            elif tp == "s":
                tmp_result += _rand_string(string_char_set, width)
            final_result.append([tmp_result])
            tmp_result = ""

            taint_position += len(extracted_string)
        else:
            # in this case no format specifier comes up, i.e. we just append the char we read
            tmp_result += c
        i += 1
        taint_position += 1
    scanf_memory[(scanf_string, id)] = final_result
    return "".join([random.choice(el) for el in final_result])

def get_cmp(taints: List[int], extracted_string: str):
    comparisons = []
    for comparison in IdxMapping.mapping.get(taints[0]):
        # if taints and value match, we can safely define the operand as a valid replacement for the scanf function
        if extracted_string == comparison["value"] and taints == comparison["index"]:
            comparisons += comparison["operand"]

    return comparisons

def _get_width_and_type(current_string_position: int, scanf_string: str) -> Tuple[int, str, int]:
    """
    Parses width and type out of the scanf_string.
    :param current_string_position: the current position in the scanf_string (i.e. the first character after the "%"
    :param scanf_string: the full scanf string
    :return: Tuple with: (width, type, pos), where width is the parsed width (-1 if no width defined), type is the type that will be parsed and pos is the position after the format specifier in the scanf string
    """
    c = scanf_string[current_string_position]
    if c == "*":
        # star means the string is parsed but not stored, we still need to generate a value for the format specifier
        current_string_position += 1
        c = scanf_string[current_string_position]
    width = -1
    if c.isdigit():
        width_string = ""
        while c.isdigit():
            width_string += c
            current_string_position += 1
            c = scanf_string[current_string_position]
        width = int(width_string)

    if c in "hlL":
        # the modifier defines the size of the memory the read value will be written to, this is not relevant for us when generating a value
        current_string_position += 1
        c = scanf_string[current_string_position]

    tp = ""
    if c == "[":
        # in this special case we have a set of chars that are parsed, not a specific modifier
        escaped = False
        tp += c
        current_string_position += 1
        c = scanf_string[current_string_position]
        while c != "]" or escaped:
            tp += c
            if c == "\\" and not escaped:
                escaped = True
            elif escaped:
                escaped = False
            current_string_position += 1
            c = scanf_string[current_string_position]
        tp += c
    else:
        tp = c

    return width, tp, current_string_position


def _rand_string(pos_chars: Union[str, List[str]], width: int):
    return "".join([random.choice(pos_chars) for _ in range(width)])


def _rand_float(width: int):
    if width < 4:
        return str(_rand_uint(1)) + "." + str(_rand_uint(1))

    result = ""
    # can optionally preceded
    result += random.choice(["", "-", "+"])
    result += str(_rand_uint(width // 2 - len(result) - 2)) + "." # width -2 as at least one decimal must be behind the decimal point and the decimal point must be accounted as well
    result += str(_rand_uint(width // 2 - len(result)))

    if width - len(result) >= 2:
        result += random.choice(["", "e", "E"])
        result += str(_rand_uint(width - len(result)))
    return result


def _rand_uint(width: int):
    return str(random.randint(0, pow(10, width)-1))



def _rand_octal(width: int):
    return str(random.randint(1, 7)) + "".join([str(random.randint(0,7)) for _ in range(0,random.randint(0, width - 1))])


def _rand_hexa(width: int):
    return ("%x" % (random.randint(0,16**30)))[0:random.randint(1, width)]
