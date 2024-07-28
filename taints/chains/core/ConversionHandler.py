# coding=utf-8

from typing import List


randomDict = {
    "tracerllvm_wrap_strtod": ["1.0", "3.0E2", "4.5e2", "-1.0", "-3.0E2", "-4.5e2"],
    "tracerllvm_wrap_strtoul": ["-1", "1", "0x1F", "0XAB", "-0x1F", "-0XAB"]
}


# TODO could also return just one alternative, will be seen empirically which is better
def get_possible_substitutions(function: str) -> List[str]:
    """
    Returns for a conversion function the possible values it can convert.
    :param function: The name of the function used for conversion.
    :return:
    """
    fun = ""
    for c in iter(function):  # some function have some platform specific names with special chars, those are deleted here
        if c.isalnum():
            fun += c
    if fun in randomDict:
        return randomDict.get(fun)
    else:
        return []

def val_in_conversions(operator: str) -> List[str]:
    # replace internal function definition with real name
    op = operator.replace("\x01_", "")
    conversions = randomDict.get(op)
    return conversions if conversions else []