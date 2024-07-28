"""
Maps each index to all the comparisons made on it.
"""

from typing import Dict, List, Any

import core.Utils as Utils
import sys

mapping: Dict[int, List[Any]] = dict()

def get_comparisons(index: int) -> List[Any]:
    return mapping.get(index)

def add_comparison(comparison: Any):
    if Utils.is_real_input_comparison(comparison, sys.maxsize):
        for idx in comparison["index"]:
            list = mapping.setdefault(idx, [])
            list.append(comparison)