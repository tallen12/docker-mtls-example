import re
from datetime import timedelta
from typing import Annotated, Any, Sequence

from cyclopts import Parameter, Token

time_units: dict[str, str] = {"d": "days", "h": "hours", "m": "minutes", "s": "seconds"}

regex_pattern = re.compile(rf"(\d+)({'|'.join(time_units)})")


def preprocess_time_delta(type_: Any, tokens: Sequence[Token]) -> timedelta:
    """
    Convert the cyclopts parameter value to timedelta since it is not inferred by cyclopts.

    Args:
        type_ (Any): The type of the parameter being processed.
        tokens (Sequence[Token]): A sequence of tokens representing time deltas.

    Returns:
        timedelta: A timedelta object representing the sum of all time deltas in the input sequence.
    """
    value = tokens[0].value
    regex_match = regex_pattern.match(value)
    if not regex_match:
        raise ValueError(f"Invalid time format: {value}")
    time_unit: str = regex_match.group(2)
    time: float = float(regex_match.group(1))
    return timedelta(**{time_units[time_unit]: time})


TimePeriod = Annotated[timedelta, Parameter(converter=preprocess_time_delta)]
