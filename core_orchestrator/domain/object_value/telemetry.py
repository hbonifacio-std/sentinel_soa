
from enum import Enum

from dataclasses import dataclass

class ThreatLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"

    @classmethod
    def from_score(cls, value: object):
        """
        Creates an instance of the class based on the given score value.

        This method evaluates the provided value to determine the corresponding instance
        of the class. The score thresholds are defined as follows:
        - 90 or above: CRITICAL
        - 70 to 89: HIGH
        - 40 to 69: MEDIUM
        - 20 to 39: LOW
        - Below 20: NONE

        If the provided value is not an integer or a float, the method will return None.

        Args:
            value: An object to be evaluated as a score. Must be of type int or float
                to be processed.

        Returns:
            An instance of the class corresponding to the range of the input score or
            None if the input is not a valid numeric value.
        """
        if isinstance(value, (int, float)):
            if value >= 90: return cls.CRITICAL
            if value >= 70: return cls.HIGH
            if value >= 40: return cls.MEDIUM
            if value >= 20: return cls.LOW
            return cls.NONE
        return None

@dataclass
class MitreAttackInfo:
    tactic: str = "Reconnaissance"
    tactic_id: str = "TA0043"
    technique: str = "Active Scanning"
    technique_id: str = "T1595"
    sub_technique: str = "Vulnerability Scanning"
    sub_technique_id: str = "T1595.002"