"""Constants for gree climate."""

from typing import Final


def generate_temperature_record(temp_f):
    """Helper function for Fahrenheit temperature."""
    temSet = round((temp_f - 32.0) * 5.0 / 9.0)
    temRec = (int)((((temp_f - 32.0) * 5.0 / 9.0) - temSet) > 0)
    return {"f": temp_f, "temSet": temSet, "temRec": temRec}


TEMP_MIN: Final = 8
TEMP_MAX: Final = 30
TEMP_OFFSET: Final = 40
TEMP_MIN_F: Final = 46
TEMP_MAX_F: Final = 86
TEMP_MIN_TABLE: Final = -60
TEMP_MAX_TABLE: Final = 60
TEMP_MIN_TABLE_F: Final = -76
TEMP_MAX_TABLE_F: Final = 140
TEMP_TABLE = [
    generate_temperature_record(x)
    for x in range(TEMP_MIN_TABLE_F, TEMP_MAX_TABLE_F + 1)
]
HUMIDITY_MIN: Final = 30
HUMIDITY_MAX: Final = 80

# Keys
# GENERIC_KEY = "{yxAHAY_Lm6pbC/<"
GENERIC_KEY: Final = "a3K8Bx%2r8Y7#xDh"


DISCOVERY_REQUEST = {"t": "scan"}
DEFAULT_PORT: Final = 7000
