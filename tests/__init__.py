import logging

from greeclimate import DeviceInfo
from greeclimate.device import Device

_LOGGER = logging.getLogger(__name__)
_LOGGER.setLevel(logging.DEBUG)

MOCK_DEVICE_INFO = DeviceInfo(
    "1.1.1.0",
    7000,
    "aabbcc001122",
    "MockDevice1",
    "MockBrand",
    "MockModel",
    "0.0.1-fake",
)

MOCK_DEVICE = Device(MOCK_DEVICE_INFO)

MOCK_STATE = {
    "Pow": 1,
    "Mod": 3,
    "SetTem": 25,
    "TemSen": 29,
    "TemUn": 0,
    "WdSpd": 0,
    "Air": 0,
    "Blo": 0,
    "Health": 0,
    "SwhSlp": 0,
    "SlpMod": 0,
    "Lig": 1,
    "SwingLfRig": 1,
    "SwUpDn": 1,
    "Quiet": 0,
    "Tur": 0,
    "StHt": 0,
    "SvSt": 0,
    "TemRec": 0,
    "HeatCoolType": 0,
    "hid": "362001000762+U-CS532AE(LT)V3.31.bin",
    "Dmod": 0,
    "Dwet": 5,
    "DwatSen": 58,
    "Dfltr": 0,
    "DwatFul": 0,
}

MOCK_STATE_OFF = {
    "Pow": 0,
    "Mod": 0,
    "SetTem": 0,
    "TemSen": 0,
    "TemUn": 0,
    "WdSpd": 0,
    "Air": 0,
    "Blo": 0,
    "Health": 0,
    "SwhSlp": 0,
    "SlpMod": 0,
    "Lig": 0,
    "SwingLfRig": 0,
    "SwUpDn": 0,
    "Quiet": 0,
    "Tur": 0,
    "StHt": 0,
    "SvSt": 0,
    "TemRec": 0,
    "HeatCoolType": 0,
    "Dmod": 0,
    "Dwet": 0,
    "DwatSen": 0,
    "Dfltr": 0,
    "DwatFul": 0,
}

MOCK_STATE_ON = {
    "Pow": 1,
    "Mod": 1,
    "SetTem": 1,
    "TemSen": 1,
    "TemUn": 1,
    "WdSpd": 1,
    "Air": 1,
    "Blo": 1,
    "Health": 1,
    "SwhSlp": 1,
    "SlpMod": 1,
    "Lig": 1,
    "SwingLfRig": 1,
    "SwUpDn": 1,
    "Quiet": 2,
    "Tur": 1,
    "StHt": 1,
    "SvSt": 1,
    "TemRec": 0,
    "HeatCoolType": 0,
    "Dmod": 0,
    "Dwet": 3,
    "DwatSen": 1,
    "Dfltr": 0,
    "DwatFul": 0,
}

MOCK_STATE_NO_TEMPERATURE = {
    "Pow": 1,
    "Mod": 3,
    "SetTem": 25,
    "TemUn": 0,
    "WdSpd": 0,
    "Air": 0,
    "Blo": 0,
    "Health": 0,
    "SwhSlp": 0,
    "SlpMod": 0,
    "Lig": 1,
    "SwingLfRig": 1,
    "SwUpDn": 1,
    "Quiet": 0,
    "Tur": 0,
    "StHt": 0,
    "SvSt": 0,
    "TemRec": 0,
    "HeatCoolType": 0,
    "Dmod": 0,
    "Dwet": 1,
    "DwatSen": 1,
    "Dfltr": 0,
    "DwatFul": 0,
}

MOCK_STATE_BAD_TEMP = {"TemSen": 69, "hid": "362001060297+U-CS532AF(MTK).bin"}
MOCK_STATE_0C_V4_TEMP = {"TemSen": 0, "hid": "362001000762+U-CS532AE(LT)V4.bin"}

MOCK_STATE_0C_V3_TEMP = {"TemSen": 0, "hid": "362001000762+U-CS532AE(LT)V3.31.bin"}
