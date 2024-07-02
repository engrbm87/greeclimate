"""Represent a gree AV device."""

import asyncio
import enum
import logging
import re
from enum import IntEnum, unique
from typing import Any, Dict, List, Optional

from greeclimate import network

from .const import (
    HUMIDITY_MAX,
    HUMIDITY_MIN,
    TEMP_MAX,
    TEMP_MAX_TABLE,
    TEMP_MIN,
    TEMP_MIN_TABLE,
    TEMP_OFFSET,
    TEMP_TABLE,
    generate_temperature_record,
)
from .exceptions import (
    DeviceNotBoundError,
    DeviceTimeoutError,
    KeyNotRetrievedError,
    NoDataReceivedError,
)

_LOGGER = logging.getLogger(__name__)


class Props(enum.Enum):
    """Gree AC device props."""

    POWER = "Pow"
    MODE = "Mod"

    # Dehumidifier fields
    HUM_SET = "Dwet"
    HUM_SENSOR = "DwatSen"
    CLEAN_FILTER = "Dfltr"
    WATER_FULL = "DwatFul"
    DEHUMIDIFIER_MODE = "Dmod"

    TEMP_SET = "SetTem"
    TEMP_SENSOR = "TemSen"
    TEMP_UNIT = "TemUn"
    TEMP_BIT = "TemRec"
    FAN_SPEED = "WdSpd"
    FRESH_AIR = "Air"
    XFAN = "Blo"
    ANION = "Health"
    SLEEP = "SwhSlp"
    SLEEP_MODE = "SlpMod"
    LIGHT = "Lig"
    SWING_HORIZ = "SwingLfRig"
    SWING_VERT = "SwUpDn"
    QUIET = "Quiet"
    TURBO = "Tur"
    STEADY_HEAT = "StHt"
    POWER_SAVE = "SvSt"
    UNKNOWN_HEATCOOLTYPE = "HeatCoolType"


@unique
class TemperatureUnits(IntEnum):
    """Temperature units."""

    C = 0
    F = 1


@unique
class Mode(IntEnum):
    """HVAC modes."""

    AUTO = 0
    COOL = 1
    DRY = 2
    FAN = 3
    HEAT = 4


@unique
class FanSpeed(IntEnum):
    """Fan speeds."""

    AUTO = 0
    LOW = 1
    MEDIUM_LOW = 2
    MEDIUM = 3
    MEDIUM_HIGH = 4
    HIGH = 5


@unique
class HorizontalSwing(IntEnum):
    """Horizontal swing."""

    DEFAULT = 0
    FULL_SWING = 1
    LEFT = 2
    LEFT_CENTER = 3
    CENTER = 4
    RIGHT_CENTER = 5
    RIGHT = 6


@unique
class VerticalSwing(IntEnum):
    """Vertical swing."""

    DEFAULT = 0
    FULL_SWING = 1
    FIXED_UPPER = 2
    FIXED_UPPER_MIDDLE = 3
    FIXED_MIDDLE = 4
    FIXED_LOWER_MIDDLE = 5
    FIXED_LOWER = 6
    SWING_UPPER = 7
    SWING_UPPER_MIDDLE = 8
    SWING_MIDDLE = 9
    SWING_LOWER_MIDDLE = 10
    SWING_LOWER = 11


class DehumidifierMode(IntEnum):
    """Dehumidifier mode."""

    DEFAULT = 0
    ANION_ONLY = 9


class DeviceInfo:
    """Device information class, used to identify and connect

    Attributes
        ip: IP address (ipv4 only) of the physical device
        port: Usually this will always be 7000
        mac: mac address, in the format 'aabbcc112233'
        name: Name of unit, if available
    """

    def __init__(
        self,
        ip: str,
        port: int,
        mac: str,
        name: Optional[str] = None,
        brand: Optional[str] = None,
        model: Optional[str] = None,
        version: Optional[str] = None,
    ) -> None:
        """
        Initialize DeviceInfo.

        Args:
            ip (str): IP address (ipv4 only) of the physical device.
            mac (str): mac address, in the format 'aabbcc112233'.
            port (int): Usually this will always be 7000.
            name (Optional[str]): Name of unit, if available.
            brand (Optional[str]): Brand of the device.
            model (Optional[str]): Model of the device.
            version (Optional[str]): Version of the device.
        """
        self.ip = ip
        self.port = port
        self.mac = mac
        self.name = name if name else mac.replace(":", "")
        self.brand = brand
        self.model = model
        self.version = version

    def __str__(self):
        """String representation of DeviceInfo"""
        return f"Device: {self.name} @ {self.ip}:{self.port} (mac: {self.mac})"

    def __eq__(self, other):
        """Check equality based on Device Info properties"""
        if isinstance(other, DeviceInfo):
            return (
                self.mac == other.mac
                and self.name == other.name
                and self.brand == other.brand
                and self.model == other.model
                and self.version == other.version
            )
        return False

    def __ne__(self, other):
        """Check inequality based on Device Info properties"""
        return not self.__eq__(other)


class Device:  # pylint: disable=too-many-public-methods
    """Class representing a physical device, it's state and properties.

    Devices must be bound, either by discovering their presence, or supplying a persistent
    device key which is then used for communication (and encryption) with the unit. See the
    `bind` function for more details on how to do this.

    Once a device is bound occasionally call `update_state` to request and update state from
    the HVAC, as it is possible that it changes state from other sources.

    Attributes:
        power: A boolean indicating if the unit is on or off
        mode: An int indicating operating mode, see `Mode` enum for possible values
        target_temperature: The target temperature, ignore if in Auto, Fan or Steady Heat mode
        temperature_units: An int indicating unit of measurement,
            see `TemperatureUnits` enum for possible values
        current_temperature: The current temperature
        fan_speed: An int indicating fan speed, see `FanSpeed` enum for possible values
        fresh_air: A boolean indicating if fresh air valve is open, if present
        xfan: A boolean to enable the fan to dry the coil, only used for cool and dry modes
        anion: A boolean to enable the ozone generator, if present
        sleep: A boolean to enable sleep mode, which adjusts temperature over time
        light: A boolean to enable the light on the unit, if present
        horizontal_swing: An int to control the horizontal blade position,
            see `HorizontalSwing` enum for possible values
        vertical_swing: An int to control the vertical blade position,
            see `VerticalSwing` enum for possible values
        quiet: A boolean to enable quiet operation
        turbo: A boolean to enable turbo operation (heat or cool faster initially)
        steady_heat: When enabled unit will maintain a target temperature of 8 degrees C
        power_save: A boolen to enable power save operation
        target_humidity: An int to set the target relative humidity
        current_humidity: The current relative humidity
        clean_filter: A bool to indicate the filter needs cleaning
        water_full: A bool to indicate the water tank is full
    """

    def __init__(self, device_info: DeviceInfo) -> None:
        """Initialize the device."""
        self.device_info = device_info
        self.device_key: Optional[str] = None
        self.version: Optional[str] = None
        self._properties: Dict[str, Any] = {}
        self._dirty: List[str] = []

    async def bind(self) -> None:
        """Run the binding procedure and return the device key."""

        _LOGGER.info("Starting device binding to %s", str(self.device_info))

        try:
            self.device_key = await network.bind_device(self.device_info)
        except (asyncio.TimeoutError, NoDataReceivedError) as err:
            # try new GCM encryption. Will be added in future PR
            raise DeviceTimeoutError from err
        except KeyNotRetrievedError:
            return None

    async def request_version(self) -> None:
        """Request the firmware version from the device."""
        if self.device_key is None:
            raise DeviceNotBoundError
        ret = await network.request_state(["hid"], self.device_info, self.device_key)
        hid: Optional[str] = ret.get("hid")

        # Ex: hid = 362001000762+U-CS532AE(LT)V3.31.bin
        if hid:
            match = re.search(r"(?<=V)([\d.]+)\.bin$", hid)
            if match and match.group(1) is not None:
                self.version = match.group(1)

            # Special case firmwares ...
            # if (
            #     self.hid.endswith("_JDV1.bin")
            #     or self.hid.endswith("362001000967V2.bin")
            #     or re.match("^.*\(MTK\)V[1-3]{1}\.bin", self.hid)  # (MTK)V[1-3].bin
            # ):
            #     self.version = "4.0"

    async def update_state(self) -> None:
        """Update the internal state of the device structure of the physical device"""
        if self.device_key is None:
            raise DeviceNotBoundError
        _LOGGER.debug("Updating device properties for (%s)", self.device_info)

        props = [x.value for x in Props]

        try:
            self._properties = await network.request_state(
                props, self.device_info, self.device_key
            )

            # This check should prevent need to do version & device overrides
            # to correctly compute the temperature. Though will need to confirm
            # that it resolves all possible cases.
            if not self.version:
                await self.request_version()

        except asyncio.TimeoutError as err:
            raise DeviceTimeoutError from err

        temp = self.get_property(Props.TEMP_SENSOR)
        if temp and temp < TEMP_OFFSET:
            self.version = "4.0"

    async def push_state_update(self) -> None:
        """Push any pending state updates to the unit"""
        if self.device_key is None:
            raise DeviceNotBoundError
        if not self._dirty:
            return

        _LOGGER.debug("Pushing state updates to (%s)", self.device_info)

        props = {}
        for name in self._dirty:
            value = self._properties.get(name)
            _LOGGER.debug("Sending remote state update %s -> %s", name, value)
            props[name] = value
            if name == Props.TEMP_SET.value:
                props[Props.TEMP_BIT.value] = self._properties.get(Props.TEMP_BIT.value)
                props[Props.TEMP_UNIT.value] = self._properties.get(
                    Props.TEMP_UNIT.value
                )

        self._dirty.clear()

        try:
            await network.send_state(props, self.device_info, key=self.device_key)
        except asyncio.TimeoutError as err:
            raise DeviceTimeoutError from err

    def get_property(self, name: Props) -> Any:
        """Generic lookup of properties tracked from the physical device"""
        return self._properties.get(name.value)

    def set_property(self, name: Props, value: Any) -> None:
        """Generic setting of properties for the physical device"""
        if self._properties.get(name.value) == value:
            return
        self._properties[name.value] = value
        if name.value not in self._dirty:
            self._dirty.append(name.value)

    @property
    def power(self) -> bool:
        """Power status of the device."""
        return bool(self.get_property(Props.POWER))

    @power.setter
    def power(self, value: int) -> None:
        self.set_property(Props.POWER, int(value))

    @property
    def mode(self) -> int:
        """Mode of the device."""
        return self.get_property(Props.MODE)

    @mode.setter
    def mode(self, value: int) -> None:
        self.set_property(Props.MODE, int(value))

    def _convert_to_units(self, value: int, bit: int) -> int:
        """Convert the value from the device to the requested unit"""
        if self.temperature_units != TemperatureUnits.F.value:
            return value

        if value < TEMP_MIN_TABLE or value > TEMP_MAX_TABLE:
            raise ValueError(f"Specified temperature {value} is out of range.")

        matching_temSet = [t for t in TEMP_TABLE if t["temSet"] == value]

        try:
            f = next(t for t in matching_temSet if t["temRec"] == bit)
        except StopIteration:
            f = matching_temSet[0]

        return f["f"]

    @property
    def target_temperature(self) -> int:
        """Target temperature of the device."""
        temSet = self.get_property(Props.TEMP_SET)
        temRec = self.get_property(Props.TEMP_BIT)
        return self._convert_to_units(temSet, temRec)

    @target_temperature.setter
    def target_temperature(self, value: int) -> None:
        def validate(val):
            if val > TEMP_MAX or val < TEMP_MIN:
                raise ValueError(f"Specified temperature {val} is out of range.")

        if self.temperature_units == 1:
            rec = generate_temperature_record(value)
            validate(rec["temSet"])
            self.set_property(Props.TEMP_SET, rec["temSet"])
            self.set_property(Props.TEMP_BIT, rec["temRec"])
        else:
            validate(value)
            self.set_property(Props.TEMP_SET, int(value))

    @property
    def temperature_units(self) -> int:
        """Unit of temperature of the device."""
        return self.get_property(Props.TEMP_UNIT)

    @temperature_units.setter
    def temperature_units(self, value: int) -> None:
        self.set_property(Props.TEMP_UNIT, int(value))

    @property
    def current_temperature(self) -> int:
        """Current temperature of the device."""
        prop = self.get_property(Props.TEMP_SENSOR)
        bit = self.get_property(Props.TEMP_BIT)
        if prop is not None:
            v = self.version and int(self.version.split(".")[0])
            try:
                if v == 4:
                    return self._convert_to_units(prop, bit)
                if prop != 0:
                    return self._convert_to_units(prop - TEMP_OFFSET, bit)
            except ValueError:
                logging.warning("Converting unexpected set temperature value %s", prop)

        return self.target_temperature

    @property
    def fan_speed(self) -> int:
        """Fan speed of the device."""
        return self.get_property(Props.FAN_SPEED)

    @fan_speed.setter
    def fan_speed(self, value: int) -> None:
        self.set_property(Props.FAN_SPEED, int(value))

    @property
    def fresh_air(self) -> bool:
        """Fresh air status of the device."""
        return bool(self.get_property(Props.FRESH_AIR))

    @fresh_air.setter
    def fresh_air(self, value: bool) -> None:
        self.set_property(Props.FRESH_AIR, int(value))

    @property
    def xfan(self) -> bool:
        """X-Fan status of the device."""
        return bool(self.get_property(Props.XFAN))

    @xfan.setter
    def xfan(self, value: bool) -> None:
        self.set_property(Props.XFAN, int(value))

    @property
    def anion(self) -> bool:
        """Anion status of the device."""
        return bool(self.get_property(Props.ANION))

    @anion.setter
    def anion(self, value: bool) -> None:
        self.set_property(Props.ANION, int(value))

    @property
    def sleep(self) -> bool:
        """Sleep status of the device."""
        return bool(self.get_property(Props.SLEEP))

    @sleep.setter
    def sleep(self, value: bool) -> None:
        self.set_property(Props.SLEEP, int(value))
        self.set_property(Props.SLEEP_MODE, int(value))

    @property
    def light(self) -> bool:
        """Light status of the device."""
        return bool(self.get_property(Props.LIGHT))

    @light.setter
    def light(self, value: bool) -> None:
        self.set_property(Props.LIGHT, int(value))

    @property
    def horizontal_swing(self) -> int:
        """Horizontal swing of the device."""
        return self.get_property(Props.SWING_HORIZ)

    @horizontal_swing.setter
    def horizontal_swing(self, value: int) -> None:
        self.set_property(Props.SWING_HORIZ, int(value))

    @property
    def vertical_swing(self) -> int:
        """Vertical swing of the device."""
        return self.get_property(Props.SWING_VERT)

    @vertical_swing.setter
    def vertical_swing(self, value: int) -> None:
        self.set_property(Props.SWING_VERT, int(value))

    @property
    def quiet(self) -> bool:
        """Quiet status of the device."""
        return self.get_property(Props.QUIET)

    @quiet.setter
    def quiet(self, value: bool) -> None:
        self.set_property(Props.QUIET, 2 if value else 0)

    @property
    def turbo(self) -> bool:
        """Turbo status of the device."""
        return bool(self.get_property(Props.TURBO))

    @turbo.setter
    def turbo(self, value: bool) -> None:
        self.set_property(Props.TURBO, int(value))

    @property
    def steady_heat(self) -> bool:
        """Steady heat status of the device."""
        return bool(self.get_property(Props.STEADY_HEAT))

    @steady_heat.setter
    def steady_heat(self, value: bool) -> None:
        self.set_property(Props.STEADY_HEAT, int(value))

    @property
    def power_save(self) -> bool:
        """Power save status of the device."""
        return bool(self.get_property(Props.POWER_SAVE))

    @power_save.setter
    def power_save(self, value: bool) -> None:
        self.set_property(Props.POWER_SAVE, int(value))

    @property
    def target_humidity(self) -> int:
        """Target humidity of the device."""
        return 15 + (self.get_property(Props.HUM_SET) * 5)

    @target_humidity.setter
    def target_humidity(self, value: int) -> None:
        if value > HUMIDITY_MAX or value < HUMIDITY_MIN:
            raise ValueError(f"Specified temperature {value} is out of range.")

        self.set_property(Props.HUM_SET, (value - 15) // 5)

    @property
    def dehumidifier_mode(self):
        """Dehumidifier mode of the device."""
        return self.get_property(Props.DEHUMIDIFIER_MODE)

    @property
    def current_humidity(self) -> int:
        """Current humidity of the device."""
        return self.get_property(Props.HUM_SENSOR)

    @property
    def clean_filter(self) -> bool:
        """Clean filter status of the device."""
        return bool(self.get_property(Props.CLEAN_FILTER))

    @property
    def water_full(self) -> bool:
        """Water full status of the device."""
        return bool(self.get_property(Props.WATER_FULL))
