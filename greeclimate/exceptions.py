class DeviceNotBoundError(Exception):
    """The device being used does not have it's device key set yet. Either provide one or bind the device"""


class DeviceTimeoutError(Exception):
    """The device timed out when trying to communicate"""


class NoDataReceivedError(Exception):
    """No data was received from the device"""


class KeyNotRetrievedError(Exception):
    """Didn't receive device key in response."""
