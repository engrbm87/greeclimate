"""Pytest module configuration."""

from unittest.mock import patch

import pytest

from greeclimate import Device, DeviceInfo

MOCK_INTERFACES = ["lo"]
MOCK_LO_IFACE = {
    2: [{"addr": "10.0.0.1", "netmask": "255.0.0.0", "peer": "10.255.255.255"}]
}


@pytest.fixture(name="netifaces")
def netifaces_fixture():
    """Patch netifaces interface discover."""
    with patch("netifaces.interfaces", return_value=MOCK_INTERFACES), patch(
        "netifaces.ifaddresses", return_value=MOCK_LO_IFACE
    ) as ifaddr_mock:
        yield ifaddr_mock


@pytest.fixture(name="mock_device")
async def setup_mock_device() -> Device:
    device = Device(DeviceInfo("192.168.1.29", "f4911e7aca59", 7000, "1e7aca59"))
    device.device_key = "St8Vw1Yz4Bc7Ef0H"
    return device
