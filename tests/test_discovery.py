"""Test gree climate discovery."""

import asyncio
import json
import socket
from threading import Thread
from typing import Any, Dict, List
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from greeclimate import Discovery, Listener
from greeclimate.const import DISCOVERY_REQUEST
from greeclimate.network import IPAddr

from . import MOCK_DEVICE
from .common import DEFAULT_TIMEOUT, DISCOVERY_RESPONSE, Responder, _encrypt_payload


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,bcast,family", [(("127.0.0.1", 7000), "127.255.255.255", socket.AF_INET)]
)
async def test_discover_devices(
    netifaces: MagicMock, addr: IPAddr, bcast: str, family: int
) -> None:
    """Test discovering devices."""
    netifaces.return_value = {
        2: [{"addr": addr[0], "netmask": "255.0.0.0", "peer": bcast}]
    }

    devices: List[Dict[str, Any]] = [
        {"cid": "aabbcc001122", "mac": "aabbcc001122", "name": "MockDevice1"},
        {"cid": "aabbcc001123", "mac": "aabbcc001123", "name": "MockDevice2"},
        {"cid": "", "mac": "aabbcc001124", "name": "MockDevice3"},
    ]

    with Responder(family, addr[1]) as sock:

        def responder(s: socket.socket) -> None:
            (data, addr) = s.recvfrom(2048)
            packet: Dict[str, Any] = json.loads(data)
            assert packet == DISCOVERY_REQUEST

            for device in devices:
                response = DISCOVERY_RESPONSE.copy()
                response["pack"].update(device)
                packet_json = json.dumps(_encrypt_payload(response))
                s.sendto(packet_json.encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        discovery = Discovery(allow_loopback=True)
        discovered_devices = await discovery.scan(wait_for=DEFAULT_TIMEOUT)
        assert discovered_devices is not None
        assert len(discovered_devices) == 3

        sock.close()
        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
async def test_discover_no_devices(netifaces: MagicMock) -> None:
    netifaces.return_value = {
        2: [{"addr": "127.0.0.1", "netmask": "255.0.0.0", "peer": "127.255.255.255"}]
    }

    discovery = Discovery(allow_loopback=True)
    devices = await discovery.scan(wait_for=DEFAULT_TIMEOUT)

    assert devices is not None
    assert len(devices) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,bcast,family", [(("127.0.0.1", 7000), "127.255.255.255", socket.AF_INET)]
)
async def test_discover_deduplicate_multiple_discoveries(
    netifaces: MagicMock, addr: IPAddr, bcast: str, family: int
) -> None:
    netifaces.return_value = {
        2: [{"addr": addr[0], "netmask": "255.0.0.0", "peer": bcast}]
    }

    devices: List[Dict[str, Any]] = [
        {"cid": "aabbcc001122", "mac": "aabbcc001122", "name": "MockDevice1"},
        {"cid": "aabbcc001123", "mac": "aabbcc001123", "name": "MockDevice2"},
        {"cid": "aabbcc001123", "mac": "aabbcc001123", "name": "MockDevice2"},
    ]

    with Responder(family, addr[1]) as sock:

        def responder(s: socket.socket) -> None:
            (data, addr) = s.recvfrom(2048)
            packet = json.loads(data)
            assert packet == DISCOVERY_REQUEST

            for device_info in devices:
                response = DISCOVERY_RESPONSE.copy()
                response["pack"].update(device_info)
                packet = json.dumps(_encrypt_payload(response))
                s.sendto(packet.encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        discovery = Discovery(allow_loopback=True)
        devices = await discovery.scan(wait_for=DEFAULT_TIMEOUT)
        assert devices is not None
        assert len(devices) == 2

        sock.close()
        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,bcast,family", [(("127.0.0.1", 7000), "127.255.255.255", socket.AF_INET)]
)
async def test_discovery_events(
    netifaces: MagicMock, addr: IPAddr, bcast: str, family: int
) -> None:
    netifaces.return_value = {
        2: [{"addr": addr[0], "netmask": "255.0.0.0", "peer": bcast}]
    }

    with Responder(family, addr[1]) as sock:

        def responder(s: socket.socket) -> None:
            (data, addr) = s.recvfrom(2048)
            packet = json.loads(data)
            assert packet == DISCOVERY_REQUEST

            packet = json.dumps(_encrypt_payload(DISCOVERY_RESPONSE))
            s.sendto(packet.encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        with patch.object(Discovery, "packet_received", return_value=None) as mock:
            discovery = Discovery(allow_loopback=True)
            await discovery.scan()
            await asyncio.sleep(DEFAULT_TIMEOUT)

            assert mock.call_count == 1

        sock.close()
        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
async def test_discovery_device_update_events() -> None:
    discovery = Discovery(allow_loopback=True)
    discovery.packet_received(
        {
            "pack": {
                "mac": "aa11bb22cc33",
                "cid": 1,
                "name": "MockDevice",
                "brand": "",
                "model": "",
                "ver": "1.0.0",
            }
        },
        ("1.1.1.1", 7000),
    )

    await asyncio.gather(*discovery.tasks, return_exceptions=True)

    assert len(discovery.devices) == 1
    assert discovery.devices[0].mac == "aa11bb22cc33"
    assert discovery.devices[0].ip == "1.1.1.1"

    discovery.packet_received(
        {
            "pack": {
                "mac": "aa11bb22cc33",
                "cid": 1,
                "name": "MockDevice",
                "brand": "",
                "model": "",
                "ver": "1.0.0",
            }
        },
        ("1.1.2.2", 7000),
    )

    await asyncio.gather(*discovery.tasks, return_exceptions=True)

    assert len(discovery.devices) == 1
    assert discovery.devices[0].mac == "aa11bb22cc33"
    assert discovery.devices[0].ip == "1.1.2.2"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "addr,bcast,family", [(("127.0.0.1", 7000), "127.255.255.255", socket.AF_INET)]
)
async def test_discover_devices_bad_data(
    netifaces: MagicMock, addr: IPAddr, bcast: str, family: int
) -> None:
    """Create a socket broadcast responder, an async broadcast listener,
    test discovery responses.
    """
    netifaces.return_value = {
        2: [{"addr": addr[0], "netmask": "255.0.0.0", "peer": bcast}]
    }

    with Responder(family, addr[1]) as sock:

        def responder(s: socket.socket) -> None:
            (data, addr) = s.recvfrom(2048)
            packet = json.loads(data)
            assert packet == DISCOVERY_REQUEST

            s.sendto("garbage data".encode(), addr)

        serv = Thread(target=responder, args=(sock,))
        serv.start()

        # Run the listener portion now
        discovery = Discovery(allow_loopback=True)
        response = await discovery.scan(wait_for=DEFAULT_TIMEOUT)

        assert response is not None
        assert len(response) == 0

        sock.close()
        serv.join(timeout=DEFAULT_TIMEOUT)


@pytest.mark.asyncio
async def test_add_new_listener() -> None:
    """Register a listener, test that is registered."""

    listener = MagicMock(spec_set=Listener)
    discovery = Discovery()

    discovery.add_listener(listener)
    assert len(discovery._listeners) == 1

    # Adding the same listener should not add another
    discovery.add_listener(listener)
    assert len(discovery._listeners) == 1


@pytest.mark.asyncio
async def test_add_new_listener_with_devices() -> None:
    """Register a listener, test that is registered."""

    with patch.object(Discovery, "devices", new_callable=PropertyMock) as mock:
        mock.return_value = [MOCK_DEVICE]
        listener = MagicMock(spec_set=Listener)
        discovery = Discovery()

        discovery.add_listener(listener)
        await asyncio.gather(*discovery.tasks)

        assert len(discovery._listeners) == 1
        assert listener.device_found.call_count == 1


@pytest.mark.asyncio
async def test_remove_listener() -> None:
    """Register, remove listener, test results."""

    listener = MagicMock(spec_set=Listener)
    discovery = Discovery()

    discovery.add_listener(listener)
    assert len(discovery._listeners) == 1

    result = discovery.remove_listener(listener)
    assert result is True

    result = discovery.remove_listener(listener)
    assert result is False
