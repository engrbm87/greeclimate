"""Network helpers for gree climate devices."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import socket
from contextlib import suppress
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from Crypto.Cipher import AES

from .const import GENERIC_KEY
from .exceptions import KeyNotRetrievedError, NoDataReceivedError

if TYPE_CHECKING:
    from .device import DeviceInfo


NETWORK_TIMEOUT = 10

_LOGGER = logging.getLogger(__name__)


IPAddr = Tuple[str, int]


class BaseDeviceProtocol(asyncio.DatagramProtocol):
    """Base class for device protocol."""

    _transport: Optional[asyncio.DatagramTransport]
    _drained: asyncio.Event

    def connection_made(self, transport) -> None:
        """Called when the Datagram protocol handler is initialized."""
        self._transport = transport

    def connection_lost(self, exc) -> None:
        """Handle a closed socket."""
        if self._transport is not None:
            self._transport.close()
            self._transport = None

    def pause_writing(self) -> None:
        """Stop writing additional data to the transport."""
        self._drained.clear()
        super().pause_writing()

    def resume_writing(self) -> None:
        """Resume writing data to the transport."""
        self._drained.set()
        super().resume_writing()


class DeviceProtocol(asyncio.DatagramProtocol):
    def __init__(
        self, recvq: asyncio.Queue, excq: asyncio.Queue, drained: asyncio.Event
    ) -> None:
        self._loop = asyncio.get_event_loop()
        self._recvq = recvq
        self._excq = excq
        self._drained = drained
        self._drained.set()

        # Transports are connected at the time a connection is made.
        self._transport: Optional[asyncio.DatagramTransport] = None

    def datagram_received(self, data: bytes, addr: IPAddr) -> None:
        self._recvq.put_nowait((data, addr))

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if exc is not None:
            self._excq.put_nowait(exc)

        super().connection_lost()

    def error_received(self, exc: Exception) -> None:
        self._excq.put_nowait(exc)


class DeviceProtocolEvent(BaseDeviceProtocol):
    """Event driven device protocol class."""

    def __init__(
        self, timeout: int = 10, drained: Optional[asyncio.Event] = None
    ) -> None:
        """Initialize the device protocol object.

        Args:
            timeout (int): Packet send timeout
            drained (asyncio.Event): Packet send drain event signal
        """
        self._timeout = timeout
        self._drained = drained or asyncio.Event()
        self._drained.set()
        self._key = GENERIC_KEY

    # This event need to be implement to handle incoming requests
    def packet_received(self, obj, addr: IPAddr) -> None:
        """Event called when a packet is received and decoded.

        Args:
            obj (JSON): Json object with decoded UDP data
            addr (IPAddr): Endpoint address of the sender
        """
        raise NotImplementedError(self)

    @property
    def device_key(self) -> str:
        """Sets the encryption key used for device data."""
        return self._key

    @device_key.setter
    def device_key(self, value: str) -> None:
        """Gets the encryption key used for device data."""
        self._key = value

    def close(self) -> None:
        """Close the UDP transport."""
        if self._transport:
            self._transport.close()

    def connection_lost(self, exc) -> None:
        """Handle a closed socket."""

        # In this case the connection was closed unexpectedly
        if exc is not None:
            _LOGGER.exception("Connection was closed unexpectedly", exc_info=exc)

        super().connection_lost()

    def error_received(self, exc: Exception) -> None:
        """Handle error while sending/receiving datagrams."""
        raise exc

    def datagram_received(self, data: bytes, addr: IPAddr) -> None:
        """Handle an incoming datagram."""
        if len(data) == 0:
            return

        obj: Dict[str, Any] = json.loads(data)
        key = GENERIC_KEY if obj.get("i") == 1 else self._key

        if obj.get("pack"):
            obj["pack"] = decrypt_payload(obj["pack"], key)

        _LOGGER.debug("Received packet from %s:\n%s", addr[0], json.dumps(obj))

        self.packet_received(obj, addr)

    async def send(self, obj: Dict[str, Any], addr: Optional[IPAddr] = None) -> None:
        """Send encode and send JSON command to the device."""
        _LOGGER.debug("Sending packet:\n%s", json.dumps(obj))

        if obj.get("pack"):
            key = GENERIC_KEY if obj.get("i") == 1 else self._key
            obj["pack"], obj["tag"] = encrypt_payload(obj["pack"], key)

        data_bytes = json.dumps(obj).encode()
        if self._transport is None:
            return
        self._transport.sendto(data_bytes, addr)

        task = asyncio.create_task(self._drained.wait())
        await asyncio.wait_for(task, self._timeout)


class BroadcastListenerProtocol(DeviceProtocolEvent):
    """Special protocol handler for when broadcast is needed."""

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        """Called when the Datagram protocol handler is initialized."""
        super().connection_made(transport)

        sock: socket.socket = transport.get_extra_info("socket")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


# Concepts and code here were taken from https://github.com/jsbronder/asyncio-dgram
class DatagramStream:
    """Datagram stream."""

    def __init__(
        self,
        transport: asyncio.DatagramTransport,
        recvq: asyncio.Queue[Tuple[bytes, IPAddr]],
        excq: asyncio.Queue[Exception],
        drained: asyncio.Event,
        timeout: int = 120,
    ) -> None:
        """Initialize DatagramStream."""
        self._transport = transport
        self._recvq = recvq
        self._excq = excq
        self._drained = drained
        self._timeout = timeout

    def __del__(self) -> None:
        self.close()

    def raise_except_if_any(self) -> None:
        """Raise exception if any in queue."""
        with suppress(asyncio.queues.QueueEmpty):
            exc = self._excq.get_nowait()
            raise exc

    @property
    def socket(self) -> socket.socket:
        """Get socket."""
        return self._transport.get_extra_info("socket")

    def close(self):
        """Close the transport."""
        try:
            self._transport.close()
        except RuntimeError:
            pass

    async def send(self, data: bytes, addr: Optional[IPAddr] = None) -> None:
        """Send data to the device."""
        self.raise_except_if_any()
        self._transport.sendto(data, addr)

        task = asyncio.create_task(self._drained.wait())
        await asyncio.wait_for(task, self._timeout)

    async def send_device_data(self, data: Dict[str, Any], key=GENERIC_KEY) -> None:
        """Send a formatted request to the device."""
        _LOGGER.debug("Sending packet:\n%s", json.dumps(data))

        if "pack" in data:
            data["pack"] = encrypt_payload(
                data["pack"], key
            )  # look into this for backwards compatibility

        data_bytes = json.dumps(data).encode()
        await self.send(data_bytes)

    def recv_ready(self) -> bool:
        """Check if data is ready to be received."""
        self.raise_except_if_any()
        return not self._recvq.empty()

    async def recv(self) -> Tuple[bytes, IPAddr]:
        """Receive data from the device."""
        self.raise_except_if_any()

        data: Tuple[bytes, IPAddr] = await asyncio.wait_for(
            self._recvq.get(), self._timeout
        )
        return data

    async def recv_device_data(
        self, key: Optional[str] = None
    ) -> Tuple[Dict[str, Any], IPAddr]:
        """Receive a formatted request from the device."""
        (data_bytes, addr) = await self.recv()
        if len(data_bytes) == 0:
            raise NoDataReceivedError

        data = json.loads(data_bytes)

        if "pack" in data:
            data["pack"] = decrypt_payload(data["pack"], key or GENERIC_KEY)

        _LOGGER.debug("Received packet:\n%s", json.dumps(data))
        return (data, addr)

    async def bind_device(self, device_info: DeviceInfo) -> str:
        """Bind a device."""
        payload = {
            "cid": "app",
            "i": 1,
            "t": "pack",
            "uid": 0,
            "tcid": device_info.mac,
            "pack": {"mac": device_info.mac, "t": "bind", "uid": 0},
        }

        try:
            await self.send_device_data(payload)
            (r, _) = await self.recv_device_data()
        except (asyncio.TimeoutError, NoDataReceivedError) as e:
            raise e
        except Exception as e:
            _LOGGER.exception("Encountered an error trying to bind device")
            raise e
        finally:
            self.close()

        if "key" not in r["pack"]:
            raise KeyNotRetrievedError

        return r["pack"]["key"]


async def create_datagram_stream(target: IPAddr) -> DatagramStream:
    """Create a datagram stream."""
    loop = asyncio.get_event_loop()
    recvq: asyncio.Queue[Tuple[bytes, IPAddr]] = asyncio.Queue()
    excq: asyncio.Queue[Exception] = asyncio.Queue()
    drained = asyncio.Event()

    transport, _ = await loop.create_datagram_endpoint(
        lambda: DeviceProtocol(recvq, excq, drained), remote_addr=target
    )
    return DatagramStream(transport, recvq, excq, drained, timeout=NETWORK_TIMEOUT)


async def bind_device(device_info: DeviceInfo) -> str:
    """Bind a device."""
    payload = {
        "cid": "app",
        "i": 1,
        "t": "pack",
        "uid": 0,
        "tcid": device_info.mac,
        "pack": {"mac": device_info.mac, "t": "bind", "uid": 0},
    }

    remote_addr = (device_info.ip, device_info.port)
    stream = await create_datagram_stream(remote_addr)
    try:
        await stream.send_device_data(payload)
        (r, _) = await stream.recv_device_data()
    except (asyncio.TimeoutError, NoDataReceivedError) as e:
        raise e
    except Exception as e:
        _LOGGER.exception("Encountered an error trying to bind device")
        raise e
    finally:
        stream.close()

    if "key" not in r["pack"]:
        raise KeyNotRetrievedError

    return r["pack"]["key"]


async def send_state(
    property_values: Dict[str, Any], device_info: DeviceInfo, key: str
) -> None:
    """Send state to device."""
    payload = {
        "cid": "app",
        "i": 0,
        "t": "pack",
        "uid": 0,
        "tcid": device_info.mac,
        "pack": {
            "opt": list(property_values.keys()),
            "p": list(property_values.values()),
            "t": "cmd",
        },
    }

    remote_addr = (device_info.ip, device_info.port)
    stream = await create_datagram_stream(remote_addr)
    try:
        await stream.send_device_data(payload, key)
    except (asyncio.TimeoutError, NoDataReceivedError) as e:
        raise e
    except Exception as e:
        _LOGGER.exception("Encountered an error sending state to device")
        raise e
    finally:
        stream.close()


async def request_state(
    properties: List[str], device_info: DeviceInfo, key: str
) -> Dict[str, Any]:
    """Request state from device."""
    payload = {
        "cid": "app",
        "i": 0,
        "t": "pack",
        "uid": 0,
        "tcid": device_info.mac,
        "pack": {"mac": device_info.mac, "t": "status", "cols": properties},
    }

    remote_addr = (device_info.ip, device_info.port)
    stream = await create_datagram_stream(remote_addr)
    try:
        await stream.send_device_data(payload, key)
        (r, _) = await stream.recv_device_data(key)
    except (asyncio.TimeoutError, NoDataReceivedError) as e:
        raise e
    except Exception as e:
        _LOGGER.exception("Encountered an error requesting update from device")
        raise e
    finally:
        stream.close()

    cols = r["pack"]["cols"]
    dat = r["pack"]["dat"]
    return dict(zip(cols, dat))


def decrypt_payload(payload: Dict[str, Any], key: str):
    """Decrypt payload."""
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    decoded = base64.b64decode(payload)
    decrypted = cipher.decrypt(decoded).decode()
    t = decrypted.replace(decrypted[decrypted.rindex("}") + 1 :], "")
    return json.loads(t)


def encrypt_payload(payload: Dict[str, Any], key: str):
    """Encrypt payload."""

    def pad(s):
        bs = 16
        return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

    cipher = AES.new(key.encode(), AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(json.dumps(payload)).encode())
    encoded = base64.b64encode(encrypted).decode()
    return encoded
