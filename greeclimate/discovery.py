"""Gree climate device discovery."""

from __future__ import annotations

import asyncio
import logging
from asyncio import Task
from asyncio.events import AbstractEventLoop
from ipaddress import IPv4Address
from typing import Any, Coroutine, Dict, List, Optional

from .const import DEFAULT_PORT, DISCOVERY_REQUEST
from .device import DeviceInfo
from .network import BroadcastListenerProtocol, IPAddr

_LOGGER = logging.getLogger(__name__)


class Listener:
    """Base class for device discovery events."""

    async def device_found(self, device_info: DeviceInfo) -> None:
        """Called any time a new (unique) device is found on the network."""

    async def device_update(self, device_info: DeviceInfo) -> None:
        """Called any time an up address for a device has changed on the network."""


class Discovery(BroadcastListenerProtocol, Listener):
    """Interact with gree devices on the network

    The `GreeClimate` class provides basic services for discovery and
    interaction with gree device on the network.
    """

    def __init__(
        self,
        timeout: int = 2,
        allow_loopback: bool = False,
        loop: Optional[AbstractEventLoop] = None,
    ):
        """Initialized the discovery manager.

        Args:
            timeout (int): Wait this long for responses to the scan request
            allow_loopback (bool): Allow scanning the loopback interface, default `False`
            loop (AbstractEventLoop): Async event loop
        """
        super(BroadcastListenerProtocol, self).__init__()
        self._timeout = timeout
        self._allow_loopback = allow_loopback

        self._device_infos: List[DeviceInfo] = []
        self._listeners: set[Listener] = set()
        self._tasks: List[Task] = []

        self._loop = loop or asyncio.get_event_loop()
        self._transport = None

    # Task management
    @property
    def tasks(self) -> List[Task]:
        """Returns the outstanding tasks waiting completion."""
        return self._tasks

    @property
    def devices(self) -> List[DeviceInfo]:
        """Return the current known list of devices."""
        return self._device_infos

    def _task_done_callback(self, task: Task) -> None:
        if task.exception():
            _LOGGER.exception("Uncaught exception", exc_info=task.exception())
        self._tasks.remove(task)

    def _create_task(self, coro: Coroutine[Any, Any, None]) -> Task:
        """Create and track tasks that are being created for events."""
        task = self._loop.create_task(coro)
        self._tasks.append(task)
        task.add_done_callback(self._task_done_callback)
        return task

    # Listener management
    def add_listener(self, listener: Listener) -> None:
        """Add a listener that will receive discovery events.

        Adding a listener will cause all currently known device to trigger a
        new device added event on the listen object.

        Args:
            listener (Listener): A listener object which will receive events
        """
        if listener not in self._listeners:
            self._listeners.add(listener)
            for device in self.devices:
                self._create_task(listener.device_found(device))

    def remove_listener(self, listener: Listener) -> bool:
        """Remove a listener that has already been registered.

        Args:
            listener (Listener): A listener object which will receive events

        Returns:
            bool: True if listener has been remove, false if it didn't exist
        """
        if listener in self._listeners:
            self._listeners.remove(listener)
            return True
        return False

    async def device_found(self, device_info: DeviceInfo) -> None:
        """Device is found.

        Notify all listeners that a device was found. Exceptions raised by
        listeners are ignored.

        Args:
            device_info (DeviceInfo): Information about the newly discovered
            device
        """

        for index, last_info in enumerate(self._device_infos):
            if device_info == last_info:
                if device_info.ip != last_info.ip:
                    # ip address info may have been updated, so store the new info
                    # and trigger a `device_update` event.
                    self._device_infos[index] = device_info
                    tasks = [
                        listener.device_update(device_info)
                        for listener in self._listeners
                    ]
                    await asyncio.gather(*tasks, return_exceptions=True)
                return

        self._device_infos.append(device_info)

        _LOGGER.info("Found gree device %s", str(device_info))

        tasks = [listener.device_found(device_info) for listener in self._listeners]
        await asyncio.gather(*tasks, return_exceptions=True)

    def packet_received(self, obj: Dict[str, Any], addr: IPAddr) -> None:
        """Event called when a packet is received and decoded."""
        pack: Optional[Dict[str, Any]] = obj.get("pack")
        if not pack:
            _LOGGER.error("Received an unexpected response during discovery")
            return

        device_info = DeviceInfo(
            addr[0],
            addr[1],
            pack.get("mac") or pack["cid"],
            pack.get("name"),
            pack.get("brand"),
            pack.get("model"),
            pack.get("ver"),
        )

        self._create_task(self.device_found(device_info))

    # Discovery
    async def scan(
        self, wait_for=0, bcast_ifaces: Optional[List[IPv4Address]] = None
    ) -> List[DeviceInfo]:
        """Sends a discovery broadcast packet on each network interface to
            locate Gree units on the network

        Args:
            wait_for (int): Optionally wait this many seconds for discovery
                            and return the devices found.

        Returns:
            List[DeviceInfo]: List of devices found during this scan
        """
        _LOGGER.info("Scanning for Gree devices ...")

        await self.search_devices(bcast_ifaces)
        if wait_for:
            await asyncio.sleep(wait_for)
            await asyncio.gather(*self.tasks, return_exceptions=True)

        return self._device_infos

    def _get_broadcast_addresses(self) -> List[IPv4Address]:
        """Return a list of broadcast addresses for each discovered interface"""
        # pylint: disable=import-outside-toplevel
        import netifaces

        broadcast_addresses: List[IPv4Address] = []
        for iface in netifaces.interfaces():
            for addr in netifaces.ifaddresses(iface).get(netifaces.AF_INET, []):
                ipaddr = addr.get("addr")
                bdr = addr.get("broadcast")
                peer = addr.get("peer")
                if addr:
                    ip4addr = IPv4Address(ipaddr)
                    if ip4addr.is_loopback and self._allow_loopback:
                        if bdr or peer:
                            broadcast_addresses.append(IPv4Address(bdr or peer))
                    elif not ip4addr.is_loopback:
                        if bdr:
                            broadcast_addresses.append(IPv4Address(bdr))

        return broadcast_addresses

    async def search_on_interface(self, bcast_iface: IPv4Address) -> None:
        """Search for devices on a specific interface."""
        _LOGGER.debug("Listening for devices on %s", bcast_iface)

        if self._transport is None:
            self._transport, _ = await self._loop.create_datagram_endpoint(
                lambda: self, local_addr=("0.0.0.0", 0), allow_broadcast=True
            )

        await self.send(DISCOVERY_REQUEST, (str(bcast_iface), DEFAULT_PORT))

    async def search_devices(
        self, broadcast_addresses: Optional[List[IPv4Address]] = None
    ) -> None:
        """Search for devices with specific broadcast addresses."""
        if not broadcast_addresses:
            broadcast_addresses = self._get_broadcast_addresses()
        await asyncio.gather(
            *[
                asyncio.create_task(self.search_on_interface(broadcast_address))
                for broadcast_address in broadcast_addresses
            ]
        )
