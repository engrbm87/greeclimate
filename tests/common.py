import socket
from socket import SOCK_DGRAM
from typing import Any, Dict, Optional

from greeclimate.network import GENERIC_KEY, DeviceProtocolEvent, encrypt_payload

DEFAULT_TIMEOUT = 5
DISCOVERY_RESPONSE = {
    "t": "pack",
    "i": 1,
    "uid": 0,
    "cid": "aabbcc112233",
    "tcid": "",
    "pack": {
        "t": "dev",
        "cid": "aabbcc112233",
        "bc": "gree",
        "brand": "gree",
        "catalog": "gree",
        "mac": "aabbcc112233",
        "mid": "10001",
        "model": "gree",
        "name": "fake unit",
        "series": "gree",
        "vender": "1",
        "ver": "V1.1.13",
        "lock": 0,
    },
}
DISCOVERY_RESPONSE_NO_CID = {
    "t": "pack",
    "i": 1,
    "uid": 0,
    "cid": "",
    "tcid": "",
    "pack": {
        "t": "dev",
        "cid": "",
        "bc": "gree",
        "brand": "gree",
        "catalog": "gree",
        "mac": "aabbcc112233",
        "mid": "10001",
        "model": "gree",
        "name": "fake unit",
        "series": "gree",
        "vender": "1",
        "ver": "V1.1.13",
        "lock": 0,
    },
}
DEFAULT_RESPONSE = {
    "t": "pack",
    "i": 1,
    "uid": 0,
    "cid": "aabbcc112233",
    "tcid": "",
    "pack": {},
}


def _encrypt_payload(data: Dict[str, Any]) -> Dict[str, Any]:
    """Encrypt the payload of responses quickly."""
    d = data.copy()
    d["pack"] = encrypt_payload(d["pack"], GENERIC_KEY)
    return d


class Responder:
    """Context manage for easy raw socket responders."""

    def __init__(self, family: int, port: int) -> None:
        """Initialize the class."""
        self.sock: Optional[socket.socket] = None
        self.family = family
        self.port = port

    def __enter__(self):
        """Enter the context manager."""
        self.sock = socket.socket(self.family, SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.settimeout(DEFAULT_TIMEOUT)
        self.sock.bind(("", self.port))
        return self.sock

    def __exit__(self, *args):
        """Exit the context manager."""
        if self.sock is not None:
            self.sock.close()
