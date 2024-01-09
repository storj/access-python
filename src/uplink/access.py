# Copyright (C) 2023 Storj Labs, Inc.
# See LICENSE for copying information.

from .common import grant
from .common.storj import NodeURL
from .common import rpc


def parse_access(access_value):
    if not access_value:
        raise ValueError("access is empty or None")
    try:
        inner = grant.Access.parse(access_value)
        return Access._from_internal(inner)
    except ValueError as e:
        raise ValueError(f"access is malformed: {e}")


def parse_node_url(address):
    if not address:
        raise ValueError("node URL is empty or None")

    node_url = NodeURL.parse(address)
    if node_url.id is None:
        node_id = rpc.known_node_id(node_url.address)
        if node_id is None:
            raise ValueError("node id is required in node URL")
        node_url.id = node_id

    return node_url


class Access:
    __slots__ = ["_satellite_url", "_api_key", "_enc_access"]

    def __init__(self, satellite_url, api_key, enc_access):
        self._satellite_url = satellite_url
        self._api_key = api_key
        self._enc_access = enc_access

    @property
    def satellite_url(self):
        return self._satellite_url

    @property
    def api_key(self):
        return self._api_key

    @property
    def enc_access(self):
        return self._enc_access

    def share(self, permission, prefixes=[]):
        return Access._from_internal(self._to_internal().restrict(permission, prefixes))

    def serialize(self):
        return self._to_internal().serialize()

    def _to_internal(self):
        return grant.Access(
            satellite_address=str(self._satellite_url),
            api_key=self._api_key,
            enc_access=self._enc_access,
        )

    @staticmethod
    def _from_internal(inner):
        satellite_url = parse_node_url(inner.satellite_address)
        return Access(
            satellite_url=satellite_url,
            api_key=inner.api_key,
            enc_access=inner.enc_access,
        )
