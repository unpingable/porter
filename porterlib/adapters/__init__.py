from __future__ import annotations

from typing import Any

from .base import SubstrateAdapter, parse_observed, record_transport
from .exact_ssh_adapter import ExactSSHAdapter
from .serial_adapter import SerialAdapter
from .ssh_adapter import SSHAdapter

# Keyed by the transport recorded in substrate.transport (what the record says it
# IS after `up`), not by the target prefix. Recipe targets resolve to one of these.
_REGISTRY: dict[str, SubstrateAdapter] = {
    SSHAdapter.transport: SSHAdapter(),
    ExactSSHAdapter.transport: ExactSSHAdapter(),
    SerialAdapter.transport: SerialAdapter(),
}


def adapter_for_transport(transport: str) -> SubstrateAdapter | None:
    return _REGISTRY.get(transport)


def adapter_for_record(record: dict[str, Any]) -> SubstrateAdapter | None:
    return adapter_for_transport(record_transport(record))


__all__ = [
    "SubstrateAdapter",
    "SSHAdapter",
    "ExactSSHAdapter",
    "SerialAdapter",
    "adapter_for_record",
    "adapter_for_transport",
    "parse_observed",
    "record_transport",
]
