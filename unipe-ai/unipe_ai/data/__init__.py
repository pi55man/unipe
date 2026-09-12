"""lab-faithful synthetic datasets for training and validation."""

from unipe_ai.data.dga import benign_qname, dga_qname, tunnel_qname
from unipe_ai.data.lab import TOOL_MAP, beacon_intervals, benign_flow, malicious_flow

__all__ = [
    "TOOL_MAP",
    "beacon_intervals",
    "benign_flow",
    "benign_qname",
    "dga_qname",
    "malicious_flow",
    "tunnel_qname",
]
