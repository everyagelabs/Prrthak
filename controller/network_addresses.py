"""Canonical native IP inputs shared with the endpoint's netip contract.

Reject scope identifiers and IPv4-mapped IPv6 before masking a CIDR. Never
silently unmap or widen an input whose family the endpoint cannot authorize.
"""
import ipaddress


def address(value):
    if not isinstance(value,str) or '%' in value:
        raise ValueError('Use a native unscoped IPv4 or IPv6 address')
    result=ipaddress.ip_address(value)
    if getattr(result,'ipv4_mapped',None) is not None:
        raise ValueError('IPv4-mapped IPv6 is unsupported; specify the native address explicitly')
    return result


def network(value):
    if not isinstance(value,str):
        raise ValueError('Use an IP address or CIDR string')
    address(value.split('/',1)[0])
    return ipaddress.ip_network(value,strict=False)
