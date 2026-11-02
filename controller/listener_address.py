"""Consistent IPv4, DNS and bracketed IPv6 listener addresses."""
import ipaddress
import re


def bind_host(value):
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError("Provide a valid listener host")
    if value.startswith('[') and value.endswith(']'):
        value = value[1:-1]
        if ':' not in value:
            raise ValueError("Brackets require an IPv6 listener")
    if any(char.isspace() for char in value) or any(char in value for char in '[]/%\\\x00'):
        raise ValueError("Listener hosts cannot contain paths, scopes or malformed brackets")
    if ':' in value:
        address = ipaddress.IPv6Address(value)
        if address.ipv4_mapped is not None:
            raise ValueError("Use a native IPv4 or IPv6 listener address")
        return str(address)
    if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', value.rstrip('.')):
        raise ValueError("Provide a valid listener hostname or address")
    return value


def split_listener(value):
    if not isinstance(value, str):
        raise ValueError("Use host:port or [IPv6]:port")
    try:
        host, number = value.rsplit(':', 1)
        if not re.fullmatch(r'[0-9]{1,5}', number) or not 1 <= int(number) <= 65535:
            raise ValueError()
        return bind_host(host), int(number)
    except (ValueError, TypeError):
        raise ValueError("Use host:port or [IPv6]:port with a port from 1 to 65535") from None


def format_listener(host, port):
    host = bind_host(host)
    return ('[' + host + ']' if ':' in host else host) + ':' + str(port)
