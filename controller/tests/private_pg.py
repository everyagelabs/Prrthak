"""Private test-cluster configuration; never choose a deployment database.

Capture explicit fixture coordinates before integration environment sanitizers.
Every caller still verifies PostgreSQL's real data_directory/current identity.
Names are unique to this run and class; existing databases are never adopted.
"""
import os
from pathlib import Path
import re
import uuid

ROOT = Path(__file__).resolve().parents[2]
ENVIRONMENT = dict(os.environ)
RUN_ID = ENVIRONMENT.get("PRTHAK_TEST_PG_RUN_ID", uuid.uuid4().hex[:12])
if not re.fullmatch(r"[a-f0-9]{8,20}", RUN_ID):
    raise RuntimeError("A bounded hexadecimal private PostgreSQL run ID is required")


def names(label, namespaces=("metadata", "traffic")):
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,17}", label):
        raise RuntimeError("A bounded private PostgreSQL fixture label is required")
    instance = uuid.uuid4().hex[:6]
    return {name: "prthak_test_" + RUN_ID + "_" + label + "_" + instance + "_" + name for name in namespaces}


def configuration(environment=None):
    from psycopg.conninfo import conninfo_to_dict
    environment = ENVIRONMENT if environment is None else environment
    explicit = environment.get("PRTHAK_TEST_PG_ADMIN_DSN") or environment.get("SEG_TEST_PLATFORM_PG_ADMIN")
    if explicit:
        if not environment.get("PRTHAK_TEST_PG_DATA"):
            raise RuntimeError("An explicit private admin DSN also requires PRTHAK_TEST_PG_DATA")
        parameters = conninfo_to_dict(explicit)
        data = Path(environment["PRTHAK_TEST_PG_DATA"]).resolve()
    else:
        parameters = {"host": str(ROOT / ".local/ha-pg-socket"), "port": "55432", "user": "prthak_test", "dbname": "postgres"}
        data = (ROOT / ".local/ha-postgres").resolve()
    if parameters.get("user") != "prthak_test" or parameters.get("dbname") != "postgres":
        raise RuntimeError("The private test admin identity must be prthak_test/postgres")
    if not data.is_relative_to((ROOT / ".local").resolve()) or data == (ROOT / ".local").resolve():
        raise RuntimeError("The expected test data directory must be private workspace state")
    info = data.stat()
    if not data.is_dir() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError("The private test data directory must be owned mode 0700")
    host = parameters.get("host", "")
    if host.startswith("/"):
        socket = Path(host).resolve()
        info = socket.stat()
        if socket.parent != data.parent or not socket.is_dir() or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise RuntimeError("The Unix test socket must be a protected sibling of its data directory")
    elif not explicit or host not in ("127.0.0.1", "::1"):
        raise RuntimeError("Only explicit loopback or private workspace Unix PostgreSQL fixtures are allowed")
    if any(key in parameters for key in ("hostaddr", "service", "passfile", "options")):
        raise RuntimeError("Implicit PostgreSQL routing or service overrides are not allowed in private fixtures")
    try:
        port = int(parameters.get("port", "5432"))
    except ValueError:
        raise RuntimeError("A single private test port is required") from None
    if not 1 <= port <= 65535:
        raise RuntimeError("A bounded private test port is required")
    parameters.pop("dbname", None)
    parameters["connect_timeout"] = "3"
    return parameters, data


def parameters():
    return configuration()[0]


def data_directory():
    return configuration()[1]


def evidence_path(name):
    directory = Path(ENVIRONMENT.get("PRTHAK_TEST_PG_EVIDENCE_DIR", str(ROOT / ".local")))
    directory = directory.resolve()
    if not directory.is_relative_to((ROOT / ".local").resolve()):
        raise RuntimeError("Fixture evidence must remain in private workspace state")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    return directory / name
