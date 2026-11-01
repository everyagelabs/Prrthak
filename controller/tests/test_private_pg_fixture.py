import importlib.util
from pathlib import Path
import tempfile
import unittest

from controller.tests import private_pg as fixture


class PrivatePostgresFixtureTests(unittest.TestCase):
    def test_names_are_unique_run_scoped_test_databases(self):
        first, second = fixture.names("first"), fixture.names("second")
        self.assertFalse(set(first.values()) & set(second.values()))
        self.assertFalse(set(first.values()) & set(fixture.names("first").values()))
        for name in (*first.values(), *second.values()):
            self.assertTrue(name.startswith("prthak_test_" + fixture.RUN_ID + "_"))
            self.assertLessEqual(len(name), 63)
        with self.assertRaises(RuntimeError):
            fixture.names("production/database")

    @unittest.skipUnless(importlib.util.find_spec("psycopg"), "Optional PostgreSQL test driver required")
    def test_explicit_coordinates_preserve_private_cluster_guard(self):
        (fixture.ROOT / ".local").mkdir(exist_ok=True, mode=0o700)
        with tempfile.TemporaryDirectory(prefix="prthak_test_fixture_", dir=fixture.ROOT / ".local") as directory:
            root = Path(directory)
            data, socket = root / "pg-data", root / "pg-socket"
            data.mkdir(mode=0o700)
            socket.mkdir(mode=0o700)
            admin = "host='" + str(socket) + "' port=55434 user=prthak_test dbname=postgres"
            values = {"PRTHAK_TEST_PG_ADMIN_DSN": admin, "PRTHAK_TEST_PG_DATA": str(data)}
            parameters, actual = fixture.configuration(values)
            self.assertEqual(actual, data.resolve())
            self.assertEqual(parameters["host"], str(socket))
            self.assertNotIn("dbname", parameters)
            for changed in ({"PRTHAK_TEST_PG_ADMIN_DSN": "host=10.1.2.3 user=prthak_test dbname=postgres"},
                            {"PRTHAK_TEST_PG_ADMIN_DSN": admin + " hostaddr=127.0.0.1"},
                            {"PRTHAK_TEST_PG_ADMIN_DSN": admin.replace("prthak_test", "ordinary_user")},
                            {"PRTHAK_TEST_PG_DATA": "/tmp"}):
                with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                    fixture.configuration({**values, **changed})
            socket.chmod(0o755)
            with self.assertRaises(RuntimeError):
                fixture.configuration(values)
