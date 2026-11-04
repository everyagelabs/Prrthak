"""Actual PostgreSQL persistence/projection seams on owner-opted private fixtures."""
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from controller.tests import private_pg
from controller.tests import test_observability_integration as fixtures


@unittest.skipUnless(os.environ.get('PRTHAK_PLATFORM_PG_ACCEPTANCE')=='1', 'Owner opt-in for private PostgreSQL observability fixture')
class PostgreSQLObservabilityTests(fixtures.ObservabilityIntegrationTests):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        cls.driver,cls.sql,cls.parameters=psycopg,sql,private_pg.parameters()
        cls.created=[];cls.addClassCleanup(cls.cleanup_databases)
        cls.names=private_pg.names('observability')
        with psycopg.connect(**cls.parameters,dbname='postgres',autocommit=True) as db:
            cls.verify_cluster(db)
            for name in cls.names.values():
                if db.execute('SELECT 1 FROM pg_database WHERE datname=%s',(name,)).fetchone():
                    raise RuntimeError('Refusing to adopt an existing fixture database')
                db.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)));cls.created.append(name)
        cls.dsns={key:make_conninfo(**cls.parameters,dbname=name) for key,name in cls.names.items()}

    @classmethod
    def verify_cluster(cls,db):
        user,directory=db.execute("SELECT current_user,current_setting('data_directory')").fetchone()
        if user!='prthak_test' or Path(directory).resolve()!=private_pg.data_directory():
            raise RuntimeError('Only the project-owned private test cluster is allowed')

    @classmethod
    def cleanup_databases(cls):
        with cls.driver.connect(**cls.parameters,dbname='postgres',autocommit=True) as db:
            cls.verify_cluster(db)
            for name in cls.created:
                db.execute(cls.sql.SQL('DROP DATABASE {} WITH (FORCE)').format(cls.sql.Identifier(name)))

    def make_store(self):
        from controller.postgres import PostgresStore
        for dsn in self.dsns.values():
            with self.driver.connect(dsn,autocommit=True) as db:
                self.verify_cluster(db);db.execute('DROP SCHEMA public CASCADE');db.execute('CREATE SCHEMA public')
        return PostgresStore(self.dsns['metadata'],self.dsns['traffic'])

    def setUp(self):
        with patch.object(fixtures,'Store',side_effect=lambda _:self.make_store()):
            super().setUp()
