"""Optional disposable PostgreSQL variant; never reuses an inventory database.

Set PRTHAK_AUDIT_POSTGRES_ADMIN_DSN to a private fixture PostgreSQL admin DSN.
Every test creates and drops only fresh prthak_test_audit_export_* databases.
"""
import os
import unittest
import uuid

from controller.tests import test_evidence_views as fixture


@unittest.skipUnless(os.environ.get('PRTHAK_AUDIT_POSTGRES_ADMIN_DSN'),'Private disposable PostgreSQL fixture not configured')
class PostgresEvidenceViews(fixture.EvidenceViewTests):
    def make_store(self):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        from controller.postgres import PostgresStore
        admin=os.environ['PRTHAK_AUDIT_POSTGRES_ADMIN_DSN']
        suffix=uuid.uuid4().hex[:12]
        names=['prthak_test_audit_export_'+suffix+'_'+kind for kind in ('meta','traffic')]
        created=[]
        def cleanup():
            with psycopg.connect(admin,autocommit=True) as connection:
                for name in created:
                    connection.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(name)))
        self.addCleanup(cleanup)
        with psycopg.connect(admin,autocommit=True) as connection:
            for name in names:
                connection.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)));created.append(name)
        return PostgresStore(*(make_conninfo(admin,dbname=name) for name in names))
