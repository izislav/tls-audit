import unittest

from shared.tls_audit.archive import PostgresArchiveStore


class _FakeResult:
    def __init__(self, count: int = 0) -> None:
        self._count = count

    def fetchone(self):
        return {"count": self._count}


class _FakeConnection:
    def __init__(self) -> None:
        self.sql: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def execute(self, sql, params=None):
        self.sql.append(str(sql))
        return _FakeResult()


class _ArchiveStoreForCleanupTest(PostgresArchiveStore):
    def __init__(self, conn: _FakeConnection) -> None:
        super().__init__("postgresql://unused")
        self.conn = conn

    def connect(self):
        return self.conn


class ArchiveCleanupTests(unittest.TestCase):
    def test_cleanup_preserves_monitoring_snapshot_scans(self) -> None:
        conn = _FakeConnection()
        store = _ArchiveStoreForCleanupTest(conn)

        store.cleanup(retention_days=30, error_retention_days=7)

        cleanup_sql = "\n".join(conn.sql)
        self.assertIn("FROM monitoring_snapshots ms", cleanup_sql)
        self.assertIn("ms.scan_id = scans.id", cleanup_sql)


if __name__ == "__main__":
    unittest.main()
