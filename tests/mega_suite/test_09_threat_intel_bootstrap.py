import pytest

from app.database import ensure_threat_intel_indexes
from app.main import bootstrap_threat_intel_to_redis
from app.utils.threat_intel import ThreatIntelligenceManager

pytestmark = [pytest.mark.asyncio, pytest.mark.backend, pytest.mark.hardening]


class _FakeCursor:
    def __init__(self, documents):
        self._documents = list(documents)
        self._index = 0

    def sort(self, *args, **kwargs):
        return self

    def __aiter__(self):
        self._index = 0
        return self

    async def __anext__(self):
        if self._index >= len(self._documents):
            raise StopAsyncIteration
        document = self._documents[self._index]
        self._index += 1
        return document


class _FakeCollection:
    def __init__(self, documents, index_information=None):
        self.documents = list(documents)
        self._index_information = index_information or {"_id_": {"key": [("_id", 1)]}}
        self.deleted_ids = []
        self.created_indexes = []
        self.dropped_indexes = []

    def find(self, query, projection=None):
        return _FakeCursor(self.documents)

    async def index_information(self):
        return self._index_information

    async def drop_index(self, index_name):
        self.dropped_indexes.append(index_name)
        self._index_information.pop(index_name, None)

    async def create_index(self, keys, name=None, unique=False, **kwargs):
        self.created_indexes.append({"keys": keys, "name": name, "unique": unique, **kwargs})
        index_name = name or "ip_1"
        self._index_information[index_name] = {"key": keys, "unique": unique}
        return index_name

    async def delete_many(self, query):
        ids = set(query.get("_id", {}).get("$in", []))
        self.deleted_ids.extend(ids)
        self.documents = [document for document in self.documents if document.get("_id") not in ids]


class _FakeDB:
    def __init__(self, collection):
        self._collection = collection

    def get_collection(self, name):
        assert name == "threat_intel_learned_ips"
        return self._collection


class _FakeMongoCollection:
    def __init__(self, documents):
        self._documents = list(documents)

    def find(self, query, projection=None):
        assert query == {}
        return _FakeCursor(self._documents)


class _FakeMongoDB:
    def __init__(self, documents):
        self._collections = {"threat_intel_learned_ips": _FakeMongoCollection(documents)}

    def __getitem__(self, name):
        return self._collections[name]


class _FakeRedisPipeline:
    def __init__(self):
        self.commands = []
    def setex(self, key, ttl, value):
        self.commands.append((key, ttl, value))
    async def execute(self):
        pass

class _FakeRedisClient:
    def __init__(self):
        self.pipeline_instance = _FakeRedisPipeline()
    def pipeline(self):
        return self.pipeline_instance

async def test_bootstrap_threat_intel_to_redis_loads_unique_ips_from_mongo():
    db = _FakeMongoDB(
        [
            {"ip": "1.1.1.1"},
            {"ip": "2.2.2.2"},
            {"ip": "1.1.1.1"},
            {"ip": ""},
            {},
        ]
    )

    redis_client = _FakeRedisClient()
    loaded = await bootstrap_threat_intel_to_redis(db, redis_client)

    assert loaded == 3 # 1.1.1.1 twice, 2.2.2.2 once. Redis SADD/SET handles duplicates implicitly.
    assert len(redis_client.pipeline_instance.commands) == 3
    keys = [cmd[0] for cmd in redis_client.pipeline_instance.commands]
    assert "threat_intel:ip:1.1.1.1" in keys
    assert "threat_intel:ip:2.2.2.2" in keys


async def test_threat_intel_manager_ignores_file_backed_intel_sources():
    manager = ThreatIntelligenceManager(
        {
            "threat_intelligence": {
                "ips": ["8.8.8.8"],
                "files": ["legacy-threats.txt"],
            }
        }
    )

    assert "8.8.8.8" in manager.threat_data["ips"]
    assert "legacy-threats.txt" not in manager.threat_data["domains"]
    assert manager.threat_data["cidrs"] == set()


async def test_ensure_threat_intel_indexes_dedupes_and_enforces_uniqueness():
    collection = _FakeCollection(
        [
            {"_id": 1, "ip": "9.9.9.9", "timestamp": 3},
            {"_id": 2, "ip": "9.9.9.9", "timestamp": 2},
            {"_id": 3, "ip": "7.7.7.7", "timestamp": 1},
        ],
        index_information={
            "_id_": {"key": [("_id", 1)]},
            "ip_1": {"key": [("ip", 1)], "unique": False},
        },
    )
    db = _FakeDB(collection)

    await ensure_threat_intel_indexes(db)

    assert collection.dropped_indexes == ["ip_1"]
    assert collection.deleted_ids == [2]
    assert any(index["unique"] is True for index in collection.created_indexes)
    assert collection._index_information["ip_1"]["unique"] is True