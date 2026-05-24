import motor.motor_asyncio
import structlog
from config.settings import settings

log = structlog.get_logger()

_client: motor.motor_asyncio.AsyncIOMotorClient = None
_db = None


async def connect_mongo():
    global _client, _db
    _client = motor.motor_asyncio.AsyncIOMotorClient(
        settings.MONGODB_URI,
        maxPoolSize=20,
        minPoolSize=5,
        serverSelectionTimeoutMS=5000,
    )
    _db = _client[settings.MONGODB_DB]
    await _ensure_indexes()
    log.info("mongodb_connected", db=settings.MONGODB_DB)


async def _ensure_indexes():
    db = get_db()
    await db.threats.create_index([("timestamp", -1)])
    await db.threats.create_index([("severity", 1), ("status", 1)])
    await db.threats.create_index([("sourceIP", 1)])
    await db.threats.create_index([("threatType", 1)])
    await db.threats.create_index([("riskScore", -1)])

    # Text index for RAG keyword search in /agent/chat
    await db.threats.create_index(
        [
            ("threatType", "text"),
            ("sourceIP", "text"),
            ("targetAsset", "text"),
            ("description", "text"),
        ],
        name="threats_text_search",
    )

    await db.fp_features.create_index([("threatType", 1)])
    log.info("mongodb_indexes_ensured")


async def disconnect_mongo():
    global _client
    if _client:
        _client.close()
        log.info("mongodb_disconnected")


def get_db():
    if _db is None:
        raise RuntimeError("MongoDB not connected")
    return _db


def get_collection(name: str):
    return get_db()[name]