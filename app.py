"""数字档案长期保存服务：SQLite 多副本、哈希校验、修复与迁移。"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sqlite3
import threading
from datetime import date, datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / "preservation.db"
MAX_FILE_SIZE = 10 * 1024 * 1024
# 轮值交接期间必须维持的最低健康副本数（法定副本数）。
REQUIRED_COPIES = 2
# 仍占用“在任”名额的交接状态；同一档案同时只允许一个处于这些状态的交接。
ACTIVE_HANDOVER_STATES = ("pending", "verified", "confirmed", "failed")


class BusinessError(Exception):
    def __init__(self, message: str, status: int = 400, code: str = "bad_request"):
        super().__init__(message)
        self.message, self.status, self.code = message, status, code


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def verify_manifest(files: object) -> list[dict]:
    if not isinstance(files, list) or not files:
        raise BusinessError("files 必须是非空数组", 422, "invalid_manifest")
    result, seen = [], set()
    for item in files:
        if not isinstance(item, dict):
            raise BusinessError("文件条目必须是对象", 422, "invalid_manifest")
        raw_path = str(item.get("path", "")).strip().replace("\\", "/")
        pure = PurePosixPath(raw_path)
        if not raw_path or pure.is_absolute() or ".." in pure.parts or pure.name in {"", ".", ".."}:
            raise BusinessError(f"档案路径不安全: {raw_path}", 422, "unsafe_path")
        if raw_path in seen:
            raise BusinessError(f"档案路径重复: {raw_path}", 409, "duplicate_path")
        seen.add(raw_path)
        encoded = item.get("content_b64")
        if not isinstance(encoded, str):
            raise BusinessError(f"{raw_path} 缺少 content_b64", 422, "content_required")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            raise BusinessError(f"{raw_path} 不是合法 Base64", 422, "invalid_base64")
        if len(content) > MAX_FILE_SIZE:
            raise BusinessError(f"{raw_path} 超过单文件大小限制", 413, "file_too_large")
        result.append(
            {"path": raw_path, "content": content, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
        )
    return result


def verify_handover_manifest(files: object) -> list[dict]:
    """轮值核对用的清单：新机构逐份提交 path/sha256/size，与原文件摘要和大小比对。"""
    if not isinstance(files, list) or not files:
        raise BusinessError("files 必须是非空数组", 422, "invalid_manifest")
    result, seen = [], set()
    for item in files:
        if not isinstance(item, dict):
            raise BusinessError("文件条目必须是对象", 422, "invalid_manifest")
        raw_path = str(item.get("path", "")).strip().replace("\\", "/")
        pure = PurePosixPath(raw_path)
        if not raw_path or pure.is_absolute() or ".." in pure.parts or pure.name in {"", ".", ".."}:
            raise BusinessError(f"档案路径不安全: {raw_path}", 422, "unsafe_path")
        if raw_path in seen:
            raise BusinessError(f"档案路径重复: {raw_path}", 409, "duplicate_path")
        seen.add(raw_path)
        sha = item.get("sha256")
        if not isinstance(sha, str) or not sha.strip():
            raise BusinessError(f"{raw_path} 缺少 sha256", 422, "sha256_required")
        size = item.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise BusinessError(f"{raw_path} size 必须是非负整数", 422, "invalid_size")
        result.append({"path": raw_path, "sha256": sha.strip().lower(), "size": size})
    return result


class PreservationStore:
    def __init__(self, db_path: str | Path = DEFAULT_DB):
        self.db_path = str(db_path)
        self._lock = threading.Lock()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def init_schema(self) -> None:
        with self._lock, self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users(
                    id TEXT PRIMARY KEY, name TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('owner','archivist','auditor'))
                );
                CREATE TABLE IF NOT EXISTS archives(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    owner_id TEXT NOT NULL REFERENCES users(id),
                    retention_until TEXT NOT NULL,
                    restricted INTEGER NOT NULL DEFAULT 1 CHECK(restricted IN (0,1)),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS archive_members(
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    user_id TEXT NOT NULL REFERENCES users(id),
                    permission TEXT NOT NULL CHECK(permission IN ('read','write')),
                    PRIMARY KEY(archive_id,user_id)
                );
                CREATE TABLE IF NOT EXISTS archive_versions(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    version INTEGER NOT NULL,
                    state TEXT NOT NULL DEFAULT 'verified' CHECK(state IN ('verified','degraded')),
                    created_by TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL,
                    UNIQUE(archive_id,version)
                );
                CREATE TABLE IF NOT EXISTS archive_files(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    content BLOB NOT NULL,
                    UNIQUE(version_id,path)
                );
                CREATE TABLE IF NOT EXISTS copies(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    location TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'healthy' CHECK(state IN ('healthy','corrupt','degraded')),
                    created_at TEXT NOT NULL,
                    last_verified_at TEXT,
                    UNIQUE(version_id,location)
                );
                CREATE TABLE IF NOT EXISTS copy_files(
                    copy_id INTEGER NOT NULL REFERENCES copies(id),
                    path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    content BLOB NOT NULL,
                    PRIMARY KEY(copy_id,path)
                );
                CREATE TABLE IF NOT EXISTS migrations(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    target_version_id INTEGER NOT NULL UNIQUE REFERENCES archive_versions(id),
                    source_path TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    target_format TEXT NOT NULL,
                    actor_id TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_log(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    actor_id TEXT NOT NULL REFERENCES users(id),
                    action TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS institutions(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    contact TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS custodianships(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    institution_id INTEGER NOT NULL REFERENCES institutions(id),
                    state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','retired')),
                    created_at TEXT NOT NULL,
                    retired_at TEXT,
                    UNIQUE(version_id,institution_id)
                );
                CREATE TABLE IF NOT EXISTS handovers(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    archive_id INTEGER NOT NULL REFERENCES archives(id),
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    from_institution_id INTEGER NOT NULL REFERENCES institutions(id),
                    to_institution_id INTEGER NOT NULL REFERENCES institutions(id),
                    state TEXT NOT NULL DEFAULT 'pending'
                        CHECK(state IN ('pending','verified','confirmed','completed','failed','aborted')),
                    required_copies INTEGER NOT NULL DEFAULT 2,
                    new_copy_id INTEGER REFERENCES copies(id),
                    fail_reason TEXT,
                    created_by TEXT NOT NULL REFERENCES users(id),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS idx_handovers_one_active
                    ON handovers(archive_id)
                    WHERE state IN ('pending','verified','confirmed','failed');
                """
            )
            self._migrate(conn)

    def _migrate(self, conn: sqlite3.Connection) -> None:
        """为旧库补充 copies.institution_id 列（幂等）。"""
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(copies)").fetchall()]
        if "institution_id" not in cols:
            conn.execute("ALTER TABLE copies ADD COLUMN institution_id INTEGER REFERENCES institutions(id)")

    def seed(self) -> None:
        self.init_schema()
        with self.connect() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO users(id,name,role) VALUES(?,?,?)",
                [
                    ("owner", "机构档案负责人", "owner"),
                    ("archivist", "档案管理员", "archivist"),
                    ("auditor", "独立审计员", "auditor"),
                    ("outsider", "未授权访客", "auditor"),
                ],
            )

    def _user(self, conn, user_id: str | None, roles: set[str] | None = None) -> sqlite3.Row:
        if not user_id:
            raise BusinessError("缺少 X-User-Id", 401, "authentication_required")
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            raise BusinessError("用户不存在", 401, "unknown_user")
        if roles and user["role"] not in roles:
            raise BusinessError("当前角色无权执行此操作", 403, "forbidden")
        return user

    def _access(self, conn, archive_id: int, user: sqlite3.Row, require_write: bool = False) -> None:
        archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
        if not archive:
            raise BusinessError("档案不存在", 404, "not_found")
        if archive["owner_id"] == user["id"]:
            return
        row = conn.execute(
            "SELECT permission FROM archive_members WHERE archive_id=? AND user_id=?", (archive_id, user["id"])
        ).fetchone()
        if not row or (require_write and row["permission"] != "write"):
            raise BusinessError("没有该受限档案的访问权限", 403, "forbidden")

    def _audit(self, conn, archive_id: int, actor: str, action: str, detail: dict) -> None:
        conn.execute(
            "INSERT INTO audit_log(archive_id,actor_id,action,detail,created_at) VALUES(?,?,?,?,?)",
            (archive_id, actor, action, json.dumps(detail, ensure_ascii=False, sort_keys=True), now()),
        )

    def create_archive(self, user_id: str, name: str, retention_until: str, restricted: bool = True) -> dict:
        name = name.strip()
        if len(name) < 2:
            raise BusinessError("档案名称至少 2 字", 422, "invalid_name")
        try:
            deadline = date.fromisoformat(retention_until)
        except ValueError:
            raise BusinessError("retention_until 必须是 YYYY-MM-DD", 422, "invalid_retention")
        if deadline < date.today():
            raise BusinessError("保留期限不能早于今天", 422, "retention_in_past")
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist"})
            try:
                cur = conn.execute(
                    "INSERT INTO archives(name,owner_id,retention_until,restricted,created_at) VALUES(?,?,?,?,?)",
                    (name, user_id, retention_until, int(bool(restricted)), now()),
                )
            except sqlite3.IntegrityError:
                raise BusinessError("档案名称已存在", 409, "archive_exists")
            archive_id = cur.lastrowid
            conn.execute(
                "INSERT INTO archive_members(archive_id,user_id,permission) VALUES(?,?,'write')", (archive_id, user_id)
            )
            self._audit(conn, archive_id, user_id, "archive.create", {"retention_until": retention_until, "restricted": restricted})
            return {"id": archive_id, "name": name, "retention_until": retention_until, "restricted": restricted}

    def grant(self, actor_id: str, archive_id: int, user_id: str, permission: str) -> dict:
        if permission not in {"read", "write"}:
            raise BusinessError("permission 必须是 read 或 write", 422, "invalid_permission")
        with self.connect() as conn:
            actor = self._user(conn, actor_id)
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
            if not archive:
                raise BusinessError("档案不存在", 404, "not_found")
            if archive["owner_id"] != actor_id:
                raise BusinessError("只有档案所有者可以授权", 403, "forbidden")
            self._user(conn, user_id)
            conn.execute(
                """INSERT INTO archive_members(archive_id,user_id,permission) VALUES(?,?,?)
                   ON CONFLICT(archive_id,user_id) DO UPDATE SET permission=excluded.permission""",
                (archive_id, user_id, permission),
            )
            self._audit(conn, archive_id, actor_id, "access.grant", {"user_id": user_id, "permission": permission})
            return {"archive_id": archive_id, "user_id": user_id, "permission": permission}

    def ingest_version(self, actor_id: str, archive_id: int, files: object) -> dict:
        manifest = verify_manifest(files)
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            self._access(conn, archive_id, actor, require_write=True)
            try:
                conn.execute("BEGIN IMMEDIATE")
                version_no = conn.execute(
                    "SELECT COALESCE(MAX(version),0)+1 FROM archive_versions WHERE archive_id=?", (archive_id,)
                ).fetchone()[0]
                cur = conn.execute(
                    "INSERT INTO archive_versions(archive_id,version,created_by,created_at) VALUES(?,?,?,?)",
                    (archive_id, version_no, actor_id, now()),
                )
                version_id = cur.lastrowid
                for item in manifest:
                    conn.execute(
                        "INSERT INTO archive_files(version_id,path,sha256,size,content) VALUES(?,?,?,?,?)",
                        (version_id, item["path"], item["sha256"], item["size"], item["content"]),
                    )
                self._audit(
                    conn, archive_id, actor_id, "version.ingest",
                    {"version_id": version_id, "version": version_no, "files": len(manifest),
                     "manifest": [{"path": x["path"], "sha256": x["sha256"], "size": x["size"]} for x in manifest]},
                )
                return {"id": version_id, "archive_id": archive_id, "version": version_no, "file_count": len(manifest)}
            except Exception:
                conn.rollback()
                raise

    def add_copy(self, actor_id: str, version_id: int, location: str) -> dict:
        location = location.strip()
        if len(location) < 2:
            raise BusinessError("副本位置不能为空", 422, "invalid_location")
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not version:
                raise BusinessError("档案版本不存在", 404, "not_found")
            self._access(conn, version["archive_id"], actor, require_write=True)
            try:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    "INSERT INTO copies(version_id,location,created_at,last_verified_at) VALUES(?,?,?,?)",
                    (version_id, location, now(), now()),
                )
                copy_id = cur.lastrowid
                conn.execute(
                    """INSERT INTO copy_files(copy_id,path,sha256,size,content)
                       SELECT ?,path,sha256,size,content FROM archive_files WHERE version_id=?""",
                    (copy_id, version_id),
                )
                self._audit(conn, version["archive_id"], actor_id, "copy.create", {"copy_id": copy_id, "version_id": version_id, "location": location})
                return {"id": copy_id, "version_id": version_id, "location": location, "state": "healthy"}
            except sqlite3.IntegrityError:
                conn.rollback()
                raise BusinessError("该版本的副本位置已存在", 409, "copy_exists")
            except Exception:
                conn.rollback()
                raise

    def get_version(self, user_id: str, version_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not version:
                raise BusinessError("档案版本不存在", 404, "not_found")
            self._access(conn, version["archive_id"], user)
            files = conn.execute(
                "SELECT path,sha256,size FROM archive_files WHERE version_id=? ORDER BY path", (version_id,)
            ).fetchall()
            copies = conn.execute(
                "SELECT id,location,state,last_verified_at FROM copies WHERE version_id=? ORDER BY id", (version_id,)
            ).fetchall()
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (version["archive_id"],)).fetchone()
            return {"version": dict(version), "archive": dict(archive), "files": [dict(x) for x in files], "copies": [dict(x) for x in copies]}

    def verify_copy(self, user_id: str, copy_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
                if not copy:
                    raise BusinessError("副本不存在", 404, "not_found")
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
                self._access(conn, version["archive_id"], user)
                stored = conn.execute(
                    "SELECT path,sha256,size,content FROM copy_files WHERE copy_id=? ORDER BY path", (copy_id,)
                ).fetchall()
                corrupt_paths = [r["path"] for r in stored if hashlib.sha256(r["content"]).hexdigest() != r["sha256"] or len(r["content"]) != r["size"]]
                repaired = False
                if not corrupt_paths:
                    conn.execute("UPDATE copies SET state='healthy',last_verified_at=? WHERE id=?", (now(), copy_id))
                    result_state = "healthy"
                else:
                    conn.execute("UPDATE copies SET state='corrupt',last_verified_at=? WHERE id=?", (now(), copy_id))
                    healthy = conn.execute(
                        "SELECT id FROM copies WHERE version_id=? AND id<>? AND state='healthy' ORDER BY last_verified_at DESC LIMIT 1",
                        (copy["version_id"], copy_id),
                    ).fetchone()
                    result_state = "degraded"
                    if healthy:
                        donor = conn.execute(
                            "SELECT path,sha256,size,content FROM copy_files WHERE copy_id=? ORDER BY path", (healthy["id"],)
                        ).fetchall()
                        donor_by_path = {r["path"]: r for r in donor}
                        expected = {r["path"]: r for r in conn.execute(
                            "SELECT path,sha256,size FROM archive_files WHERE version_id=?", (copy["version_id"],)
                        ).fetchall()}
                        if set(donor_by_path) == set(expected) and all(
                            hashlib.sha256(donor_by_path[p]["content"]).hexdigest() == expected[p]["sha256"] for p in expected
                        ):
                            conn.execute("DELETE FROM copy_files WHERE copy_id=?", (copy_id,))
                            conn.execute(
                                """INSERT INTO copy_files(copy_id,path,sha256,size,content)
                                   SELECT ?,path,sha256,size,content FROM copy_files WHERE copy_id=?""",
                                (copy_id, healthy["id"]),
                            )
                            conn.execute("UPDATE copies SET state='healthy',last_verified_at=? WHERE id=?", (now(), copy_id))
                            repaired, result_state = True, "healthy"
                    if result_state == "degraded":
                        conn.execute("UPDATE archive_versions SET state='degraded' WHERE id=?", (copy["version_id"],))
                self._audit(
                    conn, version["archive_id"], user_id, "copy.verify",
                    {"copy_id": copy_id, "state": result_state, "corrupt_paths": corrupt_paths, "repaired": repaired},
                )
                return {"copy_id": copy_id, "state": result_state, "corrupt_paths": corrupt_paths, "repaired": repaired}
            except Exception:
                conn.rollback()
                raise

    def simulate_corruption(self, user_id: str, copy_id: int, path: str) -> dict:
        """仅用于演示和测试，在受控环境中模拟底层介质损坏。"""
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist"})
            copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
            if not copy:
                raise BusinessError("副本不存在", 404, "not_found")
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (copy["version_id"],)).fetchone()
            self._access(conn, version["archive_id"], user, require_write=True)
            row = conn.execute("SELECT content FROM copy_files WHERE copy_id=? AND path=?", (copy_id, path)).fetchone()
            if not row:
                raise BusinessError("副本文件不存在", 404, "not_found")
            damaged = bytes([row["content"][0] ^ 0xFF]) + row["content"][1:] if row["content"] else b"corrupt"
            conn.execute("UPDATE copy_files SET content=? WHERE copy_id=? AND path=?", (damaged, copy_id, path))
            conn.execute("UPDATE copies SET state='corrupt' WHERE id=?", (copy_id,))
            self._audit(conn, version["archive_id"], user_id, "copy.simulate_corruption", {"copy_id": copy_id, "path": path})
            return {"copy_id": copy_id, "path": path, "state": "corrupt"}

    def migrate(self, actor_id: str, version_id: int, source_path: str, target_path: str, target_format: str, content_b64: str) -> dict:
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            source_version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not source_version:
                raise BusinessError("源档案版本不存在", 404, "not_found")
            self._access(conn, source_version["archive_id"], actor, require_write=True)
            source = conn.execute(
                "SELECT * FROM archive_files WHERE version_id=? AND path=?", (version_id, source_path)
            ).fetchone()
            if not source:
                raise BusinessError("源文件不存在", 404, "source_not_found")
            converted = verify_manifest([{"path": target_path, "content_b64": content_b64}])[0]
            try:
                conn.execute("BEGIN IMMEDIATE")
                version_no = conn.execute(
                    "SELECT COALESCE(MAX(version),0)+1 FROM archive_versions WHERE archive_id=?", (source_version["archive_id"],)
                ).fetchone()[0]
                cur = conn.execute(
                    "INSERT INTO archive_versions(archive_id,version,created_by,created_at) VALUES(?,?,?,?)",
                    (source_version["archive_id"], version_no, actor_id, now()),
                )
                target_version_id = cur.lastrowid
                conn.execute(
                    """INSERT INTO archive_files(version_id,path,sha256,size,content)
                       SELECT ?,path,sha256,size,content FROM archive_files
                       WHERE version_id=? AND path<>?""",
                    (target_version_id, version_id, source_path),
                )
                conn.execute(
                    "INSERT INTO archive_files(version_id,path,sha256,size,content) VALUES(?,?,?,?,?)",
                    (target_version_id, converted["path"], converted["sha256"], converted["size"], converted["content"]),
                )
                conn.execute(
                    "INSERT INTO migrations(source_version_id,target_version_id,source_path,target_path,target_format,actor_id,created_at) VALUES(?,?,?,?,?,?,?)",
                    (version_id, target_version_id, source_path, converted["path"], target_format.strip(), actor_id, now()),
                )
                self._audit(
                    conn, source_version["archive_id"], actor_id, "format.migrate",
                    {"source_version_id": version_id, "target_version_id": target_version_id,
                     "source_path": source_path, "target_path": converted["path"], "target_format": target_format.strip()},
                )
                return {"id": target_version_id, "version": version_no, "source_version_id": version_id, "target_path": converted["path"]}
            except Exception:
                conn.rollback()
                raise

    def archive_status(self, user_id: str, archive_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            self._access(conn, archive_id, user)
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (archive_id,)).fetchone()
            versions = conn.execute("SELECT id,version,state,created_at FROM archive_versions WHERE archive_id=? ORDER BY version", (archive_id,)).fetchall()
            deadline = date.fromisoformat(archive["retention_until"])
            return {
                "archive": dict(archive),
                "days_remaining": (deadline - date.today()).days,
                "versions": [dict(v) | {"file_count": conn.execute("SELECT COUNT(*) FROM archive_files WHERE version_id=?", (v["id"],)).fetchone()[0],
                                         "copy_count": conn.execute("SELECT COUNT(*) FROM copies WHERE version_id=?", (v["id"],)).fetchone()[0]}
                             for v in versions],
                "audit": [dict(r) | {"detail": json.loads(r["detail"])} for r in conn.execute("SELECT * FROM audit_log WHERE archive_id=? ORDER BY id", (archive_id,)).fetchall()],
            }

    # ------------------------------------------------------------------
    # 保管机构与轮值交接
    # ------------------------------------------------------------------

    def _handover_dict(self, conn: sqlite3.Connection, handover_id: int) -> dict | None:
        h = conn.execute("SELECT * FROM handovers WHERE id=?", (handover_id,)).fetchone()
        if not h:
            return None
        d = dict(h)
        from_inst = conn.execute("SELECT id,name FROM institutions WHERE id=?", (h["from_institution_id"],)).fetchone()
        to_inst = conn.execute("SELECT id,name FROM institutions WHERE id=?", (h["to_institution_id"],)).fetchone()
        d["from_institution"] = dict(from_inst) if from_inst else None
        d["to_institution"] = dict(to_inst) if to_inst else None
        d["mismatches"] = json.loads(h["fail_reason"]) if h["fail_reason"] else []
        return d

    def register_institution(self, actor_id: str, name: str, contact: str = "") -> dict:
        name = name.strip()
        if len(name) < 2:
            raise BusinessError("机构名称至少 2 字", 422, "invalid_name")
        with self.connect() as conn:
            self._user(conn, actor_id, {"owner", "archivist"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    "INSERT INTO institutions(name,contact,created_at) VALUES(?,?,?)",
                    (name, contact.strip(), now()),
                )
                return {"id": cur.lastrowid, "name": name, "contact": contact.strip()}
            except sqlite3.IntegrityError:
                conn.rollback()
                raise BusinessError("机构名称已存在", 409, "institution_exists")

    def list_institutions(self, user_id: str) -> dict:
        with self.connect() as conn:
            self._user(conn, user_id, {"owner", "archivist", "auditor"})
            rows = conn.execute(
                """SELECT i.id,i.name,i.contact,i.created_at,
                          (SELECT COUNT(*) FROM custodianships c WHERE c.institution_id=i.id AND c.state='active') AS active_custodianships
                   FROM institutions i ORDER BY i.id"""
            ).fetchall()
            return {"institutions": [dict(r) for r in rows]}

    def assign_custodian(self, actor_id: str, version_id: int, institution_id: int) -> dict:
        """把保管机构接到档案版本上（建立在任保管关系）。"""
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not version:
                raise BusinessError("档案版本不存在", 404, "not_found")
            self._access(conn, version["archive_id"], actor, require_write=True)
            inst = conn.execute("SELECT * FROM institutions WHERE id=?", (institution_id,)).fetchone()
            if not inst:
                raise BusinessError("保管机构不存在", 404, "institution_not_found")
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """INSERT INTO custodianships(version_id,institution_id,state,created_at,retired_at)
                       VALUES(?,?, 'active', ?, NULL)
                       ON CONFLICT(version_id,institution_id) DO UPDATE SET state='active', retired_at=NULL""",
                    (version_id, institution_id, now()),
                )
                self._audit(
                    conn, version["archive_id"], actor_id, "custodian.assign",
                    {"version_id": version_id, "institution_id": institution_id, "institution_name": inst["name"]},
                )
                return {"version_id": version_id, "institution_id": institution_id, "state": "active"}
            except Exception:
                conn.rollback()
                raise

    def register_handover(self, actor_id: str, version_id: int, to_institution_id: int,
                          from_institution_id: int | None = None) -> dict:
        """登记一次轮值交接。同一档案同时只允许一个未完成的交接：先登记的继续，后到的看到冲突。"""
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not version:
                raise BusinessError("档案版本不存在", 404, "not_found")
            self._access(conn, version["archive_id"], actor, require_write=True)
            to_inst = conn.execute("SELECT * FROM institutions WHERE id=?", (to_institution_id,)).fetchone()
            if not to_inst:
                raise BusinessError("接手机构不存在", 404, "institution_not_found")
            if from_institution_id is not None:
                from_inst = conn.execute("SELECT * FROM institutions WHERE id=?", (from_institution_id,)).fetchone()
                if not from_inst:
                    raise BusinessError("退出机构不存在", 404, "institution_not_found")
            try:
                conn.execute("BEGIN IMMEDIATE")
                if from_institution_id is None:
                    row = conn.execute(
                        """SELECT c.institution_id FROM custodianships c
                           WHERE c.version_id=? AND c.state='active' AND c.institution_id<>?
                           ORDER BY c.id DESC LIMIT 1""",
                        (version_id, to_institution_id),
                    ).fetchone()
                    if not row:
                        raise BusinessError("该版本没有可退出的在任保管机构", 409, "no_custodian_to_exit")
                    from_institution_id = row["institution_id"]
                cs = conn.execute(
                    "SELECT * FROM custodianships WHERE version_id=? AND institution_id=? AND state='active'",
                    (version_id, from_institution_id),
                ).fetchone()
                if not cs:
                    raise BusinessError("退出机构不是该版本的在任保管机构", 409, "not_active_custodian")
                already = conn.execute(
                    "SELECT id FROM custodianships WHERE version_id=? AND institution_id=? AND state='active'",
                    (version_id, to_institution_id),
                ).fetchone()
                if already:
                    raise BusinessError("接手机构已是该版本的在任保管机构", 409, "already_custodian")
                cur = conn.execute(
                    """INSERT INTO handovers(archive_id,version_id,from_institution_id,to_institution_id,
                                            state,required_copies,created_by,created_at,updated_at)
                       VALUES(?,?,?,?,'pending',?,?,?,?)""",
                    (version["archive_id"], version_id, from_institution_id, to_institution_id,
                     REQUIRED_COPIES, actor_id, now(), now()),
                )
                handover_id = cur.lastrowid
                self._audit(
                    conn, version["archive_id"], actor_id, "handover.register",
                    {"handover_id": handover_id, "version_id": version_id,
                     "from_institution_id": from_institution_id, "to_institution_id": to_institution_id},
                )
                return self._handover_dict(conn, handover_id)
            except sqlite3.IntegrityError:
                conn.rollback()
                raise BusinessError("该档案已有进行中的轮值交接，先登记的继续", 409, "handover_conflict")
            except Exception:
                conn.rollback()
                raise

    def verify_handover(self, actor_id: str, handover_id: int, files: object) -> dict:
        """新机构逐份核对原文件的摘要与大小。核对通过前旧副本留在原位；失败可重试。"""
        manifest = verify_handover_manifest(files)
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            handover = conn.execute("SELECT * FROM handovers WHERE id=?", (handover_id,)).fetchone()
            if not handover:
                raise BusinessError("轮值交接不存在", 404, "not_found")
            self._access(conn, handover["archive_id"], actor, require_write=True)
            if handover["state"] not in ("pending", "failed", "aborted"):
                raise BusinessError(f"当前状态({handover['state']})不允许核对", 409, "invalid_state")
            try:
                conn.execute("BEGIN IMMEDIATE")
                canonical = conn.execute(
                    "SELECT path,sha256,size FROM archive_files WHERE version_id=?", (handover["version_id"],)
                ).fetchall()
                canonical_map = {r["path"]: r for r in canonical}
                submitted_map = {item["path"]: item for item in manifest}
                mismatches: list[dict] = []
                if set(submitted_map) != set(canonical_map):
                    missing = sorted(set(canonical_map) - set(submitted_map))
                    extra = sorted(set(submitted_map) - set(canonical_map))
                    mismatches.append({"reason": "manifest_mismatch", "missing": missing, "extra": extra})
                for path, item in submitted_map.items():
                    if path not in canonical_map:
                        continue
                    canon = canonical_map[path]
                    if item["sha256"] != canon["sha256"]:
                        mismatches.append({"path": path, "reason": "sha256_mismatch",
                                           "expected": canon["sha256"], "actual": item["sha256"]})
                    if item["size"] != canon["size"]:
                        mismatches.append({"path": path, "reason": "size_mismatch",
                                           "expected": canon["size"], "actual": item["size"]})
                if not mismatches:
                    to_inst = conn.execute("SELECT * FROM institutions WHERE id=?", (handover["to_institution_id"],)).fetchone()
                    location = to_inst["name"]
                    existing = conn.execute(
                        "SELECT id FROM copies WHERE version_id=? AND location=?", (handover["version_id"], location)
                    ).fetchone()
                    if existing:
                        copy_id = existing["id"]
                        conn.execute("DELETE FROM copy_files WHERE copy_id=?", (copy_id,))
                        conn.execute(
                            "UPDATE copies SET state='healthy', institution_id=?, last_verified_at=? WHERE id=?",
                            (handover["to_institution_id"], now(), copy_id),
                        )
                    else:
                        cur = conn.execute(
                            """INSERT INTO copies(version_id,location,state,institution_id,created_at,last_verified_at)
                               VALUES(?,?, 'healthy', ?, ?, ?)""",
                            (handover["version_id"], location, handover["to_institution_id"], now(), now()),
                        )
                        copy_id = cur.lastrowid
                    conn.execute(
                        """INSERT INTO copy_files(copy_id,path,sha256,size,content)
                           SELECT ?,path,sha256,size,content FROM archive_files WHERE version_id=?""",
                        (copy_id, handover["version_id"]),
                    )
                    conn.execute(
                        "UPDATE handovers SET state='verified', new_copy_id=?, fail_reason=NULL, updated_at=? WHERE id=?",
                        (copy_id, now(), handover_id),
                    )
                    self._audit(
                        conn, handover["archive_id"], actor_id, "handover.verify",
                        {"handover_id": handover_id, "state": "verified", "mismatches": []},
                    )
                    return {"handover_id": handover_id, "state": "verified", "mismatches": []}
                conn.execute(
                    "UPDATE handovers SET state='failed', fail_reason=?, updated_at=? WHERE id=?",
                    (json.dumps(mismatches, ensure_ascii=False), now(), handover_id),
                )
                self._audit(
                    conn, handover["archive_id"], actor_id, "handover.verify",
                    {"handover_id": handover_id, "state": "failed", "mismatches": mismatches},
                )
                return {"handover_id": handover_id, "state": "failed", "mismatches": mismatches}
            except sqlite3.IntegrityError:
                conn.rollback()
                raise BusinessError("该档案已有进行中的轮值交接，先登记的继续", 409, "handover_conflict")
            except Exception:
                conn.rollback()
                raise

    def confirm_handover(self, actor_id: str, handover_id: int) -> dict:
        """在任保管机构确认交接。两边都确认过的副本合起来才算保护。"""
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            handover = conn.execute("SELECT * FROM handovers WHERE id=?", (handover_id,)).fetchone()
            if not handover:
                raise BusinessError("轮值交接不存在", 404, "not_found")
            self._access(conn, handover["archive_id"], actor, require_write=True)
            if handover["state"] != "verified":
                raise BusinessError(f"当前状态({handover['state']})不允许确认，需新机构核对通过", 409, "invalid_state")
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("UPDATE handovers SET state='confirmed', updated_at=? WHERE id=?", (now(), handover_id))
                self._audit(
                    conn, handover["archive_id"], actor_id, "handover.confirm",
                    {"handover_id": handover_id,
                     "from_institution_id": handover["from_institution_id"],
                     "to_institution_id": handover["to_institution_id"]},
                )
                return self._handover_dict(conn, handover_id)
            except Exception:
                conn.rollback()
                raise

    def complete_handover(self, actor_id: str, handover_id: int) -> dict:
        """完成交接：新机构接手，旧机构退出但副本留住；保护份数不得低于法定副本数。"""
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            handover = conn.execute("SELECT * FROM handovers WHERE id=?", (handover_id,)).fetchone()
            if not handover:
                raise BusinessError("轮值交接不存在", 404, "not_found")
            self._access(conn, handover["archive_id"], actor, require_write=True)
            if handover["state"] != "confirmed":
                raise BusinessError(f"当前状态({handover['state']})不允许完成，需双方确认", 409, "invalid_state")
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    """INSERT INTO custodianships(version_id,institution_id,state,created_at,retired_at)
                       VALUES(?,?, 'active', ?, NULL)
                       ON CONFLICT(version_id,institution_id) DO UPDATE SET state='active', retired_at=NULL""",
                    (handover["version_id"], handover["to_institution_id"], now()),
                )
                conn.execute(
                    "UPDATE custodianships SET state='retired', retired_at=? WHERE version_id=? AND institution_id=? AND state='active'",
                    (now(), handover["version_id"], handover["from_institution_id"]),
                )
                healthy = conn.execute(
                    "SELECT COUNT(*) AS c FROM copies WHERE version_id=? AND state='healthy'",
                    (handover["version_id"],),
                ).fetchone()["c"]
                if healthy < handover["required_copies"]:
                    raise BusinessError(
                        f"保护副本不足({healthy}<{handover['required_copies']})，不能完成交接",
                        409, "protection_insufficient",
                    )
                conn.execute("UPDATE handovers SET state='completed', updated_at=? WHERE id=?", (now(), handover_id))
                self._audit(
                    conn, handover["archive_id"], actor_id, "handover.complete",
                    {"handover_id": handover_id, "version_id": handover["version_id"],
                     "took_over_institution_id": handover["to_institution_id"],
                     "exited_institution_id": handover["from_institution_id"],
                     "new_copy_id": handover["new_copy_id"], "retained_copy_id": handover["new_copy_id"]},
                )
                return self._handover_dict(conn, handover_id)
            except Exception:
                conn.rollback()
                raise

    def abort_handover(self, actor_id: str, handover_id: int) -> dict:
        """中断交接。旧副本留住，已登记的交接作废；核对失败后可重新登记或重试。"""
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            handover = conn.execute("SELECT * FROM handovers WHERE id=?", (handover_id,)).fetchone()
            if not handover:
                raise BusinessError("轮值交接不存在", 404, "not_found")
            self._access(conn, handover["archive_id"], actor, require_write=True)
            if handover["state"] in ("completed", "aborted"):
                raise BusinessError(f"当前状态({handover['state']})不能中断", 409, "invalid_state")
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("UPDATE handovers SET state='aborted', updated_at=? WHERE id=?", (now(), handover_id))
                self._audit(
                    conn, handover["archive_id"], actor_id, "handover.abort",
                    {"handover_id": handover_id,
                     "from_institution_id": handover["from_institution_id"],
                     "to_institution_id": handover["to_institution_id"]},
                )
                return self._handover_dict(conn, handover_id)
            except Exception:
                conn.rollback()
                raise

    def get_handover(self, user_id: str, handover_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            handover = conn.execute("SELECT * FROM handovers WHERE id=?", (handover_id,)).fetchone()
            if not handover:
                raise BusinessError("轮值交接不存在", 404, "not_found")
            self._access(conn, handover["archive_id"], user)
            return self._handover_dict(conn, handover_id)

    def list_handovers(self, user_id: str, archive_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            self._access(conn, archive_id, user)
            rows = conn.execute(
                "SELECT * FROM handovers WHERE archive_id=? ORDER BY id", (archive_id,)
            ).fetchall()
            return {"handovers": [self._handover_dict(conn, r["id"]) for r in rows]}

    def protection_state(self, user_id: str, version_id: int) -> dict:
        """版本的保护状态：健康副本数、在任保管机构、未完成交接。"""
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not version:
                raise BusinessError("档案版本不存在", 404, "not_found")
            self._access(conn, version["archive_id"], user)
            copies = conn.execute(
                "SELECT id,location,state,institution_id FROM copies WHERE version_id=? ORDER BY id", (version_id,)
            ).fetchall()
            healthy = [c for c in copies if c["state"] == "healthy"]
            custodians = conn.execute(
                """SELECT c.institution_id, i.name, c.state FROM custodianships c
                   JOIN institutions i ON i.id=c.institution_id
                   WHERE c.version_id=? ORDER BY c.id""",
                (version_id,),
            ).fetchall()
            active_handover = conn.execute(
                """SELECT id,state,from_institution_id,to_institution_id,new_copy_id
                   FROM handovers WHERE version_id=? AND state IN ('pending','verified','confirmed','failed')
                   ORDER BY id DESC LIMIT 1""",
                (version_id,),
            ).fetchone()
            return {
                "version_id": version_id,
                "healthy_copies": len(healthy),
                "total_copies": len(copies),
                "required_copies": REQUIRED_COPIES,
                "protected": len(healthy) >= REQUIRED_COPIES,
                "copies": [dict(c) for c in copies],
                "custodians": [dict(c) for c in custodians],
                "active_handover": dict(active_handover) if active_handover else None,
            }


class Handler(BaseHTTPRequestHandler):
    server_version = "Preservation/1.0"

    def _store(self):
        return self.server.store  # type: ignore[attr-defined]

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise BusinessError("请求体必须是合法 JSON", 400, "invalid_json")
        if not isinstance(data, dict):
            raise BusinessError("JSON 顶层必须是对象", 422, "invalid_json")
        return data

    def _send(self, status: int, payload) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _dispatch(self, method: str) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"
        parts = [p for p in path.split("/") if p]
        user = self.headers.get("X-User-Id", "")
        if method == "GET" and path == "/":
            body = (BASE_DIR / "web" / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if method == "GET" and path == "/health":
            return self._send(200, {"ok": True})
        store = self._store()
        if parts == ["api", "archives"] and method == "POST":
            d = self._body()
            return self._send(201, store.create_archive(user, d.get("name", ""), d.get("retention_until", ""), bool(d.get("restricted", True))))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and method == "POST":
            archive_id = int(parts[2])
            if parts[3] == "versions":
                d = self._body()
                return self._send(201, store.ingest_version(user, archive_id, d.get("files")))
            if parts[3] == "members":
                d = self._body()
                return self._send(201, store.grant(user, archive_id, d.get("user_id", ""), d.get("permission", "")))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and parts[3] == "status" and method == "GET":
            return self._send(200, store.archive_status(user, int(parts[2])))
        if len(parts) == 3 and parts[:2] == ["api", "versions"] and method == "GET":
            return self._send(200, store.get_version(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "copies" and method == "POST":
            d = self._body()
            return self._send(201, store.add_copy(user, int(parts[2]), d.get("location", "")))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "migrate" and method == "POST":
            d = self._body()
            return self._send(201, store.migrate(user, int(parts[2]), d.get("source_path", ""), d.get("target_path", ""), d.get("target_format", ""), d.get("content_b64", "")))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "verify" and method == "POST":
            return self._send(200, store.verify_copy(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "simulate-corruption" and method == "POST":
            d = self._body()
            return self._send(200, store.simulate_corruption(user, int(parts[2]), d.get("path", "")))
        if parts == ["api", "institutions"] and method == "POST":
            d = self._body()
            return self._send(201, store.register_institution(user, d.get("name", ""), d.get("contact", "")))
        if parts == ["api", "institutions"] and method == "GET":
            return self._send(200, store.list_institutions(user))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "custodians" and method == "POST":
            d = self._body()
            return self._send(201, store.assign_custodian(user, int(parts[2]), int(d.get("institution_id", 0))))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "handovers" and method == "POST":
            d = self._body()
            return self._send(201, store.register_handover(user, int(parts[2]), int(d.get("to_institution_id", 0)),
                                                           d.get("from_institution_id")))
        if len(parts) == 4 and parts[:2] == ["api", "archives"] and parts[3] == "handovers" and method == "GET":
            return self._send(200, store.list_handovers(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "protection" and method == "GET":
            return self._send(200, store.protection_state(user, int(parts[2])))
        if len(parts) == 3 and parts[:2] == ["api", "handovers"] and method == "GET":
            return self._send(200, store.get_handover(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "handovers"] and method == "POST":
            handover_id = int(parts[2])
            action = parts[3]
            if action == "verify":
                d = self._body()
                return self._send(200, store.verify_handover(user, handover_id, d.get("files")))
            if action == "confirm":
                return self._send(200, store.confirm_handover(user, handover_id))
            if action == "complete":
                return self._send(200, store.complete_handover(user, handover_id))
            if action == "abort":
                return self._send(200, store.abort_handover(user, handover_id))
        raise BusinessError("接口不存在", 404, "not_found")

    def _handle(self, method: str) -> None:
        try:
            self._dispatch(method)
        except BusinessError as exc:
            self._send(exc.status, {"error": {"code": exc.code, "message": exc.message}})
        except (ValueError, TypeError):
            self._send(400, {"error": {"code": "invalid_path", "message": "路径参数格式错误"}})
        except Exception as exc:
            self._send(500, {"error": {"code": "internal_error", "message": str(exc)}})

    def do_GET(self): self._handle("GET")
    def do_POST(self): self._handle("POST")
    def do_DELETE(self): self._handle("DELETE")
    def log_message(self, fmt, *args): print(f"{self.address_string()} - {fmt % args}")


class PreservationServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, store):
        self.store = store
        super().__init__(address, Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description="数字档案长期保存服务")
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--port", type=int, default=8102)
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--seed", action="store_true")
    args = parser.parse_args()
    store = PreservationStore(args.db)
    store.init_schema()
    if args.seed:
        store.seed()
    if args.init or args.seed:
        print(f"数据库已初始化: {args.db}")
        return
    print(f"数字档案服务运行于 http://127.0.0.1:{args.port}")
    server = PreservationServer(("127.0.0.1", args.port), store)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
