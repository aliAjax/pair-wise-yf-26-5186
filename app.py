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
                    protection_min INTEGER NOT NULL DEFAULT 2,
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
                CREATE TABLE IF NOT EXISTS custodians(
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS copies(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    location TEXT NOT NULL,
                    custodian_id TEXT REFERENCES custodians(id),
                    state TEXT NOT NULL DEFAULT 'healthy'
                        CHECK(state IN ('healthy','corrupt','degraded','staged','retired')),
                    created_at TEXT NOT NULL,
                    last_verified_at TEXT,
                    retired_at TEXT,
                    UNIQUE(version_id,location)
                );
                -- 同一保管机构在同一版本上只能持有一份有效副本（staged/healthy 均占位）
                -- 索引在 _migrate 中统一创建，以兼容旧库
                CREATE TABLE IF NOT EXISTS handovers(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                    outgoing_copy_id INTEGER NOT NULL REFERENCES copies(id),
                    outgoing_custodian_id TEXT REFERENCES custodians(id),
                    incoming_copy_id INTEGER NOT NULL REFERENCES copies(id),
                    incoming_custodian_id TEXT NOT NULL REFERENCES custodians(id),
                    state TEXT NOT NULL CHECK(state IN ('staging','verified','failed','completed','aborted')),
                    registered_by TEXT NOT NULL REFERENCES users(id),
                    registered_at TEXT NOT NULL,
                    finished_at TEXT,
                    last_error TEXT,
                    verify_attempts INTEGER NOT NULL DEFAULT 0
                );
                -- 同一版本同时只允许一场未结束的轮值交接（先登记的继续，后到冲突）
                -- 部分唯一索引在 _migrate 中统一创建，以兼容旧库
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
                """
            )
            self._migrate(conn)

    def _migrate(self, conn: sqlite3.Connection) -> None:
        """轻量迁移：给既有数据库补齐新列，并在副本状态枚举扩展后重建 copies。"""
        archive_cols = {r["name"] for r in conn.execute("PRAGMA table_info(archives)").fetchall()}
        if "protection_min" not in archive_cols:
            conn.execute("ALTER TABLE archives ADD COLUMN protection_min INTEGER NOT NULL DEFAULT 2")
        copy_cols = {r["name"] for r in conn.execute("PRAGMA table_info(copies)").fetchall()}
        if copy_cols:
            missing = {"custodian_id", "retired_at"} - copy_cols
            if missing:
                conn.execute("PRAGMA foreign_keys=OFF")
                conn.execute("PRAGMA legacy_alter_table=ON")
                conn.executescript(
                    """
                    ALTER TABLE copies RENAME TO copies_old;
                    CREATE TABLE copies(
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        version_id INTEGER NOT NULL REFERENCES archive_versions(id),
                        location TEXT NOT NULL,
                        custodian_id TEXT REFERENCES custodians(id),
                        state TEXT NOT NULL DEFAULT 'healthy'
                            CHECK(state IN ('healthy','corrupt','degraded','staged','retired')),
                        created_at TEXT NOT NULL,
                        last_verified_at TEXT,
                        retired_at TEXT,
                        UNIQUE(version_id,location)
                    );
                    INSERT INTO copies(id,version_id,location,custodian_id,state,created_at,last_verified_at,retired_at)
                    SELECT id,version_id,location,NULL,state,created_at,last_verified_at,NULL FROM copies_old;
                    DROP TABLE copies_old;
                    CREATE UNIQUE INDEX IF NOT EXISTS uq_active_copy_custodian
                        ON copies(version_id,custodian_id)
                        WHERE custodian_id IS NOT NULL AND state <> 'retired';
                    """
                )
                conn.execute("PRAGMA legacy_alter_table=OFF")
                conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(
            """CREATE UNIQUE INDEX IF NOT EXISTS uq_active_copy_custodian
               ON copies(version_id,custodian_id)
               WHERE custodian_id IS NOT NULL AND state <> 'retired'"""
        )
        conn.execute(
            """CREATE UNIQUE INDEX IF NOT EXISTS uq_active_handover
               ON handovers(version_id) WHERE state IN ('staging','verified','failed')"""
        )

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
            conn.executemany(
                "INSERT OR IGNORE INTO custodians(id,name,created_at) VALUES(?,?,?)",
                [
                    ("inst-alpha", "甲保管机构", now()),
                    ("inst-beta", "乙保管机构", now()),
                    ("inst-gamma", "丙保管机构", now()),
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

    def create_archive(self, user_id: str, name: str, retention_until: str, restricted: bool = True,
                       protection_min: int = 2) -> dict:
        name = name.strip()
        if len(name) < 2:
            raise BusinessError("档案名称至少 2 字", 422, "invalid_name")
        if not isinstance(protection_min, int) or not 1 <= protection_min <= 10:
            raise BusinessError("protection_min 必须是 1 到 10 的整数", 422, "invalid_protection_min")
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
                    "INSERT INTO archives(name,owner_id,retention_until,restricted,protection_min,created_at) VALUES(?,?,?,?,?,?)",
                    (name, user_id, retention_until, int(bool(restricted)), protection_min, now()),
                )
            except sqlite3.IntegrityError:
                raise BusinessError("档案名称已存在", 409, "archive_exists")
            archive_id = cur.lastrowid
            conn.execute(
                "INSERT INTO archive_members(archive_id,user_id,permission) VALUES(?,?,'write')", (archive_id, user_id)
            )
            self._audit(conn, archive_id, user_id, "archive.create",
                        {"retention_until": retention_until, "restricted": restricted, "protection_min": protection_min})
            return {"id": archive_id, "name": name, "retention_until": retention_until,
                    "restricted": restricted, "protection_min": protection_min}

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

    def add_copy(self, actor_id: str, version_id: int, location: str, custodian_id: str | None = None) -> dict:
        location = location.strip()
        if len(location) < 2:
            raise BusinessError("副本位置不能为空", 422, "invalid_location")
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
            if not version:
                raise BusinessError("档案版本不存在", 404, "not_found")
            self._access(conn, version["archive_id"], actor, require_write=True)
            if custodian_id is not None:
                if not conn.execute("SELECT 1 FROM custodians WHERE id=?", (custodian_id,)).fetchone():
                    raise BusinessError("保管机构不存在", 404, "custodian_not_found")
            try:
                conn.execute("BEGIN IMMEDIATE")
                cur = conn.execute(
                    "INSERT INTO copies(version_id,location,custodian_id,created_at,last_verified_at) VALUES(?,?,?,?,?)",
                    (version_id, location, custodian_id, now(), now()),
                )
                copy_id = cur.lastrowid
                conn.execute(
                    """INSERT INTO copy_files(copy_id,path,sha256,size,content)
                       SELECT ?,path,sha256,size,content FROM archive_files WHERE version_id=?""",
                    (copy_id, version_id),
                )
                self._audit(conn, version["archive_id"], actor_id, "copy.create",
                            {"copy_id": copy_id, "version_id": version_id, "location": location,
                             "custodian_id": custodian_id})
                return {"id": copy_id, "version_id": version_id, "location": location,
                        "custodian_id": custodian_id, "state": "healthy"}
            except sqlite3.IntegrityError as exc:
                conn.rollback()
                msg = str(exc)
                if "custodian" in msg.lower():
                    raise BusinessError("该保管机构在此版本上已持有有效副本", 409, "custodian_copy_exists")
                raise BusinessError("该版本的副本位置已存在", 409, "copy_exists")
            except Exception:
                conn.rollback()
                raise

    def create_custodian(self, actor_id: str, custodian_id: str, name: str) -> dict:
        custodian_id = custodian_id.strip()
        name = name.strip()
        if not custodian_id or any(c in custodian_id for c in " /?#") or len(custodian_id) > 64:
            raise BusinessError("保管机构 ID 不合法", 422, "invalid_custodian_id")
        if len(name) < 2:
            raise BusinessError("保管机构名称至少 2 字", 422, "invalid_custodian_name")
        with self.connect() as conn:
            self._user(conn, actor_id, {"owner", "archivist"})
            try:
                conn.execute("INSERT INTO custodians(id,name,created_at) VALUES(?,?,?)", (custodian_id, name, now()))
            except sqlite3.IntegrityError:
                raise BusinessError("保管机构 ID 已存在", 409, "custodian_exists")
            return {"id": custodian_id, "name": name}

    def list_custodians(self, actor_id: str) -> list[dict]:
        with self.connect() as conn:
            self._user(conn, actor_id, {"owner", "archivist", "auditor"})
            return [dict(r) for r in conn.execute("SELECT id,name,created_at FROM custodians ORDER BY id").fetchall()]

    # ------------------------------------------------------------------
    # 保管机构轮值交接：旧副本先保留，新副本逐份核对摘要与大小，
    # 双方已确认副本合并计入保护，全部核对通过后才允许旧机构退出。
    # ------------------------------------------------------------------

    def _protection_snapshot(self, conn: sqlite3.Connection, version_id: int, active_handover: sqlite3.Row | None = None) -> dict:
        """统计当前真正受到保护的副本：healthy 且未退役；交接中的新副本已核对通过也算一份。"""
        rows = conn.execute(
            """SELECT c.id,c.location,c.custodian_id,c.state,c.last_verified_at
               FROM copies c WHERE c.version_id=? AND c.state<>'retired' ORDER BY c.id""",
            (version_id,),
        ).fetchall()
        confirmed, sides = [], set()
        for r in rows:
            if r["state"] != "healthy":
                continue
            side = "other"
            if active_handover is not None:
                if r["id"] == active_handover["outgoing_copy_id"]:
                    side = "outgoing"
                elif r["id"] == active_handover["incoming_copy_id"]:
                    side = "incoming"
            confirmed.append({
                "copy_id": r["id"], "location": r["location"],
                "custodian_id": r["custodian_id"], "side": side,
                "last_verified_at": r["last_verified_at"],
            })
            sides.add(side)
        return {
            "protected_count": len(confirmed),
            "confirmed_copies": confirmed,
            "both_sides_confirmed": active_handover is not None
            and {"outgoing", "incoming"}.issubset(sides),
        }

    def register_handover(self, actor_id: str, version_id: int, outgoing_copy_id: int,
                          incoming_custodian_id: str, incoming_location: str) -> dict:
        """登记一场轮值：先登记的继续，后到的看到 handover_conflict。

        只登记与预拷贝，旧副本留在原位；新副本为 staged，核对通过前不计入保护。
        """
        incoming_location = incoming_location.strip()
        if len(incoming_location) < 2:
            raise BusinessError("新副本位置不能为空", 422, "invalid_location")
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (version_id,)).fetchone()
                if not version:
                    raise BusinessError("档案版本不存在", 404, "not_found")
                self._access(conn, version["archive_id"], actor, require_write=True)
                archive = conn.execute("SELECT * FROM archives WHERE id=?", (version["archive_id"],)).fetchone()
                outgoing = conn.execute("SELECT * FROM copies WHERE id=? AND version_id=?",
                                        (outgoing_copy_id, version_id)).fetchone()
                if not outgoing:
                    raise BusinessError("旧保管机构副本不存在或不属于该版本", 404, "outgoing_copy_not_found")
                if outgoing["state"] == "retired":
                    raise BusinessError("旧副本已退出，不能作为交接方", 409, "copy_retired")
                incoming_cust = conn.execute("SELECT * FROM custodians WHERE id=?", (incoming_custodian_id,)).fetchone()
                if not incoming_cust:
                    raise BusinessError("新保管机构不存在", 404, "custodian_not_found")
                if outgoing["custodian_id"] == incoming_custodian_id:
                    raise BusinessError("新旧保管机构不能相同", 409, "same_custodian")
                clash = conn.execute(
                    "SELECT * FROM handovers WHERE version_id=? AND state IN ('staging','verified','failed')",
                    (version_id,),
                ).fetchone()
                if clash:
                    raise BusinessError(
                        f"该版本已有进行中的轮值交接（handover {clash['id']}，先登记者继续）",
                        409, "handover_conflict",
                    )
                # 预拷贝：新机构副本进入 staged，内容已就位但尚未逐份核对
                try:
                    cur = conn.execute(
                        "INSERT INTO copies(version_id,location,custodian_id,state,created_at,last_verified_at) VALUES(?,?,?,'staged',?,NULL)",
                        (version_id, incoming_location, incoming_custodian_id, now()),
                    )
                except sqlite3.IntegrityError as exc:
                    if "uq_active_copy_custodian" in str(exc):
                        raise BusinessError("该保管机构在此版本上已持有有效副本", 409, "custodian_copy_exists")
                    raise BusinessError("该版本的副本位置已存在", 409, "copy_exists")
                incoming_copy_id = cur.lastrowid
                conn.execute(
                    """INSERT INTO copy_files(copy_id,path,sha256,size,content)
                       SELECT ?,path,sha256,size,content FROM archive_files WHERE version_id=?""",
                    (incoming_copy_id, version_id),
                )
                hcur = conn.execute(
                    """INSERT INTO handovers(version_id,outgoing_copy_id,outgoing_custodian_id,
                          incoming_copy_id,incoming_custodian_id,state,registered_by,registered_at)
                       VALUES(?,?,?,?,?,'staging',?,?)""",
                    (version_id, outgoing_copy_id, outgoing["custodian_id"],
                     incoming_copy_id, incoming_custodian_id, actor_id, now()),
                )
                handover_id = hcur.lastrowid
                self._audit(
                    conn, version["archive_id"], actor_id, "handover.register",
                    {"handover_id": handover_id, "version_id": version_id,
                     "outgoing_copy_id": outgoing_copy_id, "outgoing_custodian_id": outgoing["custodian_id"],
                     "incoming_copy_id": incoming_copy_id, "incoming_custodian_id": incoming_custodian_id,
                     "note": "旧副本保留至新副本逐份核对通过"},
                )
                snap = self._protection_snapshot(conn, version_id,
                                                 conn.execute("SELECT * FROM handovers WHERE id=?", (handover_id,)).fetchone())
                return {"handover_id": handover_id, "state": "staging",
                        "outgoing_copy_id": outgoing_copy_id, "outgoing_custodian_id": outgoing["custodian_id"],
                        "incoming_copy_id": incoming_copy_id, "incoming_custodian_id": incoming_custodian_id,
                        "protection_min": archive["protection_min"], "protection": snap}
            except BusinessError:
                conn.rollback()
                raise
            except sqlite3.IntegrityError as exc:
                conn.rollback()
                raise BusinessError(f"交接登记冲突: {exc}", 409, "handover_conflict")
            except Exception:
                conn.rollback()
                raise

    def verify_handover(self, actor_id: str, handover_id: int, corrupt_paths: list[str] | None = None) -> dict:
        """新机构逐份核对原文件摘要（SHA-256）与大小。

        核对全部通过：新副本变 healthy 并计入保护，交接变 verified，旧副本仍不动。
        任一份失败：交接变 failed，新副本标 corrupt 且不计入保护，旧副本继续保留，可重试。
        中断恢复：staging/failed 状态可再次调用（failed 会先从权威原文件重新拉一份）。
        """
        corrupt_paths = corrupt_paths or []
        if not isinstance(corrupt_paths, list) or not all(isinstance(p, str) for p in corrupt_paths):
            raise BusinessError("corrupt_paths 必须是字符串数组", 422, "invalid_corrupt_paths")
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist", "auditor"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                handover = conn.execute("SELECT * FROM handovers WHERE id=?", (handover_id,)).fetchone()
                if not handover:
                    raise BusinessError("交接不存在", 404, "not_found")
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (handover["version_id"],)).fetchone()
                self._access(conn, version["archive_id"], actor)
                state = handover["state"]
                if state in ("completed", "aborted"):
                    raise BusinessError(f"交接已{ '完成' if state == 'completed' else '中止'}，不能再核对",
                                        409, "handover_closed")
                incoming_copy_id = handover["incoming_copy_id"]
                # failed 重试：按原文件重新拷一份，保证从干净状态重新逐份核对
                if state == "failed":
                    conn.execute("DELETE FROM copy_files WHERE copy_id=?", (incoming_copy_id,))
                    conn.execute(
                        """INSERT INTO copy_files(copy_id,path,sha256,size,content)
                           SELECT ?,path,sha256,size,content FROM archive_files WHERE version_id=?""",
                        (incoming_copy_id, version["id"]),
                    )
                # 模拟/测试介质问题：在核对前线把指定文件损坏
                for p in corrupt_paths:
                    row = conn.execute("SELECT content FROM copy_files WHERE copy_id=? AND path=?",
                                       (incoming_copy_id, p)).fetchone()
                    if not row:
                        raise BusinessError(f"副本中不存在该文件: {p}", 404, "path_not_found")
                    damaged = bytes([row["content"][0] ^ 0xFF]) + row["content"][1:] if row["content"] else b"corrupt"
                    conn.execute("UPDATE copy_files SET content=? WHERE copy_id=? AND path=?",
                                 (damaged, incoming_copy_id, p))
                expected = {r["path"]: r for r in conn.execute(
                    "SELECT path,sha256,size FROM archive_files WHERE version_id=? ORDER BY path", (version["id"],)
                ).fetchall()}
                actual = conn.execute(
                    "SELECT path,sha256,size,content FROM copy_files WHERE copy_id=? ORDER BY path",
                    (incoming_copy_id,),
                ).fetchall()
                mismatches = []
                seen = set()
                for r in actual:
                    seen.add(r["path"])
                    if r["path"] not in expected:
                        mismatches.append({"path": r["path"], "reason": "unexpected_file"})
                        continue
                    exp = expected[r["path"]]
                    actual_hash = hashlib.sha256(r["content"]).hexdigest()
                    reasons = []
                    if actual_hash != exp["sha256"]:
                        reasons.append("sha256_mismatch")
                    if len(r["content"]) != exp["size"] or r["size"] != exp["size"]:
                        reasons.append("size_mismatch")
                    if reasons:
                        mismatches.append({"path": r["path"], "reason": ",".join(reasons),
                                           "expected_sha256": exp["sha256"], "actual_sha256": actual_hash,
                                           "expected_size": exp["size"], "actual_size": len(r["content"])})
                missing = sorted(set(expected) - seen)
                attempts = handover["verify_attempts"] + 1
                if not mismatches and not missing:
                    conn.execute(
                        "UPDATE copies SET state='healthy',last_verified_at=? WHERE id=?",
                        (now(), incoming_copy_id),
                    )
                    conn.execute(
                        "UPDATE handovers SET state='verified',verify_attempts=?,last_error=NULL,finished_at=NULL WHERE id=?",
                        (attempts, handover_id),
                    )
                    self._audit(
                        conn, version["archive_id"], actor_id, "handover.verify",
                        {"handover_id": handover_id, "incoming_copy_id": incoming_copy_id,
                         "incoming_custodian_id": handover["incoming_custodian_id"],
                         "result": "verified", "files_checked": len(expected), "attempt": attempts,
                         "note": "新机构逐份核对摘要与大小全部通过"},
                    )
                    result_state = "verified"
                    last_error = None
                else:
                    conn.execute("UPDATE copies SET state='corrupt' WHERE id=?", (incoming_copy_id,))
                    last_error = json.dumps({"mismatches": mismatches, "missing": missing}, ensure_ascii=False)
                    conn.execute(
                        "UPDATE handovers SET state='failed',verify_attempts=?,last_error=? WHERE id=?",
                        (attempts, last_error, handover_id),
                    )
                    self._audit(
                        conn, version["archive_id"], actor_id, "handover.verify",
                        {"handover_id": handover_id, "incoming_copy_id": incoming_copy_id,
                         "incoming_custodian_id": handover["incoming_custodian_id"],
                         "result": "failed", "mismatches": mismatches, "missing": missing, "attempt": attempts,
                         "note": "核对失败，旧副本保留，可重试"},
                    )
                    result_state = "failed"
                fresh = conn.execute("SELECT * FROM handovers WHERE id=?", (handover_id,)).fetchone()
                snap = self._protection_snapshot(conn, version["id"], fresh)
                return {"handover_id": handover_id, "state": result_state, "attempt": attempts,
                        "files_checked": len(expected), "mismatches": mismatches, "missing": missing,
                        "protection": snap}
            except Exception:
                conn.rollback()
                raise

    def complete_handover(self, actor_id: str, handover_id: int) -> dict:
        """两边确认过的副本合起来才算保护；完成前校验不会跌破保护阈值，随后旧机构退出。"""
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                handover = conn.execute("SELECT * FROM handovers WHERE id=?", (handover_id,)).fetchone()
                if not handover:
                    raise BusinessError("交接不存在", 404, "not_found")
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (handover["version_id"],)).fetchone()
                self._access(conn, version["archive_id"], actor, require_write=True)
                archive = conn.execute("SELECT * FROM archives WHERE id=?", (version["archive_id"],)).fetchone()
                if handover["state"] == "completed":
                    raise BusinessError("交接已完成", 409, "handover_closed")
                if handover["state"] != "verified":
                    raise BusinessError("新副本尚未逐份核对通过，旧副本不能退出", 409, "handover_not_verified")
                incoming = conn.execute("SELECT * FROM copies WHERE id=?", (handover["incoming_copy_id"],)).fetchone()
                outgoing = conn.execute("SELECT * FROM copies WHERE id=?", (handover["outgoing_copy_id"],)).fetchone()
                if incoming["state"] != "healthy" or outgoing["state"] == "retired":
                    raise BusinessError("交接双方副本状态已变化，请重新核对", 409, "handover_state_changed")
                # 旧副本退出后还剩多少确认副本（新机构 + 第三方），不得跌破保护阈值
                remaining = conn.execute(
                    "SELECT COUNT(*) FROM copies WHERE version_id=? AND state='healthy' AND id<>?",
                    (version["id"], handover["outgoing_copy_id"]),
                ).fetchone()[0]
                if remaining < archive["protection_min"]:
                    raise BusinessError(
                        f"旧机构退出后仅剩 {remaining} 份确认副本，低于保护阈值 {archive['protection_min']}，"
                        "请先补足确认副本再完成交接",
                        409, "protection_below_minimum",
                    )
                ts = now()
                conn.execute("UPDATE copies SET state='retired',retired_at=? WHERE id=?",
                             (ts, handover["outgoing_copy_id"]))
                conn.execute("UPDATE handovers SET state='completed',finished_at=? WHERE id=?", (ts, handover_id))
                self._audit(
                    conn, version["archive_id"], actor_id, "handover.complete",
                    {"handover_id": handover_id, "version_id": version["id"],
                     "outgoing_copy_id": handover["outgoing_copy_id"],
                     "outgoing_custodian_id": handover["outgoing_custodian_id"],
                     "incoming_copy_id": handover["incoming_copy_id"],
                     "incoming_custodian_id": handover["incoming_custodian_id"],
                     "remaining_protected": remaining,
                     "note": "新机构接手，旧机构退出，旧副本退役"},
                )
                return {"handover_id": handover_id, "state": "completed",
                        "incoming_custodian_id": handover["incoming_custodian_id"],
                        "outgoing_custodian_id": handover["outgoing_custodian_id"],
                        "protected_count": remaining, "protection_min": archive["protection_min"]}
            except Exception:
                conn.rollback()
                raise

    def abort_handover(self, actor_id: str, handover_id: int, reason: str = "") -> dict:
        """放弃交接：新机构退出（staged/corrupt 副本退役），旧副本留住。"""
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                handover = conn.execute("SELECT * FROM handovers WHERE id=?", (handover_id,)).fetchone()
                if not handover:
                    raise BusinessError("交接不存在", 404, "not_found")
                version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (handover["version_id"],)).fetchone()
                self._access(conn, version["archive_id"], actor, require_write=True)
                if handover["state"] in ("completed", "aborted"):
                    raise BusinessError("交接已结束", 409, "handover_closed")
                ts = now()
                conn.execute("UPDATE copies SET state='retired',retired_at=? WHERE id=?",
                             (ts, handover["incoming_copy_id"]))
                conn.execute("UPDATE handovers SET state='aborted',finished_at=?,last_error=? WHERE id=?",
                             (ts, reason.strip() or "aborted", handover_id))
                self._audit(
                    conn, version["archive_id"], actor_id, "handover.abort",
                    {"handover_id": handover_id, "incoming_copy_id": handover["incoming_copy_id"],
                     "incoming_custodian_id": handover["incoming_custodian_id"],
                     "outgoing_copy_id": handover["outgoing_copy_id"], "reason": reason.strip(),
                     "note": "新机构退出，旧副本保留"},
                )
                return {"handover_id": handover_id, "state": "aborted",
                        "outgoing_copy_retained": handover["outgoing_copy_id"]}
            except Exception:
                conn.rollback()
                raise

    def get_handover(self, actor_id: str, handover_id: int) -> dict:
        with self.connect() as conn:
            actor = self._user(conn, actor_id, {"owner", "archivist", "auditor"})
            handover = conn.execute("SELECT * FROM handovers WHERE id=?", (handover_id,)).fetchone()
            if not handover:
                raise BusinessError("交接不存在", 404, "not_found")
            version = conn.execute("SELECT * FROM archive_versions WHERE id=?", (handover["version_id"],)).fetchone()
            self._access(conn, version["archive_id"], actor)
            archive = conn.execute("SELECT protection_min FROM archives WHERE id=?", (version["archive_id"],)).fetchone()
            snap = self._protection_snapshot(conn, version["id"], handover)
            data = dict(handover)
            if data.get("last_error"):
                try:
                    data["last_error"] = json.loads(data["last_error"])
                except json.JSONDecodeError:
                    pass
            data["protection_min"] = archive["protection_min"]
            data["protection"] = snap
            return data

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
                """SELECT c.id,c.location,c.state,c.custodian_id,cu.name AS custodian_name,
                          c.last_verified_at,c.retired_at
                   FROM copies c LEFT JOIN custodians cu ON cu.id=c.custodian_id
                   WHERE c.version_id=? ORDER BY c.id""",
                (version_id,),
            ).fetchall()
            archive = conn.execute("SELECT * FROM archives WHERE id=?", (version["archive_id"],)).fetchone()
            active_handover = conn.execute(
                "SELECT * FROM handovers WHERE version_id=? AND state IN ('staging','verified','failed')",
                (version_id,),
            ).fetchone()
            snap = self._protection_snapshot(conn, version_id, active_handover)
            data = {"version": dict(version), "archive": dict(archive),
                    "files": [dict(x) for x in files], "copies": [dict(x) for x in copies]}
            data["protection_min"] = archive["protection_min"]
            data["protection"] = snap
            if active_handover:
                data["active_handover_id"] = active_handover["id"]
            return data

    def verify_copy(self, user_id: str, copy_id: int) -> dict:
        with self.connect() as conn:
            user = self._user(conn, user_id, {"owner", "archivist", "auditor"})
            try:
                conn.execute("BEGIN IMMEDIATE")
                copy = conn.execute("SELECT * FROM copies WHERE id=?", (copy_id,)).fetchone()
                if not copy:
                    raise BusinessError("副本不存在", 404, "not_found")
                if copy["state"] == "retired":
                    raise BusinessError("副本已退役，不能再校验", 409, "copy_retired")
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
            versions = conn.execute(
                "SELECT id,version,state,created_at FROM archive_versions WHERE archive_id=? ORDER BY version",
                (archive_id,)).fetchall()
            deadline = date.fromisoformat(archive["retention_until"])
            versions_out = []
            for v in versions:
                active_handover = conn.execute(
                    "SELECT id,state,incoming_custodian_id,outgoing_custodian_id FROM handovers "
                    "WHERE version_id=? AND state IN ('staging','verified','failed')", (v["id"],)
                ).fetchone()
                versions_out.append(dict(v) | {
                    "file_count": conn.execute(
                        "SELECT COUNT(*) FROM archive_files WHERE version_id=?", (v["id"],)).fetchone()[0],
                    "copy_count": conn.execute(
                        "SELECT COUNT(*) FROM copies WHERE version_id=? AND state<>'retired'", (v["id"],)).fetchone()[0],
                    "protected_count": conn.execute(
                        "SELECT COUNT(*) FROM copies WHERE version_id=? AND state='healthy'", (v["id"],)).fetchone()[0],
                    "active_handover": dict(active_handover) if active_handover else None,
                })
            return {
                "archive": dict(archive),
                "days_remaining": (deadline - date.today()).days,
                "versions": versions_out,
                "audit": [dict(r) | {"detail": json.loads(r["detail"])} for r in conn.execute("SELECT * FROM audit_log WHERE archive_id=? ORDER BY id", (archive_id,)).fetchall()],
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
            return self._send(201, store.create_archive(user, d.get("name", ""), d.get("retention_until", ""),
                                                        bool(d.get("restricted", True)),
                                                        int(d.get("protection_min", 2))))
        if parts == ["api", "custodians"] and method == "GET":
            return self._send(200, store.list_custodians(user))
        if parts == ["api", "custodians"] and method == "POST":
            d = self._body()
            return self._send(201, store.create_custodian(user, d.get("id", ""), d.get("name", "")))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "copies" and method == "POST":
            d = self._body()
            return self._send(201, store.add_copy(user, int(parts[2]), d.get("location", ""), d.get("custodian_id")))
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "handovers" and method == "POST":
            d = self._body()
            return self._send(201, store.register_handover(
                user, int(parts[2]), int(d.get("outgoing_copy_id", 0)),
                d.get("incoming_custodian_id", ""), d.get("incoming_location", "")))
        if len(parts) == 3 and parts[:2] == ["api", "handovers"] and method == "GET":
            return self._send(200, store.get_handover(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "handovers"] and parts[3] == "verify" and method == "POST":
            d = self._body()
            return self._send(200, store.verify_handover(user, int(parts[2]), d.get("corrupt_paths", [])))
        if len(parts) == 4 and parts[:2] == ["api", "handovers"] and parts[3] == "complete" and method == "POST":
            return self._send(200, store.complete_handover(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "handovers"] and parts[3] == "abort" and method == "POST":
            d = self._body()
            return self._send(200, store.abort_handover(user, int(parts[2]), d.get("reason", "")))
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
        if len(parts) == 4 and parts[:2] == ["api", "versions"] and parts[3] == "migrate" and method == "POST":
            d = self._body()
            return self._send(201, store.migrate(user, int(parts[2]), d.get("source_path", ""), d.get("target_path", ""), d.get("target_format", ""), d.get("content_b64", "")))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "verify" and method == "POST":
            return self._send(200, store.verify_copy(user, int(parts[2])))
        if len(parts) == 4 and parts[:2] == ["api", "copies"] and parts[3] == "simulate-corruption" and method == "POST":
            d = self._body()
            return self._send(200, store.simulate_corruption(user, int(parts[2]), d.get("path", "")))
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
