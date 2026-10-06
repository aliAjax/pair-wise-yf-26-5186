import base64
import hashlib
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from app import BusinessError, PreservationStore


class PreservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PreservationStore(Path(self.tmp.name) / "test.db")
        self.store.seed()
        self.archive = self.store.create_archive("owner", "城市测绘档案", (date.today() + timedelta(days=3650)).isoformat())
        self.raw = b"<record><id>1</id></record>"
        self.version = self.store.ingest_version("owner", self.archive["id"], [
            {"path": "records/one.xml", "content_b64": base64.b64encode(self.raw).decode()},
            {"path": "README.txt", "content_b64": base64.b64encode(b"archive readme").decode()},
        ])
        self.copy1 = self.store.add_copy("owner", self.version["id"], "offline-disk-a", "inst-alpha")["id"]
        self.copy2 = self.store.add_copy("owner", self.version["id"], "offline-disk-b", "inst-beta")["id"]

    def tearDown(self):
        self.tmp.cleanup()
    def test_integrity_repair_and_format_migration(self):
        self.store.simulate_corruption("owner", self.copy1, "records/one.xml")
        result = self.store.verify_copy("owner", self.copy1)
        self.assertEqual(result["state"], "healthy")
        self.assertTrue(result["repaired"])
        self.assertEqual(result["corrupt_paths"], ["records/one.xml"])
        migrated = self.store.migrate(
            "owner", self.version["id"], "records/one.xml", "records/one.html", "html",
            base64.b64encode(b"<html><body><p>1</p></body></html>").decode(),
        )
        detail = self.store.get_version("owner", migrated["id"])
        self.assertEqual(detail["version"]["version"], 2)
        self.assertTrue(any(f["path"] == "records/one.html" for f in detail["files"]))
        status = self.store.archive_status("owner", self.archive["id"])
        self.assertGreater(status["days_remaining"], 3000)

    def test_restricted_access_and_invalid_manifest_are_rejected(self):
        with self.assertRaises(BusinessError) as ctx:
            self.store.get_version("outsider", self.version["id"])
        self.assertEqual(ctx.exception.status, 403)
        with self.assertRaises(BusinessError) as ctx:
            self.store.ingest_version("owner", self.archive["id"], [{"path": "../escape.txt", "content_b64": "eA=="}])
        self.assertEqual(ctx.exception.code, "unsafe_path")
        with self.assertRaises(BusinessError) as ctx:
            self.store.add_copy("owner", self.version["id"], "offline-disk-a")
        self.assertEqual(ctx.exception.code, "copy_exists")


    def test_handover_keeps_old_copy_until_new_verified_then_protection_merges(self):
        """登记后：旧副本仍在原位；新副本 staged 不计保护。核对通过：双方确认副本合并计入保护。"""
        reg = self.store.register_handover("owner", self.version["id"], self.copy1, "inst-gamma", "offline-disk-c")
        handover_id = reg["handover_id"]
        self.assertEqual(reg["state"], "staging")
        self.assertEqual(reg["protection"]["protected_count"], 2)  # 甲乙仍在，丙 staged 不计
        detail = self.store.get_version("owner", self.version["id"])
        states = {c["location"]: c["state"] for c in detail["copies"]}
        self.assertEqual(states["offline-disk-a"], "healthy")   # 旧副本留在原位
        self.assertEqual(states["offline-disk-c"], "staged")    # 新副本尚未核对

        verified = self.store.verify_handover("owner", handover_id)
        self.assertEqual(verified["state"], "verified")
        self.assertEqual(verified["files_checked"], 2)
        # 两边确认过的副本合起来才算保护：甲乙丙三份 healthy
        self.assertEqual(verified["protection"]["protected_count"], 3)
        self.assertTrue(verified["protection"]["both_sides_confirmed"])

        done = self.store.complete_handover("owner", handover_id)
        self.assertEqual(done["state"], "completed")
        detail = self.store.get_version("owner", self.version["id"])
        states = {c["location"]: c["state"] for c in detail["copies"]}
        self.assertEqual(states["offline-disk-a"], "retired")   # 旧机构退出
        self.assertEqual(states["offline-disk-c"], "healthy")   # 新机构接手
        # 乙 + 丙 = 2，仍满足默认阈值
        self.assertEqual(detail["protection"]["protected_count"], 2)

    def test_second_registration_sees_conflict_and_first_continues(self):
        first = self.store.register_handover("owner", self.version["id"], self.copy1, "inst-gamma", "disk-gamma")
        with self.assertRaises(BusinessError) as ctx:
            self.store.register_handover("owner", self.version["id"], self.copy2, "inst-gamma", "disk-gamma-2")
        self.assertEqual(ctx.exception.status, 409)
        self.assertEqual(ctx.exception.code, "handover_conflict")
        # 先登记的继续，不受后到者影响
        self.assertEqual(self.store.get_handover("owner", first["handover_id"])["state"], "staging")

    def test_failed_verification_retains_old_copy_and_succeeds_on_retry(self):
        reg = self.store.register_handover("owner", self.version["id"], self.copy1, "inst-gamma", "disk-gamma")
        # 核对时发现一份摘要不符 -> failed，旧副本必须留住
        bad = self.store.verify_handover("owner", reg["handover_id"], corrupt_paths=["records/one.xml"])
        self.assertEqual(bad["state"], "failed")
        self.assertEqual(bad["mismatches"][0]["path"], "records/one.xml")
        self.assertIn("sha256_mismatch", bad["mismatches"][0]["reason"])
        self.assertEqual(bad["protection"]["protected_count"], 2)  # 旧副本仍提供保护
        detail = self.store.get_version("owner", self.version["id"])
        self.assertEqual({c["location"]: c["state"] for c in detail["copies"]}["offline-disk-a"], "healthy")

        # 交接中断/失败后接着重试：重新拉取原文件再逐份核对
        retry = self.store.verify_handover("owner", reg["handover_id"])
        self.assertEqual(retry["state"], "verified")
        self.assertEqual(retry["attempt"], 2)
        done = self.store.complete_handover("owner", reg["handover_id"])
        self.assertEqual(done["state"], "completed")

    def test_complete_blocked_when_protection_would_drop_below_minimum(self):
        archive = self.store.create_archive(
            "owner", "高保护档案", (date.today() + timedelta(days=365)).isoformat(), protection_min=2)
        version = self.store.ingest_version("owner", archive["id"], [
            {"path": "a.txt", "content_b64": base64.b64encode(b"aaa").decode()}])
        only_copy = self.store.add_copy("owner", version["id"], "disk-alpha", "inst-alpha")["id"]
        reg = self.store.register_handover("owner", version["id"], only_copy, "inst-beta", "disk-beta")
        self.store.verify_handover("owner", reg["handover_id"])
        # 旧机构一退就只剩新机构一份，低于阈值 2 -> 拒绝完成，旧副本留住
        with self.assertRaises(BusinessError) as ctx:
            self.store.complete_handover("owner", reg["handover_id"])
        self.assertEqual(ctx.exception.code, "protection_below_minimum")
        detail = self.store.get_version("owner", version["id"])
        self.assertEqual({c["location"]: c["state"] for c in detail["copies"]}["disk-alpha"], "healthy")
        # 补上第三方确认副本后即可完成
        self.store.add_copy("owner", version["id"], "disk-gamma", "inst-gamma")
        done = self.store.complete_handover("owner", reg["handover_id"])
        self.assertEqual(done["protected_count"], 2)

    def test_abort_retires_incoming_and_audit_records_who_joined_and_left(self):
        reg = self.store.register_handover("owner", self.version["id"], self.copy1, "inst-gamma", "disk-gamma")
        aborted = self.store.abort_handover("owner", reg["handover_id"], reason="网络中断放弃")
        self.assertEqual(aborted["state"], "aborted")
        detail = self.store.get_version("owner", self.version["id"])
        self.assertEqual({c["location"]: c["state"] for c in detail["copies"]}["offline-disk-a"], "healthy")
        self.assertEqual({c["location"]: c["state"] for c in detail["copies"]}["disk-gamma"], "retired")
        # 中止后同版本可重新登记（先登记的又能继续）
        again = self.store.register_handover("owner", self.version["id"], self.copy1, "inst-gamma", "disk-gamma2")
        self.assertEqual(again["state"], "staging")
        status = self.store.archive_status("owner", self.archive["id"])
        actions = {a["action"] for a in status["audit"]}
        self.assertIn("handover.register", actions)
        self.assertIn("handover.abort", actions)
        register_events = [a for a in status["audit"] if a["action"] == "handover.register"]
        self.assertTrue(any(e["detail"].get("incoming_custodian_id") == "inst-gamma" for e in register_events))

    def test_custodian_cannot_hold_two_active_copies_on_same_version(self):
        with self.assertRaises(BusinessError) as ctx:
            self.store.add_copy("owner", self.version["id"], "disk-alpha-2", "inst-alpha")
        self.assertEqual(ctx.exception.code, "custodian_copy_exists")


if __name__ == "__main__":
    unittest.main()
