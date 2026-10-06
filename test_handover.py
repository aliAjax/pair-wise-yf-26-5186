import base64
import hashlib
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

from app import BusinessError, PreservationStore


class HandoverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PreservationStore(Path(self.tmp.name) / "test.db")
        self.store.seed()
        self.archive = self.store.create_archive("owner", "城市测绘档案", (date.today() + timedelta(days=3650)).isoformat())
        self.raw = b"<record><id>1</id></record>"
        self.raw2 = b"archive readme"
        self.version = self.store.ingest_version("owner", self.archive["id"], [
            {"path": "records/one.xml", "content_b64": base64.b64encode(self.raw).decode()},
            {"path": "README.txt", "content_b64": base64.b64encode(self.raw2).decode()},
        ])
        self.copy1 = self.store.add_copy("owner", self.version["id"], "offline-disk-a")["id"]
        self.copy2 = self.store.add_copy("owner", self.version["id"], "offline-disk-b")["id"]
        self.inst_a = self.store.register_institution("owner", "机构甲", "甲机房")["id"]
        self.inst_b = self.store.register_institution("owner", "机构乙", "乙机房")["id"]
        self.store.assign_custodian("owner", self.version["id"], self.inst_a)

    def tearDown(self):
        self.tmp.cleanup()

    def _manifest(self, *, corrupt: bool = False):
        """新机构逐份核对用的 path/sha256/size 清单。"""
        files = [
            ("records/one.xml", self.raw),
            ("README.txt", self.raw2),
        ]
        out = []
        for path, raw in files:
            digest = hashlib.sha256(raw).hexdigest()
            if corrupt and path == "records/one.xml":
                digest = "0" * 64
            out.append({"path": path, "sha256": digest, "size": len(raw)})
        return out

    def _audit_actions(self):
        status = self.store.archive_status("owner", self.archive["id"])
        return [(e["action"], e["detail"]) for e in status["audit"]]

    def test_safe_rotation_keeps_old_copies_until_confirmed(self):
        # 登记轮值：旧副本留在原位，保护不丢。
        handover = self.store.register_handover("owner", self.version["id"], self.inst_b, self.inst_a)
        self.assertEqual(handover["state"], "pending")
        protection = self.store.protection_state("owner", self.version["id"])
        self.assertEqual(protection["healthy_copies"], 2)
        self.assertTrue(protection["protected"])

        # 两家机构同时提交同一份档案的轮值：先登记的继续，后到的看到冲突。
        with self.assertRaises(BusinessError) as ctx:
            self.store.register_handover("owner", self.version["id"], self.inst_b, self.inst_a)
        self.assertEqual(ctx.exception.code, "handover_conflict")
        self.assertEqual(ctx.exception.status, 409)

        # 新机构逐份核对摘要与大小，通过前旧副本仍在。
        result = self.store.verify_handover("owner", handover["id"], self._manifest())
        self.assertEqual(result["state"], "verified")
        self.assertEqual(result["mismatches"], [])
        protection = self.store.protection_state("owner", self.version["id"])
        self.assertEqual(protection["healthy_copies"], 3)  # 旧两份 + 新一份，只增不减

        # 两边确认过的副本合起来才算保护。
        confirmed = self.store.confirm_handover("owner", handover["id"])
        self.assertEqual(confirmed["state"], "confirmed")

        # 完成交接：新机构接手，旧机构退出，但旧副本留住。
        completed = self.store.complete_handover("owner", handover["id"])
        self.assertEqual(completed["state"], "completed")
        protection = self.store.protection_state("owner", self.version["id"])
        self.assertEqual(protection["healthy_copies"], 3)
        states = {c["institution_id"]: c["state"] for c in protection["custodians"]}
        self.assertEqual(states.get(self.inst_b), "active")
        self.assertEqual(states.get(self.inst_a), "retired")

        # 审计记下谁接手、谁退出。
        actions = self._audit_actions()
        complete_entry = next(detail for action, detail in actions if action == "handover.complete")
        self.assertEqual(complete_entry["took_over_institution_id"], self.inst_b)
        self.assertEqual(complete_entry["exited_institution_id"], self.inst_a)

    def test_verify_failure_then_retry_keeps_old_copies(self):
        handover = self.store.register_handover("owner", self.version["id"], self.inst_b, self.inst_a)

        # 核对失败：摘要对不上，旧副本留住，状态 failed。
        failed = self.store.verify_handover("owner", handover["id"], self._manifest(corrupt=True))
        self.assertEqual(failed["state"], "failed")
        self.assertTrue(any(m["reason"] == "sha256_mismatch" for m in failed["mismatches"]))
        protection = self.store.protection_state("owner", self.version["id"])
        self.assertEqual(protection["healthy_copies"], 2)  # 旧副本没被撤掉

        # 核对失败后能接着重试：重新提交正确清单。
        retried = self.store.verify_handover("owner", handover["id"], self._manifest())
        self.assertEqual(retried["state"], "verified")
        self.assertEqual(retried["mismatches"], [])
        self.store.confirm_handover("owner", handover["id"])
        completed = self.store.complete_handover("owner", handover["id"])
        self.assertEqual(completed["state"], "completed")

    def test_abort_retains_old_copies_and_frees_slot(self):
        handover = self.store.register_handover("owner", self.version["id"], self.inst_b, self.inst_a)
        self.store.verify_handover("owner", handover["id"], self._manifest())
        aborted = self.store.abort_handover("owner", handover["id"])
        self.assertEqual(aborted["state"], "aborted")

        # 旧副本留住。
        protection = self.store.protection_state("owner", self.version["id"])
        self.assertEqual(protection["healthy_copies"], 3)

        # 中断后可重新登记轮值。
        again = self.store.register_handover("owner", self.version["id"], self.inst_b, self.inst_a)
        self.assertEqual(again["state"], "pending")

    def test_protection_never_drops_below_required(self):
        # 初始两份健康副本，满足法定份数。
        protection = self.store.protection_state("owner", self.version["id"])
        self.assertTrue(protection["protected"])
        self.assertEqual(protection["required_copies"], 2)

        handover = self.store.register_handover("owner", self.version["id"], self.inst_b, self.inst_a)
        # 核对前、核对中、确认后，健康副本数始终不低于法定份数。
        for _ in range(2):
            protection = self.store.protection_state("owner", self.version["id"])
            self.assertGreaterEqual(protection["healthy_copies"], protection["required_copies"])
        self.store.verify_handover("owner", handover["id"], self._manifest())
        protection = self.store.protection_state("owner", self.version["id"])
        self.assertGreaterEqual(protection["healthy_copies"], protection["required_copies"])
        self.store.confirm_handover("owner", handover["id"])
        self.store.complete_handover("owner", handover["id"])
        protection = self.store.protection_state("owner", self.version["id"])
        self.assertGreaterEqual(protection["healthy_copies"], protection["required_copies"])


if __name__ == "__main__":
    unittest.main()
