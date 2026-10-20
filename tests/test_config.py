import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import signin

MANAGED = (
    "WORKBUDDY_EXE", "WORKBUDDY_AUTH_FILE", "WORKBUDDY_SIGNIN_LOG",
    "WORKBUDDY_BUDGET_SECONDS", "WORKBUDDY_GROWTH_LOG_EMPTY",
    "WORKBUDDY_FEISHU_WEBHOOK", "WORKBUDDY_FEISHU_SECRET",
    "WORKBUDDY_FEISHU_NOTIFY", "WORKBUDDY_FEISHU_AT",
)


class ConfigFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "config.json"
        self.log = Path(self.temp.name) / "signin.log"
        env = {name: "" for name in MANAGED}          # 空串等同未设置，隔离宿主机环境
        env["WORKBUDDY_CONFIG"] = str(self.path)
        env["WORKBUDDY_SIGNIN_LOG"] = str(self.log)
        patcher = patch.dict(os.environ, env, clear=False)
        patcher.start()
        self.addCleanup(patcher.stop)
        signin._CONFIG = None
        signin._CONFIG_PATH = None
        self.addCleanup(setattr, signin, "_CONFIG", None)

    def write(self, data):
        self.path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    def test_missing_file_is_silent_and_keeps_defaults(self):
        self.assertEqual(signin._cfg("exe", env="WORKBUDDY_EXE", default="fallback"), "fallback")
        self.assertEqual({}, signin._config())
        self.assertIsNone(signin._CONFIG_WARNING)

    def test_values_are_read_from_file(self):
        self.write({"exe": r"D:\WB\WorkBuddy.exe", "feishu": {"notify": "error"}})
        self.assertEqual(signin._cfg("exe", env="WORKBUDDY_EXE", default=""),
                         r"D:\WB\WorkBuddy.exe")
        self.assertEqual(signin._cfg("feishu", "notify", default="daily"), "error")

    def test_environment_variable_wins_over_file(self):
        self.write({"exe": "from-file"})
        with patch.dict(os.environ, {"WORKBUDDY_EXE": "from-env"}):
            self.assertEqual(signin._cfg("exe", env="WORKBUDDY_EXE", default=""), "from-env")

    def test_blank_file_value_falls_back_to_default(self):
        self.write({"exe": ""})
        self.assertEqual(signin._cfg("exe", env="WORKBUDDY_EXE", default="default.exe"),
                         "default.exe")

    def test_broken_json_warns_and_still_runs(self):
        self.path.write_text("{ not json", encoding="utf-8")
        self.assertEqual(signin._cfg("exe", default="d"), "d")
        self.assertIn("读取失败", signin._CONFIG_WARNING)
        # 告警必须随第一条输出露出来，否则配错了也没人知道
        signin.emit({"result": "ALREADY"}, "silent")
        self.assertIn("config_warning", self.log.read_text(encoding="utf-8"))

    def test_non_object_json_warns(self):
        self.path.write_text("[1, 2]", encoding="utf-8")
        self.assertEqual({}, signin._config())
        self.assertIn("JSON 对象", signin._CONFIG_WARNING)

    def test_flag_accepts_bool_and_string(self):
        for raw, expected in ((True, True), ("yes", True), ("0", False), (False, False)):
            with self.subTest(raw=raw):
                self.write({"log_empty_polls": raw})
                signin._CONFIG = None
                self.assertIs(signin._cfg_flag("log_empty_polls"), expected)

    def test_budget_accepts_number_from_file(self):
        self.write({"budget_seconds": 120})
        self.assertEqual(signin._parse_budget()[0], 120)

    def test_bad_budget_from_file_warns_instead_of_crashing(self):
        self.write({"budget_seconds": "abc"})
        value, warning = signin._parse_budget()
        self.assertEqual(value, signin.DEFAULT_BUDGET_SECONDS)
        self.assertIn("不是数字", warning)

    def test_feishu_block_is_read_from_file(self):
        self.write({"feishu": {"webhook": "https://open.feishu.cn/hook/x",
                               "notify": "error",
                               "at": "ou_1234abcd5678efgh",
                               "secret": "s3cret-key"}})
        cfg = signin._feishu_config()
        self.assertEqual(cfg["policy"], "error")
        self.assertEqual(cfg["at"], "ou_1234abcd5678efgh")
        self.assertEqual(cfg["secret"], "s3cret-key")

    def test_config_path_can_be_relocated(self):
        other = Path(self.temp.name) / "nested" / "custom.json"
        other.parent.mkdir()
        other.write_text(json.dumps({"exe": "elsewhere"}), encoding="utf-8")
        with patch.dict(os.environ, {"WORKBUDDY_CONFIG": str(other)}):
            self.assertEqual(signin._cfg("exe", default=""), "elsewhere")

    def test_doctor_shows_where_config_came_from(self):
        self.write({"feishu": {"webhook": "https://open.feishu.cn/hook/x"}})
        session = {"auth": {"accessToken": "plain-token-123", "domain": "example.com"},
                   "account": {"uid": "u-1", "enterpriseId": "e-1"}}
        out = signin.run_doctor(session)
        self.assertEqual(out["config_file"], str(self.path))
        self.assertTrue(out["feishu_configured"])


if __name__ == "__main__":
    unittest.main()
