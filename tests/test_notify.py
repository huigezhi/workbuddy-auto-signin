import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

# 测试一律不读本机 config.json：否则开发者自己的 exe / webhook 会渗进断言
os.environ.setdefault("WORKBUDDY_CONFIG", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "fixtures", "absent-config.json"))

import signin

WEBHOOK = "https://open.feishu.cn/open-apis/bot/v2/hook/aaaabbbb-cccc-dddd"


def lines_of(payload):
    """把 post 消息的段落还原成纯文本，方便按人读的方式断言。"""
    zh = payload["content"]["post"]["zh_cn"]
    return ["".join(seg.get("text", "") for seg in para if seg["tag"] == "text")
            for para in zh["content"]]


class FeishuConfigTests(unittest.TestCase):
    def test_signature_follows_documented_formula(self):
        # 飞书自定义机器人：key = "<timestamp>\n<secret>"，对空串做 HMAC-SHA256 再 base64
        self.assertEqual(signin._feishu_sign("1599360473", "demo-secret-key"),
                         "q7yGrDH162Z6e7wOJwqGAM4bJcck2QI2jnyqU2G3zfs=")

    def test_webhook_must_be_https(self):
        # 令牌就在 URL 路径里，明文 http 等于把令牌广播到链路上
        with patch.dict(os.environ, {"WORKBUDDY_FEISHU_WEBHOOK": "http://example.invalid/hook"}):
            self.assertIsNone(signin._feishu_config())

    def test_missing_webhook_means_disabled(self):
        with patch.dict(os.environ, {"WORKBUDDY_FEISHU_WEBHOOK": ""}):
            self.assertIsNone(signin._feishu_config())

    def test_bad_recipient_or_policy_falls_back_instead_of_failing(self):
        with patch.dict(os.environ, {
                "WORKBUDDY_FEISHU_WEBHOOK": WEBHOOK,
                "WORKBUDDY_FEISHU_AT": "someone@example.com",
                "WORKBUDDY_FEISHU_NOTIFY": "sometimes"}):
            cfg = signin._feishu_config()
        self.assertEqual(cfg["at"], "")
        self.assertEqual(cfg["policy"], "daily")

    def test_open_id_recipient_is_kept(self):
        with patch.dict(os.environ, {"WORKBUDDY_FEISHU_WEBHOOK": WEBHOOK,
                                     "WORKBUDDY_FEISHU_AT": "ou_1234abcd5678efgh"}):
            self.assertEqual(signin._feishu_config()["at"], "ou_1234abcd5678efgh")


class FeishuPolicyTests(unittest.TestCase):
    cfg = {"webhook": WEBHOOK, "secret": "", "at": "", "policy": "daily"}

    def test_daily_task_always_notifies_even_when_nothing_happened(self):
        self.assertTrue(signin._feishu_due("silent", {"result": "ALREADY"}, self.cfg))
        self.assertTrue(signin._feishu_due("auto", {"result": "ALREADY"}, self.cfg))

    def test_quiet_poll_is_skipped_but_poll_failure_is_not(self):
        self.assertFalse(signin._feishu_due(
            "silent-poll", {"result": "ALREADY", "needs_attention": False}, self.cfg))
        self.assertTrue(signin._feishu_due(
            "silent-poll", {"result": "NETWORK", "needs_attention": True}, self.cfg))

    def test_error_policy_only_on_attention(self):
        cfg = dict(self.cfg, policy="error")
        self.assertFalse(signin._feishu_due(
            "silent", {"result": "CLAIMED", "needs_attention": False}, cfg))
        self.assertTrue(signin._feishu_due(
            "silent", {"result": "AUTH_ERROR", "needs_attention": True}, cfg))

    def test_debug_commands_never_notify(self):
        out = {"result": "ERROR", "needs_attention": True}
        for action in ("doctor", "status", "claim", "all"):
            with self.subTest(action=action):
                self.assertFalse(signin._feishu_due(action, out, self.cfg))


class FeishuPayloadTests(unittest.TestCase):
    def cfg(self, **kwargs):
        base = {"webhook": WEBHOOK, "secret": "", "at": "", "policy": "daily"}
        base.update(kwargs)
        return base

    def test_status_summary_and_failure_reason_are_included(self):
        payload = signin._feishu_payload(self.cfg(), "silent", {
            "result": "NETWORK", "report": "网络不可达", "needs_attention": True,
            "reason": "RUNTIME_UNAVAILABLE"})
        text = "\n".join(lines_of(payload))
        self.assertEqual(payload["msg_type"], "post")
        self.assertIn("网络不可达", payload["content"]["post"]["zh_cn"]["title"])
        self.assertIn("状态：⚠️ 网络不可达 · 每日任务", text)
        self.assertIn("结果：网络不可达", text)
        self.assertIn("待处理：RUNTIME_UNAVAILABLE", text)

    def test_credit_streak_and_total_are_summarised(self):
        payload = signin._feishu_payload(self.cfg(), "silent", {
            "result": "CLAIMED", "report": "成功领取 100 积分", "credit": 100,
            "streak_days": 11, "total_credits": 1100, "needs_attention": False})
        text = "\n".join(lines_of(payload))
        self.assertIn("积分：+100 积分，连续 11 天，累计 1100 积分", text)

    def test_growth_summary_is_not_printed_twice(self):
        payload = signin._feishu_payload(self.cfg(), "silent", {
            "result": "ALREADY", "report": "今日已签过；领旅行礼物 +9 积分",
            "growth": "领旅行礼物 +9 积分", "needs_attention": False})
        self.assertEqual("\n".join(lines_of(payload)).count("领旅行礼物"), 1)

    def test_long_report_is_truncated(self):
        payload = signin._feishu_payload(self.cfg(), "silent", {
            "result": "CLAIMED", "report": "长" * 5000, "needs_attention": False})
        line = next(item for item in lines_of(payload) if item.startswith("结果："))
        self.assertLessEqual(len(line), signin.FEISHU_TEXT_LIMIT + len("结果："))

    def test_signature_and_recipient_only_when_configured(self):
        plain = signin._feishu_payload(self.cfg(), "silent", {"result": "CLAIMED"})
        self.assertNotIn("sign", plain)
        self.assertFalse(any(seg["tag"] == "at" for para in
                             plain["content"]["post"]["zh_cn"]["content"] for seg in para))

        signed = signin._feishu_payload(self.cfg(secret="demo-secret-key",
                                                at="ou_1234abcd5678efgh"),
                                        "silent", {"result": "CLAIMED"})
        self.assertTrue(signed["timestamp"].isdigit())
        self.assertTrue(signed["sign"])
        last = signed["content"]["post"]["zh_cn"]["content"][-1]
        self.assertEqual(last[0], {"tag": "at", "user_id": "ou_1234abcd5678efgh"})


class NotifyRunTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.log = Path(self.temp.name) / "signin.log"
        env = patch.dict(os.environ, {"WORKBUDDY_SIGNIN_LOG": str(self.log),
                                      "WORKBUDDY_FEISHU_WEBHOOK": WEBHOOK,
                                      "WORKBUDDY_FEISHU_NOTIFY": "daily"}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        signin._last_emit = None
        signin._sensitive_values.discard(WEBHOOK)
        self.addCleanup(setattr, signin, "_last_emit", None)

    def log_text(self):
        return self.log.read_text(encoding="utf-8") if self.log.exists() else ""

    def test_disabled_config_never_touches_network(self):
        with patch.dict(os.environ, {"WORKBUDDY_FEISHU_WEBHOOK": ""}), \
                patch.object(signin, "_request") as request:
            signin.emit({"result": "CLAIMED"}, "silent")
            self.assertIsNone(signin.notify_run())
        request.assert_not_called()

    def test_success_sends_one_post_and_logs_nothing_extra(self):
        with patch.object(signin, "_request",
                          return_value=(200, {"code": 0, "msg": "success"})) as request:
            signin.emit({"result": "CLAIMED", "needs_attention": False}, "silent")
            self.assertEqual(signin.notify_run(), "ok")
        self.assertEqual(request.call_count, 1)
        args, kwargs = request.call_args
        self.assertEqual(args[0], WEBHOOK)
        self.assertEqual(kwargs["method"], "POST")
        self.assertEqual(kwargs["timeout"], signin.FEISHU_TIMEOUT)
        self.assertNotIn("feishu", self.log_text())

    def test_feishu_business_error_is_logged_once_without_token(self):
        with patch.object(signin, "_request",
                          return_value=(200, {"code": 19021, "msg": "sign match fail"})):
            signin.emit({"result": "CLAIMED", "needs_attention": False}, "silent")
            reason = signin.notify_run()
        self.assertIn("19021", reason)
        log = self.log_text()
        self.assertIn('"feishu": "failed"', log)
        self.assertNotIn("aaaabbbb-cccc-dddd", log)

    def test_network_failure_is_reported_as_fixed_text(self):
        with patch.object(signin, "_request",
                          return_value=(signin.CODE_NO_NETWORK, {"error": "x"})):
            signin.emit({"result": "CLAIMED", "needs_attention": False}, "silent")
            self.assertEqual(signin.notify_run(), "网络不可达")

    def test_notification_exception_cannot_change_exit_code(self):
        def fake_run(action):
            signin.emit({"result": "CLAIMED", "needs_attention": False}, action)
            return 0

        # main() 从 argv 取命令，这里固定成每日任务，避免测试运行时被 unittest 的参数干扰
        with patch.object(sys, "argv", ["signin.py", "silent"]), \
                patch.object(signin, "_run", side_effect=fake_run), \
                patch.object(signin, "_request", side_effect=RuntimeError("boom")):
            self.assertEqual(signin.main(), 0)
        self.assertIn('"feishu": "failed"', self.log_text())

    def test_failed_run_still_notifies_and_keeps_its_exit_code(self):
        with patch.object(sys, "argv", ["signin.py", "silent"]), \
                patch.object(signin, "_run",
                             side_effect=signin.AuthError("RUNTIME_NOT_FOUND")), \
                patch.object(signin, "_request",
                             return_value=(200, {"code": 0})) as request:
            self.assertEqual(signin.main(), 1)
        self.assertEqual(request.call_count, 1)
        body = json.dumps(request.call_args[1]["payload"], ensure_ascii=False)
        self.assertIn("认证异常", body)
        self.assertIn("RUNTIME_NOT_FOUND", body)


if __name__ == "__main__":
    unittest.main()
