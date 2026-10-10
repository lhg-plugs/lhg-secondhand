#!/usr/bin/env python3
"""lhg-secondhand 硬门之二：写入疑似二手交易信息时，提醒跑审计并核对三必须。

触发：PostToolUse / Write|Edit。只看写入的文件名与内容是否像交易信息，
不是则静默放行；是则给出一次性提醒（additionalContext）。

逃生方式：LHG_SECONDHAND_HOOKS_OFF=1（本次会话不再提醒），
或 /plugin disable lhg-secondhand。

设计原则：内部出错 fail-open；零第三方依赖。
"""

import json
import os
import re
import sys

NAME_RES = [
    re.compile(p) for p in
    ("交易", "trade", "二手", "验机", "商品", "listing")
]
CONTENT_RES = [
    re.compile(p) for p in
    ("二手", "转让", "出售", "验机", "序列号", "IMEI", "不退不换")
]


def main():
    if os.environ.get("LHG_SECONDHAND_HOOKS_OFF") == "1":
        return 0
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
    except Exception:
        return 0
    tool_input = payload.get("tool_input", {}) or {}
    path = tool_input.get("file_path", "") or ""
    base = os.path.basename(path)
    looks_like = any(r.search(base) for r in NAME_RES)
    if not looks_like and os.path.isfile(path):
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                head = f.read(4000)
            looks_like = sum(1 for r in CONTENT_RES if r.search(head)) >= 2
        except Exception:
            return 0
    if not looks_like:
        return 0
    msg = (
        "lhg-secondhand 提醒：你刚写入的文件疑似二手交易信息。"
        "付款前请跑一遍审计：\n"
        "python3 ${CLAUDE_PLUGIN_ROOT}/scripts/audit/trade_audit.py "
        "--target <目录> --format text\n"
        "并核对三必须：1) 走平台订单付款（不私下转账）"
        "2) 序列号官方查验 3) 交易确认书双方文字确认。"
    )
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": msg,
        }
    }
    sys.stdout.write(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
