#!/usr/bin/env python3
"""lhg-secondhand 确定性二手交易审计：扫描交易信息文本中的风险信号，零第三方依赖。

扫描目标目录下的 .txt / .md / .json 文件（视作交易信息文本：商品描述、
聊天记录整理、验机记录），输出 JSON 与人类可读报告；
有 blocker 时以 exit code 2 退出（供 hooks 与 CI 使用）。

价格偏离预警需要市场价区间，二选一：
  --market-low / --market-high 参数，或目标目录下的 market.txt
  （内容形如：市场参考价：2000-2500元）。

用法：
    python3 trade_audit.py --target <目录> [--format json|text]
        [--fail-on blocker|warning|nit]
        [--market-low 2000 --market-high 2500]

规则文案均为本项目原创（思路受开源交易安全清单启发，未复制任何第三方原文）。
"""

import argparse
import json
import os
import re
import sys

VERSION = "1.0.0"
TOOL = "lhg-secondhand/trade-audit"

SCAN_EXTS = {".txt", ".md", ".json"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv"}

PRICE_RES = [
    re.compile(r"(?:售价|价格|转让价|出|标价)\s*[:：]?\s*(?:人民币)?\s*(\d[\d,]*)\s*元"),
]
MARKET_RE = re.compile(r"市场参考价\s*[:：]?\s*(\d[\d,]*)\s*[-~～—]\s*(\d[\d,]*)")


class Finding:
    __slots__ = ("rule_id", "severity", "category", "title", "file", "line",
                 "snippet", "detail")

    def __init__(self, rule_id, severity, category, title, file, line,
                 snippet, detail):
        self.rule_id = rule_id
        self.severity = severity
        self.category = category
        self.title = title
        self.file = file
        self.line = line
        self.snippet = snippet
        self.detail = detail

    def to_dict(self):
        return {
            "rule_id": self.rule_id, "severity": self.severity,
            "category": self.category, "title": self.title,
            "file": self.file, "line": self.line,
            "snippet": self.snippet, "detail": self.detail,
        }


def collect_files(target):
    out = []
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if os.path.splitext(f)[1].lower() in SCAN_EXTS:
                out.append(os.path.join(root, f))
    return sorted(out)


def read_lines(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().splitlines()
    except UnicodeDecodeError:
        with open(path, encoding="gbk", errors="ignore") as f:
            return f.read().splitlines()


def num(s):
    return float(s.replace(",", ""))


class Rule:
    def __init__(self, rule_id, severity, category, title, detail):
        self.rule_id = rule_id
        self.severity = severity
        self.category = category
        self.title = title
        self.detail = detail
        RULES.append(self)

    def run(self, path, lines, text, ctx):
        raise NotImplementedError


RULES = []


class KeywordRule(Rule):
    """正文出现高危话术关键词即命中（支持否定表述排除）。"""

    def __init__(self, rule_id, severity, category, title, detail, keywords,
                 exclude=None):
        super().__init__(rule_id, severity, category, title, detail)
        self.res = [re.compile(k) for k in keywords]
        self.exclude = [re.compile(e) for e in (exclude or [])]

    def run(self, path, lines, text, ctx):
        for i, ln in enumerate(lines, 1):
            if any(e.search(ln) for e in self.exclude):
                continue
            for r in self.res:
                if r.search(ln):
                    yield Finding(self.rule_id, self.severity, self.category,
                                  self.title, path, i,
                                  ln.strip()[:120], self.detail)
                    break


class MissingRule(Rule):
    """正文缺少某类关键信息即命中一次。"""

    def __init__(self, rule_id, severity, category, title, detail, present_res):
        super().__init__(rule_id, severity, category, title, detail)
        self.present = [re.compile(p) for p in present_res]

    def run(self, path, lines, text, ctx):
        if not any(r.search(text) for r in self.present):
            yield Finding(self.rule_id, self.severity, self.category,
                          self.title, path, 0,
                          "(全文未检出相关表述)", self.detail)


# ---------------------------------------------------------------- 高危话术
KeywordRule(
    "SH-R001", "blocker", "高危话术", "高危：'不退不换/售出不退'",
    "对方声明\"不退不换/售出概不退换\"。二手交易最怕暗病，"
    "\"不退不换\"=把验机风险全甩给你。坚持：当面验机ok再付款，"
    "或走平台验机/担保交易；对方拒绝→放弃这单。",
    [r"不退不换", r"售出.{0,6}(不退|概不退换)", r"一经售出.{0,10}不退",
     r"离柜不退", r"不支持.{0,6}(退货|退款)"],
    exclude=[r"支持.{0,6}(退货|退款|7天)"],
)
KeywordRule(
    "SH-R002", "blocker", "高危话术", "高危：要求私下转账/绕过平台",
    "对方要求微信/支付宝直接转账、不走平台订单。二手平台订单有"
    "资金托管和纠纷仲裁，私下转账=裸奔，被骗难追回。坚持走平台付款；"
    "对方以\"平台扣费\"为由拒绝→大概率是骗子，放弃。",
    [r"私下转账", r"微信直接转", r"绕过平台", r"不走平台.{0,6}(付款|交易)",
     r"平台外付款", r"直接(转|付).{0,6}(微信|支付宝)"],
)
KeywordRule(
    "SH-R003", "blocker", "高危话术", "高危：走外部链接/二维码付款",
    "对方发外部链接或二维码要求付款。真平台交易都在 App 内完成，"
    "外部链接多为钓鱼（仿冒的付款页）。只点 App 内的官方付款按钮；"
    "已点开→不要输入任何密码，立即关闭并举报。",
    [r"外部链接", r"点击链接付款", r"扫码付款.{0,10}(微信|支付宝)",
     r"复制链接.{0,10}付款"],
)
KeywordRule(
    "SH-R004", "warning", "高危话术", "风险：'先付定金留货'",
    "对方要求先付定金才留货/才发货。定金一旦转出，主动权就在对方。"
    "建议：定金不超过总价 10%，走平台付（可退），并文字确认"
    "\"X 日内不发货/货不对板全额退定金\"；对方只收私下定金→放弃。",
    [r"先付定金", r"付定金.{0,6}(留货|预留|发货)", r"交定金.{0,6}才"],
)
KeywordRule(
    "SH-R005", "warning", "高危话术", "风险：拒绝验机/拒绝查序列号",
    "对方拒绝当面验机、拒绝提供序列号/IMEI 查验。二手数码的"
    "序列号能查保修、是否官换、是否被盗挂失——拒绝查=心里有鬼。"
    "坚持：序列号先行查验（官网/官方客服），当面按验机清单逐项测。",
    [r"不(支持|接受).{0,6}验机", r"拒绝.{0,6}验机", r"不给.{0,6}(序列号|IMEI)",
     r"序列号.{0,6}不(能|可以)查"],
)
KeywordRule(
    "SH-R006", "warning", "高危话术", "风险：'全新未拆封'低价话术",
    "对方宣称\"全新未拆封/官换未激活\"但价格远低于市场。真全新机"
    "不会亏本卖——多为翻新机、官换机冒充全新，或干脆是空单诈骗。"
    "对策：查序列号确认激活状态，要求未拆封塑封细节视频；"
    "价格+全新+私下交易三者叠加→直接放弃。",
    [r"全新未拆封", r"官换未激活", r"全新原封"],
)

# ---------------------------------------------------------------- 信息缺项
MissingRule(
    "SH-I001", "blocker", "信息缺项", "缺失：商品品类",
    "全文未检出明确的商品品类。连卖什么都说不清的交易信息，"
    "多为批量群发的诈骗文案。先让对方说清：品类+品牌+型号三要素。",
    [r"手机|电脑|笔记本|相机|镜头|手表|耳机|平板|显卡|主机|包|球鞋|"
     r"乐器|无人机|投影仪|显示器|键盘|iPhone|iPad|MacBook"],
)
MissingRule(
    "SH-I002", "blocker", "信息缺项", "缺失：品牌型号",
    "全文未检出品牌型号。\"苹果手机 9 成新\"和\"iPhone 14 128G 9 成新\""
    "是两种信息量——没有具体型号就无法查市场价、无法验机。要求对方"
    "提供：品牌+具体型号+配置（内存/存储/颜色）。",
    [r"iPhone\s*\d|华为\s*\w*Mate|小米\s*\d|MacBook|ThinkPad|索尼\s*\w*|"
     r"佳能\s*\w*|尼康\s*\w*|型号\s*[:：]?\s*\w+"],
)
MissingRule(
    "SH-I003", "warning", "信息缺项", "缺失：成色/使用情况描述",
    "全文未检出成色描述（几成新/使用时长/购买时间）。没有成色基准，"
    "价格无从评估，\"9 成新\"和\"7 成新\"差价可达 30%。要求对方："
    "购买时间+使用时长+外观成色照片（多角度，带时间戳）。",
    [r"\d\s*成新|使用.{0,6}(时长|时间)|购买.{0,6}时间|入手.{0,6}时间|"
     r"用了.{0,6}(年|个月)"],
)
MissingRule(
    "SH-I004", "warning", "信息缺项", "缺失：序列号/IMEI 查验约定",
    "全文未提及序列号/IMEI 查验。二手数码交易，序列号是验明正身的"
    "唯一钥匙：查保修期、查激活锁、查是否挂失。交易前要求对方提供"
    "序列号（关键位打码也行），官网/官方客服先行查验。",
    [r"序列号|IMEI|SN\s*码"],
)
MissingRule(
    "SH-I005", "warning", "信息缺项", "缺失：配件清单",
    "全文未提及配件（充电器/数据线/包装盒/发票）。配件齐全度影响"
    " 5%-15% 的估值，且是判断\"是否为原机主\"的旁证。要求对方列明："
    "原装配件有哪些、缺什么、发票/购买记录还在不在。",
    [r"配件|充电器|包装盒|发票|购买记录|原装"],
)
MissingRule(
    "SH-I006", "warning", "信息缺项", "缺失：故障/维修史声明",
    "全文未提及故障与维修史（是否拆修/进水/换屏）。二手最大的坑是"
    "暗病，要求对方文字确认：\"无拆无修、无进水、功能一切正常\"——"
    "白纸黑字写下来，事后发现问题这就是追责依据。",
    [r"无拆无修|未拆修|维修史|进水|换屏|故障"],
)
MissingRule(
    "SH-I007", "warning", "信息缺项", "缺失：交易方式约定",
    "事先说清。建议优先级：当面验货 > 平台验机服务 > 邮寄（保价+"
    "开箱视频）。邮寄务必走平台订单+保价，拒绝'货到付款'套路。",
    [r"当面|面交|验机|邮寄|平台.{0,6}(交易|担保)"],
)


class PriceRule(Rule):
    """价格偏离市场价区间预警（需市场价区间输入）。"""

    def __init__(self):
        super().__init__(
            "SH-P001", "warning", "价格异常", "预警：价格明显偏离市场价区间",
            "标价超出你给的市场价区间。明显偏低→警惕假货/问题机/钓鱼单；"
            "明显偏高→可议价，或对方在试探。注意：市场价区间是你自己调研"
            "的结果（同品类二手平台近期成交价），不是脚本编的；拿不准就多看"
            " 5 个同款链接再定。",
        )

    def run(self, path, lines, text, ctx):
        low, high = ctx.get("market_low"), ctx.get("market_high")
        if not (low and high):
            return
        price = None
        for p in PRICE_RES:
            m = p.search(text)
            if m:
                try:
                    price = num(m.group(1))
                    break
                except ValueError:
                    continue
        if price is None:
            return
        if price < low * 0.7:
            yield Finding(self.rule_id, self.severity, self.category,
                          "预警：价格远低于市场价（%.0f vs 区间 %.0f-%.0f）"
                          % (price, low, high), path, 0,
                          "标价 %g 元" % price,
                          self.detail + " 低于下限 30% 以上，钓鱼/问题机概率大增。")
        elif price > high * 1.2:
            yield Finding(self.rule_id, self.severity, self.category,
                          "预警：价格高于市场价（%.0f vs 区间 %.0f-%.0f）"
                          % (price, low, high), path, 0,
                          "标价 %g 元" % price,
                          self.detail + " 高出上限 20% 以上，建议议价或换一家。")


PriceRule()


class NoPriceRule(Rule):
    """全文无明确标价 → 无法做价格评估。"""

    def __init__(self):
        super().__init__(
            "SH-I008", "warning", "信息缺项", "缺失：明确标价",
            "全文未检出明确标价。\"价格私聊\"=看人下菜碟的第一步，"
            "先让对方报实价再谈；同时自己先查好市场价区间，带着锚点去聊。",
        )

    def run(self, path, lines, text, ctx):
        hit = any(p.search(text) for p in PRICE_RES)
        if not hit:
            yield Finding(self.rule_id, self.severity, self.category,
                          self.title, path, 0,
                          "(全文未检出明确标价)", self.detail)


NoPriceRule()


def load_market(target, args):
    if args.market_low and args.market_high:
        return float(args.market_low), float(args.market_high)
    mp = os.path.join(target, "market.txt")
    if os.path.isfile(mp):
        try:
            with open(mp, encoding="utf-8", errors="ignore") as f:
                m = MARKET_RE.search(f.read())
            if m:
                return num(m.group(1)), num(m.group(2))
        except Exception:
            pass
    return None, None


def analyze_file(path, ctx):
    lines = read_lines(path)
    if os.path.basename(path) == "market.txt":
        return []
    text = "\n".join(lines)
    findings = []
    for r in RULES:
        findings.extend(r.run(path, lines, text, ctx))
    return findings


SEV_ORDER = {"blocker": 0, "warning": 1, "nit": 2}


def main():
    ap = argparse.ArgumentParser(description="lhg-secondhand 二手交易确定性审计")
    ap.add_argument("--target", required=True, help="待扫描目录")
    ap.add_argument("--format", choices=["json", "text"], default="text")
    ap.add_argument("--fail-on", choices=["blocker", "warning", "nit"],
                    default="blocker")
    ap.add_argument("--market-low", type=float, default=None)
    ap.add_argument("--market-high", type=float, default=None)
    args = ap.parse_args()

    low, high = load_market(args.target, args)
    ctx = {"market_low": low, "market_high": high}

    files = collect_files(args.target)
    findings = []
    for p in files:
        findings.extend(analyze_file(p, ctx))
    findings.sort(key=lambda f: (SEV_ORDER[f.severity], f.rule_id))

    summary = {
        "tool": TOOL, "version": VERSION,
        "files_scanned": len(files), "rules_run": len(RULES),
        "market_range": [low, high] if low and high else None,
        "blocker": sum(1 for f in findings if f.severity == "blocker"),
        "warning": sum(1 for f in findings if f.severity == "warning"),
        "nit": sum(1 for f in findings if f.severity == "nit"),
    }

    if args.format == "json":
        print(json.dumps({"summary": summary,
                          "findings": [f.to_dict() for f in findings]},
                         ensure_ascii=False, indent=2))
    else:
        print("=" * 60)
        print("lhg-secondhand 交易审计报告（v%s）" % VERSION)
        print("扫描文件 %d 个，规则 %d 条%s" % (
            len(files), len(RULES),
            "，市场价区间 %.0f-%.0f" % (low, high) if low and high else
            "（未提供市场价区间，价格规则跳过）"))
        print("blocker=%d warning=%d nit=%d"
              % (summary["blocker"], summary["warning"], summary["nit"]))
        print("=" * 60)
        for f in findings:
            loc = f.file if f.line == 0 else "%s:%d" % (f.file, f.line)
            print("[%s][%s] %s" % (f.severity.upper(), f.rule_id, f.title))
            print("  位置: %s" % loc)
            print("  片段: %s" % f.snippet)
            print("  建议: %s" % f.detail)
            print()
        if not findings:
            print("未发现风险信号。注意：脚本只做关键词级扫描，交易前仍建议按验机清单实测。")

    fail_level = SEV_ORDER[args.fail_on]
    bad = any(SEV_ORDER[f.severity] <= fail_level for f in findings)
    return 2 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
