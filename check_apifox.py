#!/usr/bin/env python3
"""
Apifox 供应链投毒检测脚本（纯 Python 实现）
参考: https://rce.moe/2026/03/25/apifox-supply-chain-attack-analysis/

检测本机是否存在 Apifox 供应链攻击（2026-03-04 ~ 2026-03-22）的感染痕迹。
不依赖任何外部命令，全平台可用（Windows / macOS / Linux）。
"""

import os
import re
import sys
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set


# ──────────────────────────────────────────────
# 攻击背景说明
# ──────────────────────────────────────────────

ATTACK_BACKGROUND = """
╔══════════════════════════════════════════════════════════════╗
║            ⚠️  Apifox 供应链投毒攻击 — 检测说明              ║
╠══════════════════════════════════════════════════════════════╣
║  攻击窗口：2026-03-04 至 2026-03-22（共 18 天）              ║
║  影响平台：Windows / macOS / Linux 全平台                    ║
║  风险等级：🔴 严重（Critical）                               ║
╠══════════════════════════════════════════════════════════════╣
║  攻击方式：                                                  ║
║  · 攻击者篡改了 Apifox CDN 上的合法 JS 文件                  ║
║    (apifox-app-event-tracking.min.js 从 34KB 变为 77KB)     ║
║  · 凡在上述时间段内启动过 Apifox 桌面端，均可能受影响         ║
║                                                              ║
║  已确认的窃取内容：                                          ║
║  · SSH 私钥（~/.ssh/ 全部文件）                              ║
║  · Shell 历史（.zsh_history / .bash_history）                ║
║  · Git 凭证（~/.git-credentials）                            ║
║  · Kubernetes 配置（~/.kube/*）                              ║
║  · npm Token（~/.npmrc）                                     ║
║  · Apifox 账户邮箱与姓名                                     ║
║  · 机器指纹（MAC + CPU + 主机名 → SHA-256）                  ║
║  · 进程列表（ps aux / tasklist）                             ║
╚══════════════════════════════════════════════════════════════╝
"""

# 检测到痕迹时的警告
WARNING_FOUND = """
╔══════════════════════════════════════════════════════════════╗
║  🚨  检测到感染痕迹！请立即执行以下紧急措施                  ║
╠══════════════════════════════════════════════════════════════╣
║  1. 立即停用 Apifox 桌面端                                   ║
║  2. 轮换所有 SSH 密钥（~/.ssh/ 下的全部密钥对）               ║
║  3. 吊销所有 Git PAT（GitHub / GitLab / Gitea 等）           ║
║  4. 轮换 Kubernetes OIDC Token 和 kubeconfig                 ║
║  5. 轮换 npm registry Token（~/.npmrc）                      ║
║  6. 修改 Shell 历史中出现过的密码、Token、API Key             ║
║  7. 审查服务器 SSH 登录日志，确认是否有异常登录               ║
║  8. 若机器曾访问生产环境，应视为"已失陷"启动应急响应          ║
╠══════════════════════════════════════════════════════════════╣
║  ⚠️  即使已执行上述措施，攻击者在侦察阶段之后可能已经         ║
║     植入了独立的持久化后门（脱离 Apifox 进程运行），           ║
║     建议同时排查系统启动项、定时任务和异常进程。              ║
╚══════════════════════════════════════════════════════════════╝
"""

# 未检出时的补充警告
WARNING_NOT_FOUND = """
╔══════════════════════════════════════════════════════════════╗
║  ℹ️  未检出痕迹，但请注意以下情况仍可能已中招                ║
╠══════════════════════════════════════════════════════════════╣
║  本脚本仅检测残留的本地文件痕迹，以下情况下可能漏报：         ║
║                                                              ║
║  · Apifox 已重装或更新，覆盖了 localStorage 数据              ║
║  · 系统或 Apifox 数据目录已被清理                            ║
║  · 恶意代码执行后未写入本地文件（仅内存操作）                 ║
║  · 攻击者在侦察完成后已主动清除痕迹                          ║
║                                                              ║
║  如果你在 2026-03-04 至 2026-03-22 期间曾运行过              ║
║  Apifox 桌面端，建议：                                       ║
║  · 无论检测结果如何，都应主动轮换 SSH 密钥和 Git Token        ║
║  · 核查 Shell 历史中是否包含敏感凭证                         ║
║  · 留意服务器登录日志中是否有异常来源的 SSH 访问              ║
╚══════════════════════════════════════════════════════════════╝
"""


# ──────────────────────────────────────────────
# 数据结构
# ──────────────────────────────────────────────

@dataclass
class CheckResult:
    label: str
    # { 文件路径: {触发的关键词, ...} }
    matches: Dict[Path, Set[str]] = field(default_factory=dict)
    skipped: str = ""
    error: str = ""

    @property
    def found(self) -> bool:
        return bool(self.matches)

    @property
    def file_count(self) -> int:
        return len(self.matches)

    @property
    def all_keywords(self) -> Set[str]:
        result: Set[str] = set()
        for kws in self.matches.values():
            result |= kws
        return result


# ──────────────────────────────────────────────
# 核心搜索工具
# ──────────────────────────────────────────────

def scan_file_keywords(path: Path, keywords: List[str]) -> Set[str]:
    """
    扫描单个文件，返回实际命中的关键词集合（大小写不敏感）。
    以字节模式读取，兼容 leveldb 等二进制文件。
    """
    patterns = {kw: re.compile(kw.encode(), re.IGNORECASE) for kw in keywords}
    remaining = set(keywords)
    found: Set[str] = set()

    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 16), b""):
                for kw in list(remaining):
                    if patterns[kw].search(chunk):
                        found.add(kw)
                        remaining.discard(kw)
                if not remaining:
                    break
    except (PermissionError, OSError):
        pass

    return found


def grep_dir(directory: Path, keywords: List[str]) -> Dict[Path, Set[str]]:
    """递归搜索目录，返回 { 文件路径: 触发关键词集合 }。"""
    result: Dict[Path, Set[str]] = {}
    if not directory.is_dir():
        return result
    for entry in directory.rglob("*"):
        if entry.is_file():
            found = scan_file_keywords(entry, keywords)
            if found:
                result[entry] = found
    return result


def grep_single(file: Path, keywords: List[str]) -> Dict[Path, Set[str]]:
    """搜索单个文件。"""
    found = scan_file_keywords(file, keywords)
    return {file: found} if found else {}


# ──────────────────────────────────────────────
# 输出工具
# ──────────────────────────────────────────────

def section(title: str):
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def print_result(result: CheckResult):
    print(f"\n[{result.label}]")

    if result.skipped:
        print(f"  ⚠️  {result.skipped}")
        return
    if result.error:
        print(f"  ❌  {result.error}")
        return
    if not result.found:
        print("  ℹ️  未找到匹配内容")
        return

    triggered = ", ".join(sorted(result.all_keywords))
    print(f"  ✅ 命中 {result.file_count} 个文件  |  触发关键词: {triggered}\n")
    for filepath, keywords in result.matches.items():
        kw_str = "  ".join(f"[{kw}]" for kw in sorted(keywords))
        print(f"  📄 {filepath}")
        print(f"       触发: {kw_str}")
    print()

    # 关键词对应的感染含义说明
    all_kw = result.all_keywords
    if "_rl_mc" in all_kw or "rl_mc" in all_kw:
        print("  ⚠️  [rl_mc] = 机器指纹已被写入，恶意代码曾在本机执行")
    if "_rl_headers" in all_kw or "rl_headers" in all_kw:
        print("  ⚠️  [rl_headers] = C2 请求头记录已写入，本机曾与攻击者服务器通信")
    if "__apifox.it.com__" in all_kw:
        print("  ⚠️  [__apifox.it.com__] = 恶意 C2 域名标记，本机曾加载攻击者代码")


# ──────────────────────────────────────────────
# 各平台检测逻辑
# ──────────────────────────────────────────────

def check_windows() -> List[CheckResult]:
    section("Windows 检测")

    results: List[CheckResult] = []
    appdata = os.environ.get("APPDATA", "")
    if not appdata:
        print("  ❌ 未找到 %APPDATA% 环境变量")
        return results

    appdata_path = Path(appdata)
    print(f"  APPDATA: {appdata_path}")

    # ── 检测 1：%APPDATA%\Apifox* 搜索 __apifox.it.com__
    kw1 = ["__apifox.it.com__"]
    r1 = CheckResult(label="C2 域名标记（%APPDATA%\\Apifox*）")
    apifox_entries = list(appdata_path.glob("Apifox*"))
    if not apifox_entries:
        r1.skipped = f"未找到匹配 Apifox* 的目录/文件：{appdata_path}"
    else:
        for target in apifox_entries:
            if target.is_dir():
                r1.matches.update(grep_dir(target, kw1))
            elif target.is_file():
                r1.matches.update(grep_single(target, kw1))
    results.append(r1)
    print_result(r1)

    # ── 检测 2：leveldb 搜索机器指纹键 / C2 请求头记录
    kw2 = ["rl_mc", "rl_headers"]
    leveldb = appdata_path / "apifox" / "Local Storage" / "leveldb"
    r2 = CheckResult(label="机器指纹 & C2 通信记录（leveldb）")
    if not leveldb.exists():
        r2.skipped = f"目录不存在：{leveldb}"
    else:
        r2.matches = grep_dir(leveldb, kw2)
    results.append(r2)
    print_result(r2)

    return results


def check_mac() -> List[CheckResult]:
    section("macOS 检测")

    results: List[CheckResult] = []
    base = Path.home() / "Library" / "Application Support" / "apifox"
    print(f"  基础目录: {base}")

    # ── 检测 1：Network Persistent State 搜索 __apifox.it.com__
    kw1 = ["__apifox.it.com__"]
    nps = base / "Network Persistent State"
    r1 = CheckResult(label="C2 域名标记（Network Persistent State）")
    if not nps.exists():
        r1.skipped = f"文件不存在：{nps}"
    else:
        r1.matches = grep_single(nps, kw1)
    results.append(r1)
    print_result(r1)

    # ── 检测 2：leveldb 搜索机器指纹键 / C2 请求头记录
    kw2 = ["rl_mc", "rl_headers"]
    leveldb = base / "Local Storage" / "leveldb"
    r2 = CheckResult(label="机器指纹 & C2 通信记录（leveldb）")
    if not leveldb.exists():
        r2.skipped = f"目录不存在：{leveldb}"
    else:
        r2.matches = grep_dir(leveldb, kw2)
    results.append(r2)
    print_result(r2)

    return results


def check_linux() -> List[CheckResult]:
    section("Linux 检测")

    results: List[CheckResult] = []
    leveldb = Path.home() / ".config" / "apifox" / "Local Storage" / "leveldb"
    print(f"  leveldb 目录: {leveldb}")

    kw = ["rl_mc", "rl_headers"]
    r = CheckResult(label="机器指纹 & C2 通信记录（leveldb）")
    if not leveldb.exists():
        r.skipped = f"目录不存在：{leveldb}"
    else:
        r.matches = grep_dir(leveldb, kw)
    results.append(r)
    print_result(r)

    return results


# ──────────────────────────────────────────────
# 主入口
# ──────────────────────────────────────────────

PLATFORM_MAP = {
    "Windows": check_windows,
    "Darwin":  check_mac,
    "Linux":   check_linux,
}


def main():
    print(ATTACK_BACKGROUND)

    sys_name = platform.system()
    check_fn = PLATFORM_MAP.get(sys_name)

    print(f"检测平台: {sys_name}")
    print(f"Python  : {sys.version}")

    if check_fn is None:
        print(f"❌ 不支持的平台: {sys_name}")
        sys.exit(1)

    all_results = check_fn()

    # ── 汇总
    section("检测汇总")
    total   = len(all_results)
    found   = sum(1 for r in all_results if r.found)
    skipped = sum(1 for r in all_results if r.skipped)
    print(f"\n  共 {total} 项检测  |  命中 {found} 项  |  跳过 {skipped} 项")

    # ── 最终结论与建议
    if found > 0:
        print(WARNING_FOUND)
    else:
        print(WARNING_NOT_FOUND)


if __name__ == "__main__":
    main()