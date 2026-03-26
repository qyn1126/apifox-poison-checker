# apifox-poison-checker

> 针对 Apifox 供应链投毒事件（2026-03-04 ~ 2026-03-22）的本地感染痕迹检测工具

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)]()
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## 背景

2026 年 3 月，Apifox CDN 上的合法 JS 文件（`apifox-app-event-tracking.min.js`）遭到篡改，被植入约 42KB 的恶意后门代码。凡在 **2026-03-04 至 2026-03-22** 期间启动过 Apifox 桌面端的用户，均可能受到影响。

攻击采用多阶段载荷，已确认的窃取目标包括：

| 类别 | 具体内容 |
|------|---------|
| 密钥凭证 | `~/.ssh/`（全部私钥）、`~/.git-credentials`、`~/.npmrc` Token |
| 云原生配置 | `~/.kube/*`（Kubernetes kubeconfig / OIDC Token） |
| Shell 历史 | `~/.zsh_history`、`~/.bash_history`（可能含硬编码密码、内部 URL） |
| 系统信息 | 机器指纹（MAC + CPU + 主机名 → SHA-256）、进程列表 |
| 账户信息 | Apifox 登录令牌、用户邮箱与姓名 |

攻击的本质是一个基于 `eval()` 的完整远程代码执行（RCE）平台，侦察阶段之后可能还下发了持久化后门或横向移动载荷。

> 完整技术分析：[Apifox 供应链投毒攻击 — 完整技术分析](https://rce.moe/2026/03/25/apifox-supply-chain-attack-analysis/)

---

## 检测原理

本工具通过扫描 Apifox 的本地数据目录（`localStorage` / `leveldb`）查找攻击留下的特征字符串：

| 特征 | 含义 |
|------|------|
| `_rl_mc` | 恶意代码写入的机器指纹键，说明恶意代码**曾在本机执行** |
| `_rl_headers` | C2 通信请求头记录，说明本机**曾与攻击者服务器通信** |
| `__apifox.it.com__` | 恶意 C2 域名标记，说明本机**曾加载攻击者的恶意脚本** |

---

## 快速开始

无需安装任何依赖，仅需 Python 3.8+。

```bash
# 克隆仓库
git clone https://github.com/yourname/apifox-poison-checker.git
cd apifox-poison-checker

# 直接运行
python checker.py
```

或单文件运行（无需克隆）：

```bash
python -c "import urllib.request; exec(urllib.request.urlopen('https://raw.githubusercontent.com/yourname/apifox-poison-checker/main/checker.py').read())"
```

---

## 各平台检测目录

| 平台 | 检测路径 |
|------|---------|
| Windows | `%APPDATA%\Apifox*`、`%APPDATA%\apifox\Local Storage\leveldb\` |
| macOS | `~/Library/Application Support/apifox/Network Persistent State`、`…/Local Storage/leveldb/` |
| Linux | `~/.config/apifox/Local Storage/leveldb/` |

---

## 输出示例

**检测到感染痕迹：**

```
[机器指纹 & C2 通信记录（leveldb）]
  ✅ 命中 2 个文件  |  触发关键词: rl_headers, rl_mc

  📄 /home/user/.config/apifox/Local Storage/leveldb/000042.ldb
       触发: [rl_headers]  [rl_mc]

  ⚠️  [rl_mc]      = 机器指纹已被写入，恶意代码曾在本机执行
  ⚠️  [rl_headers] = C2 请求头记录已写入，本机曾与攻击者服务器通信

🚨 检测到感染痕迹！请立即执行以下紧急措施：
  1. 立即停用 Apifox 桌面端
  2. 轮换所有 SSH 密钥（~/.ssh/ 下的全部密钥对）
  3. 吊销所有 Git PAT（GitHub / GitLab / Gitea 等）
  ...
```

**未检出痕迹：**

```
ℹ️  未检出痕迹，但请注意以下情况仍可能已中招：
  · Apifox 已重装或更新，覆盖了 localStorage 数据
  · 恶意代码执行后未写入本地文件（仅内存操作）
  · 攻击者在侦察完成后已主动清除痕迹
```

---

## ⚠️ 重要说明：未检出不代表未感染

本工具仅检测**残留的本地文件痕迹**。以下情况下检测结果可能为阴性，但实际已中招：

- **Apifox 重装或升级**覆盖了 `localStorage` 数据
- **系统数据目录被清理**（如重装系统、清理缓存）
- 恶意代码在**内存中执行**后未写入本地文件
- 攻击者在侦察完成后**主动清除了痕迹**
- 载荷通过**一次性 URL** 下发，本地不留存任何文件

**如果你在 2026-03-04 至 2026-03-22 期间曾运行过 Apifox 桌面端，无论本工具检测结果如何，都建议主动执行以下操作：**

1. 轮换 `~/.ssh/` 下的全部 SSH 密钥对
2. 吊销 GitHub / GitLab 等平台的 Personal Access Token
3. 轮换 Kubernetes kubeconfig 及 OIDC Token
4. 轮换 `~/.npmrc` 中的 registry Token
5. 检查 Shell 历史，修改其中出现的密码、API Key
6. 审查服务器 SSH 登录日志，确认是否有异常来源的访问
7. 若机器曾访问生产环境，建议**按"已失陷"级别**启动应急响应

---

## IoC 参考

| 类型 | 指标 |
|------|------|
| C2 域名 | `apifox.it.com`（非官方域名，`.it.com` 为商业二级域名） |
| 投毒文件 | `apifox-app-event-tracking.min.js`（77KB，正常为 34KB） |
| 数据外泄端点 | `apifox.it.com/event/0/log`、`/event/2/log` |
| localStorage 键 | `_rl_mc`、`_rl_headers` |
| HTTP 异常请求头 | `af_uuid`、`af_os`、`af_user`、`af_name`、`af_apifox_user` |
| 攻击活跃窗口 | 2026-03-04 至 2026-03-22 |

---

## 免责声明

本工具仅用于安全自查目的，不提供任何形式的安全保证。检测结果仅供参考，不能替代专业的安全应急响应。

---

## License

MIT
