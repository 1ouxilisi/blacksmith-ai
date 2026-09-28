# BlacksmithAI 增强升级说明

## 新增功能模块

参考 CyberStrikeAI 的架构设计，为 BlacksmithAI 补充了以下核心能力：

---

## 1. 审计日志系统 (`utils/audit_logger.py`)

**功能：** 完整记录渗透测试的每一步操作，生成可审计的操作日志。

**记录内容：**
- 所有 shell 命令执行（命令、输出、退出码、耗时）
- 安全发现（漏洞、证据、CVE）
- Agent 决策点（为什么选择某个行动）
- 人工审批记录（谁批准了什么操作）
- Agent 间消息通信

**输出位置：** `outputs/audit/{session_id}/`
- `audit.jsonl` - 结构化日志
- `evidence/` - 完整输出证据文件
- `session_report.json` - 会话总结

---

## 2. 攻击链分析 (`utils/attack_chain.py`)

**功能：** 可视化展示从侦察到后利用的完整攻击路径。

**5个阶段：**
- 侦察 (Recon)
- 扫描枚举 (Scan/Enum)
- 漏洞映射 (Vuln Map)
- 漏洞利用 (Exploit)
- 后利用 (Post-Exploit)

**节点状态：**
- `[?]` 已发现 (discovered)
- `[+]` 已确认 (confirmed)
- `[!]` 已利用 (exploited)
- `[X]` 被阻止 (blocked)

**自动计算关键攻击路径** - 找出成功率最高的攻击链。

---

## 3. 人工审批系统 (`utils/approval.py`)

**功能：** 高危操作前需要人工确认，防止误操作造成损失。

**风险等级：**
- **LOW** - 自动执行（whois, dig, subfinder 等被动侦察）
- **MEDIUM** - 自动执行但记录（nmap 扫描、目录爆破）
- **HIGH** - 需要人工审批（sqlmap, hydra, metasploit）
- **CRITICAL** - 必须人工审批（secretsdump, psexec, rm -rf）

**内置预设：** 15+ 常见渗透工具的风险等级自动评估。

---

## 4. 渗透测试知识库 RAG (`utils/knowledge_base.py`)

**功能：** 内置渗透测试方法论知识库，Agent 可以查询获取指导。

**内置内容：**
- 侦察技术（被动/主动）
- 扫描枚举方法（Web/服务）
- 常见漏洞类型（Web/网络）
- 利用方法论
- 后利用技术
- 报告结构
- 严重性评级标准

**向量检索：** 基于 chromadb 的语义搜索，支持自然语言查询。

---

## 5. 增强报告生成器 (`utils/report_generator.py`)

**功能：** 自动生成专业级渗透测试报告。

**输出格式：**
- Markdown 报告（`outputs/reports/report_*.md`）
- JSON 结构化报告（`outputs/reports/report_*.json`）
- 审计日志导出（`outputs/reports/audit_*.json`）

**报告包含：**
- 执行摘要（目标、时长、发现统计）
- 方法论说明
- 按严重性分类的详细发现
- 每个发现的证据和修复建议
- 攻击链可视化
- 审计日志统计

---

## 新增 Agent 工具

以下工具已集成到 `tools/tools.py`，Agent 可以直接调用：

| 工具 | 说明 |
|------|------|
| `log_finding()` | 记录一个安全发现到报告和审计日志 |
| `add_attack_node()` | 添加攻击链节点，构建攻击路径 |
| `request_approval()` | 请求人工审批高危操作 |
| `query_knowledge_base()` | 查询渗透测试知识库 |
| `generate_report()` | 生成最终渗透测试报告 |

---

## 文件变更清单

**新增文件：**
- `utils/audit_logger.py` - 审计日志系统
- `utils/attack_chain.py` - 攻击链分析
- `utils/approval.py` - 人工审批系统
- `utils/knowledge_base.py` - 渗透测试知识库
- `utils/report_generator.py` - 增强报告生成器

**修改文件：**
- `tools/tools.py` - 集成新增工具函数

---

## 使用方式

这些增强模块会自动初始化，Agent 在执行任务时可以自动使用。

**典型工作流：**
1. Recon Agent 执行侦察 → 自动记录到审计日志
2. Scan Agent 发现端口 → 添加攻击链节点
3. Vuln Agent 发现漏洞 → 调用 `log_finding()` 记录
4. Exploit Agent 准备利用 → 高危操作前调用 `request_approval()`
5. 整个过程自动构建攻击链
6. 任务结束调用 `generate_report()` 生成完整报告

---

## 对比 CyberStrikeAI 的提升

| 特性 | BlacksmithAI (原版) | BlacksmithAI (增强版) | CyberStrikeAI |
|------|---------------------|----------------------|---------------|
| 多智能体架构 | ✅ 5个子Agent | ✅ 5个子Agent | ✅ Eino编排 |
| 工具执行 | ✅ Docker容器 | ✅ Docker容器 | ✅ MCP调度 |
| RAG知识库 | ⚠️ 仅工具文档 | ✅ 完整渗透方法论 | ✅ RAG知识库 |
| 人工审批 | ❌ | ✅ 风险分级审批 | ✅ 人工监督 |
| 审计日志 | ❌ | ✅ 完整操作追踪 | ✅ 证据留存 |
| 攻击链分析 | ❌ | ✅ 可视化攻击路径 | ✅ 攻击链分析 |
| 报告生成 | ⚠️ 基础 | ✅ 专业级报告 | ✅ 复盘报告 |
| 可视化工作流 | ⚠️ Web UI | ✅ 攻击链可视化 | ✅ 可视化工作流 |

增强后的 BlacksmithAI 在功能覆盖上已经对齐甚至部分超越了 CyberStrikeAI 的核心特性。

---

# 第二次升级：Auto Hunter 批量挖洞系统

参考 AutoHunter 架构，新增**批量自动化漏洞挖掘流水线**，从"单目标渗透"升级为"7×24 批量刷洞平台"。

## 新增模块

### 1. 资产收集器 (`utils/asset_collector.py`)
- 集成 FOFA / Quake / Shodan 三大资产搜索引擎
- 自动批量拉取目标、探活、评分、去重
- 目标评分算法：高价值关键词、高危服务器、非标端口、响应状态等加权计算

### 2. 任务队列 (`utils/task_queue.py`)
- 优先级队列（高/中/低）
- 并发控制、失败重试、状态追踪
- 批量目标排队执行，支持断点续扫

### 3. 误报过滤 (`utils/fp_filter.py`)
- LLM 自动初审扫描结果
- 四级判定：confirmed / likely / false_positive / low_value
- 自动计算置信度和建议严重性
- 输出人工复审清单，过滤掉垃圾洞

### 4. 自动流水线 (`utils/auto_hunt.py`)
- 完整流水线：收集目标 → 探活 → 排队 → 自动扫描(nuclei) → LLM初审 → 复审清单
- 批量执行，支持最大目标数限制
- 自动导出报告和任务结果

## 新增 Agent 工具

| 工具 | 说明 |
|------|------|
| `collect_targets()` | 从 FOFA/Quake/Shodan 批量收集目标 |
| `probe_targets_alive()` | 探测目标存活状态 |
| `build_scan_queue()` | 构建扫描任务队列 |
| `run_batch_hunt()` | 运行批量自动挖洞 |
| `get_review_list()` | 获取待人工复审的漏洞清单 |
| `get_hunt_stats()` | 查看批量挖洞统计 |

## 完整工作流

```
Collector(FOFA/Quake) → 目标收集 → 探活筛选 → 评分排序
    ↓
任务队列（优先级调度）
    ↓
Worker 自动扫描（nmap + nuclei + 目录枚举）
    ↓
LLM 初审（误报过滤）
    ↓
人工复审清单（调级/通过/打回）
    ↓
待提交漏洞报告
```

## 配置说明

需要在 `.env` 中添加对应 API Key：
```
FOFA_API_KEY=your_fofa_key
FOFA_EMAIL=your_fofa_email
QUAKE_API_KEY=your_quake_key
SHODAN_API_KEY=your_shodan_key
```

## 对比 AutoHunter

| 特性 | AutoHunter | BlacksmithAI (Auto Hunter) |
|------|-----------|---------------------------|
| 多 Agent 协作 | ✅ | ✅ |
| FOFA 资产收集 | ✅ | ✅ |
| 自动扫描流水线 | ✅ nuclei/sqlmap | ✅ nuclei（可扩展） |
| LLM 误报过滤 | ✅ | ✅ |
| 人工复审面板 | ✅ | ✅ 复审清单导出 |
| 任务队列 | ✅ | ✅ 优先级队列 |
| 攻击链分析 | ❌ | ✅ |
| 审计日志 | ❌ | ✅ |
| 渗透方法论知识库 | ❌ | ✅ |

**输出位置：** `outputs/autohunt/`
- `tasks_*.json` - 任务执行结果
- `review_*.json` - 待人工复审清单
- `summary_*.json` - 批量挖洞统计摘要

---

# 第三次升级：全面补全

## 新增模块

### 1. Web Dashboard (`web/dashboard.py`)
- 基于 Flask 的 Web 控制面板
- 实时显示目标统计、任务状态、复审队列
- 自动每 10 秒刷新
- API 接口：`/api/stats`、`/api/review`
- 访问地址：http://localhost:8501

### 2. 通知系统 (`utils/notifier.py`)
- Webhook 通知（支持钉钉/飞书/企业微信）
- 高危漏洞自动告警
- 批量挖洞完成通知
- 可配置告警级别阈值

### 3. 增强扫描器 (`utils/enhanced_scanner.py`)
- 多工具串联扫描：Web指纹 → Nuclei → Nmap → 目录枚举
- 自动解析扫描结果为结构化 Finding
- 高危发现自动触发通知

### 4. 一键启动脚本 (`start.bat`)
- 自动检查 Docker 容器状态
- 自动启动 Web Dashboard
- 自动启动 CLI 界面
- 双击即可运行

## 完整功能清单

### 渗透测试模式（单目标）
- ✅ 多智能体架构（Recon/Scan/Vuln/Exploit/PostExploit）
- ✅ Docker 容器隔离执行
- ✅ 审计日志 + 攻击链可视化
- ✅ 人工审批（高危操作）
- ✅ 渗透方法论知识库 RAG
- ✅ 专业级报告生成

### 批量挖洞模式（7×24）
- ✅ FOFA/Quake/Shodan 资产收集
- ✅ 目标评分 + 自动优先级
- ✅ 任务队列 + 失败重试
- ✅ 多工具自动扫描（nmap/nuclei/gobuster/whatweb）
- ✅ LLM 误报过滤
- ✅ Web Dashboard 实时监控
- ✅ 高危漏洞 Webhook 通知
- ✅ 人工复审清单导出

## 启动方式

**方式一：一键启动（推荐）**
```
双击 start.bat
```

**方式二：手动启动**
```powershell
# 1. 启动 Docker 容器
cd blacksmithAI
docker compose up -d

# 2. 启动 Web Dashboard
.venv\Scripts\python.exe -m web.dashboard

# 3. 启动 CLI
.venv\Scripts\python.exe main.py
```

## 配置项（.env）

```
# LLM
OPENROUTER_API_KEY=your_key

# 资产搜索引擎
FOFA_API_KEY=your_fofa_key
FOFA_EMAIL=your_fofa_email
QUAKE_API_KEY=your_quake_key
SHODAN_API_KEY=your_shodan_key

# 通知
NOTIFY_WEBHOOK_URL=your_webhook_url
NOTIFY_MIN_SEVERITY=high
```

## 最终架构

```
BlacksmithAI
├── agents/           # 多智能体（5个专业Agent）
├── tools/            # 工具集（Shell + MCP + 增强工具）
├── utils/
│   ├── audit_logger.py      # 审计日志
│   ├── attack_chain.py      # 攻击链分析
│   ├── approval.py          # 人工审批
│   ├── knowledge_base.py     # 渗透知识库
│   ├── report_generator.py   # 报告生成
│   ├── asset_collector.py    # 资产收集
│   ├── task_queue.py         # 任务队列
│   ├── fp_filter.py          # 误报过滤
│   ├── auto_hunt.py          # 自动流水线
│   ├── enhanced_scanner.py   # 增强扫描器
│   └── notifier.py           # 通知系统
├── web/
│   └── dashboard.py          # Web控制面板
├── store/            # 向量数据库
├── mcp/              # MCP工具配置
├── outputs/          # 输出目录
│   ├── audit/        # 审计日志
│   ├── reports/      # 渗透报告
│   └── autohunt/     # 批量挖洞结果
└── start.bat         # 一键启动
```

**现在已经是一个完整的专业级 AI 安全测试平台了。**

---

# 第四次升级：高级智能与报告

## 新增模块

### 1. EXP 自动验证器 (`utils/exploit_verifier.py`)
- 发现漏洞后自动运行 PoC 验证
- 支持 SQL注入、XSS、目录遍历、默认凭证、开放重定向等
- 自动计算置信度提升/降低
- 进一步减少误报

### 2. 策略规划 Agent (`utils/strategy_planner.py`)
- AI 自动决定下一步最佳行动
- 基于当前进度和发现动态调整策略
- 输出优先级和理由
- 不再只是按流程走，而是智能决策

### 3. 历史扫描对比 (`utils/history_comparator.py`)
- 多次扫描结果对比
- 自动识别新发现的漏洞
- 自动识别已修复的漏洞
- 适合持续监控场景

### 4. HTML 报告生成器 (`utils/html_report.py`)
- 美观的交互式 HTML 报告
- 按严重性配色
- 内嵌证据和修复建议
- 攻击链可视化
- 适合直接发给客户

### 5. Web Dashboard 操作功能
- POST /api/hunt/start - 从 Web 启动批量挖洞
- POST /api/hunt/stop - 停止挖洞
- GET /api/history - 查看扫描历史
- GET /api/report/html - 生成 HTML 报告

## 新增 Agent 工具

| 工具 | 说明 |
|------|------|
| `verify_finding()` | 自动验证漏洞是否真实可利用 |
| `generate_html_report()` | 生成美观的 HTML 报告 |
| `plan_next_action()` | AI 规划下一步最佳行动 |
| `compare_scans()` | 对比两次扫描结果找新漏洞 |

## 完整功能矩阵

| 功能 | 原版 | 现在 |
|------|------|------|
| 多智能体架构 | ✅ | ✅ |
| Docker 容器执行 | ✅ | ✅ |
| 审计日志 | ❌ | ✅ |
| 攻击链可视化 | ❌ | ✅ |
| 人工审批 | ❌ | ✅ |
| 知识库 RAG | ❌ | ✅ |
| 批量资产收集 | ❌ | ✅ FOFA/Quake/Shodan |
| 任务队列 | ❌ | ✅ 优先级队列 |
| 自动扫描 | ❌ | ✅ 多工具串联 |
| LLM 误报过滤 | ❌ | ✅ |
| 漏洞自动验证 | ❌ | ✅ |
| AI 策略规划 | ❌ | ✅ |
| Web Dashboard | ❌ | ✅ 可操作 |
| 通知告警 | ❌ | ✅ Webhook |
| 历史扫描对比 | ❌ | ✅ |
| HTML 报告 | ❌ | ✅ 美观交互式 |
| 一键启动 | ❌ | ✅ start.bat |

## 最终目录结构

```
BlacksmithAI
├── agents/
│   ├── base.py
│   ├── recon.py
│   ├── scan_enum.py
│   ├── vuln_map.py
│   ├── exploit.py
│   ├── post_exploit.py
│   └── pentester.py
├── tools/
│   ├── tools.py
│   └── shell/
├── utils/
│   ├── audit_logger.py
│   ├── attack_chain.py
│   ├── approval.py
│   ├── knowledge_base.py
│   ├── report_generator.py
│   ├── asset_collector.py
│   ├── task_queue.py
│   ├── fp_filter.py
│   ├── auto_hunt.py
│   ├── enhanced_scanner.py
│   ├── notifier.py
│   ├── exploit_verifier.py
│   ├── html_report.py
│   ├── strategy_planner.py
│   └── history_comparator.py
├── web/
│   ├── __init__.py
│   └── dashboard.py
├── store/
├── mcp/
├── outputs/
│   ├── audit/
│   ├── reports/
│   ├── autohunt/
│   └── history/
├── main.py
├── config.json
├── .env
├── docker-compose.yml
├── start.bat
└── UPGRADE_NOTES.md
```

**经过四次升级，BlacksmithAI 已经从一个简单的多智能体 Demo，变成了一个功能完整的专业级 AI 安全测试平台。**

## v2.1 Upgrade (2026-09-26)

### New Modules
- `orchestrated_scan.py` - Full multi-agent scan pipeline
  - Recon Agent: subfinder + whatweb + nmap
  - Exploit Agent: nuclei + nikto
  - Coordinator: chain analysis + report generation
  - Memory check: skip recently scanned targets

### New Tools in Container
- sqlmap 1.10.9 - SQL injection detection
- nikto 2.6.1 - Web server vulnerability scanner
- whatweb 0.6.4 - Technology fingerprinting

### New Dashboard Pages
- `/orchestrated-scan` - Multi-agent scan with real-time progress
- `/agents` - Multi-agent team status
- `/chains` - Attack chain analysis
- `/runs` - Run history and cost tracking
- `/budget` - LLM budget control

### Total Tools: 7
nmap, nuclei, gobuster, subfinder, whatweb, nikto, sqlmap

### Total Modules: 10
1. SQLite Database
2. Scan Engine (7 tools)
3. Result Parsers
4. PoC Validator
5. Attack Chain Analyzer
6. Multi-Agent Orchestrator
7. Agent Memory System
8. Budget Control
9. Report Generator (Pro HTML)
10. Orchestrated Scan Pipeline
