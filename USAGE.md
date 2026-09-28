# BlacksmithAI 使用指南

## 快速开始

### 1. 安装依赖

```bash
cd blacksmithAI
pip install -r requirements.txt
```

### 2. 启动 Dashboard

```bash
python web/dashboard.py
```

打开浏览器访问 http://localhost:8501

### 3. 命令行使用

```bash
# 健康检查
python health_check.py

# 测试 LLM 端点
python cli.py test --endpoint http://localhost:11434/api/generate
```

---

## 测试模块

### OWASP LLM Top 10

测试以下 10 个类别：

| ID | 类别 | 说明 |
|----|------|------|
| LLM01 | Prompt Injection | 提示词注入 |
| LLM02 | Sensitive Info Disclosure | 敏感信息泄露 |
| LLM03 | Supply Chain | 供应链安全 |
| LLM04 | Data Poisoning | 数据投毒 |
| LLM05 | Improper Output Handling | 输出处理不当 |
| LLM06 | Excessive Agency | 过度代理 |
| LLM07 | System Prompt Leakage | 系统提示词泄露 |
| LLM08 | Vector Weaknesses | 向量弱点 |
| LLM09 | Misinformation | 错误信息 |
| LLM10 | Unbounded Consumption | 无限制消耗 |

### RAG 安全测试

- 知识库投毒
- 文档注入
- 跨文档泄露
- 检索增强攻击

### Agent 安全测试

- 工具调用滥用
- 权限提升
- 间接提示注入
- 多步攻击链

### 隐私安全测试

- PII 泄露
- 训练数据提取
- 成员推理攻击
- 模型逆向

---

## 输出报告

### HTML 报告

```python
from utils.llm_report import llm_report
report_path = llm_report.generate_report(target, findings)
```

### JSON 报告（SIEM 集成）

```python
from utils.pdf_report import pdf_report_generator
json_path = pdf_report_generator.generate_json_report(target, findings)
```

### PDF 报告

```python
from utils.pdf_report import pdf_report_generator
pdf_path = pdf_report_generator.generate_pdf_report(target, findings)
```

---

## 误报过滤

```python
from utils.llm_fp_filter import llm_fp_filter

result = llm_fp_filter.filter_finding(model_response, "prompt_injection")
print(result["is_fp"])  # True if likely false positive
print(result["confidence"])  # 0-1
```

---

## 智能检测

```python
from utils.smart_detection import smart_detector

result = smart_detector.detect(model_response)
print(result["score"])  # 0-100
print(result["is_vulnerability"])
```

---

## 项目结构

```
blacksmithAI/
├── utils/               # 核心模块
│   ├── owasp_llm_tester.py      # OWASP LLM Top 10
│   ├── owasp_agentic_tester.py   # OWASP Agentic Top 10
│   ├── rag_security_tester.py    # RAG 安全
│   ├── agent_security_tester.py  # Agent 安全
│   ├── model_security_tester.py  # 模型安全
│   ├── privacy_security_tester.py # 隐私安全
│   ├── supply_chain_tester.py    # 供应链安全
│   ├── adversarial_attacks.py    # 对抗性攻击
│   ├── auto_attacker.py          # 自动攻击生成
│   ├── llm_fp_filter.py          # 误报过滤
│   ├── smart_detection.py         # 智能检测
│   ├── auth.py                   # 用户认证
│   ├── benchmark.py               # 基准测试
│   └── pdf_report.py             # PDF 报告
├── web/                 # Web Dashboard
├── cli.py               # 命令行接口
└── health_check.py      # 健康检查
```

---

## 安全提示

本工具仅用于授权的安全测试。请勿用于未授权的系统测试。
