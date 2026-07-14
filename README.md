<h1 align="center">AlterHive 幻巢智能欺骗蜜罐平台</h1>

<div align="center">

<p align="center">
  <a href="https://github.com/Fausto-404/AlterHive/releases">
    <img src="https://img.shields.io/github/v/release/Fausto-404/AlterHive?style=flat-square&label=release&color=blue&cacheSeconds=3600" alt="Release">
  </a>

  <a href="https://github.com/Fausto-404/AlterHive/stargazers">
    <img src="https://img.shields.io/github/stars/Fausto-404/AlterHive?style=flat-square&label=stars&color=brightgreen&cacheSeconds=3600" alt="GitHub Stars">
  </a>

  <a href="https://github.com/Fausto-404/AlterHive/network/members">
    <img src="https://img.shields.io/github/forks/Fausto-404/AlterHive?style=flat-square&label=forks&color=orange&cacheSeconds=3600" alt="GitHub Forks">
  </a>

  <a href="https://github.com/Fausto-404/AlterHive">
    <img src="https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go">
  </a>
</p>

</div>

AlterHive（幻巢）是一款面向攻防演练、红蓝对抗和安全研究场景的高交互智能欺骗蜜罐平台。平台以虚拟拓扑、会话记忆、规则引擎和多 Agent 欺骗规划为核心，将攻击者/渗透Agent引导进可控的“子网幻象”环境中，帮助防守方观察攻击意图、拖延攻击节奏、保护真实目标。

<img width="2958" height="1502" alt="image" src="https://github.com/user-attachments/assets/7d64669a-b9b2-4943-b585-38ad4e32db2f" />
---

- **<font style="color:#000000;background-color:#FBF5CB;">架构设计与多 Agent 机制请查看：</font>**[**<font style="color:#000000;background-color:#FBF5CB;">docs/agent架构.md</font>**](./docs/agent架构.md)
- **<font style="color:#000000;background-color:#FBF5CB;">效果实测请查看：</font>**[**<font style="color:#000000;background-color:#FBF5CB;">https://xz.aliyun.com/news/92504</font>**](https://xz.aliyun.com/news/92504)

## 平台价值
+ **高交互欺骗**：提供 SSH 入口、模拟服务、虚拟文件系统和命令响应，让攻击者获得连续交互体验。
+ **子网幻象**：根据攻击意图动态扩展影子子网、跳板主机、服务资产和可见路径。
+ **证据驱动**：通过 `.env`、日志、bash history、GitLab、Jenkins、数据库、Kubernetes 等线索逐步引导攻击链。
+ **状态可控**：通过 gate、required_state、visible_after、protected target 等机制控制事实暴露节奏。
+ **安全边界**：Safety Agent 和规则引擎默认阻断真实扫描、真实连接和真实破坏性命令。
+ **可视化审计**：Web 控制台展示会话、命令、拓扑、证据命中、攻击者画像和系统状态。
+ **可扩展配置**：支持 YAML 拓扑、运行时端口配置、LLM Provider 配置和 Docker Compose 一键部署。

## 适用场景
+ 攻防演练期间部署可控入口，观察攻击者后渗透路径和目标偏好。
+ 蓝队希望将攻击者从真实资产引流到虚拟网络和影子目标。
+ 安全研究人员验证自动化渗透 Agent、扫描器和横向移动工具的行为模式。
+ 企业内网需要构造 GitLab、Jenkins、Redis、MySQL、DC、跳板机等组合诱饵场景。
+ 需要沉淀攻击命令、证据命中、拓扑扩展和欺骗策略的复盘材料。

## 核心场景流程
### 1、攻击会话进入欺骗环境
```text
Attacker / AI Pentest Agent
  -> SSH Honeypot / Simulation API
  -> Session Manager
  -> Rule Engine
  -> Safety Agent
  -> Response Agent
  -> Virtual World State
```

### 2、子网幻象与多 Agent 规划
```text
Command Input
  -> Intent Router Agent
  -> Evidence Agent
  -> Topology Planner
  -> World Builder
  -> Consistency Critic
  -> Safety Review
  -> Approved Shadow Topology
```

### 3、可视化监控与复盘
```text
Sessions / Commands / Evidence
  -> REST API
  -> React Console
  -> Dashboard
  -> Topology View
  -> Command Replay
```

## 核心亮点功能展示
### 1、动态拓扑欺骗
+ 基于 `configs/topology.yaml` 定义入口网段、主机、服务、边和访问状态。
+ 支持运行时根据攻击者目标扩展 shadow segment、shadow host 和 pivot edge。
+ 已暴露事实会被锁定，避免前后响应不一致。
<img width="2952" height="1524" alt="image" src="https://github.com/user-attachments/assets/0c09d871-641e-475e-8614-97759b1e2c5d" />

### 2、高交互 SSH 蜜罐
+ 支持 SSH 入口、shell 命令、嵌套 SSH、密码提示和跳板上下文。
+ 内置常见命令响应，包括 `nmap`、`fscan`、`curl`、`ssh`、`mysql`、`redis-cli`、`kubectl` 等。
+ 可记录攻击者命令、远端地址、会话状态、证据命中和拓扑变化。
<img width="1450" height="1484" alt="image" src="https://github.com/user-attachments/assets/2f4bf28f-92f3-4fce-8a8c-9aa28fa5f309" />

### 3、证据链投放
+ 在虚拟文件系统中放置 `.env`、应用日志、Git 凭据、部署脚本、kubeconfig 等线索。
+ 使用 `visible_after` 和 gate 控制证据出现时机。
+ 根据攻击者行为画像调整线索密度和响应策略。
<img width="2450" height="1334" alt="image" src="https://github.com/user-attachments/assets/c31aef21-ded3-4fa2-8ccf-0868bdfe98e1" />

### 4、Web 管理控制台
+ 运营总览：查看会话数量、活跃攻击者、证据命中和系统状态。
+ 会话管理：查看会话列表、命令历史、攻击者画像和终端回放。
+ 拓扑视图：查看入口网段、主机、服务、边、影子资产和当前会话可见范围。
+ 系统配置：管理 SSH/API 端口、拓扑 CIDR、会话超时和 LLM Provider。
<img width="2956" height="1522" alt="image" src="https://github.com/user-attachments/assets/2845d359-38e0-4cc3-ae96-7a6118caf330" />


## 项目目录
```latex
AlterHive-v1.0.0/
├── api/                     # REST API、认证、会话查询、模拟接口和配置接口
├── configs/                 # 运行时配置、拓扑配置、LLM Provider 配置
│   ├── alterhive.yaml       # 日志、Prometheus、Tracing 等基础配置
│   ├── topology.yaml        # 虚拟拓扑、主机、服务、边和 gate 定义
│   └── llm.yaml             # LLM 配置，默认关闭
├── docs/                    # 架构设计、多 Agent 欺骗规划文档
├── frontend/                # React + TypeScript Web 控制台
├── internal/                # 核心域模型、规则引擎、欺骗 Agent、响应器、会话管理
│   ├── deception/           # 多 Agent、证据、规划、一致性和安全策略
│   ├── domain/              # 拓扑、世界状态、会话、证据、模型定义
│   ├── engine/              # 命令规则引擎与响应调度
│   ├── llm/                 # LLM Provider 管理与安全门控
│   ├── responders/          # SSH、HTTP、MySQL、Redis、网络等协议响应
│   └── session/             # 会话生命周期与上下文管理
├── scripts/                 # 攻击链模拟脚本
├── Dockerfile               # 后端镜像构建
├── docker-compose.yml       # 一键部署容器编排
├── Makefile                 # 常用构建、测试、Docker 命令
└── main.go                  # 服务启动入口
```

## 快速启动
### Docker 一键部署
```bash
cp .env.example .env
docker compose up -d --build
```


默认访问地址：

+ 前端页面：`http://localhost:3000`
+ 后端 API：`http://localhost:8000`
+ 健康检查：`http://localhost:8000/healthz`
+ SSH 蜜罐入口：`ssh root@127.0.0.1 -p 2222`

默认运行时配置：

```bash
SSH_PORT=2222
API_PORT=8000
TOPOLOGY_CIDR=192.168.56.0/24
SESSION_TIMEOUT=600
FRONTEND_PORT=3000
```

> Docker Compose 默认只绑定 `127.0.0.1`，如果需要对外暴露，请先修改默认账号、访问控制和 LLM 外联策略。

### 本地开发
后端：

```bash
go mod download
go run .
```

前端：

```bash
cd frontend
npm install
npm run dev
```

默认前端开发地址通常为：`http://localhost:5173`

## 功能模块概览
| 模块 | 主要能力 |
| :--- | :--- |
| 运营总览 | 会话数量、活跃攻击者、证据命中、PPF 触发、近期会话和系统健康状态  |
| 会话管理 | 会话列表、会话详情、命令历史、远端地址、攻击者画像和删除会话 |
| 拓扑视图 | 主机、网段、服务、边、跳板关系、影子资产和会话可见范围 |
| 命令审计 | 记录 SSH 和模拟 API 中的命令、输出、证据 token 和策略结果 |
| 模拟 API | 提供 nmap、fscan、curl、ssh、nc、ping、goal 等自动化测试接口 |
| 证据系统 | 证据 token、可见条件、命中状态、证据网格和攻击阶段判断 |
| 规则引擎 | 本地命令响应、协议响应、服务枚举、复杂命令处理和安全拦截 |
| 多 Agent 欺骗 | Intent Router、Topology Planner、World Builder、Evidence、Safety、Consistency |
| LLM 配置 | 支持 OpenAI-Compatible、Anthropic、DeepSeek、Qwen、Zhipu、Moonshot、Ollama 等 Provider |
| 系统配置 | LLM配置、SSH/API 端口、拓扑 CIDR、会话超时、自动重启状态和系统信息 |


## 安全边界
+ 平台用于授权的安全研究、攻防演练和内部防守验证。
+ 默认配置不应直接暴露到公网。
+ 修改端口绑定、后台账号、Bearer Token、模拟 API 访问控制前，请先完成安全加固。
+ LLM 外联默认关闭，避免命令历史、拓扑、保护目标和诱饵设计上下文被发送到外部服务。
+ 拓扑中的密码、Token、内网地址默认是欺骗内容，不应复用真实生产凭据。

## 技术架构
+ 后端：Go + Gin + Logrus
+ SSH：gliderlabs/ssh
+ 前端：React + TypeScript + Ant Design + Vite
+ 配置：YAML + dotenv
+ 可观测：Prometheus metrics
+ Agent：Intent Router、Topology Planner、World Builder、Evidence Agent、Safety Agent、Consistency Critic
+ 部署：Docker Compose

## 版本说明
本版本重点能力：
+ 高交互 SSH 蜜罐入口。
+ 子网幻象拓扑和 shadow asset 扩展。
+ Web 控制台会话、拓扑、命令和系统配置管理。
+ 多 Agent 欺骗规划和证据投放机制。

## 免责声明
本项目仅用于合法授权的安全测试、攻防演练、防守验证和安全研究。请勿将本项目用于未授权访问、攻击真实系统或规避安全监测。使用者应自行承担部署、配置和使用过程中的合规与安全责任。
