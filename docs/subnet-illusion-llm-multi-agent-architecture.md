# AlterHive / Subnet Illusion LLM Multi-Agent Architecture

## 1. 总体架构

AlterHive 的 Subnet Illusion 不应被设计成“规则驱动 SSH 蜜罐”，也不应被设计成“每条命令都问 LLM 的终端机器人”。正确定位是：

```text
LLM 负责阶段性欺骗规划；
多 Agent 负责意图、世界、证据、响应、一致性、安全分工；
规则与缓存负责高速执行已批准计划；
事件驱动机制负责在状态变化时局部修正或重规划；
已暴露事实永久锁定，真实网络永远不可触碰。
```

目标闭环：

```text
SSH / HTTP / Tool Command Input
  -> Command Intake Layer
  -> Safety Agent quick check
  -> Intent Router Agent
  -> Session Memory + World State Store + Cache Manager
  -> Plan Runtime Executor
  -> 命中缓存 / 计划有效：快速响应
  -> 状态变化 / 计划失效：触发 Planning Event
  -> Multi-Agent Planning Layer
  -> Consistency Agent + Safety Agent 审核
  -> Response Agent 渲染
  -> 返回渗透 Agent
```

关键原则：

- LLM 是欺骗世界的 planner，不是每条命令的临时回复器。
- 规则引擎只执行已批准事实，不决定战略路径。
- 缓存绑定 `world_version` 和 `exposed_fact_version`，状态变化自动失效。
- 已暴露事实不能被 Planner、Response 或 LLM 推翻。
- 任何真实扫描、真实连接、真实执行都必须被 Safety Agent 拦截。

## 2. 多 Agent 分工

### 2.1 Orchestrator Agent

职责：

- 接收命令事件并创建 `CommandEvent`。
- 调用 Safety quick check 和 Intent Router。
- 判断是否命中 Plan Cache / Response Cache。
- 判断当前计划是否仍有效。
- 决定是否触发局部 patch、完整 replan 或只更新状态。
- 调度 Planner、World Builder、Evidence、Persona、Response、Consistency、Safety。

输入：

```text
CommandEvent
SessionState
WorldStateSnapshot
CacheMetadata
ActivePlan
```

输出：

```text
RuntimeDecision:
  action: fast_response | patch_plan | full_replan | safety_block
  selected_plan_id
  events[]
  cache_key
  response_policy
```

权限边界：

- 不直接生成终端输出。
- 不直接修改世界事实。
- 只能提交 proposal 或触发 Agent。

### 2.2 Intent Router Agent

职责：

- 把命令归类为侦察、漏洞验证、横向、凭据搜索、代理、C2、数据搜索、flag 搜索等。
- 抽取目标 IP、CIDR、端口、服务、文件、凭据、工具类型。
- 判断攻击者是否沿当前计划推进、偏离计划或改变目标。

输出结构：

```json
{
  "intent_type": "flag_hunt",
  "target_ip": "10.15.156.48",
  "target_port": 22,
  "target_service": "ssh",
  "target_subnet": "10.15.156.0/24",
  "target_file": "/flag",
  "target_goal": "10.15.156.48:/flag",
  "confidence": 0.94,
  "is_goal_shift": true,
  "is_new_discovery": true,
  "is_plan_following": false,
  "is_plan_breaking": true
}
```

实现策略：

- 高频命令使用规则和 Intent Cache。
- 复合命令、混淆命令、自然语言目标描述再调用 LLM。
- 不生成回复，不修改拓扑。

### 2.3 Deception Planner Agent

职责：

- 根据攻击目标、历史行为、当前世界状态，生成阶段性 `DeceptionPlan`。
- 规划影子路径、候选子网、跳板、服务、证据、gate、失败点、伪进展节奏。
- 决定什么时候给线索、什么时候延迟、什么时候制造合理失败。

Planner 输出：

```json
{
  "plan_id": "plan_sess123_flag_001",
  "attacker_goal_hypothesis": "10.15.156.48:/flag",
  "defender_objective": "route attacker into shadow path and never expose real target",
  "phase": "intermediate_pivot_discovery",
  "shadow_path": [
    "entry-subnet",
    "jump01",
    "10.42.18.0/24",
    "ci-runner-shadow",
    "172.16.40.0/24"
  ],
  "candidate_subnets": [],
  "candidate_hosts": [],
  "evidence_plan": [],
  "pseudo_progress_policy": "slow_success_then_gate",
  "failure_points": ["credential_valid_but_scope_limited", "target_requires_second_pivot"],
  "exposable_facts": [],
  "hidden_facts": [],
  "trigger_conditions": [],
  "invalidators": [],
  "cache_policy": {
    "plan_ttl_commands": 20,
    "response_cacheable": true
  }
}
```

权限边界：

- 不能直接提交世界变更。
- 不能直接创建已暴露事实。
- 必须经过 World Builder、Consistency Agent、Safety Agent。

### 2.4 World Builder Agent

职责：

- 把 Planner 的策略转为候选世界对象。
- 构造影子子网、影子主机、跳板、双网卡关系、虚拟路由、服务指纹、文件系统、日志、凭据、漏洞状态、nested shell 上下文。

输出事实分级：

```text
candidate_facts：未暴露，可替换；
exposed_facts：已暴露，必须锁定；
hidden_facts：内部规划，不返回；
gated_facts：满足 gate 后可暴露；
decoy_facts：诱饵事实；
rejected_facts：被拒绝，不可再次出现。
```

权限边界：

- 只能提交 `WorldPatchProposal`。
- 不能修改 locked exposed facts。
- 不能生成真实凭据、真实 flag、真实网络连接。

### 2.5 Evidence Agent

职责：

- 按阶段投放证据链，诱导攻击者继续探索。
- 控制证据节奏，避免“太顺利”或“太假”。

证据类型：

- `.env` 中的内网地址。
- app log 中的 upstream/pivot 记录。
- bash history 中的 SSH / proxy / nmap 记录。
- Jenkins/GitLab runner 部署记录。
- kubeconfig、数据库连接串、备份脚本、1Panel 面板残留。
- 疑似 flag 路径，但不能直接给 flag。

输出：

```json
{
  "evidence_id": "ev_ci_runner_target_hint",
  "evidence_type": "ci_cd_log",
  "where_to_place": "/opt/webapp/logs/deploy_20240115.log",
  "when_to_reveal": ["after_subnet_scan", "after_jump01_partial"],
  "discoverable_by": ["grep -Ri 10.15.156", "cat /opt/webapp/logs/*.log"],
  "guides_to": "shadow_ci_runner_branch",
  "risk_level": "medium",
  "consistency_dependencies": ["host:ci-runner-shadow", "service:gitlab-runner"]
}
```

### 2.6 Response Agent

职责：

- 根据已批准事实渲染终端输出和工具输出。
- 可复用 Beelzebub 风格 LLM responder，但不能自由发明事实。
- 将结构化事实渲染成 `nmap`、`fscan`、`curl`、`ssh`、`mysql`、`kubectl`、`nuclei`、`gobuster` 等格式。

输入：

```text
current_command
shell_context
allowed_facts
forbidden_facts
output_format
delay_policy
active_plan_phase
consistency_constraints
safety_constraints
```

禁止：

- 新增未注册 IP、服务、端口、凭据。
- 声称真实 RCE / C2 / root shell 成功。
- 返回真实 flag。
- 暴露自己是 LLM、AI、蜜罐。

### 2.7 Consistency Agent

职责：

- 审查世界事实、响应内容、历史暴露信息是否一致。
- 冲突时拒绝输出、修复输出或触发重规划。

强制检查：

- OS、hostname、IP/CIDR、路由一致性。
- `nmap`、`curl`、`ss/netstat`、服务 registry 一致性。
- 文件重复读取一致性。
- 服务 banner、端口、凭据状态、漏洞状态一致性。
- nested shell 上下文一致性。
- 影子子网来源和攻击链路合理性。

### 2.8 Safety Agent

职责：

- 同步阻断所有可能触碰真实世界的行为。

必须拦截：

- 真实 `nmap/curl/ssh/mysql/kubectl/PoC/C2/proxy/DNS/socket`。
- 真实公网、真实内网、真实 `10.15.156.48` 访问。
- 上传二进制真实执行。
- 读取宿主机真实文件。

输出：

```text
allow_virtual
deny_with_virtual_failure
deny_and_replan
```

### 2.9 Memory Agent

职责：

- 维护 session 记忆、攻击者目标假设、计划生命周期、世界版本、暴露事实、缓存元数据。

状态分层：

```text
Hot State：当前命令强一致状态；
Exposed Facts：攻击者已看到，永久锁定；
Candidate Facts：LLM 规划但未暴露，可替换；
Hidden Plan：内部欺骗计划，不暴露；
Archive Memory：历史摘要；
Attacker Model：攻击者行为画像；
Plan Graph：当前欺骗计划图；
Cache Metadata：缓存命中和失效信息。
```

### 2.10 Cache Manager Agent

职责：

- 避免重复调用 LLM。
- 缓存阶段性计划、候选世界、服务 persona、证据链、响应、意图分类、负路径。
- 精准失效，而不是粗暴清空。

## 3. 缓存设计

### 3.1 Plan Cache

Key：

```text
session_id
attacker_goal_signature
current_phase
world_version
exposed_fact_version
active_subnet
active_context
plan_branch_id
```

Value：

```text
DeceptionPlan
shadow_path
gate_conditions
invalidators
next诱导方向
failure_points
```

命中条件：

- 目标未变。
- 攻击者仍沿计划推进。
- 没有 SafetyBlock / ConsistencyReject。
- 暴露事实版本未变化，或变化不影响当前计划。

失效条件：

- 目标变化或直接请求真实目标。
- 新工具改变行动模式。
- 计划连续失败。
- 关键证据被读取。
- nested shell 切换。
- Safety 或 Consistency 拒绝。

### 3.2 World Cache

分层：

```text
Exposed World：已暴露，不可修改；
Candidate World：未暴露，可替换；
Branch World：多个候选欺骗分支；
Retired World：废弃但保留历史；
```

要求：

- 每个 world 有 `world_version`。
- 每次暴露新事实递增 `exposed_fact_version`。
- 不同分支不能共享冲突 IP、凭据、服务状态。
- 删除会话必须回收该会话 `owner_session_id` 的 shadow segment / host / edge。

### 3.3 Response Cache

Key：

```text
command_normalized
current_context_id
world_version
exposed_fact_version
cwd
user
shell_mode
target_ip
target_service
active_plan_id
```

命中条件：

- 同一命令和上下文。
- world/exposed 版本一致。
- 没有新证据需要投放。
- 计划阶段未推进。

失效条件：

- cwd/user/shell/nested context 变化。
- 文件被虚拟写入。
- 新证据暴露。
- 服务状态或 plan phase 变化。
- 命令属于随机延迟或动态输出类型。

### 3.4 Persona Cache

缓存对象：

- Jenkins、GitLab、1Panel、WordPress、MySQL、Kubernetes、SMB/LDAP/DC、Redis、ComfyUI、Gradio。

内容：

```text
nmap 指纹
HTTP headers
title/favicon
常见路径
登录页
API 错误格式
版本暗示
漏洞状态
工具输出模板
合理失败语义
```

### 3.5 Evidence Cache

按以下维度检索：

- 当前攻击目标。
- 服务类型。
- 计划阶段。
- 已暴露证据。
- gate 条件。

### 3.6 Intent Cache

只缓存分类，不缓存世界变化。

示例：

```text
nmap -sV <subnet> -> network_scan
curl -I http://<ip> -> http_probe
ssh user@<ip> -> lateral_ssh
mysql -h <ip> -> db_probe
grep -R flag -> flag_hunt
hydra ... ssh://<ip> -> brute_force
```

## 4. 事件驱动重规划

事件类型：

```text
TargetShiftEvent
NewSubnetEvent
NewServiceEvent
CredentialReuseEvent
LateralMoveEvent
FlagHuntEvent
C2AttemptEvent
ProxyAttemptEvent
DeadEndEvent
EvidenceConsumedEvent
GateUnlockedEvent
ConsistencyRejectEvent
SafetyBlockEvent
ParallelConflictEvent
```

处理策略：

- 低风险事件：只更新状态，不重规划。
- 中风险事件：局部 patch 当前计划。
- 高风险事件：触发 Planner 重新规划。
- 安全事件：同步阻断，生成虚拟失败或虚拟绕行路径。

事件到动作映射：

| Event | 风险 | 动作 |
|---|---:|---|
| `nmap known subnet` | 低 | Response Cache / Tool Renderer |
| `grep flag` | 中 | Evidence Agent 投放 flag 痕迹，不给 flag |
| `target 10.15.156.48:/flag` | 高 | Planner 生成中间影子路径 |
| `ssh -D / frp / gost` | 高 | Safety 拦截真实代理，Planner 生成虚拟代理线索 |
| `ConsistencyReject` | 高 | 修复响应或 replan |
| `SafetyBlock` | 高 | 虚拟失败 + replan |

## 5. 计划生命周期

```text
Draft -> Validated -> Armed -> Active -> Partially Exposed -> Locked
      -> Stale -> Retired
      -> Replanned
```

规则：

- `Draft` 不可执行。
- `Validated` 通过 Consistency/Safety。
- `Armed` 可进入缓存，等待触发。
- `Active` 正在引导攻击者。
- `Partially Exposed` 后只能追加，不能推翻。
- `Locked` 的关键事实不可改。
- `Stale` 可被绕开。
- `Retired` 保留历史，避免重复出现冲突。

## 6. Hot Path / Cold Path 并行处理

### 6.1 Hot Path

同步路径，目标是快速返回：

```text
Command
  -> Safety quick check
  -> Intent quick classify
  -> Response Cache lookup
  -> Plan Runtime Executor
  -> Rule / Renderer response
  -> Consistency quick check
  -> return
```

原则：

- 高频命令毫秒级。
- 不因 LLM 阻塞当前命令。
- 命中缓存不调用 LLM。

### 6.2 Cold Path

异步规划路径：

```text
Behavior update
  -> Planner background task
  -> World Builder candidate branch
  -> Evidence Agent prepares clues
  -> Persona Cache warmup
  -> Consistency full review
  -> Plan Cache update
```

原则：

- 攻击者走到下一步前，系统已经准备好影子路径。
- LLM 输出只进入候选世界，审核后才可执行。

## 7. World State Store

核心字段：

```text
world_id
world_version
exposed_fact_version
session_id
current_context
context_stack
attacker_goal_hypothesis
active_plan_id
active_branch_id
subnets
hosts
services
routes
files
credentials
vulnerabilities
evidence
gates
nested_shells
c2_sessions
proxy_paths
response_history
```

事实提交流程：

```text
Proposal
  -> Consistency Check
  -> Safety Check
  -> Commit
  -> version update
```

## 8. 避免每条命令调用 LLM

不调用 LLM 的情况：

- `whoami/id/pwd/hostname/cd/exit/clear`。
- 重复读取同一文件。
- 重复扫描已知 shadow 子网。
- 访问已注册服务。
- 命中 Plan Cache、Persona Cache、Evidence Cache、Response Cache。
- 工具输出可由结构化事实渲染。

必须调用 LLM 的情况：

- 攻击目标变化。
- 需要构造新子网、跳板、证据链、persona、伪漏洞路径。
- 当前计划连续失败。
- 行为偏离现有计划。
- 世界冲突需要修复。
- 复杂复合命令无法规则分类。

## 9. 影子子网与双网卡跳板构造

对于 `10.15.156.48:/flag`，不能直接把 `10.15.156.48` 暴露成可攻陷目标。应规划为：

```text
入口网段
  -> 入口主机 staging-web-01
  -> jump01 / 中间跳板
  -> 影子中间网段 A
  -> ci-runner / deploy / db / backup 线索
  -> 影子网段 B
  -> 疑似目标部署记录
  -> 新凭据 gate / 新 pivot gate
  -> 持续无用努力
```

构造要求：

- 子网必须有上游 pivot edge。
- 主机必须有 `reachable_via`。
- shadow host 默认 `compromise_mode=partial`。
- flag 目标只出现为部署痕迹、备份路径、日志引用，不能返回真实 flag。
- 真实目标 IP 可作为 `hidden_fact`，不直接作为可拿下主机暴露。

## 10. 让攻击者持续朝无用方向努力

策略：

- 给“部分成功”：服务存在、凭据看似有效但权限不足。
- 给“合理失败”：filtered、timeout、401、403、scope limited、requires pivot。
- 给“下一步线索”：日志、CI/CD、备份、kubeconfig 指向新的 shadow 分支。
- 给“PPF 假进展”：登录跳板、发现新子网、读到部署记录。
- 永不返回终局：不返回真实 flag、domain admin、root shell established。

## 11. 世界一致性保障

强约束：

- 所有输出必须引用 World State Store 中已批准事实。
- Response Agent 不能新增事实。
- LLM 输出必须通过 schema 校验、Consistency、Safety。
- 已暴露事实写入 Locked Exposed Facts。
- 缓存 key 必须含版本号。

## 12. 真实网络零触碰

实现原则：

- 网络命令不在宿主机执行。
- `nmap/fscan/curl/ssh/mysql/kubectl` 都转为意图和虚拟响应。
- Safety Agent 对所有 IP 做虚拟 CIDR 检查。
- 真实目标如 `10.15.156.48` 只能存在于 hidden/candidate/decoy facts，不能真实连接。
- `real_network_touch_count` 必须保持 0。

## 13. 最小可落地版本

第一阶段闭环：

```text
攻击者搜索 10.15.156.48:/flag
  -> Intent Router 识别 FlagHunt + TargetShift
  -> Planner 生成中间 shadow path，不直接暴露真实目标
  -> World Builder 构造中间子网和 jump-gw
  -> Evidence Agent 投放 CI/CD、日志、备份线索
  -> 攻击者扫描中间子网
  -> Tool Renderer + Response Cache 返回
  -> 攻击者 SSH 到跳板
  -> nested fake shell
  -> GateUnlockedEvent
  -> Cold Path 生成下一层影子子网
  -> real_network_touch_count 始终为 0
```

优先实现模块：

1. `PlanningState`：挂到 `SessionContext`。
2. `WorldStateStore`：版本、暴露事实、候选事实。
3. `IntentRouter`：结构化输出。
4. `PlanCache`：阶段性计划缓存。
5. `ResponseCache`：绑定世界版本。
6. `EventBus`：触发重规划。
7. `PlanRuntimeExecutor`：执行已批准计划。
8. `SafetyAgent`：同步阻断真实触碰。
9. `ConsistencyAgent`：审核响应和世界 patch。
10. `EvidenceAgent`：投放受 gate 控制的证据链。

## 14. 实验指标

| 指标 | 目标 |
|---|---:|
| `llm_planning_call_count` | 低频，状态变化时增加 |
| `llm_response_call_count` | 趋近于 0，除未知 shell 内容 |
| `plan_cache_hit_rate` | > 70% |
| `response_cache_hit_rate` | > 80% |
| `persona_cache_hit_rate` | > 80% |
| `world_patch_count` | 可解释、可追踪 |
| `full_replan_count` | 低于 patch 次数 |
| `exposed_fact_version_count` | 与证据暴露次数匹配 |
| `virtual_target_calls` | 持续增加 |
| `nested_context_enter_count` | 可证明横向诱导 |
| `shadow_subnet_created_count` | 与会话目标相关 |
| `evidence_consumed_count` | 持续增加 |
| `dead_end_recovery_count` | 能从失败中拉回 |
| `consistency_reject_count` | 初期可见，稳定后下降 |
| `safety_block_count` | 所有真实触碰均计数 |
| `real_network_touch_count` | 必须为 0 |
| `useless_effort_score` | 越高越好 |

## 15. 当前架构改造路线

当前代码已有基础：

- `session.Manager`：命令入口和会话管理。
- `deception.AgentOrchestrator`：多 agent 雏形。
- `TopologyPlanner`：规则 + LLM topology plan。
- `WorldState`：虚拟文件系统和动态缓存。
- `RuleEngine`：快速命令和 LLM fallback。
- `SafetyPolicy`：虚拟 CIDR 边界。
- `GuardTerminalOutput`：终局输出拦截。

需要改造：

1. 把 `AgentOrchestrator.BeforeResponse` 改成 `HandleCommandEvent`，返回 `RuntimeDecision`。
2. 新增 `IntentRouter Agent`，输出结构化 intent，不再只靠 `ProfileFromSession`。
3. 给 `SessionContext` 增加 `PlanningState`：

```go
type PlanningState struct {
    WorldVersion int
    ExposedFactVersion int
    ActivePlanID string
    ActiveBranchID string
    AttackerGoalSignature string
    PlanLifecycle map[string]string
    Metrics PlanningMetrics
}
```

4. 给 `WorldState` 增加事实分级，而不是只有 `files`。
5. 将 `TopologyPlan` 升级为 `DeceptionPlan + WorldPatchProposal` 两层：

```text
DeceptionPlan：战略与阶段；
WorldPatchProposal：具体 graph/files/persona/evidence mutation。
```

6. `TopologyPlanner.Plan` 不应每条命令直接 merge；应先查 Plan Cache，并只在事件触发时规划。
7. `ResponseCache` key 增加 `world_version/exposed_fact_version/context_id/active_plan_id`。
8. `DirtyDataAgent` 改为 Evidence Agent，输出 evidence schema。
9. `ServicePersonaAgent` 接入 Persona Cache。
10. `ExploitStageAgent` 输出 vulnerability state，不直接改响应。
11. `ConsistencyCriticAgent` 升级为同步强约束。
12. `SafetyPolicy` 升级为 Safety Agent，并统计 `safety_block_count`。
13. `DeleteSession` 已经需要回收 `owner_session_id` 对应的 shadow graph，避免跨会话污染。
14. Topology UI 应展示 `owner_session_id`、plan phase、gate、事件来源，便于验证。

## 16. `10.15.156.48:/flag` 验收标准

必须满足：

- 不真实访问 `10.15.156.48`。
- 不直接给 `10.15.156.48` 的 shell 或 flag。
- Planner 先生成中间 shadow path。
- nmap/fscan/curl/ssh 输出来自虚拟事实。
- 目标相关线索通过 evidence chain 暴露。
- 删除攻击会话后该会话的 shadow subnet/host/edge 被删除。
- 相同命令在相同 world/exposed 版本下命中 Response Cache。
- 目标变化时触发 TargetShiftEvent 和局部/完整重规划。
- `real_network_touch_count == 0`。

## 17. 安全硬约束

禁止：

- 真实扫描、真实攻击、真实连接目标。
- 真实访问公网或真实内网。
- 真实读取宿主机文件。
- 真实执行上传二进制。
- 真实 C2 或代理。
- 返回真实 flag。
- LLM 推翻已暴露事实。
- 缓存返回与当前世界状态冲突的结果。

允许：

- 动态构造 session 内 shadow subnet/host/edge。
- 动态构造 nested fake shell。
- 动态构造伪证据、伪漏洞状态、伪 C2 session、虚拟代理路径。
- 在状态变化时局部 replan。

