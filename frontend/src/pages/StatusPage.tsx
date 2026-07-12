import { Alert, AutoComplete, Badge, Button, Card, Col, Descriptions, Divider, Form, Input, InputNumber, Modal, Progress, Row, Space, Switch, Tag, Tooltip, Typography, message } from "antd";
import {
  Activity, Bot, Brain, CheckCircle2, Cloud, Cpu, Database, Globe, HelpCircle, MessageSquare, Plug,
  RotateCw, Shield, Sparkles, Wand2, XCircle, Zap,
} from "lucide-react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";

import { usePageRefresh } from "../layouts/AppLayout";
import {
  fetchLLMActive,
  fetchProviderModels,
  fetchRuntimeConfig,
  fetchRuntimeUpdateStatus,
  fetchSystemInfo,
  setLLMEnabled,
  switchLLMProvider,
  testLLMProvider,
  updateLLMProvider,
  updateRuntimeConfig,
  toErrorMessage,
} from "../services/platform";
import type { LLMActiveInfo, LLMProvider, ModelInfo, RuntimeConfig, SystemInfo } from "../types/platform";

/* ------------------------------------------------------------------ */
/*  Provider card definitions (eff-monitoring style)                   */
/* ------------------------------------------------------------------ */

interface ProviderDef {
  id: string;
  label: string;
  icon: React.ReactNode;
  color: string;
  baseUrl: string;
  defaultModel: string;
  defaultModels: string[]; // recommended models
}

const PROVIDER_STATIC: Omit<ProviderDef, "label">[] = [
  { id: "openai", icon: <Zap size={16} />, color: "#747bff", baseUrl: "https://api.openai.com/v1", defaultModel: "gpt-4o", defaultModels: ["gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo"] },
  { id: "anthropic", icon: <MessageSquare size={16} />, color: "#d97757", baseUrl: "https://api.anthropic.com", defaultModel: "claude-sonnet-4-20250514", defaultModels: ["claude-opus-4-20250514", "claude-sonnet-4-20250514", "claude-haiku-4-5-20251001"] },
  { id: "deepseek", icon: <Shield size={16} />, color: "#0052D9", baseUrl: "https://api.deepseek.com/v1", defaultModel: "deepseek-chat", defaultModels: ["deepseek-chat", "deepseek-reasoner"] },
  { id: "qwen", icon: <Cloud size={16} />, color: "#ff9c6e", baseUrl: "https://dashscope.aliyuncs.com/compatible-mode/v1", defaultModel: "qwen-turbo", defaultModels: ["qwen-max", "qwen-plus", "qwen-turbo"] },
  { id: "zhipu", icon: <Activity size={16} />, color: "#36cfc9", baseUrl: "https://open.bigmodel.cn/api/paas/v4", defaultModel: "glm-4-flash", defaultModels: ["glm-4-plus", "glm-4-air", "glm-4-flash"] },
  { id: "moonshot", icon: <Sparkles size={16} />, color: "#323232", baseUrl: "https://api.moonshot.cn/v1", defaultModel: "moonshot-v1-8k", defaultModels: ["moonshot-v1-8k", "moonshot-v1-32k", "moonshot-v1-128k"] },
  { id: "google", icon: <Bot size={16} />, color: "#4285f4", baseUrl: "https://generativelanguage.googleapis.com/v1beta/openai", defaultModel: "gemini-1.5-flash", defaultModels: ["gemini-1.5-pro", "gemini-1.5-flash"] },
  { id: "ollama", icon: <Database size={16} />, color: "#52c41a", baseUrl: "http://host.docker.internal:11434", defaultModel: "", defaultModels: ["llama3", "qwen2.5", "deepseek-r1"] },
  { id: "openrouter", icon: <Cpu size={16} />, color: "#6366f1", baseUrl: "https://openrouter.ai/api/v1", defaultModel: "", defaultModels: ["anthropic/claude-sonnet-4-20250514", "openai/gpt-4o"] },
  { id: "minimax", icon: <Brain size={16} />, color: "#FF6B6B", baseUrl: "https://api.minimaxi.com/v1", defaultModel: "MiniMax-M2.7", defaultModels: ["MiniMax-M2.7"] },
  { id: "xiaomi_mimo", icon: <Wand2 size={16} />, color: "#ff6900", baseUrl: "https://api.xiaomimimo.com/v1", defaultModel: "mimo-v2.5-pro", defaultModels: ["mimo-v2.5-pro"] },
  { id: "custom", icon: <Globe size={16} />, color: "#8c8c8c", baseUrl: "", defaultModel: "", defaultModels: [] },
];

function getProviderDefs(t: TFunction<"status">): ProviderDef[] {
  return PROVIDER_STATIC.map((p) => ({
    ...p,
    label: t(`providers.${p.id}`),
  }));
}

const DEFAULT_HONEYPOT_CONFIG: RuntimeConfig["honeypot"] = {
  ssh_port: 2222,
  api_port: 8000,
  topology_cidr: "192.168.56.0/24",
  session_timeout: 600,
};

/* ------------------------------------------------------------------ */
/*  StatusPage                                                         */
/* ------------------------------------------------------------------ */

export function StatusPage() {
  const { t } = useTranslation("status");
  const [info, setInfo] = useState<SystemInfo | null>(null);
  const [config, setConfig] = useState<RuntimeConfig | null>(null);
  const [llm, setLLM] = useState<LLMActiveInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadData() {
    setLoading(true);
    setError("");
    try {
      const [infoData, configData, llmData] = await Promise.all([
        fetchSystemInfo(),
        fetchRuntimeConfig(),
        fetchLLMActive(),
      ]);
      setInfo(infoData);
      setConfig(configData);
      setLLM(llmData);
    } catch (err) {
      setError(toErrorMessage(err, t("error.loadFailed")));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { loadData(); }, []);
  usePageRefresh(loadData, loading);

  if (loading) return <Card className="ah-panel" loading />;
  if (error) return <Alert type="error" message={t("error.loadError")} description={error} showIcon />;

  const providers = llm?.providers || [];
  const activeId = llm?.active_provider || "";

  return (
    <div className="page">
      {/* ---- System Info ---- */}
      <Row gutter={[16, 16]} className="status-summary-grid">
        <Col xs={24} lg={12}>
          <Card title={t("systemInfo")} className="ah-panel status-top-card">
            <Descriptions bordered size="small" column={1}>
              <Descriptions.Item label={t("labels.appName")}>{info?.app_name}</Descriptions.Item>
              <Descriptions.Item label={t("labels.version")}><Tag color="blue">{info?.app_version}</Tag></Descriptions.Item>
              <Descriptions.Item label={t("labels.mode")}><Tag color="green">{info?.mode}</Tag></Descriptions.Item>
              <Descriptions.Item label={t("labels.apiPrefix")}>{info?.api_prefix}</Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card title={t("honeypotConfig")} className="ah-panel status-top-card">
            <HoneypotConfigForm config={config?.honeypot} onSaved={loadData} />
          </Card>
        </Col>
      </Row>

      {/* ---- LLM Config ---- */}
      <Card
        title={<Space><Plug size={16} />{t("llm.title")}{llm?.is_active ? <Tag color="green">{t("llm.enabled")}</Tag> : <Tag>{t("llm.disabled")}</Tag>}</Space>}
        className="ah-panel"
      >
        <AiConfigForm providers={providers} activeId={activeId} llmEnabled={!!llm?.enabled} onSaved={loadData} />
      </Card>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  HoneypotConfigForm                                                 */
/* ------------------------------------------------------------------ */

function HoneypotConfigForm({ config, onSaved }: {
  config?: RuntimeConfig["honeypot"];
  onSaved: () => void;
}) {
  const { t } = useTranslation("status");
  const [form] = Form.useForm<RuntimeConfig["honeypot"]>();
  const [saving, setSaving] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [updateStep, setUpdateStep] = useState(t("updateModal.progressSteps.preparing"));
  const [updatePercent, setUpdatePercent] = useState(8);

  useEffect(() => {
    if (config) {
      form.setFieldsValue(config);
    }
  }, [config, form]);

  async function handleSave() {
    setSaving(true);
    try {
      const values = await form.validateFields();
      setUpdating(true);
      setUpdatePercent(12);
      setUpdateStep(t("updateModal.progressSteps.writingConfig"));
      await updateRuntimeConfig({ honeypot: values });
      setUpdatePercent(28);
      setUpdateStep(t("updateModal.progressSteps.rebuilding"));
      waitForRuntimeRecovery(values);
    } catch (err) {
      setUpdating(false);
      message.error(toErrorMessage(err, t("error.saveFailed")));
    } finally {
      setSaving(false);
    }
  }

  async function waitForRuntimeRecovery(expected: RuntimeConfig["honeypot"]) {
    await new Promise((resolve) => window.setTimeout(resolve, 2500));
    for (let attempt = 1; attempt <= 75; attempt += 1) {
      try {
        const status = await fetchRuntimeUpdateStatus();
        if (status.phase === "queued") {
          setUpdatePercent(35);
          setUpdateStep(t("updateModal.progressSteps.queued"));
        } else if (status.phase === "running") {
          setUpdatePercent(Math.min(82, 42 + attempt));
          setUpdateStep(t("updateModal.progressSteps.running"));
        } else if (status.phase === "failed") {
          setUpdating(false);
          message.error(status.error || t("updateModal.progressSteps.failed"));
          return;
        } else if (status.phase === "complete") {
          setUpdatePercent(92);
          setUpdateStep(t("updateModal.progressSteps.configValidating"));
          const current = await fetchRuntimeConfig();
          if (
            current.honeypot.ssh_port === expected.ssh_port &&
            current.honeypot.api_port === expected.api_port &&
            current.honeypot.topology_cidr === expected.topology_cidr &&
            current.honeypot.session_timeout === expected.session_timeout
          ) {
            setUpdatePercent(100);
            setUpdateStep(t("updateModal.progressSteps.complete"));
            message.success(t("updateModal.honeypotUpdated"));
            window.setTimeout(() => window.location.reload(), 900);
            return;
          }
          setUpdateStep(t("updateModal.progressSteps.waitingConsistency"));
        } else {
          setUpdatePercent(Math.min(65, 30 + attempt));
          setUpdateStep(t("updateModal.progressSteps.waitingStart"));
        }
      } catch {
        if (attempt > 2) {
          setUpdatePercent(Math.min(78, 38 + attempt));
          setUpdateStep(t("updateModal.progressSteps.apiUnavailable"));
        }
        try {
          const response = await fetch(`/healthz?t=${Date.now()}`, { cache: "no-store" });
          if (response.ok && attempt > 8) {
            setUpdateStep(t("updateModal.progressSteps.apiRecovered"));
          }
        } catch {
          // Expected while Docker is recreating the honeypot/API container.
        }
      }
      await new Promise((resolve) => window.setTimeout(resolve, 2000));
    }
    setUpdating(false);
    message.warning(t("updateModal.progressSteps.timeoutWarning"));
    onSaved();
  }

  /*
   * The update modal intentionally blocks navigation while Docker is changing
   * ports and topology. Without this, users can keep clicking stale pages while
   * containers are being recreated underneath them.
   */
  function renderUpdatePercent() {
    return updatePercent;
  }

  return (
    <div>
      <Modal
        open={updating}
        centered
        closable={false}
        keyboard={false}
        maskClosable={false}
        footer={null}
        width={680}
        className="runtime-update-modal"
      >
        <div className="runtime-update-panel">
          <div className="runtime-update-orb" />
          <Typography.Title level={3}>{t("updateModal.title")}</Typography.Title>
          <Typography.Paragraph type="secondary">
            {t("updateModal.body")}
          </Typography.Paragraph>
          <Progress percent={renderUpdatePercent()} status="active" />
          <Typography.Text>{updateStep}</Typography.Text>
        </div>
      </Modal>
      <Form
        form={form}
        layout="vertical"
        initialValues={config}
      >
        <Row gutter={[12, 0]}>
          <Col xs={24} md={12}>
            <Form.Item
              label={t("labels.sshPort")}
              name="ssh_port"
              rules={[{ required: true, message: t("validation.sshPortRequired") }]}
            >
              <InputNumber min={1} max={65535} style={{ width: "100%" }} />
            </Form.Item>
          </Col>
          <Col xs={24} md={12}>
            <Form.Item
              label={t("labels.apiPort")}
              name="api_port"
              rules={[{ required: true, message: t("validation.apiPortRequired") }]}
            >
              <InputNumber min={1} max={65535} style={{ width: "100%" }} />
            </Form.Item>
          </Col>
          <Col xs={24} md={12}>
            <Form.Item
              label={
                <span className="field-label-help">
                  {t("labels.topologyCidr")}
                  <Tooltip title={t("tooltip.topologyCidr")}>
                    <HelpCircle size={14} />
                  </Tooltip>
                </span>
              }
              name="topology_cidr"
              rules={[
                { required: true, message: t("validation.cidrRequired") },
                { pattern: /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/, message: t("validation.cidrFormat") },
              ]}
            >
              <Input placeholder="192.168.56.0/24" />
            </Form.Item>
          </Col>
          <Col xs={24} md={12}>
            <Form.Item
              label={t("labels.sessionTimeout")}
              name="session_timeout"
              rules={[{ required: true, message: t("validation.timeoutRequired") }]}
            >
              <InputNumber min={60} max={86400} style={{ width: "100%" }} />
            </Form.Item>
          </Col>
        </Row>
        <Space>
          <Button type="primary" loading={saving} onClick={handleSave}>{t("buttons.saveConfig")}</Button>
          <Tooltip title={t("llm.honeypotSaveTooltip")}>
            <HelpCircle className="runtime-save-help" size={16} />
          </Tooltip>
          <Button disabled={saving} onClick={() => form.setFieldsValue(DEFAULT_HONEYPOT_CONFIG)}>{t("buttons.resetDefault")}</Button>
        </Space>
      </Form>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  AiConfigForm — the main LLM config component                       */
/* ------------------------------------------------------------------ */

function AiConfigForm({ providers, activeId, llmEnabled, onSaved }: {
  providers: LLMProvider[];
  activeId: string;
  llmEnabled: boolean;
  onSaved: () => void;
}) {
  const { t } = useTranslation("status");
  const initial = providers.find(p => p.id === activeId) || providers[0];
  const [selectedId, setSelectedId] = useState(initial?.id || "openai");
  const [form, setForm] = useState<LLMProvider>(initial || { ...emptyProvider("openai") });
  const [dynamicModels, setDynamicModels] = useState<ModelInfo[]>([]);
  const [modelsLoading, setModelsLoading] = useState(false);
  const [testState, setTestState] = useState<"idle" | "loading" | "success" | "error">("idle");
  const [testMsg, setTestMsg] = useState("");
  const [saving, setSaving] = useState(false);

  // Sync form when providers change
  useEffect(() => {
    const p = providers.find(x => x.id === selectedId);
    if (p) {
      setForm({ ...p });
      setDynamicModels([]);
      setTestState("idle");
    }
  }, [providers, selectedId]);

  function handleSelectProvider(id: string) {
    setSelectedId(id);
    const existing = providers.find(p => p.id === id);
    if (existing) {
      setForm({ ...existing, model: "" });
    } else {
      const def = PROVIDER_STATIC.find(d => d.id === id);
      setForm({
        id,
        name: id,
        type: id === "ollama" ? "ollama" : id === "anthropic" ? "anthropic" : "openai",
        base_url: def?.baseUrl || "",
        api_key: "",
        model: "",
        max_tokens: 2048,
        temperature: 0.7,
        enabled: false,
      });
    }
    setDynamicModels([]);
    setTestState("idle");
  }

  async function handleFetchModels() {
    setModelsLoading(true);
    try {
      const models = await fetchProviderModels(form.id, form.base_url, form.api_key);
      setDynamicModels(models);
      if (models.length > 0) {
        message.success(t("llm.messages.modelsFetched", { count: models.length }));
      } else {
        message.warning(t("llm.messages.noModels"));
      }
    } catch {
      message.error(t("llm.messages.fetchFailed"));
    } finally {
      setModelsLoading(false);
    }
  }

  async function handleTest() {
    setTestState("loading");
    setTestMsg("");
    try {
      const res = await testLLMProvider(form.id, form.base_url, form.api_key);
      if (res.ok) {
        setTestState("success");
        setTestMsg(t("llm.messages.connectionOk"));
      } else {
        setTestState("error");
        setTestMsg(res.message || t("llm.messages.connectionFailed"));
      }
    } catch (err) {
      setTestState("error");
      setTestMsg(toErrorMessage(err, t("llm.messages.testFailed")));
    }
  }

  async function handleSave() {
    setSaving(true);
    const scrollY = window.scrollY;
    try {
      // Saving a provider means it is intended to become active. Persist the
      // provider as enabled before switching; otherwise the API correctly
      // rejects the switch with "provider ... is not enabled".
      const enabledForm = { ...form, enabled: true };
      await updateLLMProvider(form.id, enabledForm);
      await switchLLMProvider(form.id);
      await setLLMEnabled(true);
      setForm(enabledForm);
      message.success(t("llm.messages.saved"));
      onSaved();
      setTimeout(() => window.scrollTo(0, scrollY), 50);
    } catch (err) {
      message.error(toErrorMessage(err, t("llm.messages.saveFailed")));
    } finally {
      setSaving(false);
    }
  }

  async function handleToggleEnabled(enabled: boolean) {
    try {
      await setLLMEnabled(enabled);
      onSaved();
      message.success(enabled ? t("llm.messages.llmEnabled") : t("llm.messages.llmDisabled"));
    } catch (err) {
      message.error(toErrorMessage(err, t("llm.messages.operationFailed")));
    }
  }

  const isOllama = form.type === "ollama";

  // Build model options — only dynamically fetched + current config
  const grouped: Record<string, string[]> = {};
  dynamicModels.forEach(m => {
    const vendor = m.owned_by || t("llm.modelGroupOther");
    if (!grouped[vendor]) grouped[vendor] = [];
    if (!grouped[vendor].includes(m.id)) grouped[vendor].push(m.id);
  });
  // Add current model if not in any group
  if (form.model && !Object.values(grouped).flat().includes(form.model)) {
    if (!grouped[t("llm.modelGroupCurrent")]) grouped[t("llm.modelGroupCurrent")] = [];
    grouped[t("llm.modelGroupCurrent")].push(form.model);
  }
  const modelOptions = Object.entries(grouped)
    .filter(([, v]) => v.length > 0)
    .map(([vendor, models]) => ({
      label: vendor,
      options: models.map(id => ({ value: id, label: id })),
    }));

  return (
    <div>
      {/* Global enable + provider cards */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
          <span style={{ fontWeight: 500, fontSize: 14 }}>{t("llm.selectProvider")}</span>
          <Space>
            <span style={{ fontWeight: 500, fontSize: 13 }}>{t("llm.llmEnable")}</span>
            <Switch checked={llmEnabled} onChange={handleToggleEnabled} />
          </Space>
        </div>
        <Row gutter={[12, 12]}>
          {getProviderDefs(t).map(p => {
            const isActive = selectedId === p.id;
            const isActiveProvider = activeId === p.id;
            return (
              <Col key={p.id} xs={12} sm={8} md={6} lg={4}>
                <div
                  className={`provider-card ${isActive ? "active" : ""}`}
                  onClick={() => handleSelectProvider(p.id)}
                  style={{
                    border: `1.5px solid ${isActive ? p.color : isActiveProvider ? "#52c41a" : "#f0f0f0"}`,
                    background: isActive ? `${p.color}0a` : "#fff",
                    color: isActive ? p.color : "inherit",
                  }}
                >
                  {p.icon}
                  <span style={{ fontSize: 13 }}>{p.label}</span>
                  {isActiveProvider && !isActive && (
                    <div style={{ position: "absolute", top: 6, right: 8 }}>
                      <Badge status="success" />
                    </div>
                  )}
                </div>
              </Col>
            );
          })}
        </Row>
      </div>

      {/* Config form */}
      <Card size="small" style={{ marginBottom: 16 }}>
        <div style={{ display: "grid", gap: 16 }}>
          {/* Row 1: Base URL + API Key */}
          <Row gutter={16}>
            <Col span={14}>
              <div style={{ marginBottom: 4, fontWeight: 500 }}>{t("llm.baseUrl")}</div>
              <Input
                prefix={<Globe size={14} />}
                value={form.base_url}
                onChange={e => setForm({ ...form, base_url: e.target.value })}
                placeholder={isOllama ? "http://127.0.0.1:11434" : "https://api.openai.com/v1"}
              />
            </Col>
            <Col span={10}>
              <div style={{ marginBottom: 4, fontWeight: 500 }}>
                {t("llm.apiKey")}
                {isOllama && <Typography.Text type="secondary" style={{ fontSize: 12, marginLeft: 8 }}>{t("llm.ollamaHint")}</Typography.Text>}
              </div>
              <Input.Password
                value={form.api_key}
                onChange={e => setForm({ ...form, api_key: e.target.value })}
                placeholder={isOllama ? t("llm.customHint") : "sk-..."}
                disabled={isOllama}
              />
            </Col>
          </Row>

          {/* Row 2: Model + Refresh */}
          <div>
            <div style={{ marginBottom: 4, fontWeight: 500 }}>
              <Space size={4}>
                {t("llm.modelId")}
                <Tooltip title={t("llm.fetchModelsTooltip")}>
                  <Button
                    type="link"
                    size="small"
                    icon={<RotateCw size={12} className={modelsLoading ? "spin-icon" : ""} />}
                    style={{ padding: 0, height: "auto" }}
                    onClick={handleFetchModels}
                    disabled={modelsLoading}
                  />
                </Tooltip>
              </Space>
            </div>
            <AutoComplete
              style={{ width: "100%" }}
              options={modelOptions}
              value={form.model}
              onChange={v => setForm({ ...form, model: v })}
              placeholder={t("llm.modelPlaceholder")}
              filterOption={(input, option) => {
                const val = (option as Record<string, unknown>)?.value;
                return typeof val === "string" && val.toLowerCase().includes(input.toLowerCase());
              }}
            />
          </div>

          {/* Row 3: Test + Save */}
          <Divider style={{ margin: "4px 0" }} />
          <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
            <div style={{ flex: 1 }}>
              {testState !== "idle" && (
                <Alert
                  type={testState === "success" ? "success" : testState === "error" ? "error" : "info"}
                  message={testState === "loading" ? t("llm.alert.testing") : testState === "success" ? t("llm.alert.passed") : t("llm.alert.failed")}
                  description={testMsg}
                  showIcon
                  banner
                  style={{ marginBottom: 0 }}
                />
              )}
            </div>

            <Button
              icon={testState === "success" ? <CheckCircle2 size={14} /> : testState === "error" ? <XCircle size={14} /> : <Zap size={14} />}
              loading={testState === "loading"}
              onClick={handleTest}
            >
              {t("llm.testConnection")}
            </Button>

            <Button type="primary" loading={saving} onClick={handleSave}>
              {t("llm.saveConfig")}
            </Button>
          </div>
        </div>
      </Card>

      <style>{`
        .provider-card {
          position: relative;
          border-radius: 8px;
          padding: 14px 8px;
          cursor: pointer;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          gap: 6px;
          transition: all 0.2s;
          height: 76px;
          user-select: none;
        }
        .provider-card:hover {
          box-shadow: 0 2px 8px rgba(0,0,0,0.08);
          transform: translateY(-1px);
        }
        .provider-card.active {
          font-weight: 600;
          box-shadow: 0 2px 12px rgba(0,0,0,0.1);
        }
        .spin-icon {
          animation: spin 1s linear infinite;
        }
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}

function emptyProvider(id: string): LLMProvider {
  const def = PROVIDER_STATIC.find(d => d.id === id);
  return {
    id,
    name: id,
    type: id === "ollama" ? "ollama" : id === "anthropic" ? "anthropic" : "openai",
    base_url: def?.baseUrl || "",
    api_key: "",
    model: "",
    max_tokens: 2048,
    temperature: 0.7,
    enabled: false,
  };
}
