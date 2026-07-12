import { ArrowLeft, Bot, Maximize2 } from "lucide-react";
import { Alert, Button, Card, Col, Empty, Input, Modal, Pagination, Row, Table, Tabs, Tag, Tooltip, message } from "antd";
import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useParams, useSearchParams } from "react-router-dom";

import { HostPosition } from "../components/HostPosition";
import { PPFGauge } from "../components/PPFGauge";
import { EvidenceGrid } from "../components/EvidenceGrid";
import { ScoreBreakdown } from "../components/ScoreBreakdown";
import { ThreatLevel } from "../components/ThreatBadge";
import { usePageRefresh } from "../layouts/AppLayout";
import { fetchSessionCommands, fetchSessionDetail, toErrorMessage } from "../services/platform";
import type { CommandRow, SessionDetail } from "../types/platform";
import { formatTime } from "../utils/format";
import { getTokenColor } from "../utils/evidence";
import { getTriggeredByLabel } from "../utils/topology";

const INTENT_COLORS: Record<string, string> = {
  network_scan: "#3b82f6",
  service_probe: "#3b82f6",
  http_probe: "#f59e0b",
  db_probe: "#f59e0b",
  domain_probe: "#f59e0b",
  evidence_search: "#f59e0b",
  lateral_movement: "#f97316",
  privilege_escalation: "#f97316",
  data_exfiltration: "#ef4444",
  shell_command: "#94a3b8",
  unknown: "#94a3b8",
};

function CommandDetailModal({
  item,
  index,
  open,
  onClose,
}: {
  item: CommandRow | null;
  index: number;
  open: boolean;
  onClose: () => void;
}) {
  const { t } = useTranslation("sessions");
  if (!item) return null;
  return (
    <Modal
      className="command-detail-modal"
      open={open}
      onCancel={onClose}
      footer={null}
      width={720}
      title={t("commandModal.title", { number: index + 1 })}
      styles={{ body: { padding: 0 } }}
    >
      <div className="cmd-detail">
        <div className="cmd-detail__meta">
          <div className="cmd-detail__row">
            <span>{t("commandModal.time")}</span>
            <strong>{formatTime(item.timestamp)}</strong>
          </div>
          {item.hostname && (
            <div className="cmd-detail__row">
              <span>{t("commandModal.host")}</span>
              <strong>{item.hostname}</strong>
            </div>
          )}
          <div className="cmd-detail__row">
            <span>{t("commandModal.source")}</span>
            <strong>
              {item.llm_generated ? (
                <Tag icon={<Bot size={12} />} color="purple">{t("common:source.llm")}</Tag>
              ) : (
                <Tag color="default">{t("common:source.rule")}</Tag>
              )}
            </strong>
          </div>
          {item.intent && (
            <div className="cmd-detail__row">
              <span>{t("commandModal.intent")}</span>
              <strong>
                <Tag color={INTENT_COLORS[item.intent] || "#94a3b8"}>{item.intent}</Tag>
              </strong>
            </div>
          )}
          <div className="cmd-detail__row">
            <span>{t("commandModal.score")}</span>
            <strong>{item.score}</strong>
          </div>
          {item.evidence_hits?.length > 0 && (
            <div className="cmd-detail__row">
              <span>{t("commandModal.evidence")}</span>
              <strong>
                {item.evidence_hits.map((tok) => (
                  <Tag key={tok} style={{ borderColor: getTokenColor(tok), color: getTokenColor(tok) }}>
                    {tok}
                  </Tag>
                ))}
              </strong>
            </div>
          )}
        </div>
        <div className="cmd-detail__terminal">
          <div className="cmd-detail__command">
            <span className="terminal-prompt">$</span>
            <span>{item.command}</span>
          </div>
          <pre className="cmd-detail__output">{item.output || "(no output)"}</pre>
        </div>
      </div>
    </Modal>
  );
}

const TERMINAL_MAX_LINES = 12;
const TABLE_OUTPUT_PREVIEW_LIMIT = 4000;

function outputPreview(value: string) {
  if (!value || value.length <= TABLE_OUTPUT_PREVIEW_LIMIT) return value || "--";
  return `${value.slice(0, TABLE_OUTPUT_PREVIEW_LIMIT)}\n… (${value.length - TABLE_OUTPUT_PREVIEW_LIMIT} more characters; open details for full output)`;
}

function TerminalBlock({ item, index }: { item: CommandRow; index: number }) {
  const { t } = useTranslation("common");
  const [expanded, setExpanded] = useState(false);
  const output = item.output || "(no output)";
  const lines = output.split("\n");
  const needsTruncate = lines.length > TERMINAL_MAX_LINES && !expanded;
  const display = needsTruncate ? lines.slice(0, TERMINAL_MAX_LINES).join("\n") : output;

  return (
    <section className="terminal-block">
      <div className="terminal-meta">
        <span>#{index + 1}</span>
        <span>{formatTime(item.timestamp)}</span>
        {item.hostname && (
          <span className="terminal-meta__host">{item.hostname}</span>
        )}
        {item.llm_generated ? (
          <Tag icon={<Bot size={12} />} color="purple">{t("source.llm")}</Tag>
        ) : null}
        {item.intent ? (
          <Tag color={INTENT_COLORS[item.intent] || "#94a3b8"} style={{ borderColor: INTENT_COLORS[item.intent] }}>
            {item.intent}
          </Tag>
        ) : null}
        {item.evidence_hits?.length
          ? item.evidence_hits.map((tok) => (
              <Tooltip key={tok} title={`${t("sessions:evidencePrefix")}${tok}`}>
                <span
                  style={{
                    display: "inline-block",
                    width: 8,
                    height: 8,
                    borderRadius: "50%",
                    background: getTokenColor(tok),
                  }}
                />
              </Tooltip>
            ))
          : null}
      </div>
      <div className="terminal-command">
        <span className="terminal-prompt">$</span>
        <span>{item.command || "-"}</span>
      </div>
      <pre>{display}</pre>
      {needsTruncate && (
        <button className="terminal-expand" onClick={() => setExpanded(true)}>
          {t("shell.expandAll", { count: lines.length })}
        </button>
      )}
      {expanded && lines.length > TERMINAL_MAX_LINES && (
        <button className="terminal-expand" onClick={() => setExpanded(false)}>
          {t("shell.collapse")}
        </button>
      )}
    </section>
  );
}

function TerminalReplay({ commands }: { commands: CommandRow[] }) {
  const { t } = useTranslation("sessions");
  if (!commands.length) {
    return <Empty description={t("empty.noReplay")} />;
  }
  return (
    <div className="terminal-replay">
      {commands.map((item, index) => (
        <TerminalBlock key={index} item={item} index={index} />
      ))}
    </div>
  );
}

export function SessionDetailPage() {
  const { sessionId } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const { t } = useTranslation("sessions");
  const [session, setSession] = useState<SessionDetail | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [commandQuery, setCommandQuery] = useState("");
  const [commandPage, setCommandPage] = useState(1);
  const [commandPageSize, setCommandPageSize] = useState(20);
  const [commands, setCommands] = useState<CommandRow[]>([]);
  const [commandTotal, setCommandTotal] = useState(0);
  const detailRequestRef = useRef(0);
  const commandRequestRef = useRef(0);

  useEffect(() => {
    setCommandPage(1);
  }, [sessionId]);
  const [detailCmd, setDetailCmd] = useState<{ item: CommandRow; index: number } | null>(null);
  const activeTab = searchParams.get("tab") === "replay" ? "replay" : "timeline";

  const loadData = useCallback(async (silent = false) => {
    if (!sessionId) return;
    const requestId = ++detailRequestRef.current;
    if (!silent) setLoading(true);
    setError("");
    try {
      const data = await fetchSessionDetail(sessionId);
      if (requestId === detailRequestRef.current) setSession(data);
    } catch (err) {
      if (requestId === detailRequestRef.current) setError(toErrorMessage(err, t("error.loadFailed")));
    } finally {
      if (!silent && requestId === detailRequestRef.current) setLoading(false);
    }
  }, [sessionId, t]);

  const loadCommands = useCallback(async () => {
    if (!sessionId) return;
    const requestId = ++commandRequestRef.current;
    try {
      const data = await fetchSessionCommands(sessionId, {
        page: commandPage,
        pageSize: commandPageSize,
        query: commandQuery,
      });
      if (requestId !== commandRequestRef.current) return;
      setCommands(data.items || []);
      setCommandTotal(data.total);
    } catch (err) {
      if (requestId === commandRequestRef.current) message.error(toErrorMessage(err, t("message.loadFailed")));
    }
  }, [sessionId, commandPage, commandPageSize, commandQuery, t]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  useEffect(() => {
    loadCommands();
  }, [loadCommands]);

  useEffect(() => {
    if (!session || session.status !== "active") return;
    const timer = setInterval(() => {
      loadData(true);
      loadCommands();
    }, 5000);
    return () => clearInterval(timer);
  }, [session?.status, loadData, loadCommands]);
  usePageRefresh(loadData, loading);

  if (loading) return <Card className="ah-panel" loading />;
  if (error) return <Alert type="error" message={t("error.loadFailed")} description={error} showIcon />;
  if (!session) return <Empty description={t("empty.notFound")} />;

  const lm = session.loop_metrics;
  const shadowHosts = session.shadow_hosts || [];

  return (
    <div className="page session-detail-page">
      <div className="page-toolbar">
        <div className="page-header-inline">
          <Link to="/sessions">
            <Button icon={<ArrowLeft size={16} />} />
          </Link>
          <div className="session-identity">
            <strong>
              {session.username}@{session.hostname}
              <ThreatLevel score={session.score} />
            </strong>
            <span>
              {session.session_id} | {session.remote_addr} | {formatTime(session.connected_at)} |{" "}
              <Tag color={session.status === "active" ? "green" : "default"}>{session.status}</Tag>
            </span>
          </div>
        </div>
      </div>

      <HostPosition session={session} />

      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={6}>
          <Card className="ah-metric-card">
            <span>{t("cards.commandCount")}</span>
            <strong>{session.command_count}</strong>
            <p>{t("cards.commandCountDesc")}</p>
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="ah-metric-card">
            <span>{t("cards.evidenceHits")}</span>
            <strong>{session.evidence_hits}</strong>
            <p>{t("cards.evidenceHitsDesc")}</p>
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="ah-metric-card">
            <span>{t("cards.threatScore")}</span>
            <strong style={{ color: session.score >= 50 ? "#ef4444" : session.score >= 20 ? "#f59e0b" : "#22c55e" }}>
              {session.score}
            </strong>
            <p>{t("cards.threatScoreDesc")}</p>
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card className="ah-metric-card">
            <span>{t("cards.ppfTriggered")}</span>
            <strong style={{ color: session.ppf_triggered ? "#f59e0b" : "#94a3b8" }}>
              {session.ppf_triggered ? t("common:ppf.active") : t("common:ppf.waiting")}
            </strong>
            <p>{t("cards.ppfTriggeredDesc")}</p>
          </Card>
        </Col>
      </Row>

      <Card title={t("sections.ppfProgress")} className="ah-panel">
        <PPFGauge loopMetrics={lm} ppfTriggered={session.ppf_triggered} />
      </Card>

      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <Card title={t("sections.evidenceFound")} className="ah-panel">
            <EvidenceGrid hitTokens={session.evidence_tokens || []} />
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card title={t("sections.scoreBreakdown")} className="ah-panel">
            <ScoreBreakdown loopMetrics={lm} />
          </Card>
        </Col>
      </Row>

      {shadowHosts.length > 0 && (
        <Card title={t("sections.shadowHosts")} className="ah-panel">
          <div className="shadow-hosts-list">
            {shadowHosts.map((host, i) => (
              <span key={i} className="shadow-host-chip">
                {host.hostname} ({host.ip})
                {host.triggered_by && (
                  <span className="shadow-host-chip__trigger">via {getTriggeredByLabel(host.triggered_by)}</span>
                )}
              </span>
            ))}
          </div>
        </Card>
      )}

      <Card className="ah-panel">
        <Tabs
          activeKey={activeTab}
          onChange={(key) => setSearchParams(key === "replay" ? { tab: "replay" } : {})}
          items={[
            {
              key: "timeline",
              label: t("tabs.commandTimeline"),
              children: (
                <div className="page-section">
                  <Input.Search
                    allowClear
                    placeholder={t("searchPlaceholder")}
                    value={commandQuery}
                    onChange={(e) => {
                      setCommandQuery(e.target.value);
                      setCommandPage(1);
                    }}
                    style={{ maxWidth: 320, marginBottom: 12 }}
                  />
                  <Table<CommandRow>
                    className="session-command-table"
                    rowKey={(_, i) => String(i)}
                    dataSource={commands}
                    size="small"
                    scroll={{ x: 1100 }}
                    pagination={{
                      current: commandPage,
                      pageSize: commandPageSize,
                      total: commandTotal,
                      showSizeChanger: true,
                      pageSizeOptions: [20, 50, 100],
                      showTotal: (total, range) => `${range[0]}-${range[1]} / ${total}`,
                      onChange: (nextPage, nextPageSize) => {
                        if (nextPageSize !== commandPageSize) {
                          setCommandPageSize(nextPageSize);
                          setCommandPage(1);
                        } else {
                          setCommandPage(nextPage);
                        }
                      },
                    }}
                    onRow={(record, index) => ({
                      onClick: () => setDetailCmd({ item: record, index: index ?? 0 }),
                      style: { cursor: "pointer" },
                    })}
                    columns={[
                      { title: t("columns.time"), dataIndex: "timestamp", width: 160, render: (v: string) => formatTime(v) },
                      { title: t("columns.host"), dataIndex: "hostname", width: 130, ellipsis: true, render: (v: string) => v || "--" },
                      {
                        title: t("columns.command"),
                        dataIndex: "command",
                        width: 320,
                        render: (v: string) => (
                          <div className="cmd-cell cmd-cell--command" title={t("action.scrollHint", "可滑动查看完整命令")}>
                            <code>{v}</code>
                            <Maximize2 size={11} className="cmd-cell__icon" />
                          </div>
                        ),
                      },
                      {
                        title: t("columns.source"),
                        dataIndex: "llm_generated",
                        width: 80,
                        render: (v: boolean) =>
                          v ? (
                            <Tag icon={<Bot size={12} />} color="purple">{t("common:source.llm")}</Tag>
                          ) : (
                            <Tag color="default">{t("common:source.rule")}</Tag>
                          ),
                      },
                      {
                        title: t("columns.intent"),
                        dataIndex: "intent",
                        width: 120,
                        render: (v: string) =>
                          v ? (
                            <Tag color={INTENT_COLORS[v] || "#94a3b8"}>{v}</Tag>
                          ) : (
                            "--"
                          ),
                      },
                      {
                        title: t("columns.evidence"),
                        dataIndex: "evidence_hits",
                        width: 80,
                        render: (hits: string[]) =>
                          hits?.length
                            ? hits.map((tok) => (
                                <Tooltip key={tok} title={tok}>
                                  <span
                                    style={{
                                      display: "inline-block",
                                      width: 8,
                                      height: 8,
                                      borderRadius: "50%",
                                      background: getTokenColor(tok),
                                      marginRight: 2,
                                    }}
                                  />
                                </Tooltip>
                              ))
                            : "--",
                      },
                      { title: t("columns.score"), dataIndex: "score", width: 60 },
                      {
                        title: t("columns.output"),
                        dataIndex: "output",
                        width: 420,
                        render: (v: string) => (
                          <div className="cmd-cell cmd-cell--output" title={t("action.scrollHint", "可滑动查看完整输出")}>
                            <pre>{outputPreview(v)}</pre>
                            {v && v.length > 40 && <Maximize2 size={11} className="cmd-cell__icon" />}
                          </div>
                        ),
                      },
                    ]}
                  />
                </div>
              ),
            },
            {
              key: "replay",
              label: t("tabs.terminalReplay"),
              children: (
                <div className="terminal-replay-page">
                  <TerminalReplay commands={commands} />
                  {commandTotal > 0 ? (
                    <Pagination
                      current={commandPage}
                      pageSize={commandPageSize}
                      total={commandTotal}
                      showSizeChanger
                      pageSizeOptions={[20, 50, 100]}
                      showTotal={(total, range) => `${range[0]}-${range[1]} / ${total}`}
                      onChange={(nextPage, nextPageSize) => {
                        if (nextPageSize !== commandPageSize) {
                          setCommandPageSize(nextPageSize);
                          setCommandPage(1);
                        } else {
                          setCommandPage(nextPage);
                        }
                      }}
                    />
                  ) : null}
                </div>
              ),
            },
          ]}
        />
      </Card>

      <CommandDetailModal
        item={detailCmd?.item ?? null}
        index={detailCmd?.index ?? 0}
        open={detailCmd !== null}
        onClose={() => setDetailCmd(null)}
      />
    </div>
  );
}
