import { Alert, Card, Col, Empty, Row, Table, Tag } from "antd";
import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";

import { usePageRefresh } from "../layouts/AppLayout";
import { fetchDashboardSummary, toErrorMessage } from "../services/platform";
import type { DashboardSummary } from "../types/platform";
import { formatTime } from "../utils/format";

const INTENT_CATEGORIES: Record<string, string> = {
  network_scan: "recon",
  service_probe: "recon",
  subnet_scan: "recon",
  http_probe: "exploit",
  db_probe: "exploit",
  domain_probe: "exploit",
  evidence_search: "exploit",
  lateral_movement: "lateral",
  privilege_escalation: "lateral",
  data_exfiltration: "deception",
  shell_command: "noise",
  unknown: "noise",
};

export function DashboardPage() {
  const { t } = useTranslation("dashboard");
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const timerRef = useRef<ReturnType<typeof setInterval>>();

  async function loadData() {
    setLoading(true);
    try {
      setSummary(await fetchDashboardSummary());
      setError("");
    } catch (err) {
      setError(toErrorMessage(err, t("error.loadFailed")));
    } finally {
      setLoading(false);
    }
  }

  usePageRefresh(loadData, loading);

  useEffect(() => {
    loadData();
    timerRef.current = setInterval(loadData, 10000);
    return () => clearInterval(timerRef.current);
  }, []);

  const metrics = summary?.playbook_metrics || [];
  const maxCount = Math.max(...metrics.map((m) => m.count), 1);

  return (
    <div className="page">
      {error && <Alert type="error" message={t("error.loadFailed")} description={error} showIcon />}

      <Row gutter={[16, 16]}>
        <Col xs={12} lg={6}>
          <Card className="ah-metric-card" loading={loading}>
            <span>{summary?.active_sessions ? <span className="kpi-pulse" /> : null}{t("cards.activeSessions")}</span>
            <strong>{summary?.active_sessions ?? "--"}</strong>
            <p>{t("cards.activeSessionsDesc")}</p>
          </Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="ah-metric-card" loading={loading}>
            <span>{t("cards.ppfTriggered")}</span>
            <strong>{summary?.ppf_triggered_count ?? "--"}</strong>
            <p>{t("cards.ppfTriggeredDesc")}</p>
          </Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="ah-metric-card" loading={loading}>
            <span>{t("cards.evidenceHits")}</span>
            <strong>{summary?.total_evidence_hits ?? "--"}</strong>
            <p>{t("cards.evidenceHitsDesc")}</p>
          </Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="ah-metric-card" loading={loading}>
            <span>{t("cards.totalScore")}</span>
            <strong>{summary?.total_score ?? "--"}</strong>
            <p>{t("cards.totalScoreDesc")}</p>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={12} lg={6}>
          <Card className="ah-metric-card" loading={loading}>
            <span>{t("cards.totalSessions", "累计会话")}</span>
            <strong>{summary?.total_sessions ?? "--"}</strong>
            <p>{t("cards.totalSessionsDesc", "已记录的攻击会话总数")}</p>
          </Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="ah-metric-card" loading={loading}>
            <span>{t("cards.totalCommands")}</span>
            <strong>{summary?.total_commands ?? "--"}</strong>
            <p>{t("cards.totalCommandsDesc")}</p>
          </Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="ah-metric-card" loading={loading}>
            <span>{t("cards.uniqueAttackers")}</span>
            <strong>{summary?.unique_attackers ?? "--"}</strong>
            <p>{t("cards.uniqueAttackersDesc")}</p>
          </Card>
        </Col>
        <Col xs={12} lg={6}>
          <Card className="ah-metric-card" loading={loading}>
            <span>{t("cards.intentTypes", "意图类型")}</span>
            <strong>{summary?.playbook_metrics?.length ?? "--"}</strong>
            <p>{t("cards.intentTypesDesc", "已识别的不同攻击意图数")}</p>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} xl={14}>
          <Card title={t("intentDistribution")} className="ah-panel" loading={loading} style={{ height: "100%" }}>
            {metrics.length ? (
              <div style={{ padding: "8px 0" }}>
                {metrics
                  .sort((a, b) => b.count - a.count)
                  .map((item) => {
                    const category = INTENT_CATEGORIES[item.handler] || "noise";
                    const label = t(`evidence:intent.${item.handler}`, item.handler);
                    return (
                      <div key={item.handler} className="intent-bar-row">
                        <span className="intent-bar-label">{label}</span>
                        <div className="intent-bar-track">
                          <div
                            className={`intent-bar-fill intent-bar-fill--${category}`}
                            style={{ width: `${(item.count / maxCount) * 100}%` }}
                          />
                        </div>
                        <span className="intent-bar-count">{item.count}</span>
                      </div>
                    );
                  })}
              </div>
            ) : (
              <Empty description={t("empty.intents")} />
            )}
          </Card>
        </Col>
        <Col xs={24} xl={10}>
          <Card title={t("topAttackers")} className="ah-panel" loading={loading} style={{ height: "100%" }}>
            {summary?.top_attackers?.length ? (
              <Table
                rowKey="ip"
                dataSource={summary.top_attackers}
                pagination={false}
                size="small"
                columns={[
                  { title: t("columns.sourceIp"), dataIndex: "ip" },
                  { title: t("columns.sessions", "会话数"), dataIndex: "sessions", width: 100 },
                ]}
              />
            ) : (
              <Empty description={t("empty.attackers")} />
            )}
          </Card>
        </Col>
      </Row>

      <Card title={t("recentSessions")} className="ah-panel" loading={loading}>
        {summary?.recent_sessions?.length ? (
          <Table
            rowKey="session_id"
            dataSource={summary.recent_sessions}
            size="small"
            pagination={false}
            columns={[
              {
                title: t("columns.sessionId"),
                dataIndex: "session_id",
                render: (id: string) => <Link to={`/sessions/${id}`}>{id.slice(0, 8)}...</Link>,
              },
              { title: t("columns.username"), dataIndex: "username", width: 120 },
              { title: t("columns.sourceIp"), dataIndex: "remote_addr", width: 150 },
              { title: t("columns.commands"), dataIndex: "commands", width: 80 },
              { title: t("columns.evidence"), dataIndex: "evidence_hits", width: 70 },
              { title: t("columns.score"), dataIndex: "score", width: 70 },
              {
                title: t("columns.ppf"),
                dataIndex: "ppf_triggered",
                width: 70,
                render: (v: boolean) =>
                  v ? <Tag color="orange">{t("common:ppf.triggered")}</Tag> : <Tag>{t("common:ppf.pending")}</Tag>,
              },
              { title: t("columns.connectedAt"), dataIndex: "connected_at", width: 168, render: (v: string) => formatTime(v) },
            ]}
          />
        ) : (
          <Empty description={t("empty.sessions")} />
        )}
      </Card>
    </div>
  );
}
