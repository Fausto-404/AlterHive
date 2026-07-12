import { Button, Card, Popconfirm, Space, Table, Tag, Tooltip, message } from "antd";
import { Eye, Network, TerminalSquare, Trash2 } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useSearchParams } from "react-router-dom";

import { ThreatLevel, getThreatClass } from "../components/ThreatBadge";
import { usePageRefresh } from "../layouts/AppLayout";
import { deleteSession, fetchSessions, toErrorMessage } from "../services/platform";
import type { SessionRow } from "../types/platform";
import { formatTime } from "../utils/format";

export function SessionsPage() {
  const { t } = useTranslation("sessions");
  const [searchParams, setSearchParams] = useSearchParams();
  const [items, setItems] = useState<SessionRow[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(() => Math.max(1, Number(searchParams.get("page")) || 1));
  const [pageSize, setPageSize] = useState(() => {
    const value = Number(searchParams.get("pageSize")) || 20;
    return [10, 20, 50, 100].includes(value) ? value : 20;
  });
  const [loading, setLoading] = useState(true);
  const timerRef = useRef<ReturnType<typeof setInterval>>();
  const requestRef = useRef(0);

  const loadData = useCallback(async (nextPage = page, nextPageSize = pageSize) => {
    const requestId = ++requestRef.current;
    setLoading(true);
    try {
      const response = await fetchSessions({ page: nextPage, pageSize: nextPageSize });
      if (requestId !== requestRef.current) return;

      const lastPage = Math.max(1, Math.ceil(response.total / nextPageSize));
      if (nextPage > lastPage) {
        setPage(lastPage);
        return;
      }
      setItems(response.items);
      setTotal(response.total);
    } catch (err) {
      if (requestId !== requestRef.current) return;
      message.error(toErrorMessage(err, t("message.loadFailed")));
    } finally {
      if (requestId === requestRef.current) setLoading(false);
    }
  }, [page, pageSize, t]);

  usePageRefresh(loadData, loading);

  useEffect(() => {
    loadData();
    timerRef.current = setInterval(() => {
      if (document.visibilityState === "visible") loadData();
    }, 10000);
    return () => clearInterval(timerRef.current);
  }, [loadData]);

  useEffect(() => {
    setSearchParams((params) => {
      const next = new URLSearchParams(params);
      next.set("page", String(page));
      next.set("pageSize", String(pageSize));
      return next;
    }, { replace: true });
  }, [page, pageSize, setSearchParams]);

  async function handleDelete(sessionId: string) {
    try {
      await deleteSession(sessionId);
      message.success(t("message.deleted"));
      const nextPage = items.length === 1 && page > 1 ? page - 1 : page;
      if (nextPage !== page) setPage(nextPage);
      else loadData(nextPage, pageSize);
    } catch (err) {
      message.error(toErrorMessage(err, t("message.deleteFailed")));
    }
  }

  return (
    <div className="page">
      <Card className="ah-panel sessions-panel">
        <div className="sessions-summary" aria-live="polite">
          <span>{t("pagination.total", { total })}</span>
          <span className="sessions-summary__refresh">{t("pagination.autoRefresh")}</span>
        </div>
        <Table<SessionRow>
          rowKey="session_id"
          dataSource={items}
          loading={loading}
          size="small"
          scroll={{ x: 1200 }}
          pagination={{
            total,
            current: page,
            pageSize,
            showSizeChanger: true,
            pageSizeOptions: [10, 20, 50, 100],
            showLessItems: true,
            showQuickJumper: total > pageSize * 5,
            responsive: true,
            showTotal: (count, range) => t("pagination.range", { start: range[0], end: range[1], total: count }),
            onChange: (nextPage, nextPageSize) => {
              if (nextPageSize !== pageSize) {
                setPageSize(nextPageSize);
                setPage(1);
              } else {
                setPage(nextPage);
              }
            },
          }}
          rowClassName={(row) => {
            const classes = [getThreatClass(row.score)];
            if (row.ppf_triggered) classes.push("session-row--ppf");
            return classes.filter(Boolean).join(" ");
          }}
          columns={[
            {
              title: t("columns.sessionId"),
              dataIndex: "session_id",
              width: 140,
              render: (id: string) => (
                <Tooltip title={id}>
                  <Link className="session-id-link" to={`/sessions/${id}`}>{id.slice(0, 8)}...</Link>
                </Tooltip>
              ),
            },
            { title: t("columns.username"), dataIndex: "username", width: 100 },
            { title: t("columns.sourceIp"), dataIndex: "remote_addr", width: 140 },
            {
              title: t("columns.status"),
              dataIndex: "status",
              width: 80,
              render: (value: string) => <Tag color={value === "active" ? "green" : "default"}>{t(`status.${value}`, value)}</Tag>,
            },
            { title: t("columns.commands"), dataIndex: "command_count", width: 60 },
            { title: t("columns.evidence"), dataIndex: "evidence_hits", width: 60 },
            {
              title: t("columns.threat"),
              width: 70,
              render: (_, row) => <ThreatLevel score={row.score} />,
            },
            { title: t("columns.score"), dataIndex: "score", width: 60 },
            {
              title: t("columns.ppf"),
              dataIndex: "ppf_triggered",
              width: 80,
              render: (value: boolean) =>
                value ? (
                  <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
                    <span className="kpi-pulse" style={{ background: "#f59e0b" }} />
                    <Tag color="orange">{t("ppf.engaged")}</Tag>
                  </span>
                ) : (
                  <Tag>{t("ppf.pending")}</Tag>
                ),
            },
            { title: t("columns.connectedAt"), dataIndex: "connected_at", width: 160, render: (value: string) => formatTime(value) },
            {
              title: t("columns.actions"),
              width: 200,
              fixed: "right",
              render: (_, row) => (
                <Space size={4}>
                  <Link to={`/sessions/${row.session_id}`}>
                    <Button size="small" icon={<Eye size={14} />}>
                      {t("action.detail")}
                    </Button>
                  </Link>
                  <Link to={`/sessions/${row.session_id}?tab=replay`}>
                    <Button size="small" icon={<TerminalSquare size={14} />} type="primary">
                      {t("action.replay")}
                    </Button>
                  </Link>
                  <Tooltip title={t("action.topology")}>
                    <Link to={`/sessions/${row.session_id}/topology`}>
                      <Button size="small" icon={<Network size={14} />} aria-label={t("action.topology")} />
                    </Link>
                  </Tooltip>
                  <Popconfirm
                    title={t("confirm.title")}
                    okText={t("confirm.okText")}
                    cancelText={t("confirm.cancelText")}
                    okButtonProps={{ danger: true }}
                    onConfirm={() => handleDelete(row.session_id)}
                  >
                    <Button size="small" danger icon={<Trash2 size={14} />}>
                      {t("action.delete")}
                    </Button>
                  </Popconfirm>
                </Space>
              ),
            },
          ]}
        />
      </Card>
    </div>
  );
}
