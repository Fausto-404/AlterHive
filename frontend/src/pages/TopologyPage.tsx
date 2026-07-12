import { Alert, Button, Card, Empty, Input, Segmented, Select, Table, Tag, Tooltip } from "antd";
import type { ColumnsType } from "antd/es/table";
import {
  Boxes,
  ChevronRight,
  Crosshair,
  Database,
  Lock,
  Minus,
  Network,
  Plus,
  Search,
  Server,
  ShieldCheck,
} from "lucide-react";
import { type MouseEvent, type PointerEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Link, useParams, useSearchParams } from "react-router-dom";
import type { TFunction } from "i18next";

import { usePageRefresh } from "../layouts/AppLayout";
import { fetchNodes, fetchSessions, fetchSessionTopology, toErrorMessage } from "../services/platform";
import type { NetworkEdge, NetworkSegment, NodeItem, SessionRow } from "../types/platform";
import { getRoleLabel, getServicePorts, isShadowHost } from "../utils/topology";

type ViewMode = "global" | "node";
type GraphNodeKind = "entry" | "subnet" | "shadow-subnet" | "host" | "pivot" | "database" | "web" | "domain" | "shadow-host" | "cluster";
type GraphSelection = { type: "node"; id: string } | { type: "edge"; id: string } | null;
type DetailSelection = GraphSelection;
type NodeOffsets = Record<string, { x: number; y: number }>;
type DragState =
  | { kind: "pan"; startX: number; startY: number; scrollLeft: number; scrollTop: number; moved: boolean }
  | { kind: "node"; id: string; startX: number; startY: number; offsetX: number; offsetY: number; baseX: number; baseY: number; w: number; h: number; moved: boolean };

interface GraphNode {
  id: string;
  kind: GraphNodeKind;
  label: string;
  sublabel: string;
  meta?: string;
  badge?: string;
  status: "entry" | "active" | "locked" | "shadow" | "folded";
  x: number;
  y: number;
  w: number;
  h: number;
  host?: NodeItem;
  segment?: NetworkSegment;
  ports?: string;
  metrics?: SegmentMetrics;
}

interface GraphEdge {
  id: string;
  from: string;
  to: string;
  label: string;
  relation: string;
  status: "active" | "locked" | "conditional" | "shadow";
  protocol: string;
  gate: string;
  evidence: string;
  lastSeen: string;
}

interface SegmentMetrics {
  total: number;
  active: number;
  locked: number;
  shadow: number;
  services: string[];
}

const fallbackEntry = {
  hostname: "staging-web-01",
  ip: "192.168.56.23",
};

const MIN_CANVAS_SCALE = 0.35;
const MAX_CANVAS_SCALE = 2;
const CANVAS_ZOOM_STEP = 0.15;

function nodeStatus(node: NodeItem): "active" | "locked" | "shadow" {
  if (node.required_state?.length) return "locked";
  if (isShadowHost(node)) return "shadow";
  return "active";
}

function edgeStatus(edge: NetworkEdge): GraphEdge["status"] {
  if (edge.status === "locked") return "locked";
  if (edge.status === "shadow" || edge.type.includes("nmap") || edge.type.includes("planner")) return "shadow";
  if (edge.required_state?.length) return "conditional";
  return "active";
}

function roleKind(node: NodeItem): GraphNodeKind {
  if (isShadowHost(node)) return "shadow-host";
  if (node.role.includes("jump")) return "pivot";
  if (node.role.includes("db") || node.role.includes("database") || node.services.some((svc) => /mysql|postgres|redis/i.test(svc.protocol))) return "database";
  if (node.role.includes("dc") || node.role.includes("domain") || node.services.some((svc) => /ldap|smb|kerberos/i.test(svc.protocol))) return "domain";
  if (node.role.includes("web") || node.role.includes("gitlab") || node.role.includes("jenkins") || node.services.some((svc) => /http/i.test(svc.protocol))) return "web";
  return "host";
}

function iconFor(kind: GraphNodeKind) {
  switch (kind) {
    case "entry":
      return <ShieldCheck size={20} />;
    case "subnet":
    case "shadow-subnet":
      return <Network size={20} />;
    case "pivot":
      return <Server size={18} />;
    case "database":
      return <Database size={18} />;
    case "domain":
      return <Lock size={18} />;
    case "cluster":
      return <Boxes size={18} />;
    default:
      return <Server size={18} />;
  }
}

function serviceSummary(hosts: NodeItem[]) {
  const set = new Set<string>();
  hosts.forEach((host) => host.services.forEach((svc) => set.add(svc.protocol.toUpperCase())));
  return [...set].slice(0, 4);
}

function segmentMetrics(hosts: NodeItem[]): SegmentMetrics {
  return {
    total: hosts.length,
    active: hosts.filter((host) => nodeStatus(host) === "active").length,
    locked: hosts.filter((host) => nodeStatus(host) === "locked").length,
    shadow: hosts.filter((host) => isShadowHost(host)).length,
    services: serviceSummary(hosts),
  };
}

function statusLabel(status: GraphEdge["status"] | GraphNode["status"], t: TFunction) {
  const color: Record<string, string> = {
    entry: "blue",
    active: "green",
    locked: "gold",
    shadow: "purple",
    conditional: "orange",
    folded: "default",
  };
  return <Tag color={color[status] || "default"}>{t(`common:status.${status}`)}</Tag>;
}

function relationLabel(edge: NetworkEdge, t: TFunction) {
  if (edge.type === "dual_nic") return "dual_nic";
  if (edge.type === "ssh") return "ssh";
  if (edge.type === "pivot") return "pivot";
  if (edge.type.includes("nmap")) return t("edgeLabel.nmapDiscovered");
  return edge.type || "relation";
}

function edgeProtocol(edge: NetworkEdge) {
  const lower = `${edge.type} ${edge.via}`.toLowerCase();
  if (lower.includes("ssh")) return "22/SSH";
  if (lower.includes("mysql")) return "3306/MySQL";
  if (lower.includes("redis")) return "6379/Redis";
  if (lower.includes("smb")) return "445/SMB";
  if (lower.includes("ldap")) return "389/LDAP";
  if (lower.includes("http")) return "80/HTTP";
  if (lower.includes("dual")) return "dual_nic";
  if (lower.includes("nmap")) return "nmap";
  return edge.via || "-";
}

export function TopologyPage() {
  const { t } = useTranslation("topology");
  const { sessionId } = useParams<{ sessionId: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const [sessionOptions, setSessionOptions] = useState<SessionRow[]>([]);
  const [sessionSearch, setSessionSearch] = useState("");
  const requestedScope = sessionId || searchParams.get("scope") === "session" ? "session" : "global";
  const selectedSessionId = sessionId || searchParams.get("sessionId") || "";
  const [nodes, setNodes] = useState<NodeItem[]>([]);
  const [segments, setSegments] = useState<NetworkSegment[]>([]);
  const [edges, setEdges] = useState<NetworkEdge[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [viewMode, setViewMode] = useState<ViewMode>("global");
  const [expandedSegment, setExpandedSegment] = useState("");
  const [selection, setSelection] = useState<GraphSelection>(null);
  const [detailSelection, setDetailSelection] = useState<DetailSelection>(null);
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "active" | "locked" | "shadow">("all");
  const [edgePage, setEdgePage] = useState(1);
  const [edgePageSize, setEdgePageSize] = useState(20);

  useEffect(() => {
    setEdgePage(1);
  }, [requestedScope, selectedSessionId]);
  const [canvasScale, setCanvasScale] = useState(1);
  const [canvasLocked, setCanvasLocked] = useState(false);
  const [canvasViewport, setCanvasViewport] = useState({ scrollLeft: 0, scrollTop: 0, clientWidth: 1, clientHeight: 1 });
  const [nodeOffsets, setNodeOffsets] = useState<NodeOffsets>({});
  const [draggingNodeID, setDraggingNodeID] = useState("");
  const [isPanning, setIsPanning] = useState(false);
  const canvasShellRef = useRef<HTMLDivElement>(null);
  const dragRef = useRef<DragState | null>(null);
  const suppressClickRef = useRef(false);
  const viewportFrameRef = useRef<number>();
  const topologyRequestRef = useRef(0);
  const sessionOptionRequestRef = useRef(0);

  const viewOptions = [
    { label: t("view.global"), value: "global" as const },
    { label: t("view.currentSubnet"), value: "node" as const },
  ];

  const loadData = useCallback(async () => {
    const requestId = ++topologyRequestRef.current;
    setLoading(true);
    setError("");
    try {
      if (requestedScope === "session" && !selectedSessionId) {
        setNodes([]);
        setSegments([]);
        setEdges([]);
        return;
      }
      const data = requestedScope === "session" ? await fetchSessionTopology(selectedSessionId) : await fetchNodes();
      if (requestId !== topologyRequestRef.current) return;
      setNodes(data.nodes || []);
      setSegments(data.segments || []);
      setEdges(data.edges || []);
      const primary = data.segments?.find((segment) => !segment.shadow) || data.segments?.[0];
      setExpandedSegment(primary?.cidr || "");
    } catch (err) {
      if (requestId === topologyRequestRef.current) setError(toErrorMessage(err, t("error.loadFailed")));
    } finally {
      if (requestId === topologyRequestRef.current) setLoading(false);
    }
  }, [requestedScope, selectedSessionId, t]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  useEffect(() => {
    if (requestedScope !== "session") return;
    const requestId = ++sessionOptionRequestRef.current;
    const timer = window.setTimeout(() => fetchSessions({ page: 1, pageSize: 100, query: sessionSearch })
      .then((data) => {
        if (requestId !== sessionOptionRequestRef.current) return;
        setSessionOptions(data.items || []);
        if (requestedScope === "session" && !selectedSessionId && data.items?.[0]) {
          setSearchParams((current) => {
            const next = new URLSearchParams(current);
            next.set("scope", "session");
            next.set("sessionId", data.items[0].session_id);
            return next;
          }, { replace: true });
        }
      })
      .catch(() => { if (requestId === sessionOptionRequestRef.current) setSessionOptions([]); }), 200);
    return () => window.clearTimeout(timer);
  }, [requestedScope, selectedSessionId, sessionSearch, setSearchParams]);

  useEffect(() => {
    setSelection(null);
    setDetailSelection(null);
    setNodeOffsets({});
    setExpandedSegment("");
    setCanvasScale(1);
    canvasShellRef.current?.scrollTo({ left: 0, top: 0 });
  }, [requestedScope, selectedSessionId]);

  const changeTopologyScope = (value: string | number) => {
    if (sessionId) return;
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      if (value === "session") {
        next.set("scope", "session");
        if (!next.get("sessionId") && sessionOptions[0]) next.set("sessionId", sessionOptions[0].session_id);
      } else {
        next.delete("scope");
        next.delete("sessionId");
      }
      return next;
    });
  };

  const changeSession = (value: string) => {
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      next.set("scope", "session");
      next.set("sessionId", value);
      return next;
    });
  };

  const hostByIP = useMemo(() => new Map(nodes.map((node) => [node.ip, node])), [nodes]);
  const hostsBySegment = useMemo(() => {
    const grouped = new Map<string, NodeItem[]>();
    for (const node of nodes) {
      const key = node.segment_cidr || "unknown";
      grouped.set(key, [...(grouped.get(key) || []), node]);
    }
    return grouped;
  }, [nodes]);

  const primarySegment = segments.find((segment) => !segment.shadow) || segments[0];
  const entryHost = nodes.find((node) => node.hostname.includes("staging")) || nodes.find((node) => node.ip === "192.168.56.23");

  const graph = useMemo(
    () =>
      buildGraph({
        nodes,
        segments,
        edges,
        hostByIP,
        hostsBySegment,
        expandedSegment: expandedSegment || primarySegment?.cidr || "",
        query,
        statusFilter,
        selectedNodeID:
          detailSelection?.type === "node"
            ? detailSelection.id
            : selection?.type === "node"
              ? selection.id
              : "",
        viewMode,
        entryHost,
        nodeOffsets,
        t,
      }),
    [nodes, segments, edges, hostByIP, hostsBySegment, expandedSegment, primarySegment?.cidr, query, statusFilter, detailSelection, selection, viewMode, entryHost, nodeOffsets, t],
  );

  const selectedNode = detailSelection?.type === "node" ? graph.nodes.find((node) => node.id === detailSelection.id) : undefined;
  const selectedEdge = detailSelection?.type === "edge" ? graph.edges.find((edge) => edge.id === detailSelection.id) : undefined;
  const activeHosts = nodes.filter((node) => nodeStatus(node) === "active").length;
  const shadowHosts = nodes.filter((node) => isShadowHost(node)).length;
  const lockedHosts = nodes.filter((node) => nodeStatus(node) === "locked").length;
  const evidenceCount = Math.max(23, edges.length * 3 + shadowHosts);
  const denseGraph = graph.nodes.length > 80 || graph.edges.length > 100;
  const fitCanvas = () => {
    const shell = canvasShellRef.current;
    if (!shell) return;
    const nextScale = Math.min(1.15, Math.max(MIN_CANVAS_SCALE, Math.min((shell.clientWidth - 36) / graph.width, (shell.clientHeight - 36) / graph.height)));
    setCanvasScale(Number(nextScale.toFixed(2)));
    shell.scrollTo({ left: 0, top: 0, behavior: "smooth" });
  };
  const autoArrangeLayout = () => {
    setNodeOffsets({});
    setSelection(null);
    setDetailSelection(null);
    window.requestAnimationFrame(fitCanvas);
  };
  const resetCanvas = () => {
    setCanvasScale(1);
    setSelection(null);
    setDetailSelection(null);
    setNodeOffsets({});
    canvasShellRef.current?.scrollTo({ left: 0, top: 0, behavior: "smooth" });
  };
  usePageRefresh(loadData, loading);
  const updateCanvasViewport = useCallback(() => {
    if (viewportFrameRef.current !== undefined) return;
    viewportFrameRef.current = window.requestAnimationFrame(() => {
      viewportFrameRef.current = undefined;
      const shell = canvasShellRef.current;
      if (!shell) return;
      setCanvasViewport((current) => {
        const next = {
          scrollLeft: shell.scrollLeft,
          scrollTop: shell.scrollTop,
          clientWidth: shell.clientWidth,
          clientHeight: shell.clientHeight,
        };
        if (
          current.scrollLeft === next.scrollLeft &&
          current.scrollTop === next.scrollTop &&
          current.clientWidth === next.clientWidth &&
          current.clientHeight === next.clientHeight
        ) return current;
        return next;
      });
    });
  }, []);

  useEffect(() => () => {
    if (viewportFrameRef.current !== undefined) window.cancelAnimationFrame(viewportFrameRef.current);
  }, []);
  useEffect(() => {
    const frame = window.requestAnimationFrame(() => {
      const shell = canvasShellRef.current;
      if (shell) {
        const nextScale = Math.min(1, Math.max(0.55, Math.min((shell.clientWidth - 24) / graph.width, (shell.clientHeight - 24) / graph.height)));
        setCanvasScale(Number(nextScale.toFixed(2)));
      }
      updateCanvasViewport();
    });
    return () => window.cancelAnimationFrame(frame);
  }, [graph.width, graph.height]);
  useEffect(() => {
    updateCanvasViewport();
  }, [canvasScale]);
  const jumpMiniMap = (event: MouseEvent<HTMLButtonElement>) => {
    if (canvasLocked) return;
    const shell = canvasShellRef.current;
    if (!shell) return;
    const rect = event.currentTarget.getBoundingClientRect();
    const ratioX = Math.max(0, Math.min(1, (event.clientX - rect.left) / rect.width));
    const ratioY = Math.max(0, Math.min(1, (event.clientY - rect.top) / rect.height));
    const contentWidth = graph.width * canvasScale;
    const contentHeight = graph.height * canvasScale;
    shell.scrollTo({
      left: Math.min(Math.max(0, contentWidth - shell.clientWidth), Math.max(0, ratioX * contentWidth - shell.clientWidth / 2)),
      top: Math.min(Math.max(0, contentHeight - shell.clientHeight), Math.max(0, ratioY * contentHeight - shell.clientHeight / 2)),
      behavior: "smooth",
    });
  };
  const miniViewport = buildMiniViewport(canvasViewport, graph.width * canvasScale, graph.height * canvasScale);
  const suppressNextClick = () => {
    suppressClickRef.current = true;
    window.setTimeout(() => {
      suppressClickRef.current = false;
    }, 0);
  };
  const startCanvasPan = (event: PointerEvent<HTMLDivElement>) => {
    if (canvasLocked || event.button !== 0) return;
    const target = event.target as HTMLElement;
    if (target.closest(".graph-node, .canvas-tools, .mini-map")) return;
    const shell = canvasShellRef.current;
    if (!shell) return;
    dragRef.current = {
      kind: "pan",
      startX: event.clientX,
      startY: event.clientY,
      scrollLeft: shell.scrollLeft,
      scrollTop: shell.scrollTop,
      moved: false,
    };
    setIsPanning(true);
    shell.setPointerCapture(event.pointerId);
  };
  const startNodeDrag = (event: PointerEvent<HTMLButtonElement>, nodeID: string) => {
    if (canvasLocked || event.button !== 0) return;
    event.stopPropagation();
    const offset = nodeOffsets[nodeID] || { x: 0, y: 0 };
    const node = graph.nodeBox.get(nodeID);
    if (!node) return;
    dragRef.current = {
      kind: "node",
      id: nodeID,
      startX: event.clientX,
      startY: event.clientY,
      offsetX: offset.x,
      offsetY: offset.y,
      baseX: node.x - offset.x,
      baseY: node.y - offset.y,
      w: node.w,
      h: node.h,
      moved: false,
    };
    setDraggingNodeID(nodeID);
    event.currentTarget.setPointerCapture(event.pointerId);
  };
  const moveDrag = (event: PointerEvent<HTMLDivElement>) => {
    const drag = dragRef.current;
    if (!drag) return;
    if (drag.kind === "pan") {
      const shell = canvasShellRef.current;
      if (!shell) return;
      if (Math.abs(event.clientX - drag.startX) + Math.abs(event.clientY - drag.startY) > 3) {
        drag.moved = true;
      }
      shell.scrollLeft = drag.scrollLeft - (event.clientX - drag.startX);
      shell.scrollTop = drag.scrollTop - (event.clientY - drag.startY);
      updateCanvasViewport();
      return;
    }
    const dx = (event.clientX - drag.startX) / canvasScale;
    const dy = (event.clientY - drag.startY) / canvasScale;
    if (Math.abs(dx) + Math.abs(dy) > 3) {
      drag.moved = true;
    }
    const nextX = Math.min(graph.width - drag.w - drag.baseX, Math.max(-drag.baseX, drag.offsetX + dx));
    const nextY = Math.min(graph.height - drag.h - drag.baseY, Math.max(-drag.baseY, drag.offsetY + dy));
    setNodeOffsets((current) => ({
      ...current,
      [drag.id]: { x: nextX, y: nextY },
    }));
  };
  const endDrag = () => {
    const drag = dragRef.current;
    if (drag?.moved) {
      suppressNextClick();
    }
    dragRef.current = null;
    setDraggingNodeID("");
    setIsPanning(false);
  };
  const closeDetailOnBlankCanvas = (event: MouseEvent<HTMLDivElement>) => {
    if (suppressClickRef.current) return;
    const target = event.target as HTMLElement;
    if (target.closest(".graph-node, .graph-edge, .canvas-tools, .mini-map")) return;
    setSelection(null);
    setDetailSelection(null);
  };

  const columns: ColumnsType<GraphEdge> = [
    { title: t("table.columns.source"), dataIndex: "from", render: (from) => graph.nodeLabel.get(from) || from },
    { title: t("table.columns.target"), dataIndex: "to", render: (to) => graph.nodeLabel.get(to) || to },
    { title: t("table.columns.relation"), dataIndex: "relation" },
    { title: t("table.columns.status"), dataIndex: "status", render: (status) => statusLabel(status, t) },
    { title: t("table.columns.protocolPort"), dataIndex: "protocol" },
    { title: t("table.columns.gate"), dataIndex: "gate", render: (gate) => gate || "-" },
    { title: t("table.columns.evidence"), dataIndex: "evidence" },
    { title: t("table.columns.lastProbe"), dataIndex: "lastSeen" },
  ];

  if (loading) return <Card className="ah-panel" loading />;
  if (error) return <Alert type="error" message={t("error.loadFailed")} description={error} showIcon />;

  return (
    <div className="page subnet-illusion-page">
      {!sessionId ? (
        <div className="topology-scope-bar">
          <div className="topology-scope-bar__intro">
            <strong>{t("scope.title")}</strong>
            <span>{requestedScope === "global" ? t("scope.globalHint") : t("scope.sessionHint")}</span>
          </div>
          <Segmented
            value={requestedScope}
            onChange={changeTopologyScope}
            options={[
              { label: t("scope.global"), value: "global" },
              { label: t("scope.session"), value: "session" },
            ]}
          />
          {requestedScope === "session" ? (
            <>
              <Select
                className="topology-session-select"
                showSearch
                value={selectedSessionId || undefined}
                placeholder={t("scope.selectSession")}
                optionFilterProp="label"
                filterOption={false}
                onSearch={setSessionSearch}
                onChange={changeSession}
                notFoundContent={t("scope.noSessions")}
                options={sessionOptions.map((session) => ({
                  value: session.session_id,
                  label: `${session.username} · ${session.remote_addr} · ${session.session_id.slice(0, 8)}`,
                }))}
              />
              {selectedSessionId ? (
                <Link className="topology-session-detail-link" to={`/sessions/${selectedSessionId}`}>
                  {t("scope.openSession")}
                </Link>
              ) : null}
            </>
          ) : null}
        </div>
      ) : null}
      {sessionId ? (
        <div className="session-topology-context">
          <div>
            <Tag color="blue">{t("sessionView.badge")}</Tag>
            <strong>{t("sessionView.title")}</strong>
            <span>{sessionId.slice(0, 8)}...</span>
          </div>
          <Link to={`/sessions/${sessionId}`}>{t("sessionView.back")}</Link>
        </div>
      ) : null}
      <div className="subnet-control-row">
        <div className="subnet-viewline">
          <span className="subnet-viewline__label">{t("view.viewMode")}</span>
          <div className="subnet-view-switch" role="tablist" aria-label={t("view.viewMode")}>
            {viewOptions.map((option) => (
              <button
                key={option.value}
                className={viewMode === option.value ? "is-active" : ""}
                role="tab"
                aria-selected={viewMode === option.value}
                onClick={() => setViewMode(option.value)}
              >
                {option.label}
              </button>
            ))}
          </div>
        </div>
        <div className="subnet-stat-row">
          <StatCard label={t("stats.subnets")} value={segments.length} suffix={t("units.count")} />
          <StatCard label={t("stats.activeHosts")} value={activeHosts} suffix={t("units.count")} accent="green" />
          <StatCard label={t("stats.shadowAssets")} value={shadowHosts} suffix={t("units.count")} accent="blue" />
          <StatCard label={t("stats.lockedNodes")} value={lockedHosts} suffix={t("units.count")} accent="orange" />
          <StatCard label={t("stats.attackPaths")} value={graph.edges.length} suffix={t("units.lines")} accent="green" />
          <StatCard label={t("stats.evidenceClues")} value={evidenceCount} suffix={t("units.lines")} />
        </div>
        <div className="subnet-legend">
          <LegendDot color="#0b6fe8" label={t("legend.entry")} />
          <LegendDot color="#16a878" label={t("legend.active")} />
          <LegendDot color="#f59e0b" label={t("legend.locked")} />
          <LegendDot color="#8b5cf6" label={t("legend.shadow")} />
        </div>
        <Input
          className="subnet-search"
          allowClear
          prefix={<Search size={15} />}
          placeholder={t("searchPlaceholder")}
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
      </div>

      <div className={`subnet-workspace ${selectedNode || selectedEdge ? "" : "subnet-workspace--canvas-only"}`}>
        <section className="subnet-canvas-card">
          {graph.nodes.length === 0 ? (
            <Empty description={requestedScope === "session" && !selectedSessionId ? t("scope.selectSession") : t("empty")} />
          ) : (
            <div className="subnet-canvas-frame">
              <div className="canvas-tools">
                <Tooltip title={t("tooltip.autoLayout")}>
                  <button onClick={autoArrangeLayout}>
                    <Boxes size={15} />
                  </button>
                </Tooltip>
                <button onClick={() => setCanvasScale((current) => Math.min(MAX_CANVAS_SCALE, Number((current + CANVAS_ZOOM_STEP).toFixed(2))))}>
                  <Plus size={15} />
                </button>
                <button onClick={() => setCanvasScale((current) => Math.max(MIN_CANVAS_SCALE, Number((current - CANVAS_ZOOM_STEP).toFixed(2))))}>
                  <Minus size={15} />
                </button>
                <button className={canvasLocked ? "is-active" : ""} onClick={() => setCanvasLocked((current) => !current)}>
                  <Lock size={15} />
                </button>
                <button onClick={resetCanvas}>
                  <Crosshair size={15} />
                </button>
              </div>

              <div
                ref={canvasShellRef}
                className={`subnet-canvas-shell ${canvasLocked ? "is-locked" : ""} ${isPanning ? "is-panning" : ""}`}
                onPointerDown={startCanvasPan}
                onPointerMove={moveDrag}
                onPointerUp={endDrag}
                onPointerCancel={endDrag}
                onScroll={updateCanvasViewport}
                onClick={closeDetailOnBlankCanvas}
              >
                <div
                  className="subnet-canvas-space"
                  style={{
                    width: graph.width * canvasScale,
                    height: graph.height * canvasScale,
                  }}
                >
                  <div
                    className="subnet-canvas"
                    style={{
                      width: graph.width,
                      height: graph.height,
                      transform: `scale(${canvasScale})`,
                    }}
                  >
                    {graph.layers.map((layer) => (
                      <div
                        key={layer.depth}
                        className="topology-depth-guide"
                        style={{ left: layer.x, width: layer.width }}
                      >
                        <span>{t("badge.hop", { n: layer.depth + 1 })}</span>
                        <small>{t("stats.subnets")} · {layer.count}</small>
                      </div>
                    ))}
                    <svg className={`subnet-edges ${denseGraph ? "is-dense" : ""}`} width={graph.width} height={graph.height} viewBox={`0 0 ${graph.width} ${graph.height}`}>
                      <defs>
                        <marker id="arrow-active" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
                          <path d="M0,0 L8,4 L0,8 z" fill="#0f5f8f" />
                        </marker>
                        <marker id="arrow-shadow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto">
                          <path d="M0,0 L8,4 L0,8 z" fill="#8b5cf6" />
                        </marker>
                      </defs>
                      {graph.edges.map((edge) => (
                        <GraphConnector
                          key={edge.id}
                          edge={edge}
                          nodeBox={graph.nodeBox}
                          selected={selection?.type === "edge" && selection.id === edge.id}
                          detailActive={detailSelection?.type === "edge" && detailSelection.id === edge.id}
                          showLabel={!denseGraph || selection?.id === edge.id || detailSelection?.id === edge.id}
                          onClick={(event) => {
                            event.stopPropagation();
                            setSelection({ type: "edge", id: edge.id });
                            setDetailSelection({ type: "edge", id: edge.id });
                          }}
                        />
                      ))}
                    </svg>

                    {graph.nodes.map((node) => (
                      <GraphNodeCard
                        key={node.id}
                        node={node}
                        selected={selection?.type === "node" && selection.id === node.id}
                        detailActive={detailSelection?.type === "node" && detailSelection.id === node.id}
                        dimmed={graph.dimmedNodeIDs.has(node.id)}
                        dragging={draggingNodeID === node.id}
                        onPointerDown={(event) => startNodeDrag(event, node.id)}
                        onClick={(event) => {
                          event.stopPropagation();
                          if (suppressClickRef.current) return;
                          setSelection({ type: "node", id: node.id });
                          setDetailSelection({ type: "node", id: node.id });
                          if (node.segment) setExpandedSegment(node.segment.cidr);
                        }}
                      />
                    ))}
                  </div>
                </div>
              </div>

              <button className={`mini-map ${canvasLocked ? "is-locked" : ""}`} onClick={jumpMiniMap} aria-label={t("tooltip.minimap")}>
                <div className="mini-map__viewport" style={miniViewport} />
                {graph.nodes.slice(0, 12).map((node) => (
                  <span
                    key={node.id}
                    style={{
                      left: `${(node.x / graph.width) * 100}%`,
                      top: `${(node.y / graph.height) * 100}%`,
                    }}
                  />
                ))}
              </button>
            </div>
          )}
        </section>

        {(selectedNode || selectedEdge) && (
          <aside className="subnet-detail-panel">
            <DetailPanel
              selectedNode={selectedNode}
              selectedEdge={selectedEdge}
              graph={graph}
              t={t}
            />
          </aside>
        )}
      </div>

      <Card className="subnet-table-card" title={t("table.title")}>
        <Table
          rowKey="id"
          size="small"
          scroll={{ x: 980 }}
          pagination={{
            current: edgePage,
            pageSize: edgePageSize,
            showSizeChanger: true,
            pageSizeOptions: [20, 50, 100],
            showTotal: (total, range) => `${range[0]}-${range[1]} / ${total}`,
            onChange: (nextPage, nextPageSize) => {
              if (nextPageSize !== edgePageSize) {
                setEdgePageSize(nextPageSize);
                setEdgePage(1);
              } else {
                setEdgePage(nextPage);
              }
            },
          }}
          columns={columns}
          dataSource={graph.edges}
        />
      </Card>
    </div>
  );
}

function buildGraph({
  nodes,
  segments,
  edges,
  hostByIP,
  hostsBySegment,
  expandedSegment,
  query,
  statusFilter,
  selectedNodeID,
  viewMode,
  entryHost,
  nodeOffsets,
  t,
}: {
  nodes: NodeItem[];
  segments: NetworkSegment[];
  edges: NetworkEdge[];
  hostByIP: Map<string, NodeItem>;
  hostsBySegment: Map<string, NodeItem[]>;
  expandedSegment: string;
  query: string;
  statusFilter: "all" | "active" | "locked" | "shadow";
  selectedNodeID: string;
  viewMode: ViewMode;
  entryHost?: NodeItem;
  nodeOffsets: NodeOffsets;
  t: TFunction;
}) {
  const graphNodes: GraphNode[] = [];
  const graphEdges: GraphEdge[] = [];
  const primary = segments.find((segment) => !segment.shadow) || segments[0];
  const shadowSegments = segments.filter((segment) => segment.shadow);
  const normalizedQuery = query.trim().toLowerCase();
  const matches = (host: NodeItem) =>
    !normalizedQuery || host.ip.includes(normalizedQuery) || host.hostname.toLowerCase().includes(normalizedQuery) || host.role.toLowerCase().includes(normalizedQuery);
  const passesStatus = (host: NodeItem) => statusFilter === "all" || nodeStatus(host) === statusFilter;

  const entryIP = entryHost?.ip || fallbackEntry.ip;
  const entryHostID = `host:${entryIP}`;
  const entrySegmentID = primary ? `segment:${primary.cidr}` : "segment:entry";

  if (primary) {
    const hosts = hostsBySegment.get(primary.cidr) || [];
    const metrics = segmentMetrics(hosts);
    graphNodes.push({
      id: entrySegmentID,
      kind: "subnet",
      label: primary.cidr,
      sublabel: t("subnetInfo", { total: metrics.total, active: metrics.active }),
      meta: t("subnetMeta", { locked: metrics.locked, shadow: metrics.shadow }),
      badge: t("badge.entrySegment"),
      status: "entry",
      x: 54,
      y: 238,
      w: 176,
      h: 104,
      segment: primary,
      metrics,
      ports: metrics.services.join(" · "),
    });
  }

  const rawExpandedHosts = (hostsBySegment.get(primary?.cidr || expandedSegment) || [])
    .filter((host) => matches(host) && passesStatus(host))
    .sort((a, b) => roleWeight(a) - roleWeight(b) || a.ip.localeCompare(b.ip));
  const expandedHosts = rawExpandedHosts;
  const pivotHost = expandedHosts.find((host) => host.role.includes("jump") || host.hostname.toLowerCase().includes("jump"));
  const pivotID = pivotHost ? `host:${pivotHost.ip}` : "";

  const placedRects = graphNodes.map((node) => ({ x: node.x, y: node.y, w: node.w, h: node.h }));
  const segmentByCIDR = new Map(segments.map((segment) => [segment.cidr, segment]));
  const graphNodeByID = new Map(graphNodes.map((node) => [node.id, node]));
  const graphEdgeExists = (from: string, to: string) => graphEdges.some((edge) => edge.from === from && edge.to === to);
  const endpointID = (value: string) => {
    if (value === entryHost?.hostname || value === fallbackEntry.hostname) return entryHostID;
    if (hostByIP.has(value)) return `host:${value}`;
    if (segmentByCIDR.has(value)) return `segment:${value}`;
    return "";
  };
  const incomingEdgeFor = (target: string) => edges.find((edge) => edge.to === target);
  const segmentParentID = (segment: NetworkSegment) => {
    const explicit = incomingEdgeFor(segment.cidr);
    const explicitID = explicit ? endpointID(explicit.from || explicit.via) : "";
    if (explicitID) return explicitID;
    const hosts = hostsBySegment.get(segment.cidr) || [];
    const reachableVia = hosts.find((host) => host.reachable_via)?.reachable_via;
    if (reachableVia && hostByIP.has(reachableVia)) return `host:${reachableVia}`;
    return primary ? `segment:${primary.cidr}` : entrySegmentID;
  };
  const hostParentID = (host: NodeItem, fallbackSegmentCIDR: string) => {
    if (host.ip === entryIP) return `segment:${fallbackSegmentCIDR}`;
    const explicit = incomingEdgeFor(host.ip);
    if (explicit?.from === entryIP && host.segment_cidr === primary?.cidr) {
      return entryHostID;
    }
    const explicitID = explicit ? endpointID(explicit.from || explicit.via) : "";
    if (explicitID) return explicitID;
    if (host.reachable_via && hostByIP.has(host.reachable_via)) return `host:${host.reachable_via}`;
    return edgeSourceForHost(host, fallbackSegmentCIDR, pivotID, entryHostID, primary?.cidr);
  };

  expandedHosts.forEach((host, index) => {
    const isEntrySubnetMember = host.ip === entryIP;
    const pos = avoidOverlap(primaryHostPosition(host, index, !!pivotHost), 190, 82, placedRects, { maxY: 820 });
    placedRects.push({ x: pos.x, y: pos.y, w: 190, h: 82 });
    const fromID = hostParentID(host, primary?.cidr || expandedSegment);
    graphNodes.push({
      id: `host:${host.ip}`,
      kind: roleKind(host),
      label: host.hostname,
      sublabel: host.ip,
      meta: getRoleLabel(host.role),
      badge: host.ip === entryIP ? t("badge.entryHost") : isShadowHost(host) ? "SHADOW" : host.required_state?.length ? "LOCKED" : "ACTIVE",
      status: isEntrySubnetMember ? "entry" : nodeStatus(host),
      x: pos.x,
      y: pos.y,
      w: 190,
      h: 82,
      host,
      ports: getServicePorts(host),
    });
    graphNodeByID.set(`host:${host.ip}`, graphNodes[graphNodes.length - 1]);
    if (!graphEdgeExists(fromID, `host:${host.ip}`)) {
      graphEdges.push({
        id: `edge:segment-${host.ip}`,
        from: fromID,
        to: `host:${host.ip}`,
        label: isEntrySubnetMember ? "member" : edgeLabelForHost(host),
        relation: isEntrySubnetMember ? "entry_host" : host.role.includes("jump") ? "ssh_login" : `${inferMainProtocol(host)}_probe`,
        status: nodeStatus(host) === "locked" ? "locked" : isShadowHost(host) ? "shadow" : "active",
        protocol: isEntrySubnetMember ? "192.168.56.23/24" : getServicePorts(host) || inferMainProtocol(host),
        gate: host.required_state?.join(", ") || "-",
        evidence: isEntrySubnetMember ? "ip addr eth1 / dual_nic" : host.role.includes("jump") ? `ssh root@${host.ip}` : `nmap -sV ${primary?.cidr || expandedSegment}`,
        lastSeen: "14:28:11",
      });
    }
  });

  // Compute attack-chain depth for each shadow segment by walking parent links.
  // Depth 0 = directly connected to jump01/dc01/primary.
  // Depth N = parent is a host in a depth N-1 shadow segment.
  const segmentDepthCache = new Map<string, number>();
  const computeSegmentDepth = (segmentCIDR: string, visited: Set<string> = new Set()): number => {
    if (visited.has(segmentCIDR)) return 0;
    if (segmentDepthCache.has(segmentCIDR)) return segmentDepthCache.get(segmentCIDR)!;
    visited.add(segmentCIDR);
    const seg = segmentByCIDR.get(segmentCIDR);
    if (!seg || !seg.shadow) {
      segmentDepthCache.set(segmentCIDR, 0);
      return 0;
    }
    const pid = segmentParentID(seg);
    if (pid.startsWith("host:")) {
      const hostIP = pid.replace("host:", "");
      const host = hostByIP.get(hostIP);
      if (host && host.segment_cidr && host.segment_cidr !== segmentCIDR) {
        const depth = 1 + computeSegmentDepth(host.segment_cidr, visited);
        segmentDepthCache.set(segmentCIDR, depth);
        return depth;
      }
    } else if (pid.startsWith("segment:")) {
      const parentCIDR = pid.replace("segment:", "");
      if (parentCIDR !== segmentCIDR) {
        const depth = 1 + computeSegmentDepth(parentCIDR, visited);
        segmentDepthCache.set(segmentCIDR, depth);
        return depth;
      }
    }
    segmentDepthCache.set(segmentCIDR, 0);
    return 0;
  };

  // Group shadow segments by attack depth. The x-axis represents hop depth;
  // items in the same column are ordered by their parent so branches stay
  // together and long chains do not turn into a crossing grid.
  const depthGroups = new Map<number, { segment: NetworkSegment; parentID: string }[]>();
  for (const segment of shadowSegments) {
    const depth = computeSegmentDepth(segment.cidr);
    if (!depthGroups.has(depth)) depthGroups.set(depth, []);
    depthGroups.get(depth)!.push({ segment, parentID: segmentParentID(segment) });
  }
  const sortedDepths = [...depthGroups.keys()].sort((a, b) => a - b);
  const columnBaseX = 1080;
  const segmentHostColumns = (segment: NetworkSegment) => {
    const count = (hostsBySegment.get(segment.cidr) || []).length;
    return count ? Math.min(4, Math.max(1, Math.ceil(Math.sqrt(count)))) : 0;
  };
  const segmentClusterWidth = (segment: NetworkSegment) => {
    const columns = segmentHostColumns(segment);
    return columns ? 460 + (columns - 1) * 220 : 200;
  };
  const segmentClusterHeight = (segment: NetworkSegment) => {
    const count = (hostsBySegment.get(segment.cidr) || []).length;
    const columns = segmentHostColumns(segment);
    return columns ? Math.max(92, Math.ceil(count / columns) * 106) : 92;
  };
  const depthWidths = new Map<number, number>();
  for (const depth of sortedDepths) {
    depthWidths.set(depth, Math.max(200, ...(depthGroups.get(depth) || []).map(({ segment }) => segmentClusterWidth(segment))));
  }
  const depthX = new Map<number, number>();
  let nextDepthX = columnBaseX;
  for (const depth of sortedDepths) {
    depthX.set(depth, nextDepthX);
    nextDepthX += (depthWidths.get(depth) || 200) + 190;
  }
  const layers = sortedDepths.map((depth) => ({
    depth,
    x: (depthX.get(depth) || columnBaseX) - 28,
    width: (depthWidths.get(depth) || 200) + 56,
    count: (depthGroups.get(depth) || []).length,
  }));

  for (const depth of sortedDepths) {
    const groupItems = depthGroups.get(depth) || [];
    groupItems.sort((a, b) => {
      const parentA = graphNodeByID.get(a.parentID);
      const parentB = graphNodeByID.get(b.parentID);
      return (parentA?.y || 0) - (parentB?.y || 0) || a.parentID.localeCompare(b.parentID) || a.segment.cidr.localeCompare(b.segment.cidr);
    });

    let rowCursor = 92;

    for (const { segment, parentID } of groupItems) {
      const hosts = hostsBySegment.get(segment.cidr) || [];
      const metrics = segmentMetrics(hosts);
      const segmentX = depthX.get(depth) || columnBaseX;
      const clusterHeight = segmentClusterHeight(segment);
      const parent = graphNodeByID.get(parentID);
      const preferredY = parent ? Math.max(92, parent.y + parent.h / 2 - clusterHeight / 2) : rowCursor;
      const rowY = Math.max(rowCursor, preferredY);
      const segmentPos = { x: segmentX, y: rowY };
      placedRects.push({ x: segmentPos.x, y: segmentPos.y, w: 200, h: 92 });
      graphNodes.push({
        id: `segment:${segment.cidr}`,
        kind: "shadow-subnet",
        label: segment.cidr,
        sublabel: `${metrics.total} hosts · ${metrics.active} active`,
        meta: `${metrics.locked} locked · ${metrics.shadow} shadow`,
        badge: depth > 0 ? t("badge.hop", { n: depth + 1 }) : t("badge.shadowSubnet"),
        status: "shadow",
        x: segmentPos.x,
        y: segmentPos.y,
        w: 200,
        h: 92,
        segment,
        metrics,
        ports: metrics.services.join(" · "),
      });
      graphNodeByID.set(`segment:${segment.cidr}`, graphNodes[graphNodes.length - 1]);
      if (!graphEdgeExists(parentID, `segment:${segment.cidr}`)) {
        graphEdges.push({
          id: `edge:shadow-segment-${segment.cidr}`,
          from: parentID,
          to: `segment:${segment.cidr}`,
          label: incomingEdgeFor(segment.cidr) ? relationLabel(incomingEdgeFor(segment.cidr)!, t) : "pivot",
          relation: incomingEdgeFor(segment.cidr)?.type || "pivot",
          status: edgeStatus(incomingEdgeFor(segment.cidr) || { from: "", to: segment.cidr, type: "pivot", via: "", status: "shadow" }),
          protocol: incomingEdgeFor(segment.cidr)?.type || "pivot",
          gate: incomingEdgeFor(segment.cidr)?.required_state?.join(", ") || segment.visible_after?.join(", ") || "-",
          evidence: `via ${graphNodeByID.get(parentID)?.label || parentID} · nmap -sV ${segment.cidr}`,
          lastSeen: "14:32:04",
        });
      }
      const hostColumns = segmentHostColumns(segment);
      hosts
        .slice()
        .sort((a, b) => roleWeight(a) - roleWeight(b) || a.ip.localeCompare(b.ip))
        .forEach((host, hostIndex) => {
        const parentForHost = hostParentID(host, segment.cidr);
        const hostBaseX = segmentX + 270;
        const hostPos = {
          x: hostBaseX + (hostIndex % Math.max(1, hostColumns)) * 220,
          y: rowY + Math.floor(hostIndex / Math.max(1, hostColumns)) * 106,
        };
        placedRects.push({ x: hostPos.x, y: hostPos.y, w: 190, h: 78 });
        graphNodes.push({
          id: `host:${host.ip}`,
          kind: roleKind(host),
          label: host.hostname,
          sublabel: host.ip,
          meta: getRoleLabel(host.role),
          badge: "SHADOW",
          status: nodeStatus(host),
          x: hostPos.x,
          y: hostPos.y,
          w: 190,
          h: 78,
          host,
          ports: getServicePorts(host),
        });
        graphNodeByID.set(`host:${host.ip}`, graphNodes[graphNodes.length - 1]);
        if (!graphEdgeExists(parentForHost, `host:${host.ip}`)) {
          graphEdges.push({
            id: `edge:${segment.cidr}-${host.ip}`,
            from: parentForHost,
            to: `host:${host.ip}`,
            label: inferMainProtocol(host),
            relation: `${inferMainProtocol(host)}_probe`,
            status: "shadow",
            protocol: getServicePorts(host) || inferMainProtocol(host),
            gate: host.required_state?.join(", ") || "-",
            evidence: `planner generated ${host.hostname}`,
            lastSeen: "14:34:22",
          });
        }
        });
      rowCursor = rowY + clusterHeight + 72;
    }
  }

  for (const edge of edges) {
    if (edge.from === entryIP && hostByIP.get(edge.to)?.segment_cidr === primary?.cidr) {
      continue;
    }
    if ((edge.from === entryHost?.hostname || edge.from === fallbackEntry.hostname) && edge.to === primary?.cidr) {
      continue;
    }
    const fromID = endpointID(edge.from || edge.via);
    const toID = endpointID(edge.to);
    if (!fromID || !toID || graphEdges.some((item) => item.from === fromID && item.to === toID)) continue;
    graphEdges.push({
      id: `edge:${edge.from}-${edge.to}-${edge.type}`,
      from: fromID,
      to: toID,
      label: relationLabel(edge, t),
      relation: edge.type,
      status: edgeStatus(edge),
      protocol: edgeProtocol(edge),
      gate: edge.required_state?.join(", ") || "-",
      evidence: `${relationLabel(edge, t)} ${edge.to}`,
      lastSeen: "14:28:11",
    });
  }

  const uniqueGraphNodes = dedupeGraphNodes(graphNodes);
  const uniqueGraphEdges = dedupeGraphEdges(graphEdges);
  const offsetGraphNodes = uniqueGraphNodes.map((node) => {
    const offset = nodeOffsets[node.id];
    return offset ? { ...node, x: node.x + offset.x, y: node.y + offset.y } : node;
  });
  const selectedGraphNode = selectedNodeID ? offsetGraphNodes.find((node) => node.id === selectedNodeID) : undefined;
  const selectedSegmentCIDR = selectedGraphNode?.host?.segment_cidr || selectedGraphNode?.segment?.cidr || "";
  const visibleGraphNodes =
    viewMode === "node" && selectedSegmentCIDR
      ? offsetGraphNodes.filter((node) => node.host?.segment_cidr === selectedSegmentCIDR || node.segment?.cidr === selectedSegmentCIDR)
      : offsetGraphNodes;
  const visibleIDs = new Set(visibleGraphNodes.map((node) => node.id));
  const filteredEdges = uniqueGraphEdges.filter((edge) => visibleIDs.has(edge.from) && visibleIDs.has(edge.to));
  const nodeBox = new Map(visibleGraphNodes.map((node) => [node.id, node]));
  const nodeLabel = new Map(visibleGraphNodes.map((node) => [node.id, node.label]));

  const contentWidth = visibleGraphNodes.reduce((max, node) => Math.max(max, node.x + node.w + 140), 1760);
  const contentHeight = visibleGraphNodes.reduce((max, node) => Math.max(max, node.y + node.h + 140), 900);

  return {
    nodes: visibleGraphNodes,
    edges: filteredEdges,
    nodeBox,
    nodeLabel,
    dimmedNodeIDs: new Set<string>(),
    layers,
    width: contentWidth,
    height: contentHeight,
  };
}

function dedupeGraphNodes(nodes: GraphNode[]) {
  const seen = new Set<string>();
  const result: GraphNode[] = [];
  for (const node of nodes) {
    if (seen.has(node.id)) continue;
    seen.add(node.id);
    result.push(node);
  }
  return result;
}

function dedupeGraphEdges(edges: GraphEdge[]) {
  const seen = new Set<string>();
  const result: GraphEdge[] = [];
  for (const edge of edges) {
    const key = `${edge.from}->${edge.to}:${edge.relation}:${edge.label}`;
    if (seen.has(edge.id) || seen.has(key)) continue;
    seen.add(edge.id);
    seen.add(key);
    result.push(edge);
  }
  return result;
}

function GraphConnector({
  edge,
  nodeBox,
  selected,
  detailActive,
  showLabel,
  onClick,
}: {
  edge: GraphEdge;
  nodeBox: Map<string, GraphNode>;
  selected: boolean;
  detailActive: boolean;
  showLabel: boolean;
  onClick: (event: MouseEvent<SVGGElement>) => void;
}) {
  const from = nodeBox.get(edge.from);
  const to = nodeBox.get(edge.to);
  if (!from || !to) return null;
  const sx = from.x + from.w;
  const sy = from.y + from.h / 2;
  const tx = to.x;
  const ty = to.y + to.h / 2;
  const forward = tx >= sx;
  const midX = forward ? sx + Math.max(48, (tx - sx) / 2) : Math.max(sx, tx) + 64;
  const path = `M ${sx} ${sy} H ${midX} V ${ty} H ${tx}`;
  const labelX = midX;
  const labelY = sy + (ty - sy) / 2 - 10;
  return (
    <g className={`graph-edge graph-edge--${edge.status} ${selected || detailActive ? "is-selected" : ""}`} onClick={onClick}>
      <path className="graph-edge-hit" d={path} />
      <path d={path} />
      {showLabel ? (
        <foreignObject x={labelX - 46} y={labelY - 13} width={92} height={28}>
          <div className="edge-label">{edge.label}</div>
        </foreignObject>
      ) : null}
    </g>
  );
}

function GraphNodeCard({
  node,
  selected,
  detailActive,
  dimmed,
  dragging,
  onPointerDown,
  onClick,
}: {
  node: GraphNode;
  selected: boolean;
  detailActive: boolean;
  dimmed: boolean;
  dragging: boolean;
  onPointerDown: (event: PointerEvent<HTMLButtonElement>) => void;
  onClick: (event: MouseEvent<HTMLButtonElement>) => void;
}) {
  return (
    <button
      className={`graph-node graph-node--${node.kind} graph-node--${node.status} ${selected ? "is-selected" : ""} ${detailActive ? "is-detail-active" : ""} ${dimmed ? "is-dimmed" : ""} ${dragging ? "is-dragging" : ""}`}
      style={{ left: node.x, top: node.y, width: node.w, minHeight: node.h }}
      onPointerDown={onPointerDown}
      onClick={onClick}
    >
      <span className="graph-node__icon">{iconFor(node.kind)}</span>
      <span className="graph-node__body">
        <strong>{node.label}</strong>
        <small>{node.sublabel}</small>
        {node.meta ? <em>{node.meta}</em> : null}
        {node.ports ? <code title={node.ports}>{compactPorts(node.ports)}</code> : null}
      </span>
      <span className="graph-node__badge">{node.badge}</span>
    </button>
  );
}

function compactPorts(ports: string) {
  const parts = ports
    .split(/[,\s]+/)
    .map((part) => part.trim())
    .filter(Boolean);
  if (parts.length <= 3) return ports;
  return `${parts.slice(0, 3).join(", ")} +${parts.length - 3}`;
}

function DetailPanel({
  selectedNode,
  selectedEdge,
  graph,
  t,
}: {
  selectedNode?: GraphNode;
  selectedEdge?: GraphEdge;
  graph: ReturnType<typeof buildGraph>;
  t: TFunction;
}) {
  if (selectedEdge) {
    return (
      <>
        <PanelTitle title={t("detail.edgeTitle")} />
        <DetailRow label={t("table.columns.source")} value={graph.nodeLabel.get(selectedEdge.from) || selectedEdge.from} />
        <DetailRow label={t("table.columns.target")} value={graph.nodeLabel.get(selectedEdge.to) || selectedEdge.to} />
        <DetailRow label={t("table.columns.relation")} value={selectedEdge.relation} />
        <DetailRow label={t("table.columns.protocolPort")} value={selectedEdge.protocol} />
        <DetailRow label={t("table.columns.status")} value={selectedEdge.status} tag />
        <DetailRow label={t("table.columns.gate")} value={selectedEdge.gate} mono />
        <DetailRow label={t("table.columns.evidence")} value={selectedEdge.evidence} />
        <DetailRow label={t("table.columns.lastProbe")} value={selectedEdge.lastSeen} />
      </>
    );
  }

  if (selectedNode) {
    const outgoing = graph.edges.filter((edge) => edge.from === selectedNode.id);
    return (
      <>
        <PanelTitle title={t("detail.nodeTitle")} />
        <div className="detail-hero">
          <span>{iconFor(selectedNode.kind)}</span>
          <div>
            <strong>{selectedNode.label}</strong>
            <small>{selectedNode.sublabel}</small>
          </div>
          {statusLabel(selectedNode.status, t)}
        </div>
        <DetailRow label={t("detail.role")} value={selectedNode.meta || selectedNode.kind} />
        <DetailRow label={t("detail.openPorts")} value={selectedNode.ports || "-"} mono />
        <DetailRow label={t("detail.os")} value={selectedNode.host?.os || "-"} />
        <DetailRow label={t("detail.gateCondition")} value={selectedNode.host?.required_state?.join(", ") || "-"} mono />
        <DetailRow label={t("detail.upstreamNodes")} value={upstreamOf(selectedNode.id, graph)} />
        <DetailRow label={t("detail.reachableNodes")} value={`${outgoing.length}${t("units.count")}`} />
        <div className="detail-subsection">
          <h4>{t("detail.outEdges")}</h4>
          {outgoing.length ? (
            outgoing.map((edge) => (
              <div key={edge.id} className="detail-edge-row">
                <span>→ {graph.nodeLabel.get(edge.to) || edge.to}</span>
                <code>{edge.protocol}</code>
                {statusLabel(edge.status, t)}
              </div>
            ))
          ) : (
            <div className="detail-empty">{t("detail.noOutEdges")}</div>
          )}
        </div>
      </>
    );
  }

  return null;
}

function PanelTitle({ title }: { title: string }) {
  return (
    <div className="detail-title">
      <h3>{title}</h3>
      <ChevronRight size={16} />
    </div>
  );
}

function DetailRow({ label, value, mono, tag }: { label: string; value: string; mono?: boolean; tag?: boolean }) {
  return (
    <div className="detail-row">
      <span>{label}</span>
      {tag ? <Tag>{value}</Tag> : <strong className={mono ? "is-mono" : ""}>{value}</strong>}
    </div>
  );
}

function StatCard({ label, value, suffix, accent }: { label: string; value: number; suffix: string; accent?: "green" | "blue" | "orange" }) {
  return (
    <div className={`subnet-stat-card ${accent ? `subnet-stat-card--${accent}` : ""}`}>
      <span>{label}</span>
      <strong>
        {value}
        <small>{suffix}</small>
      </strong>
    </div>
  );
}

function buildMiniViewport(viewport: { scrollLeft: number; scrollTop: number; clientWidth: number; clientHeight: number }, contentWidth: number, contentHeight: number) {
  const width = contentWidth <= viewport.clientWidth ? 100 : Math.min(100, Math.max(14, (viewport.clientWidth / contentWidth) * 100));
  const height = contentHeight <= viewport.clientHeight ? 100 : Math.min(100, Math.max(16, (viewport.clientHeight / contentHeight) * 100));
  const left = contentWidth <= viewport.clientWidth ? 0 : Math.min(100 - width, Math.max(0, (viewport.scrollLeft / contentWidth) * 100));
  const top = contentHeight <= viewport.clientHeight ? 0 : Math.min(100 - height, Math.max(0, (viewport.scrollTop / contentHeight) * 100));
  return {
    left: `${left}%`,
    top: `${top}%`,
    width: `${width}%`,
    height: `${height}%`,
  };
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <span>
      <i style={{ background: color }} />
      {label}
    </span>
  );
}

function roleWeight(node: NodeItem) {
  if (node.role.includes("jump")) return 0;
  if (node.role.includes("redis")) return 1;
  if (node.role.includes("jenkins") || node.role.includes("gitlab") || node.role.includes("web")) return 2;
  if (node.role.includes("db") || node.role.includes("database")) return 3;
  if (node.role.includes("dc") || node.role.includes("domain")) return 4;
  return 5;
}

function avoidOverlap(pos: { x: number; y: number }, w: number, h: number, placed: { x: number; y: number; w: number; h: number }[], options?: { maxY?: number }) {
  const next = { ...pos };
  let guard = 0;
  const collides = () => placed.some((rect) => next.x < rect.x + rect.w + 16 && next.x + w + 16 > rect.x && next.y < rect.y + rect.h + 14 && next.y + h + 14 > rect.y);
  const maxY = options?.maxY ?? 760;
  while (collides() && guard < 14) {
    next.y += 96;
    if (next.y > maxY) {
      next.y = 118 + (guard % 3) * 116;
      next.x += 236;
    }
    guard += 1;
  }
  return next;
}

function primaryHostPosition(host: NodeItem, index: number, hasPivot: boolean) {
  const lower = `${host.hostname} ${host.role}`.toLowerCase();
  if (host.ip === fallbackEntry.ip || lower.includes("staging-web")) return { x: 296, y: 250 };
  if (lower.includes("jump")) return { x: 530, y: 118 };
  if (lower.includes("redis") || lower.includes("cache")) return { x: 530, y: 310 };
  if (hasPivot) {
    if (lower.includes("jenkins")) return { x: 760, y: 64 };
    if (lower.includes("db") || lower.includes("mysql") || lower.includes("database")) return { x: 760, y: 176 };
    if (lower.includes("dc") || lower.includes("domain")) return { x: 760, y: 408 };
    if (lower.includes("gitlab")) return { x: 760, y: 292 };
    if (lower.includes("gateway")) return { x: 530, y: 430 };
    if (lower.includes("web")) return { x: 530, y: 548 };
  }
  return { x: 530 + Math.floor(index / 4) * 250, y: 118 + (index % 4) * 108 };
}

function edgeSourceForHost(host: NodeItem, segmentCIDR: string, pivotID: string, entryHostID: string, primaryCIDR?: string) {
  const lower = `${host.hostname} ${host.role}`.toLowerCase();
  if (segmentCIDR === primaryCIDR) {
    if (lower.includes("jump") || lower.includes("redis") || lower.includes("cache") || lower.includes("gateway")) return entryHostID;
  }
  if (!pivotID || lower.includes("jump") || lower.includes("redis") || lower.includes("cache") || lower.includes("web-service") || lower.includes("file-shadow")) {
    return `segment:${segmentCIDR}`;
  }
  return pivotID;
}

function edgeLabelForHost(host: NodeItem) {
  const lower = `${host.hostname} ${host.role}`.toLowerCase();
  if (lower.includes("jump")) return "ssh";
  if (lower.includes("jenkins") || lower.includes("gitlab") || lower.includes("web")) return "http";
  if (lower.includes("db") || lower.includes("mysql") || lower.includes("database")) return "mysql";
  if (lower.includes("dc") || lower.includes("domain")) return "ssh";
  return inferMainProtocol(host);
}

function inferMainProtocol(host: NodeItem) {
  const svc = host.services[0];
  if (!svc) return "probe";
  return svc.protocol.toLowerCase();
}

function upstreamOf(nodeID: string, graph: ReturnType<typeof buildGraph>) {
  const incoming = graph.edges.find((edge) => edge.to === nodeID);
  if (!incoming) return "-";
  return graph.nodeLabel.get(incoming.from) || incoming.from;
}
