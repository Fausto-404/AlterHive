import {
  ClipboardList,
  LayoutDashboard,
  LogOut,
  Network,
  RefreshCw,
  Shield,
} from "lucide-react";
import { Button, Segmented, Tag } from "antd";
import { createContext, useContext, useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { NavLink, useLocation, useNavigate } from "react-router-dom";

import { useAuth } from "../auth/AuthProvider";
import { hasPermission } from "../services/session";
import alterHiveMark from "../assets/alterhive-mark.svg";

interface AppLayoutProps {
  children: React.ReactNode;
}

interface PageRefreshAction {
  label?: string;
  loading?: boolean;
  onRefresh: () => void | Promise<void>;
}

const PageRefreshContext = createContext<(action: PageRefreshAction | null) => void>(() => undefined);

export function usePageRefresh(onRefresh: () => void | Promise<void>, loading?: boolean, label?: string) {
  const { t } = useTranslation("common");
  const setPageRefresh = useContext(PageRefreshContext);
  useEffect(() => {
    setPageRefresh({ label: label || t("action.refresh"), loading, onRefresh });
    return () => setPageRefresh(null);
  }, [label, loading, onRefresh, setPageRefresh, t]);
}

export function AppLayout({ children }: AppLayoutProps) {
  const { t, i18n } = useTranslation("common");
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const meta = pageMeta(location.pathname, t);
  const [pageRefresh, setPageRefresh] = useState<PageRefreshAction | null>(null);
  const refreshContextValue = useMemo(() => setPageRefresh, []);

  async function onLogout() {
    await logout();
    navigate("/login", { replace: true });
  }

  const navItems = [
    { to: "/dashboard", label: t("nav.dashboard"), icon: LayoutDashboard },
    { to: "/topology", label: t("nav.topology"), icon: Network, permission: "system:read" },
    { to: "/sessions", label: t("nav.sessions"), icon: ClipboardList, permission: "session:read" },
    { to: "/status", label: t("nav.status"), icon: Shield, permission: "system:read" },
  ];

  const roleLabels: Record<string, string> = {
    admin: t("role.admin"),
    operator: t("role.operator"),
    analyst: t("role.analyst"),
    researcher: t("role.researcher"),
    viewer: t("role.readonly"),
  };

  function handleLanguageChange(value: string | number) {
    i18n.changeLanguage(String(value));
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <img src={alterHiveMark} alt="幻巢 AlterHive" className="brand-logo" />
          <div>
            <strong>幻巢 AlterHive</strong>
          </div>
        </div>
        <nav className="nav">
          {navItems
            .filter((item) => hasPermission(user, item.permission))
            .map((item) => {
              const Icon = item.icon;
              return (
                <NavLink key={item.to} to={item.to} className="nav-link">
                  <Icon size={18} />
                  <span>{item.label}</span>
                </NavLink>
              );
            })}
        </nav>
      </aside>
      <main className="main">
        <header className="topbar">
          <div>
            <h1>{meta.title}</h1>
            <p>{meta.description}</p>
          </div>
          <div className="topbar-user">
            <div className="user-meta">
              <strong>{user?.display_name || user?.username}</strong>
              <Tag>{roleLabels[user?.role || ""] || user?.role}</Tag>
            </div>
            {pageRefresh ? (
              <Button icon={<RefreshCw size={16} />} onClick={pageRefresh.onRefresh} loading={pageRefresh.loading}>
                {pageRefresh.label || t("action.refresh")}
              </Button>
            ) : null}
            <Segmented
              size="small"
              value={i18n.language?.startsWith("en") ? "en" : "zh-CN"}
              onChange={handleLanguageChange}
              options={[
                { label: "中", value: "zh-CN" },
                { label: "EN", value: "en" },
              ]}
            />
            <Button icon={<LogOut size={16} />} onClick={onLogout}>
              {t("action.logout")}
            </Button>
          </div>
        </header>
        <PageRefreshContext.Provider value={refreshContextValue}>
          <section className="content">{children}</section>
        </PageRefreshContext.Provider>
      </main>
    </div>
  );
}

function pageMeta(pathname: string, t: (key: string, options?: Record<string, unknown>) => string) {
  if (pathname.startsWith("/sessions/")) {
    return {
      title: t("nav.sessionDetail", { defaultValue: "会话详情" }),
      description: t("nav.sessionDetailDesc", { defaultValue: "攻击命令、证据命中与伪进展状态追踪" }),
    };
  }
  if (pathname.startsWith("/sessions")) {
    return {
      title: t("nav.sessions"),
      description: t("nav.sessionsDesc", { defaultValue: "查看所有捕获的攻击会话及其详情（10 秒自动刷新）" }),
    };
  }
  if (pathname.startsWith("/topology")) {
    return {
      title: t("nav.topology"),
      description: t("nav.topologyDesc", { defaultValue: "入口、网段、跳板与动态影子资产拓扑" }),
    };
  }
  if (pathname.startsWith("/status")) {
    return {
      title: t("nav.status"),
      description: t("nav.statusDesc", { defaultValue: "运行状态、蜜罐配置与 LLM 模型管理" }),
    };
  }
  return {
    title: t("nav.dashboard"),
    description: t("nav.dashboardDesc", { defaultValue: "蜜罐运行核心指标概览（10 秒自动刷新）" }),
  };
}
