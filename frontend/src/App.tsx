import { lazy, Suspense } from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
import { Spin } from "antd";

import { AuthProvider, useAuth } from "./auth/AuthProvider";
import { AppLayout } from "./layouts/AppLayout";

const DashboardPage = lazy(() => import("./pages/DashboardPage").then((mod) => ({ default: mod.DashboardPage })));
const LoginPage = lazy(() => import("./pages/LoginPage").then((mod) => ({ default: mod.LoginPage })));
const TopologyPage = lazy(() => import("./pages/TopologyPage").then((mod) => ({ default: mod.TopologyPage })));
const SessionDetailPage = lazy(() => import("./pages/SessionDetailPage").then((mod) => ({ default: mod.SessionDetailPage })));
const SessionsPage = lazy(() => import("./pages/SessionsPage").then((mod) => ({ default: mod.SessionsPage })));
const StatusPage = lazy(() => import("./pages/StatusPage").then((mod) => ({ default: mod.StatusPage })));

function PageLoading() {
  return (
    <div className="page-loading">
      <Spin />
    </div>
  );
}

function ProtectedShell() {
  const { user, loading } = useAuth();
  const location = useLocation();

  if (loading) return <PageLoading />;
  if (!user) return <Navigate to="/login" replace state={{ from: location.pathname }} />;

  return (
    <AppLayout>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/topology" element={<TopologyPage />} />
        <Route path="/sessions" element={<SessionsPage />} />
        <Route path="/sessions/:sessionId" element={<SessionDetailPage />} />
        <Route path="/sessions/:sessionId/topology" element={<TopologyPage />} />
        <Route path="/status" element={<StatusPage />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </AppLayout>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <Suspense fallback={<PageLoading />}>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/*" element={<ProtectedShell />} />
        </Routes>
      </Suspense>
    </AuthProvider>
  );
}
