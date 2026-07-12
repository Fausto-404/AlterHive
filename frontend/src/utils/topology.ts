import type { NodeItem } from "../types/platform";
import i18n from "../i18n";

export const ROLE_COLORS: Record<string, string> = {
  gateway: "#0d9488",
  jump: "#3b82f6",
  jumpbox: "#3b82f6",
  dc: "#8b5cf6",
  dc_shadow: "#8b5cf6",
  db: "#f59e0b",
  db_shadow: "#f59e0b",
  web: "#22c55e",
  cache: "#6366f1",
  gitlab: "#e11d48",
  gitlab_shadow: "#e11d48",
  jenkins_shadow: "#f97316",
  k8s_shadow: "#06b6d4",
};

export function getRoleLabel(role: string): string {
  const t = i18n.getFixedT(i18n.language, "evidence");
  const map: Record<string, string> = {
    gateway: t("roleLabels.gateway"),
    jump: t("roleLabels.jumpbox"),
    jumpbox: t("roleLabels.jumpbox"),
    dc: t("roleLabels.dc"),
    dc_shadow: t("roleLabels.dc_shadow"),
    db: t("roleLabels.database"),
    db_shadow: t("roleLabels.database_shadow"),
    web: t("roleLabels.web_app"),
    cache: t("roleLabels.cache"),
    gitlab: t("roleLabels.gitlab"),
    gitlab_shadow: t("roleLabels.gitlab_shadow"),
    jenkins_shadow: t("roleLabels.jenkins_shadow"),
    k8s_shadow: t("roleLabels.k8s_shadow"),
  };
  for (const [key, label] of Object.entries(map)) {
    if (role.includes(key)) return label;
  }
  return role;
}

export function getRoleColor(role: string): string {
  for (const [key, color] of Object.entries(ROLE_COLORS)) {
    if (role.includes(key)) return color;
  }
  return "#64748b";
}

export function isShadowHost(node: NodeItem): boolean {
  return Boolean(node.shadow) || node.role.includes("shadow");
}

export function getServicePorts(node: NodeItem): string {
  return node.services.map((s) => String(s.port)).join(", ");
}

export function getTriggeredByLabel(triggeredBy: string): string {
  const t = i18n.getFixedT(i18n.language, "evidence");
  const map: Record<string, string> = {
    db_probe: t("triggeredBy.db_probe"),
    http_probe: t("triggeredBy.http_probe"),
    domain_probe: t("triggeredBy.domain_probe"),
    lateral_movement: t("triggeredBy.lateral_movement"),
  };
  return map[triggeredBy] || triggeredBy;
}
