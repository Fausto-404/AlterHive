import i18n from "../i18n";

export type EvidenceCategory = "recon" | "exploit" | "lateral" | "deception";

export interface EvidenceTokenDef {
  token: string;
  label: string;
  category: EvidenceCategory;
  description: string;
}

export function getEVIDENCE_TOKENS(): Record<string, EvidenceTokenDef> {
  const t = i18n.getFixedT(i18n.language, "evidence");
  return {
    route_info: { token: "route_info", label: t("evidenceTokens.routing_info"), category: "recon", description: t("evidenceDescriptions.routing_info") },
    arp_cache: { token: "arp_cache", label: t("evidenceTokens.arp_cache"), category: "recon", description: t("evidenceDescriptions.arp_cache") },
    subnet_scan: { token: "subnet_scan", label: t("evidenceTokens.subnet_scan"), category: "recon", description: t("evidenceDescriptions.subnet_scan") },
    app_config: { token: "app_config", label: t("evidenceTokens.app_config"), category: "exploit", description: t("evidenceDescriptions.app_config") },
    app_log: { token: "app_log", label: t("evidenceTokens.app_log"), category: "exploit", description: t("evidenceDescriptions.app_log") },
    db_probe: { token: "db_probe", label: t("evidenceTokens.db_probe"), category: "exploit", description: t("evidenceDescriptions.db_probe") },
    domain_probe: { token: "domain_probe", label: t("evidenceTokens.domain_probe"), category: "exploit", description: t("evidenceDescriptions.domain_probe") },
    http_probe: { token: "http_probe", label: t("evidenceTokens.http_probe"), category: "exploit", description: t("evidenceDescriptions.http_probe") },
    lateral_probe: { token: "lateral_probe", label: t("evidenceTokens.lateral_probe"), category: "lateral", description: t("evidenceDescriptions.lateral_probe") },
    service_enum: { token: "service_enum", label: t("evidenceTokens.service_enum"), category: "recon", description: t("evidenceDescriptions.service_enum") },
    pseudo_progress: { token: "pseudo_progress", label: t("evidenceTokens.pseudo_progress"), category: "deception", description: t("evidenceDescriptions.pseudo_progress") },
  };
}

export const ALL_TOKENS = ["route_info", "arp_cache", "subnet_scan", "app_config", "app_log", "db_probe", "domain_probe", "http_probe", "lateral_probe", "service_enum", "pseudo_progress"];

export const CATEGORY_COLORS: Record<EvidenceCategory, string> = {
  recon: "#3b82f6",
  exploit: "#f59e0b",
  lateral: "#f97316",
  deception: "#ef4444",
};

export function getCategoryLabel(category: EvidenceCategory): string {
  return i18n.t(`evidence.categoryLabels.${category}`, { ns: "evidence" });
}

export function getTokenDef(token: string): EvidenceTokenDef {
  const tokens = getEVIDENCE_TOKENS();
  return tokens[token] || { token, label: token, category: "recon", description: token };
}

export function getTokenColor(token: string): string {
  return CATEGORY_COLORS[getTokenDef(token).category];
}

export function groupTokensByCategory(tokens: string[]): Map<EvidenceCategory, string[]> {
  const groups = new Map<EvidenceCategory, string[]>();
  for (const token of tokens) {
    const cat = getTokenDef(token).category;
    if (!groups.has(cat)) groups.set(cat, []);
    groups.get(cat)!.push(token);
  }
  return groups;
}
