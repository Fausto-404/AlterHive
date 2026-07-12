import { Tag } from "antd";
import { useTranslation } from "react-i18next";

interface ThreatBadgeProps {
  score: number;
}

export function ThreatLevel({ score }: ThreatBadgeProps) {
  const { t } = useTranslation("common");

  if (score >= 50) {
    return <Tag color="red">{t("threat.high")}</Tag>;
  }
  if (score >= 20) {
    return <Tag color="orange">{t("threat.medium")}</Tag>;
  }
  return <Tag color="green">{t("threat.low")}</Tag>;
}

export function getThreatClass(score: number): string {
  if (score >= 50) return "session-row--high";
  if (score >= 20) return "session-row--medium";
  return "";
}
