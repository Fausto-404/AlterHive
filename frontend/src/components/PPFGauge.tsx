import { useTranslation } from "react-i18next";

interface PPFGaugeProps {
  loopMetrics: {
    evidence_hit_count: number;
    credential_reuse_attempt: number;
    protocol_switch_count: number;
    real_network_touch_count: number;
  };
  ppfTriggered: boolean;
}

export function PPFGauge({ loopMetrics, ppfTriggered }: PPFGaugeProps) {
  const { t } = useTranslation("common");

  const PPF_CONDITIONS: { key: keyof PPFGaugeProps["loopMetrics"]; label: string; threshold: number; inverted?: boolean }[] = [
    { key: "evidence_hit_count", label: t("ppf.evidenceDiscovery", "证据发现"), threshold: 3 },
    { key: "credential_reuse_attempt", label: t("ppf.credentialReuse", "凭据复用"), threshold: 1 },
    { key: "protocol_switch_count", label: t("ppf.protocolSwitch", "协议切换"), threshold: 2 },
    { key: "real_network_touch_count", label: t("ppf.networkIsolation", "网络隔离"), threshold: 0, inverted: true },
  ];

  return (
    <div className="ppf-gauge">
      {PPF_CONDITIONS.map((cond, i) => {
        const current = loopMetrics[cond.key as keyof typeof loopMetrics];
        const met = cond.inverted ? current === 0 : current >= cond.threshold;
        return (
          <span key={cond.key}>
            <span className={`ppf-step ${met ? "ppf-step--met" : ""}`}>
              {cond.label}: {current}/{cond.threshold} {met ? "\u2713" : ""}
            </span>
            {i < PPF_CONDITIONS.length - 1 && <span className="ppf-arrow">&rarr;</span>}
          </span>
        );
      })}
      <span className="ppf-arrow">&rarr;</span>
      {ppfTriggered ? (
        <span className="ppf-active-badge">{t("ppf.active")}</span>
      ) : (
        <span className="ppf-inactive-badge">{t("ppf.waiting")}</span>
      )}
    </div>
  );
}
