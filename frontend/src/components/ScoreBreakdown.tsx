import { useTranslation } from "react-i18next";

interface ScoreBreakdownProps {
  loopMetrics: {
    evidence_hit_count: number;
    credential_reuse_attempt: number;
    protocol_switch_count: number;
    real_network_touch_count: number;
  };
}

export function ScoreBreakdown({ loopMetrics }: ScoreBreakdownProps) {
  const { t } = useTranslation("common");
  const { evidence_hit_count, credential_reuse_attempt, protocol_switch_count, real_network_touch_count } = loopMetrics;

  const segments = [
    { label: t("shell.evidence") || "证据", value: evidence_hit_count * 10, cls: "evidence" },
    { label: t("shell.credential") || "凭据", value: credential_reuse_attempt * 25, cls: "credential" },
    { label: t("shell.protocol") || "协议", value: protocol_switch_count * 15, cls: "protocol" },
  ];

  const penalty = real_network_touch_count * 50;
  const total = evidence_hit_count * 10 + credential_reuse_attempt * 25 + protocol_switch_count * 15 - penalty;
  const maxVal = Math.max(total, 1);

  return (
    <div>
      <div className="score-bar">
        {segments.map((seg) => {
          if (seg.value <= 0) return null;
          const width = Math.max((seg.value / maxVal) * 100, 5);
          return (
            <div
              key={seg.cls}
              className={`score-bar__segment score-bar__segment--${seg.cls}`}
              style={{ width: `${width}%` }}
              title={`${seg.label}: ${seg.value}`}
            >
              {seg.value}
            </div>
          );
        })}
        {penalty > 0 && (
          <div
            className="score-bar__segment score-bar__segment--penalty"
            style={{ width: `${Math.max((penalty / maxVal) * 100, 5)}%` }}
            title={`${t("shell.networkPenalty") || "网络触碰惩罚"}: -${penalty}`}
          >
            -{penalty}
          </div>
        )}
      </div>
      <div className="score-formula">
        Score = {evidence_hit_count}*10 + {credential_reuse_attempt}*25 + {protocol_switch_count}*15 - {real_network_touch_count}*50 = <strong>{total}</strong>
      </div>
    </div>
  );
}
