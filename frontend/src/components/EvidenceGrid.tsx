import { ALL_TOKENS, getTokenDef, CATEGORY_COLORS, type EvidenceCategory } from "../utils/evidence";
import { Tooltip } from "antd";

interface EvidenceGridProps {
  hitTokens: string[];
}

export function EvidenceGrid({ hitTokens }: EvidenceGridProps) {
  const hitSet = new Set(hitTokens);

  return (
    <div className="evidence-grid">
      {ALL_TOKENS.map((token) => {
        const def = getTokenDef(token);
        const isHit = hitSet.has(token);
        return (
          <Tooltip key={token} title={def.description}>
            <span
              className={`evidence-token evidence-token--${def.category} ${isHit ? "evidence-token--hit" : "evidence-token--miss"}`}
            >
              <span style={{ width: 6, height: 6, borderRadius: "50%", background: CATEGORY_COLORS[def.category as EvidenceCategory], flexShrink: 0 }} />
              {def.label}
            </span>
          </Tooltip>
        );
      })}
    </div>
  );
}
