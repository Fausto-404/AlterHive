import { Tag } from "antd";
import { useTranslation } from "react-i18next";
import type { SessionDetail } from "../types/platform";

interface Props {
  session: SessionDetail;
}

export function HostPosition({ session }: Props) {
  const { t } = useTranslation("common");
  const sshStack = session.ssh_stack || [];
  const currentHost = session.hostname;
  const currentUser = session.user || session.username;
  const currentCWD = session.cwd || "~";
  const currentIP = sshStack.length > 0
    ? sshStack[sshStack.length - 1]?.SubnetLocalIP || ""
    : session.current_host_ip || "";
  const shellMode = session.shell_mode || "bash";

  const journey: { hostname: string; ip: string; user: string }[] = [];

  if (sshStack.length > 0) {
    journey.push({
      hostname: sshStack[0]?.Hostname || session.hostname,
      ip: sshStack[0]?.SubnetLocalIP || "",
      user: sshStack[0]?.User || session.username,
    });
    for (let i = 1; i < sshStack.length; i++) {
      journey.push({
        hostname: sshStack[i]?.Hostname || "",
        ip: sshStack[i]?.SubnetLocalIP || "",
        user: sshStack[i]?.User || "",
      });
    }
  }

  return (
    <div className="host-position">
      <div className="host-position__card">
        <div className="host-position__header">
          <span className="host-position__label">{t("shell.currentPosition")}</span>
          {sshStack.length > 0 && (
            <Tag color="orange" style={{ marginLeft: 8 }}>
              {t("shell.hopCount", { count: sshStack.length })}
            </Tag>
          )}
        </div>
        <div className="host-position__main">
          <div className="host-badge">
            <span className="host-badge__icon">~</span>
            <div className="host-badge__info">
              <strong>{currentHost}</strong>
              <small>{session.current_target || currentIP}</small>
            </div>
          </div>
          <div className="host-position__prompt">
            <code>
              {currentUser}@{currentHost}:{currentCWD}$
            </code>
            <span className="host-position__shell">
              {t("shell.shell")}{shellMode}
            </span>
          </div>
        </div>
      </div>

      {journey.length > 0 && (
        <div className="host-journey">
          <div className="host-journey__label">{t("shell.sshPath")}</div>
          <div className="host-journey__timeline">
            {journey.map((hop, i) => (
              <div className="host-journey__step" key={i}>
                <div className="host-journey__node">
                  <span className="host-journey__dot" />
                  <div className="host-journey__info">
                    <strong>{hop.hostname}</strong>
                    <small>{hop.ip}</small>
                    <small>{hop.user}@{hop.hostname}</small>
                  </div>
                </div>
                <div className="host-journey__arrow">
                  <span>SSH</span>
                  <span className="host-journey__arrow-line">&rarr;</span>
                </div>
              </div>
            ))}
            <div className="host-journey__step host-journey__step--current">
              <div className="host-journey__node">
                <span className="host-journey__dot host-journey__dot--active" />
                <div className="host-journey__info">
                  <strong>{currentHost}</strong>
                  <small>{session.current_target || currentIP}</small>
                  <small>{currentUser}@{currentHost}</small>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
