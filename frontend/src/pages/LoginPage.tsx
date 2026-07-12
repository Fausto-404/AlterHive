import { Button, Card, Form, Input, Typography, message } from "antd";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";

import { useAuth } from "../auth/AuthProvider";
import { toErrorMessage } from "../services/platform";
import alterHiveBackground from "../assets/alterhive-background.png";
import alterHiveLogo from "../assets/alterhive-logo.svg";

export function LoginPage() {
  const { user, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [form] = Form.useForm();
  const { t } = useTranslation("evidence");

  if (user) {
    return <Navigate to="/dashboard" replace />;
  }

  async function onFinish(values: { username: string; password: string }) {
    try {
      await login(values.username, values.password);
      const state = location.state as { from?: string } | null;
      message.success(t("login.success"));
      navigate(state?.from || "/dashboard", { replace: true });
    } catch (error) {
      message.error(toErrorMessage(error, t("login.failed")));
    }
  }

  return (
    <div className="login-shell" style={{ backgroundImage: `linear-gradient(rgba(5, 11, 20, 0.52), rgba(5, 11, 20, 0.82)), url(${alterHiveBackground})` }}>
      <Card className="login-card">
        <div className="login-brand login-brand-simple">
          <img src={alterHiveLogo} alt="幻巢 AlterHive" className="login-logo" />
          <Typography.Paragraph>{t("login.subtitle")}</Typography.Paragraph>
        </div>

        <Form form={form} layout="vertical" onFinish={onFinish} initialValues={{ username: "admin" }}>
          <Form.Item label={t("login.username")} name="username" rules={[{ required: true, message: t("login.usernameRequired") }]}>
            <Input autoComplete="username" />
          </Form.Item>
          <Form.Item label={t("login.password")} name="password" rules={[{ required: true, message: t("login.passwordRequired") }]}>
            <Input.Password autoComplete="current-password" />
          </Form.Item>
          <Button type="primary" htmlType="submit" block size="large">
            {t("login.submit")}
          </Button>
        </Form>

        <div className="login-powered">
          <a href="https://github.com/Fausto-404/AlterHive" target="_blank" rel="noreferrer">
            Powered by Fausto
          </a>
        </div>
      </Card>
    </div>
  );
}
