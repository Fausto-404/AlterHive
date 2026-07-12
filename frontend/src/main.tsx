import React, { useEffect, useState } from "react";
import ReactDOM from "react-dom/client";
import { ConfigProvider } from "antd";
import zhCN from "antd/locale/zh_CN";
import enUS from "antd/locale/en_US";
import { BrowserRouter } from "react-router-dom";

import App from "./App";
import "./styles.css";
import "./i18n";
import i18n from "./i18n";

const antdLocales: Record<string, typeof zhCN> = {
  "zh-CN": zhCN,
  en: enUS,
};

function Root() {
  const [antdLocale, setAntdLocale] = useState(
    () => antdLocales[i18n.language] || zhCN
  );

  useEffect(() => {
    const handler = (lng: string) => {
      setAntdLocale(antdLocales[lng] || zhCN);
    };
    i18n.on("languageChanged", handler);
    return () => {
      i18n.off("languageChanged", handler);
    };
  }, []);

  return (
    <ConfigProvider
      locale={antdLocale}
      theme={{
        token: {
          colorPrimary: "#1f7a8c",
          colorInfo: "#1f7a8c",
          borderRadius: 10,
          fontFamily:
            '"IBM Plex Sans", "PingFang SC", "Microsoft YaHei", sans-serif'
        }
      }}
    >
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </ConfigProvider>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>
);
