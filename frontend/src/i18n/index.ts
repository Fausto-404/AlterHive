import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import LanguageDetector from "i18next-browser-languagedetector";

import commonZh from "./zh-CN/common.json";
import dashboardZh from "./zh-CN/dashboard.json";
import sessionsZh from "./zh-CN/sessions.json";
import topologyZh from "./zh-CN/topology.json";
import statusZh from "./zh-CN/status.json";
import evidenceZh from "./zh-CN/evidence.json";

import commonEn from "./en/common.json";
import dashboardEn from "./en/dashboard.json";
import sessionsEn from "./en/sessions.json";
import topologyEn from "./en/topology.json";
import statusEn from "./en/status.json";
import evidenceEn from "./en/evidence.json";

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      "zh-CN": {
        common: commonZh,
        dashboard: dashboardZh,
        sessions: sessionsZh,
        topology: topologyZh,
        status: statusZh,
        evidence: evidenceZh,
      },
      en: {
        common: commonEn,
        dashboard: dashboardEn,
        sessions: sessionsEn,
        topology: topologyEn,
        status: statusEn,
        evidence: evidenceEn,
      },
    },
    supportedLngs: ["zh-CN", "en"],
    fallbackLng: "zh-CN",
    detection: {
      order: ["localStorage"],
      caches: ["localStorage"],
      lookupLocalStorage: "alterhive-lang",
    },
    interpolation: {
      escapeValue: false,
    },
    defaultNS: "common",
  });

export default i18n;
