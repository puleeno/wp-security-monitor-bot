import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';

// Import translation files
import en from './locales/en.json';
import vi from './locales/vi.json';
import zh from './locales/zh.json';
import ja from './locales/ja.json';
import ko from './locales/ko.json';
import fr from './locales/fr.json';
import de from './locales/de.json';

// Detect WordPress locale
const wpLocale = (window as any).wpSecurityMonitorLocale || 'en';

// Map WordPress locales to i18next language codes
const localeMap: Record<string, string> = {
  'en_US': 'en',
  'en_GB': 'en',
  'vi': 'vi',
  'vi_VN': 'vi',
  'zh_CN': 'zh',
  'zh_TW': 'zh',
  'ja': 'ja',
  'ko_KR': 'ko',
  'fr_FR': 'fr',
  'de_DE': 'de',
};

const language = localeMap[wpLocale] || 'en';

i18n
  .use(initReactI18next)
  .init({
    resources: {
      en: { translation: en },
      vi: { translation: vi },
      zh: { translation: zh },
      ja: { translation: ja },
      ko: { translation: ko },
      fr: { translation: fr },
      de: { translation: de },
    },
    lng: language,
    fallbackLng: 'en',
    interpolation: {
      escapeValue: false, // React already escapes
    },
  });

export default i18n;

