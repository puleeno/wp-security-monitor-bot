import React from 'react';
import ReactDOM from 'react-dom/client';
import { Provider } from 'react-redux';
import { ConfigProvider } from 'antd';
import viVN from 'antd/locale/vi_VN';
import { store } from './store';
import App from './App';
import { antdTheme } from './utils/theme';
import './styles/global.css';
import './i18n'; // Initialize i18next

// Strict mode enabled
ReactDOM.createRoot(document.getElementById('wp-security-monitor-root')!).render(
  <React.StrictMode>
    <Provider store={store}>
      <ConfigProvider locale={viVN} theme={antdTheme}>
        <App />
      </ConfigProvider>
    </Provider>
  </React.StrictMode>
);

