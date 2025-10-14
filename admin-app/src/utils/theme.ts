import type { ThemeConfig } from 'antd';

// Custom Ant Design theme
export const antdTheme: ThemeConfig = {
  token: {
    // Colors
    colorPrimary: '#2271b1', // WordPress blue
    colorSuccess: '#00a32a',
    colorWarning: '#dba617',
    colorError: '#d63638',
    colorInfo: '#72aee6',

    // Typography
    fontSize: 14,
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif',

    // Border
    borderRadius: 4,

    // Layout
    padding: 16,
    margin: 16,

    // Component specific
    controlHeight: 32,
  },
  components: {
    Layout: {
      headerBg: '#ffffff',
      headerPadding: '0 24px',
      siderBg: '#001529',
    },
    Menu: {
      darkItemBg: '#001529',
      darkItemSelectedBg: '#1890ff',
    },
    Table: {
      headerBg: '#f0f0f1',
      rowHoverBg: '#f6f7f7',
    },
    Button: {
      controlHeight: 32,
      borderRadius: 4,
    },
    Card: {
      headerBg: '#f0f0f1',
      borderRadiusLG: 8,
    },
  },
};

