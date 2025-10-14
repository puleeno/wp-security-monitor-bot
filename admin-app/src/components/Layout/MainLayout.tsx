import React from 'react';
import { Layout, Menu, theme as antTheme } from 'antd';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  DashboardOutlined,
  WarningOutlined,
  SecurityScanOutlined,
  SafetyOutlined,
  SettingOutlined,
  SyncOutlined,
} from '@ant-design/icons';
import { useSelector } from 'react-redux';
import type { RootState } from '../../store';

const { Header, Sider, Content } = Layout;

interface MainLayoutProps {
  children: React.ReactNode;
}

const MainLayout: React.FC<MainLayoutProps> = ({ children }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const { token } = antTheme.useToken();

  const sidebarCollapsed = useSelector((state: RootState) => state.ui.sidebarCollapsed);

  const menuItems = [
    {
      key: '/',
      icon: <DashboardOutlined />,
      label: 'Dashboard',
    },
    {
      key: '/issues',
      icon: <WarningOutlined />,
      label: 'Issues',
    },
    {
      key: '/security',
      icon: <SecurityScanOutlined />,
      label: 'Security Status',
    },
    {
      key: '/external-redirects',
      icon: <SafetyOutlined />,
      label: 'Domains',
    },
    {
      key: '/access-control',
      icon: <SafetyOutlined />,
      label: 'Access Control',
    },
    {
      key: '/settings',
      icon: <SettingOutlined />,
      label: 'Settings',
    },
    {
      key: '/migration',
      icon: <SyncOutlined />,
      label: 'Migration',
      danger: true,
    },
  ];

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider
        collapsible
        collapsed={sidebarCollapsed}
        theme="dark"
        width={250}
      >
        <div style={{
          height: 64,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: '#fff',
          fontSize: 18,
          fontWeight: 'bold',
          borderBottom: '1px solid rgba(255,255,255,0.1)',
        }}>
          {!sidebarCollapsed && '🛡️ Security Monitor'}
          {sidebarCollapsed && '🛡️'}
        </div>

        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[location.pathname]}
          items={menuItems}
          onClick={({ key }) => navigate(key)}
        />
      </Sider>

      <Layout>
        <Header style={{
          background: token.colorBgContainer,
          padding: '0 24px',
          boxShadow: '0 1px 4px rgba(0,0,0,0.08)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}>
          <h1 style={{ margin: 0, fontSize: 20 }}>
            WP Security Monitor
          </h1>

          <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
            <span style={{ color: token.colorTextSecondary }}>
              Version 1.2.0
            </span>
          </div>
        </Header>

        <Content style={{
          margin: '24px',
          padding: '24px',
          background: token.colorBgContainer,
          borderRadius: token.borderRadiusLG,
          minHeight: 280,
        }}>
          {children}
        </Content>
      </Layout>
    </Layout>
  );
};

export default MainLayout;

