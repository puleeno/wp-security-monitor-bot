import React from 'react';
import { HashRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from 'antd';
import MainLayout from './components/Layout/MainLayout';
import Dashboard from './pages/Dashboard';
import Issues from './pages/Issues';
import Settings from './pages/Settings';
import Security from './pages/Security';
import AccessControl from './pages/AccessControl';
import Migration from './pages/Migration';

const App: React.FC = () => {
  return (
    <HashRouter>
      <Layout style={{ minHeight: '100vh' }}>
        <MainLayout>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/issues" element={<Issues />} />
            <Route path="/security" element={<Security />} />
            <Route path="/access-control" element={<AccessControl />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/migration" element={<Migration />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </MainLayout>
      </Layout>
    </HashRouter>
  );
};

export default App;

