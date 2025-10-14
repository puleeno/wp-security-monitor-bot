import React, { useEffect } from 'react';
import { Card, Row, Col, Statistic, Table, Tag, Space, Alert } from 'antd';
import {
  WarningOutlined,
  CheckCircleOutlined,
  ClockCircleOutlined,
  BellOutlined,
} from '@ant-design/icons';
import { useDispatch, useSelector } from 'react-redux';
import type { RootState, AppDispatch } from '../store';
import { fetchStats } from '../reducers/statsReducer';
import { fetchIssues } from '../reducers/issuesReducer';
import type { Issue } from '../types';
import { getIssuerName } from '../utils/issuerNames';

const Dashboard: React.FC = () => {
  const dispatch = useDispatch<AppDispatch>();

  const { security, bot, loading } = useSelector((state: RootState) => state.stats);
  const { items: recentIssues } = useSelector((state: RootState) => state.issues);

  useEffect(() => {
    dispatch(fetchStats());
    dispatch(fetchIssues({ page: 1, filters: {} }));
  }, [dispatch]);

  const getSeverityColor = (severity: string): string => {
    const colors: Record<string, string> = {
      critical: 'red',
      high: 'orange',
      medium: 'gold',
      low: 'green',
    };
    return colors[severity] || 'default';
  };

  const columns = [
    {
      title: 'Severity',
      dataIndex: 'severity',
      key: 'severity',
      width: 100,
      render: (severity: string) => (
        <Tag color={getSeverityColor(severity)}>{severity.toUpperCase()}</Tag>
      ),
    },
    {
      title: 'Issue',
      dataIndex: 'title',
      key: 'title',
      render: (title: string, record: Issue) => (
        <Space direction="vertical" size={0}>
          <strong>{title}</strong>
          {record.ip_address && <span style={{ fontSize: 12, color: '#666' }}>🌐 {record.ip_address}</span>}
        </Space>
      ),
    },
    {
      title: 'Issuer',
      dataIndex: 'issuer_name',
      key: 'issuer_name',
      width: 200,
      render: (issuerName: string) => getIssuerName(issuerName),
    },
    {
      title: 'Last Detected',
      dataIndex: 'last_detected',
      key: 'last_detected',
      width: 160,
      render: (date: string) => new Date(date).toLocaleString('vi-VN'),
    },
  ];

  return (
    <div>
      <h1 style={{ marginBottom: 24 }}>🛡️ Security Dashboard</h1>

      {/* Quick Stats */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="Tổng Issues"
              value={security?.total_issues || 0}
              prefix={<WarningOutlined />}
              valueStyle={{ color: '#d63638' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="Issues Mới"
              value={security?.new_issues || 0}
              prefix={<BellOutlined />}
              valueStyle={{ color: '#f56e28' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="Đã Resolved"
              value={security?.resolved_issues || 0}
              prefix={<CheckCircleOutlined />}
              valueStyle={{ color: '#00a32a' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="Monitors"
              value={bot?.issuers_count || 0}
              prefix={<ClockCircleOutlined />}
              valueStyle={{ color: '#2271b1' }}
            />
          </Card>
        </Col>
      </Row>

      {/* Bot Status */}
      {bot && (
        <Alert
          message={bot.is_running ? '✅ Security Monitor đang hoạt động' : '⚠️ Security Monitor đã dừng'}
          type={bot.is_running ? 'success' : 'warning'}
          showIcon
          style={{ marginBottom: 24 }}
        />
      )}

      {/* Recent Issues */}
      <Card title="⚠️ Issues Gần đây" loading={loading}>
        <Table
          columns={columns}
          dataSource={Array.isArray(recentIssues) ? recentIssues.slice(0, 5) : []}
          rowKey="id"
          pagination={false}
          size="middle"
          locale={{ emptyText: 'Chưa có issues nào' }}
        />
      </Card>

      {/* Severity Breakdown */}
      <Row gutter={[16, 16]}>
        <Col xs={24} md={12}>
          <Card title="📊 Phân loại theo Severity">
            <Space direction="vertical" style={{ width: '100%' }}>
              {security?.by_severity && typeof security.by_severity === 'object' &&
                Object.entries(security.by_severity).map(([severity, count]) => (
                  <div key={severity} style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <Tag color={getSeverityColor(severity)}>{severity.toUpperCase()}</Tag>
                    <span style={{ fontWeight: 'bold' }}>{count}</span>
                  </div>
                ))}
              {(!security?.by_severity || Object.keys(security.by_severity).length === 0) && (
                <div style={{ textAlign: 'center', color: '#999' }}>Chưa có dữ liệu</div>
              )}
            </Space>
          </Card>
        </Col>

        <Col xs={24} md={12}>
          <Card title="🔍 Top Issuers">
            <Space direction="vertical" style={{ width: '100%' }}>
              {security?.by_issuer && typeof security.by_issuer === 'object' &&
                Object.entries(security.by_issuer)
                  .slice(0, 5)
                  .map(([issuer, count]) => (
                    <div key={issuer} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '14px' }}>{getIssuerName(issuer)}</span>
                      <Tag color="blue" style={{ fontWeight: 'bold', minWidth: '40px', textAlign: 'center' }}>
                        {count}
                      </Tag>
                    </div>
                  ))}
              {(!security?.by_issuer || Object.keys(security.by_issuer).length === 0) && (
                <div style={{ textAlign: 'center', color: '#999' }}>Chưa có dữ liệu</div>
              )}
            </Space>
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default Dashboard;

