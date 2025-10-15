import React, { useEffect, useState } from 'react';
import { Card, Row, Col, Statistic, Table, Tag, Space, Alert, Descriptions, Typography } from 'antd';
import {
  WarningOutlined,
  CheckCircleOutlined,
  ClockCircleOutlined,
  BellOutlined,
} from '@ant-design/icons';
import { useDispatch, useSelector } from 'react-redux';
import { useTranslation } from 'react-i18next';
import type { RootState, AppDispatch } from '../store';
import { fetchStats } from '../reducers/statsReducer';
import { fetchIssues } from '../reducers/issuesReducer';
import { fetchSettings } from '../reducers/settingsReducer';
import type { Issue } from '../types';
import { getIssuerName } from '../utils/issuerNames';
import PageLoading from '../components/Loading/PageLoading';

const { Text } = Typography;

const Dashboard: React.FC = () => {
  const dispatch = useDispatch<AppDispatch>();
  const { t } = useTranslation();
  const [initialLoading, setInitialLoading] = useState(true);

  const { security, bot, loading } = useSelector((state: RootState) => state.stats);
  const { items: recentIssues } = useSelector((state: RootState) => state.issues);
  const { telegram, email, slack, log } = useSelector((state: RootState) => state.settings);

  useEffect(() => {
    dispatch(fetchStats());
    dispatch(fetchIssues({ page: 1, filters: {} }));
    dispatch(fetchSettings());
  }, [dispatch]);

  useEffect(() => {
    if (security && bot && telegram) {
      setInitialLoading(false);
    }
  }, [security, bot, telegram]);

  const getSeverityColor = (severity: string): string => {
    const colors: Record<string, string> = {
      critical: 'red',
      high: 'orange',
      medium: 'gold',
      low: 'green',
    };
    return colors[severity] || 'default';
  };

  if (initialLoading) {
    return <PageLoading message={t('common.loading')} />;
  }

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
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title={t('dashboard.totalIssues')}
              value={security?.total_issues || 0}
              prefix={<WarningOutlined />}
              valueStyle={{ color: '#d63638' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title={t('common.newIssues')}
              value={security?.new_issues || 0}
              prefix={<BellOutlined />}
              valueStyle={{ color: '#f56e28' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title={t('common.resolved')}
              value={security?.resolved_issues || 0}
              prefix={<CheckCircleOutlined />}
              valueStyle={{ color: '#00a32a' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title={t('common.monitors')}
              value={bot?.issuers_count || 0}
              prefix={<ClockCircleOutlined />}
              valueStyle={{ color: '#2271b1' }}
            />
          </Card>
        </Col>
      </Row>

      {/* Channels & Bot Info */}
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} md={12}>
          <Card title={`📡 ${t('dashboard.notificationChannels')}`}>
            <Space direction="vertical" style={{ width: '100%' }} size="middle">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Space>
                  <span style={{ fontSize: 32 }}>📱</span>
                  <div>
                    <div><Text strong>Telegram</Text></div>
                    <Text type="secondary" style={{ fontSize: 12 }}>Instant messaging</Text>
                  </div>
                </Space>
                {telegram?.enabled ? (
                  <Tag color="green" icon={<CheckCircleOutlined />}>{t('common.active')}</Tag>
                ) : (
                  <Tag color="default">{t('common.inactive')}</Tag>
                )}
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Space>
                  <span style={{ fontSize: 32 }}>📧</span>
                  <div>
                    <div><Text strong>Email</Text></div>
                    <Text type="secondary" style={{ fontSize: 12 }}>Email notifications</Text>
                  </div>
                </Space>
                {email?.enabled ? (
                  <Tag color="green" icon={<CheckCircleOutlined />}>{t('common.active')}</Tag>
                ) : (
                  <Tag color="default">{t('common.inactive')}</Tag>
                )}
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Space>
                  <span style={{ fontSize: 32 }}>💬</span>
                  <div>
                    <div><Text strong>Slack</Text></div>
                    <Text type="secondary" style={{ fontSize: 12 }}>Team collaboration</Text>
                  </div>
                </Space>
                {slack?.enabled ? (
                  <Tag color="green" icon={<CheckCircleOutlined />}>{t('common.active')}</Tag>
                ) : (
                  <Tag color="default">{t('common.inactive')}</Tag>
                )}
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Space>
                  <span style={{ fontSize: 32 }}>📝</span>
                  <div>
                    <div><Text strong>Log</Text></div>
                    <Text type="secondary" style={{ fontSize: 12 }}>File logging</Text>
                  </div>
                </Space>
                {log?.enabled ? (
                  <Tag color="green" icon={<CheckCircleOutlined />}>{t('common.active')}</Tag>
                ) : (
                  <Tag color="default">{t('common.inactive')}</Tag>
                )}
              </div>

              <div style={{
                marginTop: 16,
                padding: '12px',
                background: '#f0f6fc',
                borderRadius: '4px',
                textAlign: 'center'
              }}>
                <Text strong style={{ fontSize: 18 }}>
                  {bot?.channels_count || 0}
                </Text>
                <Text type="secondary" style={{ marginLeft: 8 }}>
                  / 4 channels active
                </Text>
              </div>
            </Space>
          </Card>
        </Col>

        <Col xs={24} md={12}>
          <Card title={`⏰ ${t('dashboard.botSchedule')}`}>
            <Space direction="vertical" style={{ width: '100%' }} size="middle">
              <Descriptions column={1} size="small" bordered>
                <Descriptions.Item label={t('dashboard.lastCheck')}>
                  {bot?.last_check ? (
                    <Text>{new Date(bot.last_check * 1000).toLocaleString()}</Text>
                  ) : (
                    <Text type="secondary">{t('common.noData')}</Text>
                  )}
                </Descriptions.Item>
                <Descriptions.Item label={t('dashboard.nextCheck')}>
                  {bot?.next_scheduled_check ? (
                    <Text>{new Date(bot.next_scheduled_check * 1000).toLocaleString()}</Text>
                  ) : (
                    <Text type="secondary">{t('common.noData')}</Text>
                  )}
                </Descriptions.Item>
                <Descriptions.Item label={t('dashboard.totalFound')}>
                  <Tag color="blue">{bot?.total_issues_found || 0} {t('issues.title').toLowerCase()}</Tag>
                </Descriptions.Item>
              </Descriptions>
            </Space>
          </Card>
        </Col>
      </Row>

      {/* Bot Status */}
      {bot && (
        <Alert
          message={bot.is_running ? `✅ ${t('dashboard.monitorStatus')}: ${t('dashboard.running')}` : `⚠️ ${t('dashboard.monitorStatus')}: ${t('dashboard.stopped')}`}
          type={bot.is_running ? 'success' : 'warning'}
          showIcon
          style={{ marginBottom: 24 }}
        />
      )}

      {/* Recent Issues */}
      <Card title={`⚠️ ${t('dashboard.recentIssues')}`} loading={loading}>
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

