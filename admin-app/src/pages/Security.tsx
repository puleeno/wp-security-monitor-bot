import React, { useEffect, useState } from 'react';
import {
  Card, Row, Col, Typography, Alert, Progress, Tag, Space,
  Descriptions, Statistic, Timeline, Button
} from 'antd';
import {
  CheckCircleOutlined,
  CloseCircleOutlined,
  WarningOutlined,
  SyncOutlined,
  SafetyOutlined,
  EyeOutlined,
} from '@ant-design/icons';
import { useDispatch, useSelector } from 'react-redux';
import { useTranslation } from 'react-i18next';
import type { RootState, AppDispatch } from '../store';
import { fetchStats } from '../reducers/statsReducer';
import { fetchIssues } from '../reducers/issuesReducer';
import PageLoading from '../components/Loading/PageLoading';
import { getIssuerName } from '../utils/issuerNames';

const { Title, Text } = Typography;

const Security: React.FC = () => {
  const dispatch = useDispatch<AppDispatch>();
  const { t } = useTranslation();
  const [initialLoading, setInitialLoading] = useState(true);

  const { security, bot } = useSelector((state: RootState) => state.stats);
  const { items } = useSelector((state: RootState) => state.issues);

  useEffect(() => {
    dispatch(fetchStats());
    dispatch(fetchIssues({ page: 1, filters: {} }));
  }, [dispatch]);

  useEffect(() => {
    if (security && bot) {
      setInitialLoading(false);
    }
  }, [security, bot]);

  if (initialLoading) {
    return <PageLoading message={t('common.loading')} />;
  }

  // Calculate security score (0-100)
  const calculateSecurityScore = (): number => {
    if (!security) return 0;

    const totalIssues = parseInt(security.total_issues.toString()) || 0;
    const criticalCount = parseInt((security.by_severity?.critical || 0).toString());
    const highCount = parseInt((security.by_severity?.high || 0).toString());

    // Base score
    let score = 100;

    // Deduct points
    score -= criticalCount * 15; // Critical: -15 points each
    score -= highCount * 10;     // High: -10 points each
    score -= totalIssues * 2;    // All issues: -2 points each

    return Math.max(0, Math.min(100, score));
  };

  const securityScore = calculateSecurityScore();

  const getScoreStatus = (score: number): {
    status: 'success' | 'exception' | 'normal' | 'active';
    color: string;
    text: string;
  } => {
    if (score >= 80) return { status: 'success', color: 'green', text: 'Tốt' };
    if (score >= 60) return { status: 'active', color: 'blue', text: 'Khá' };
    if (score >= 40) return { status: 'normal', color: 'orange', text: 'Trung bình' };
    return { status: 'exception', color: 'red', text: 'Cần cải thiện' };
  };

  const scoreStatus = getScoreStatus(securityScore);

  // Recent critical/high issues
  const criticalIssues = items.filter(i =>
    i.severity === 'critical' || i.severity === 'high'
  ).slice(0, 5);

  return (
    <div>
      <Title level={2}>🔒 Security Status</Title>

      {/* Security Score Card */}
      <Card style={{ marginBottom: 24 }}>
        <Row gutter={24} align="middle">
          <Col xs={24} md={8} style={{ textAlign: 'center' }}>
            <Progress
              type="circle"
              percent={securityScore}
              status={scoreStatus.status}
              strokeColor={scoreStatus.color}
              width={180}
              format={(percent) => (
                <div>
                  <div style={{ fontSize: 48, fontWeight: 'bold' }}>{percent}</div>
                  <div style={{ fontSize: 16 }}>{scoreStatus.text}</div>
                </div>
              )}
            />
            <div style={{ marginTop: 16 }}>
              <Title level={4}>Security Score</Title>
              <Text type="secondary">Điểm đánh giá tổng thể</Text>
            </div>
          </Col>

          <Col xs={24} md={16}>
            <Space direction="vertical" size="large" style={{ width: '100%' }}>
              <div>
                <Title level={5}>📊 Tổng quan Issues</Title>
                <Row gutter={16}>
                  <Col span={6}>
                    <Statistic
                      title="Tổng Issues"
                      value={security?.total_issues || 0}
                      prefix={<WarningOutlined />}
                      valueStyle={{ fontSize: 24 }}
                    />
                  </Col>
                  <Col span={6}>
                    <Statistic
                      title="Critical"
                      value={security?.by_severity?.critical || 0}
                      valueStyle={{ color: '#d63638', fontSize: 24 }}
                    />
                  </Col>
                  <Col span={6}>
                    <Statistic
                      title="High"
                      value={security?.by_severity?.high || 0}
                      valueStyle={{ color: '#f56e28', fontSize: 24 }}
                    />
                  </Col>
                  <Col span={6}>
                    <Statistic
                      title="Resolved"
                      value={security?.resolved_issues || 0}
                      valueStyle={{ color: '#00a32a', fontSize: 24 }}
                    />
                  </Col>
                </Row>
              </div>

              {securityScore < 60 && (
                <Alert
                  message="⚠️ Cảnh báo bảo mật"
                  description="Website có nhiều vấn đề bảo mật cần xử lý ngay. Vui lòng kiểm tra Issues page."
                  type="warning"
                  showIcon
                />
              )}

              {securityScore >= 80 && (
                <Alert
                  message="✅ Trạng thái tốt"
                  description="Website đang ở trạng thái bảo mật tốt. Tiếp tục giám sát!"
                  type="success"
                  showIcon
                />
              )}
            </Space>
          </Col>
        </Row>
      </Card>

      {/* Bot Status */}
      <Row gutter={16} style={{ marginBottom: 24 }}>
        <Col xs={24} md={12}>
          <Card title="🤖 Bot Status" extra={
            bot?.is_running ? (
              <Tag icon={<CheckCircleOutlined />} color="success">Running</Tag>
            ) : (
              <Tag icon={<CloseCircleOutlined />} color="error">Stopped</Tag>
            )
          }>
            <Descriptions column={1} size="small">
              <Descriptions.Item label="Status">
                {bot?.is_running ? (
                  <Text type="success">✅ Đang hoạt động</Text>
                ) : (
                  <Text type="danger">❌ Đã dừng</Text>
                )}
              </Descriptions.Item>
              <Descriptions.Item label="Active Monitors">
                {bot?.issuers_count || 0} monitors
              </Descriptions.Item>
              <Descriptions.Item label="Channels">
                {bot?.channels_count || 0} notification channels
              </Descriptions.Item>
              <Descriptions.Item label="Last Check">
                {bot?.last_check ? new Date(bot.last_check * 1000).toLocaleString('vi-VN') : 'Chưa có'}
              </Descriptions.Item>
              <Descriptions.Item label="Next Check">
                {bot?.next_scheduled_check ?
                  new Date(bot.next_scheduled_check * 1000).toLocaleString('vi-VN') :
                  'Chưa lên lịch'
                }
              </Descriptions.Item>
            </Descriptions>
          </Card>
        </Col>

        <Col xs={24} md={12}>
          <Card title="📈 Activity (7 ngày)" extra={
            <Button size="small" icon={<SyncOutlined />} type="link">
              Refresh
            </Button>
          }>
            <Space direction="vertical" size="middle" style={{ width: '100%' }}>
              <div>
                <Text type="secondary">Issues phát hiện 24h qua:</Text>
                <div style={{ fontSize: 32, fontWeight: 'bold', color: '#2271b1' }}>
                  {security?.issues_last_24h || 0}
                </div>
              </div>
              <div>
                <Text type="secondary">Issues phát hiện 7 ngày qua:</Text>
                <div style={{ fontSize: 32, fontWeight: 'bold', color: '#2271b1' }}>
                  {security?.issues_last_7d || 0}
                </div>
              </div>
              <div>
                <Text type="secondary">Ignore rules active:</Text>
                <div style={{ fontSize: 24, fontWeight: 'bold' }}>
                  {security?.active_ignore_rules || 0} / {security?.total_ignore_rules || 0}
                </div>
              </div>
            </Space>
          </Card>
        </Col>
      </Row>

      {/* Critical Issues Alert */}
      {criticalIssues.length > 0 && (
        <Card
          title="🚨 Issues Cần Chú Ý"
          style={{ marginBottom: 24 }}
          extra={<Tag color="red">{criticalIssues.length} issues</Tag>}
        >
          <Timeline>
            {criticalIssues.map((issue) => (
              <Timeline.Item
                key={issue.id}
                color={issue.severity === 'critical' ? 'red' : 'orange'}
                dot={issue.severity === 'critical' ? <WarningOutlined /> : <EyeOutlined />}
              >
                <Space direction="vertical" size={0}>
                  <Text strong>{issue.title}</Text>
                  <Space size="small">
                    <Tag color={issue.severity === 'critical' ? 'red' : 'orange'}>
                      {issue.severity.toUpperCase()}
                    </Tag>
                    <Text type="secondary" style={{ fontSize: 12 }}>
                      {getIssuerName(issue.issuer_name)}
                    </Text>
                    <Text type="secondary" style={{ fontSize: 12 }}>
                      {new Date(issue.last_detected).toLocaleString('vi-VN')}
                    </Text>
                  </Space>
                  {issue.ip_address && (
                    <Text type="secondary" style={{ fontSize: 12 }}>
                      🌐 {issue.ip_address}
                    </Text>
                  )}
                </Space>
              </Timeline.Item>
            ))}
          </Timeline>
        </Card>
      )}

      {/* Top Threats */}
      <Row gutter={16}>
        <Col xs={24} md={12}>
          <Card title="🎯 Top Threats" extra={<SafetyOutlined />}>
            <Space direction="vertical" style={{ width: '100%' }}>
              {security?.by_issuer && Object.entries(security.by_issuer)
                .sort((a, b) => (b[1] as number) - (a[1] as number))
                .slice(0, 5)
                .map(([issuer, count], index) => (
                  <div key={issuer} style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '8px 0',
                    borderBottom: index < 4 ? '1px solid #f0f0f0' : 'none'
                  }}>
                    <Space>
                      <Tag color="blue">{index + 1}</Tag>
                      <Text>{getIssuerName(issuer)}</Text>
                    </Space>
                    <Tag color="red" style={{ fontWeight: 'bold' }}>
                      {count} issues
                    </Tag>
                  </div>
                ))}
            </Space>
          </Card>
        </Col>

        <Col xs={24} md={12}>
          <Card title="📊 Severity Distribution">
            <Space direction="vertical" style={{ width: '100%' }} size="large">
              {security?.by_severity && Object.entries(security.by_severity).map(([severity, count]) => {
                const total = parseInt(security.total_issues.toString()) || 1;
                const percentage = ((count as number) / total) * 100;

                const colors: Record<string, string> = {
                  critical: '#d63638',
                  high: '#f56e28',
                  medium: '#dba617',
                  low: '#00a32a',
                };

                return (
                  <div key={severity}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                      <Text strong>{severity.toUpperCase()}</Text>
                      <Text>{count} ({percentage.toFixed(1)}%)</Text>
                    </div>
                    <Progress
                      percent={percentage}
                      strokeColor={colors[severity]}
                      showInfo={false}
                    />
                  </div>
                );
              })}
            </Space>
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default Security;
