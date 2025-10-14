import React, { useEffect, useState } from 'react';
import {
  Card, Typography, Alert, Button, Space, Descriptions,
  Timeline, Tag, Divider, Steps
} from 'antd';
import {
  CheckCircleOutlined,
  SyncOutlined,
  WarningOutlined,
  DatabaseOutlined,
  RocketOutlined,
  SafetyOutlined,
} from '@ant-design/icons';
import { ajax } from 'rxjs/ajax';
import { buildUrl, getApiHeaders } from '../services/api';
import PageLoading from '../components/Loading/PageLoading';
import { addNotification } from '../reducers/uiReducer';
import { useDispatch } from 'react-redux';

const { Title, Text } = Typography;

interface MigrationStatus {
  current_version: string;
  latest_version: string;
  needs_migration: boolean;
  last_updated: string | null;
}

const Migration: React.FC = () => {
  const dispatch = useDispatch();
  const [loading, setLoading] = useState(true);
  const [migrating, setMigrating] = useState(false);
  const [status, setStatus] = useState<MigrationStatus | null>(null);

  useEffect(() => {
    loadMigrationStatus();
  }, []);

  const loadMigrationStatus = async () => {
    try {
      const response = await ajax({
        url: buildUrl('wp-security-monitor/v1/migration/status'),
        method: 'GET',
        headers: getApiHeaders(),
      }).toPromise();

      setStatus(response?.response as MigrationStatus);
    } catch (error) {
      console.error('Failed to load migration status:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleMigrate = async () => {
    if (!window.confirm('⚠️ Bạn có chắc muốn chạy database migration?\n\nLưu ý: Nên backup database trước khi migration.')) {
      return;
    }

    try {
      setMigrating(true);

      const response = await ajax({
        url: buildUrl('wp-security-monitor/v1/migration/run'),
        method: 'POST',
        headers: getApiHeaders(),
      }).toPromise();

      const data = response?.response as any;

      if (data?.success) {
        dispatch(addNotification({
          type: 'success',
          message: '✅ Migration thành công! Database đã được cập nhật.',
        }));

        // Reload status
        await loadMigrationStatus();
      } else {
        dispatch(addNotification({
          type: 'error',
          message: `❌ Migration thất bại: ${data?.message || 'Unknown error'}`,
        }));
      }
    } catch (error: any) {
      dispatch(addNotification({
        type: 'error',
        message: `❌ Lỗi migration: ${error.message}`,
      }));
    } finally {
      setMigrating(false);
    }
  };

  if (loading) {
    return <PageLoading message="Đang kiểm tra migration status..." />;
  }

  const needsMigration = status?.needs_migration || false;
  const currentVersion = status?.current_version || '0';
  const latestVersion = status?.latest_version || '1.2';

  return (
    <div>
      <Title level={2}>🔄 Database Migration</Title>

      {/* Migration Status Card */}
      <Card style={{ marginBottom: 24 }}>
        <Space direction="vertical" style={{ width: '100%' }} size="large">
          <div style={{ textAlign: 'center' }}>
            {needsMigration ? (
              <Alert
                message="⚠️ Cần Migration Database"
                description="Database schema cần được cập nhật lên phiên bản mới. Vui lòng chạy migration để sử dụng các tính năng mới."
                type="warning"
                showIcon
                icon={<WarningOutlined style={{ fontSize: 24 }} />}
              />
            ) : (
              <Alert
                message="✅ Database đã cập nhật"
                description="Database schema đang ở phiên bản mới nhất. Không cần migration."
                type="success"
                showIcon
                icon={<CheckCircleOutlined style={{ fontSize: 24 }} />}
              />
            )}
          </div>

          <Descriptions bordered column={2}>
            <Descriptions.Item label="Current Version">
              <Tag color={needsMigration ? 'orange' : 'green'} style={{ fontSize: 14 }}>
                {currentVersion}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Latest Version">
              <Tag color="blue" style={{ fontSize: 14 }}>
                {latestVersion}
              </Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Status" span={2}>
              {needsMigration ? (
                <Tag icon={<SyncOutlined spin />} color="warning">
                  Cần cập nhật
                </Tag>
              ) : (
                <Tag icon={<CheckCircleOutlined />} color="success">
                  Up to date
                </Tag>
              )}
            </Descriptions.Item>
            {status?.last_updated && (
              <Descriptions.Item label="Last Updated" span={2}>
                {new Date(status.last_updated).toLocaleString('vi-VN')}
              </Descriptions.Item>
            )}
          </Descriptions>

          {needsMigration && (
            <>
              <Divider />

              <Alert
                message="⚠️ Lưu ý quan trọng"
                description={
                  <ul style={{ marginLeft: 20, marginBottom: 0 }}>
                    <li>Nên <strong>backup database</strong> trước khi chạy migration</li>
                    <li>Migration có thể mất vài giây đến vài phút tùy kích thước database</li>
                    <li>Không tắt trình duyệt trong quá trình migration</li>
                    <li>Sau migration, tất cả dữ liệu hiện tại sẽ được giữ nguyên</li>
                  </ul>
                }
                type="error"
                showIcon
              />

              <div style={{ textAlign: 'center' }}>
                <Button
                  type="primary"
                  size="large"
                  danger
                  icon={<RocketOutlined />}
                  onClick={handleMigrate}
                  loading={migrating}
                  disabled={migrating}
                >
                  {migrating ? 'Đang Migration...' : 'Chạy Migration Ngay'}
                </Button>
              </div>
            </>
          )}
        </Space>
      </Card>

      {/* Migration Steps */}
      {needsMigration && (
        <Card title="📋 Migration Process" style={{ marginBottom: 24 }}>
          <Steps
            direction="vertical"
            current={migrating ? 1 : 0}
            items={[
              {
                title: 'Kiểm tra Database',
                description: 'Phát hiện cần migration từ v' + currentVersion + ' lên v' + latestVersion,
                status: 'finish',
                icon: <DatabaseOutlined />,
              },
              {
                title: 'Backup Database',
                description: 'Khuyến nghị backup database trước khi migration (thủ công)',
                status: migrating ? 'process' : 'wait',
                icon: <SafetyOutlined />,
              },
              {
                title: 'Run Migration',
                description: 'Cập nhật schema, thêm columns, migrate data',
                status: migrating ? 'process' : 'wait',
                icon: <SyncOutlined spin={migrating} />,
              },
              {
                title: 'Verify',
                description: 'Kiểm tra migration thành công',
                status: 'wait',
                icon: <CheckCircleOutlined />,
              },
            ]}
          />
        </Card>
      )}

      {/* Changelog */}
      <Card title="📝 Changelog - Version 1.2">
        <Timeline>
          <Timeline.Item color="green">
            <Text strong>✨ New Features</Text>
            <ul style={{ marginTop: 8 }}>
              <li>Thêm <code>viewed</code>, <code>viewed_by</code>, <code>viewed_at</code> columns cho Issues</li>
              <li>Chức năng "Mark as Viewed" để track issues đã check</li>
              <li>Realtime notification cho issues đã viewed</li>
              <li>React TypeScript Admin UI với Ant Design</li>
            </ul>
          </Timeline.Item>

          <Timeline.Item color="blue">
            <Text strong>🔧 Database Changes</Text>
            <ul style={{ marginTop: 8 }}>
              <li><code>ALTER TABLE security_monitor_issues ADD COLUMN viewed TINYINT(1) DEFAULT 0</code></li>
              <li><code>ALTER TABLE security_monitor_issues ADD COLUMN viewed_by BIGINT UNSIGNED</code></li>
              <li><code>ALTER TABLE security_monitor_issues ADD COLUMN viewed_at DATETIME</code></li>
            </ul>
          </Timeline.Item>

          <Timeline.Item color="orange">
            <Text strong>⚡ Improvements</Text>
            <ul style={{ marginTop: 8 }}>
              <li>Improved backtrace accuracy cho Login Attempt Monitor</li>
              <li>Better notification logic: Realtime vs Scheduled issuers</li>
              <li>Prevent notification spam cho brute force attacks</li>
              <li>Enhanced issue details với full backtrace</li>
            </ul>
          </Timeline.Item>

          <Timeline.Item color="purple">
            <Text strong>🐛 Bug Fixes</Text>
            <ul style={{ marginTop: 8 }}>
              <li>Fixed ArgumentCountError trong RealtimeRedirectIssuer</li>
              <li>Fixed backtrace showing detection code instead of event origin</li>
              <li>Fixed dashboard issuer count displaying wrong number</li>
              <li>Fixed Telegram markdown escaping issues</li>
            </ul>
          </Timeline.Item>
        </Timeline>
      </Card>
    </div>
  );
};

export default Migration;
