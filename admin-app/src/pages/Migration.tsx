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

interface ChangelogEntry {
  version: string;
  content: string;
  file: string;
}

const Migration: React.FC = () => {
  const dispatch = useDispatch();
  const [loading, setLoading] = useState(true);
  const [migrating, setMigrating] = useState(false);
  const [status, setStatus] = useState<MigrationStatus | null>(null);
  const [changelog, setChangelog] = useState<ChangelogEntry[]>([]);

  useEffect(() => {
    loadMigrationStatus();
    loadChangelog();
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

  const loadChangelog = async () => {
    try {
      const response = await ajax({
        url: buildUrl('wp-security-monitor/v1/migration/changelog'),
        method: 'GET',
        headers: getApiHeaders(),
      }).toPromise();

      const data = response?.response as any;
      setChangelog(data?.changelog || []);
    } catch (error) {
      console.error('Failed to load changelog:', error);
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
      <Card title="📝 Database Changelog">
        <Timeline>
          {changelog.map((entry) => {
            const lines = entry.content.split('\n');
            const version = lines.find(line => line.startsWith('Version:'))?.replace('Version:', '').trim() || entry.version;
            const date = lines.find(line => line.startsWith('Date:'))?.replace('Date:', '').trim() || '';
            const type = lines.find(line => line.startsWith('Type:'))?.replace('Type:', '').trim() || '';
            const title = lines.find(line => line.startsWith('Title:'))?.replace('Title:', '').trim() || '';

            const getColor = (type: string) => {
              if (type.includes('Major')) return 'red';
              if (type.includes('Minor')) return 'blue';
              if (type.includes('Patch')) return 'green';
              return 'gray';
            };

            const getIcon = (type: string) => {
              if (type.includes('Major')) return '🚀';
              if (type.includes('Minor')) return '✨';
              if (type.includes('Patch')) return '🔧';
              return '📝';
            };

            return (
              <Timeline.Item key={entry.version} color={getColor(type)}>
                <Space direction="vertical" size="small" style={{ width: '100%' }}>
                  <div>
                    <Tag color={getColor(type)}>{getIcon(type)} v{version}</Tag>
                    <Text strong>{title}</Text>
                    <Text type="secondary" style={{ marginLeft: 8 }}>({date})</Text>
                  </div>

                  <div style={{
                    backgroundColor: '#f5f5f5',
                    padding: 12,
                    borderRadius: 6,
                    fontSize: 12,
                    fontFamily: 'monospace',
                    whiteSpace: 'pre-wrap',
                    maxHeight: 200,
                    overflow: 'auto'
                  }}>
                    {entry.content}
                  </div>
                </Space>
              </Timeline.Item>
            );
          })}
        </Timeline>
      </Card>
    </div>
  );
};

export default Migration;
