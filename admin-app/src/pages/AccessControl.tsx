import React, { useEffect, useState } from 'react';
import {
  Card, Typography, Table, Tag, Button, Space,
  Input, Modal, Form, Switch, Tabs, Alert
} from 'antd';
import {
  UserOutlined,
  LockOutlined,
  UnlockOutlined,
  GlobalOutlined,
  HistoryOutlined,
  PlusOutlined,
  DeleteOutlined,
} from '@ant-design/icons';
import PageLoading from '../components/Loading/PageLoading';

const { Title, Text } = Typography;
const { Search } = Input;

interface IPRule {
  id: number;
  ip: string;
  type: 'whitelist' | 'blacklist';
  reason: string;
  created_at: string;
}

interface LoginAttempt {
  id: number;
  username: string;
  ip_address: string;
  user_agent: string;
  status: 'success' | 'failed';
  timestamp: string;
}

const AccessControl: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('login-history');

  // IP Rules
  const [ipRules] = useState<IPRule[]>([]);
  const [ipModalVisible, setIpModalVisible] = useState(false);
  const [ipModalType, setIpModalType] = useState<'whitelist' | 'blacklist'>('blacklist');
  const [ipForm] = Form.useForm();

  // Login History
  const [loginHistory] = useState<LoginAttempt[]>([]);

  useEffect(() => {
    // TODO: Load data từ API
    setLoading(false);
  }, []);

  if (loading) {
    return <PageLoading message="Đang tải access control..." />;
  }

  const handleAddIPRule = (type: 'whitelist' | 'blacklist') => {
    setIpModalType(type);
    setIpModalVisible(true);
  };

  const handleSaveIPRule = () => {
    ipForm.validateFields().then((values) => {
      console.log('Adding IP rule:', { ...values, type: ipModalType });
      // TODO: Call API
      setIpModalVisible(false);
      ipForm.resetFields();
    });
  };

  const handleDeleteIPRule = (id: number) => {
    Modal.confirm({
      title: 'Xác nhận xóa',
      content: 'Bạn có chắc muốn xóa IP rule này?',
      onOk: () => {
        console.log('Deleting IP rule:', id);
        // TODO: Call API
      },
    });
  };

  const ipRulesColumns = [
    {
      title: 'IP Address',
      dataIndex: 'ip',
      key: 'ip',
      render: (ip: string) => <Text code>{ip}</Text>,
    },
    {
      title: 'Type',
      dataIndex: 'type',
      key: 'type',
      width: 120,
      render: (type: string) => (
        <Tag color={type === 'whitelist' ? 'green' : 'red'}>
          {type === 'whitelist' ? '✅ Whitelist' : '🚫 Blacklist'}
        </Tag>
      ),
    },
    {
      title: 'Reason',
      dataIndex: 'reason',
      key: 'reason',
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 160,
      render: (date: string) => new Date(date).toLocaleString('vi-VN'),
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 100,
      render: (_: any, record: IPRule) => (
        <Button
          danger
          size="small"
          icon={<DeleteOutlined />}
          onClick={() => handleDeleteIPRule(record.id)}
        >
          Xóa
        </Button>
      ),
    },
  ];

  const loginHistoryColumns = [
    {
      title: 'User',
      dataIndex: 'username',
      key: 'username',
      render: (username: string) => (
        <Space>
          <UserOutlined />
          <Text strong>{username}</Text>
        </Space>
      ),
    },
    {
      title: 'IP Address',
      dataIndex: 'ip_address',
      key: 'ip_address',
      render: (ip: string) => <Text code>{ip}</Text>,
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 120,
      render: (status: string) => (
        <Tag color={status === 'success' ? 'green' : 'red'} icon={
          status === 'success' ? <UnlockOutlined /> : <LockOutlined />
        }>
          {status === 'success' ? 'Success' : 'Failed'}
        </Tag>
      ),
    },
    {
      title: 'User Agent',
      dataIndex: 'user_agent',
      key: 'user_agent',
      ellipsis: true,
      render: (ua: string) => <Text type="secondary" style={{ fontSize: 12 }}>{ua}</Text>,
    },
    {
      title: 'Time',
      dataIndex: 'timestamp',
      key: 'timestamp',
      width: 160,
      render: (time: string) => new Date(time).toLocaleString('vi-VN'),
    },
  ];

  return (
    <div>
      <Title level={2}>🔐 Access Control</Title>

      <Tabs activeKey={activeTab} onChange={setActiveTab}>
        {/* Login History Tab */}
        <Tabs.TabPane
          tab={<span><HistoryOutlined /> Login History</span>}
          key="login-history"
        >
          <Card>
            <div style={{ marginBottom: 16 }}>
              <Search
                placeholder="Tìm theo username hoặc IP..."
                allowClear
                style={{ width: 300 }}
                onSearch={(value) => console.log('Search:', value)}
              />
            </div>

            <Table
              columns={loginHistoryColumns}
              dataSource={loginHistory}
              rowKey="id"
              pagination={{ pageSize: 20 }}
              locale={{ emptyText: 'Chưa có lịch sử login' }}
            />
          </Card>
        </Tabs.TabPane>

        {/* IP Rules Tab */}
        <Tabs.TabPane
          tab={<span><GlobalOutlined /> IP Rules</span>}
          key="ip-rules"
        >
          <Card
            extra={
              <Space>
                <Button
                  type="primary"
                  icon={<PlusOutlined />}
                  onClick={() => handleAddIPRule('whitelist')}
                  style={{ background: '#00a32a' }}
                >
                  Add Whitelist
                </Button>
                <Button
                  danger
                  icon={<PlusOutlined />}
                  onClick={() => handleAddIPRule('blacklist')}
                >
                  Add Blacklist
                </Button>
              </Space>
            }
          >
            <Space direction="vertical" style={{ width: '100%', marginBottom: 16 }}>
              <Alert
                message="IP Access Control"
                description={
                  <div>
                    <p><strong>Whitelist:</strong> Các IP trong whitelist sẽ KHÔNG bị giám sát và không tạo security issues.</p>
                    <p><strong>Blacklist:</strong> Các IP trong blacklist sẽ bị chặn hoàn toàn khỏi website.</p>
                  </div>
                }
                type="info"
                showIcon
              />
            </Space>

            <Table
              columns={ipRulesColumns}
              dataSource={ipRules}
              rowKey="id"
              pagination={false}
              locale={{ emptyText: 'Chưa có IP rules nào' }}
            />
          </Card>
        </Tabs.TabPane>

        {/* User Permissions Tab */}
        <Tabs.TabPane
          tab={<span><UserOutlined /> User Permissions</span>}
          key="permissions"
        >
          <Card>
            <Space direction="vertical" style={{ width: '100%' }} size="large">
              <Alert
                message="User Capabilities"
                description="Quản lý quyền truy cập Security Monitor plugin cho các user roles."
                type="info"
                showIcon
              />

              <div>
                <Title level={5}>🔑 Quyền truy cập Plugin</Title>
                <Space direction="vertical" style={{ width: '100%' }}>
                  <Space>
                    <Switch defaultChecked />
                    <Text strong>Administrator</Text>
                    <Text type="secondary">- Full access (không thể tắt)</Text>
                  </Space>
                  <Space>
                    <Switch />
                    <Text strong>Editor</Text>
                    <Text type="secondary">- Cho phép xem Issues và Stats</Text>
                  </Space>
                  <Space>
                    <Switch />
                    <Text strong>Author</Text>
                    <Text type="secondary">- Chỉ xem Issues liên quan đến content</Text>
                  </Space>
                </Space>
              </div>

              <div>
                <Title level={5}>⚙️ Quyền chỉnh sửa Settings</Title>
                <Space direction="vertical">
                  <Space>
                    <Switch defaultChecked disabled />
                    <Text strong>Administrator</Text>
                    <Text type="secondary">- Luôn có quyền</Text>
                  </Space>
                  <Space>
                    <Switch />
                    <Text>Editor</Text>
                    <Text type="secondary">- Cho phép chỉnh sửa channel settings</Text>
                  </Space>
                </Space>
              </div>

              <Button type="primary" style={{ marginTop: 16 }}>
                Save Permissions
              </Button>
            </Space>
          </Card>
        </Tabs.TabPane>
      </Tabs>

      {/* Add IP Rule Modal */}
      <Modal
        title={ipModalType === 'whitelist' ? '✅ Add IP Whitelist' : '🚫 Add IP Blacklist'}
        open={ipModalVisible}
        onOk={handleSaveIPRule}
        onCancel={() => {
          setIpModalVisible(false);
          ipForm.resetFields();
        }}
        okText="Add"
        cancelText="Cancel"
      >
        <Form form={ipForm} layout="vertical">
          <Form.Item
            label="IP Address"
            name="ip"
            rules={[
              { required: true, message: 'Vui lòng nhập IP address' },
              {
                pattern: /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/,
                message: 'IP address không hợp lệ (VD: 192.168.1.1 hoặc 192.168.1.0/24)'
              },
            ]}
          >
            <Input placeholder="192.168.1.100 hoặc 192.168.1.0/24" />
          </Form.Item>

          <Form.Item
            label="Reason"
            name="reason"
            rules={[{ required: true, message: 'Vui lòng nhập lý do' }]}
          >
            <Input.TextArea
              rows={3}
              placeholder={
                ipModalType === 'whitelist'
                  ? 'VD: Office IP - không giám sát'
                  : 'VD: Spam bot - chặn hoàn toàn'
              }
            />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default AccessControl;
