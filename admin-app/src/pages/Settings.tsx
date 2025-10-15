import React, { useEffect, useState } from 'react';
import {
  Card, Form, Input, Switch, Button, Space, Divider, Typography,
  Row, Col, Alert, Tabs
} from 'antd';
import { SaveOutlined, ReloadOutlined } from '@ant-design/icons';
import { useDispatch, useSelector } from 'react-redux';
import { ajax } from 'rxjs/ajax';
import type { RootState, AppDispatch } from '../store';
import { fetchSettings, updateSettings } from '../reducers/settingsReducer';
import { addNotification } from '../reducers/uiReducer';
import { buildUrl, getApiHeaders } from '../services/api';
import PageLoading from '../components/Loading/PageLoading';

const { Title, Text } = Typography;
const { TextArea } = Input;

const Settings: React.FC = () => {
  const dispatch = useDispatch<AppDispatch>();
  const settingsState = useSelector((state: RootState) => state.settings);
  const [form] = Form.useForm();
  const [initialLoading, setInitialLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [testingChannel, setTestingChannel] = useState<string | null>(null);

  useEffect(() => {
    dispatch(fetchSettings());
  }, [dispatch]);

  // Update form khi settings load
  useEffect(() => {
    if (settingsState.telegram && settingsState.email && settingsState.slack) {
      form.setFieldsValue({
        telegram_enabled: settingsState.telegram.enabled,
        telegram_bot_token: settingsState.telegram.bot_token,
        telegram_chat_id: settingsState.telegram.chat_id,
        email_enabled: settingsState.email.enabled,
        email_to: settingsState.email.to,
        slack_enabled: settingsState.slack.enabled,
        slack_webhook_url: settingsState.slack.webhook_url,
        log_enabled: settingsState.log.enabled,
      });
      setInitialLoading(false);
    }
  }, [settingsState, form]);

  const handleSave = () => {
    form.validateFields().then((values) => {
      setIsSaving(true);
      dispatch(updateSettings({
        telegram: {
          enabled: values.telegram_enabled || false,
          bot_token: values.telegram_bot_token || '',
          chat_id: values.telegram_chat_id || '',
        },
        email: {
          enabled: values.email_enabled || false,
          to: values.email_to || '',
        },
        slack: {
          enabled: values.slack_enabled || false,
          webhook_url: values.slack_webhook_url || '',
        },
        log: {
          enabled: values.log_enabled !== false,
        },
      }));
    });
  };

  // Reset isSaving khi save xong
  useEffect(() => {
    if (isSaving && !settingsState.loading) {
      setIsSaving(false);
    }
  }, [isSaving, settingsState.loading]);

  const handleReset = () => {
    dispatch(fetchSettings());
  };

  const handleTestChannel = async (channel: string) => {
    try {
      setTestingChannel(channel);

      const response = await ajax({
        url: buildUrl(`wp-security-monitor/v1/test-channel/${channel}`),
        method: 'POST',
        headers: getApiHeaders(),
      }).toPromise();

      const data = response?.response as any;

      if (data?.success) {
        dispatch(addNotification({
          type: 'success',
          message: `✅ ${channel.toUpperCase()}: ${data.message || 'Test thành công'}`
        }));
      } else {
        dispatch(addNotification({
          type: 'error',
          message: `❌ ${channel.toUpperCase()}: ${data?.message || 'Test thất bại'}`
        }));
      }
    } catch (error: any) {
      dispatch(addNotification({
        type: 'error',
        message: `❌ Lỗi test ${channel}: ${error.message}`
      }));
    } finally {
      setTestingChannel(null);
    }
  };

  // Show loading CHỈ khi initial load
  if (initialLoading) {
    return <PageLoading message="Đang tải settings..." />;
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <Title level={2} style={{ margin: 0 }}>⚙️ Settings</Title>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={handleReset}>Reset</Button>
          <Button type="primary" icon={<SaveOutlined />} onClick={handleSave} loading={isSaving}>
            Save Settings
          </Button>
        </Space>
      </div>

      {isSaving && (
        <Alert
          message="⏳ Đang lưu settings..."
          description="Vui lòng đợi, đang cập nhật cấu hình..."
          type="warning"
          showIcon
          style={{ marginBottom: 24 }}
        />
      )}

      {!isSaving && (
        <Alert
          message="Cấu hình Notification Channels"
          description="Cấu hình các kênh để nhận thông báo khi phát hiện vấn đề bảo mật"
          type="info"
          showIcon
          style={{ marginBottom: 24 }}
        />
      )}

      <Form
        form={form}
        layout="vertical"
        disabled={isSaving}
      >
        <Tabs defaultActiveKey="telegram">
          {/* Telegram Tab */}
          <Tabs.TabPane tab="📱 Telegram" key="telegram">
            <Card>
              <Space align="center" style={{ marginBottom: 16 }}>
                <Form.Item name="telegram_enabled" valuePropName="checked" noStyle>
                  <Switch />
                </Form.Item>
                <Text strong>Enable Telegram Notifications</Text>
              </Space>

              <Divider />

              <Form.Item noStyle shouldUpdate>
                {() => {
                  const enabled = form.getFieldValue('telegram_enabled');
                  return (
                    <>
                      <Row gutter={16}>
                        <Col span={12}>
                          <Form.Item
                            label="Bot Token"
                            name="telegram_bot_token"
                            rules={[{ required: enabled, message: 'Vui lòng nhập Bot Token' }]}
                          >
                            <Input.Password
                              placeholder="123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
                              disabled={!enabled}
                            />
                          </Form.Item>
                        </Col>
                        <Col span={12}>
                          <Form.Item
                            label="Chat ID"
                            name="telegram_chat_id"
                            rules={[{ required: enabled, message: 'Vui lòng nhập Chat ID' }]}
                          >
                            <Input
                              placeholder="-1001234567890"
                              disabled={!enabled}
                            />
                          </Form.Item>
                        </Col>
                      </Row>

              <Divider />

              <Space direction="vertical" style={{ width: '100%' }} size="middle">
                <div>
                  <Text strong>🧪 Test Telegram</Text>
                  <div style={{ marginTop: 8 }}>
                    <Button
                      onClick={() => handleTestChannel('telegram')}
                      loading={testingChannel === 'telegram'}
                      disabled={!form.getFieldValue('telegram_enabled') || isSaving}
                    >
                      📤 Gửi tin nhắn test
                    </Button>
                    <Text type="secondary" style={{ marginLeft: 12, fontSize: 12 }}>
                      Gửi tin nhắn test để kiểm tra bot có hoạt động không
                    </Text>
                  </div>
                </div>
              </Space>

              <Divider />

              <Alert
                message="Hướng dẫn lấy Telegram Bot Token & Chat ID"
                description={
                  <div>
                    <p><strong>Bot Token:</strong></p>
                    <ol style={{ marginLeft: 20 }}>
                      <li>Tìm @BotFather trên Telegram</li>
                      <li>Gửi lệnh /newbot và làm theo hướng dẫn</li>
                      <li>Copy token nhận được</li>
                    </ol>
                    <p><strong>Chat ID:</strong></p>
                    <ol style={{ marginLeft: 20 }}>
                      <li>Tìm @userinfobot trên Telegram</li>
                      <li>Gửi bất kỳ tin nhắn nào</li>
                      <li>Bot sẽ trả về Chat ID của bạn</li>
                    </ol>
                  </div>
                }
                type="info"
                showIcon
              />
                    </>
                  );
                }}
              </Form.Item>
            </Card>
          </Tabs.TabPane>

          {/* Email Tab */}
          <Tabs.TabPane tab="📧 Email" key="email">
            <Card>
              <Space align="center" style={{ marginBottom: 16 }}>
                <Form.Item name="email_enabled" valuePropName="checked" noStyle>
                  <Switch />
                </Form.Item>
                <Text strong>Enable Email Notifications</Text>
              </Space>

              <Divider />

              <Form.Item noStyle shouldUpdate>
                {() => {
                  const enabled = form.getFieldValue('email_enabled');
                  return (
                    <>
                      <Form.Item
                        label="Email Address"
                        name="email_to"
                        rules={[
                          { type: 'email', message: 'Email không hợp lệ' },
                          { required: enabled, message: 'Vui lòng nhập email' },
                        ]}
                      >
                        <Input
                          placeholder="admin@example.com"
                          disabled={!enabled}
                        />
                      </Form.Item>

              <Divider />

              <Space direction="vertical" style={{ width: '100%' }} size="middle">
                <div>
                  <Text strong>🧪 Test Email</Text>
                  <div style={{ marginTop: 8 }}>
                    <Button
                      onClick={() => handleTestChannel('email')}
                      loading={testingChannel === 'email'}
                      disabled={!form.getFieldValue('email_enabled') || isSaving}
                    >
                      📤 Gửi email test
                    </Button>
                    <Text type="secondary" style={{ marginLeft: 12, fontSize: 12 }}>
                      Gửi email test để kiểm tra SMTP configuration
                    </Text>
                  </div>
                </div>
              </Space>

              <Divider />

              <Alert
                message="Email Configuration"
                description="Emails sẽ được gửi qua WordPress mail function. Đảm bảo SMTP đã được cấu hình đúng."
                type="info"
                showIcon
              />
                    </>
                  );
                }}
              </Form.Item>
            </Card>
          </Tabs.TabPane>

          {/* Slack Tab */}
          <Tabs.TabPane tab="💬 Slack" key="slack">
            <Card>
              <Space align="center" style={{ marginBottom: 16 }}>
                <Form.Item name="slack_enabled" valuePropName="checked" noStyle>
                  <Switch />
                </Form.Item>
                <Text strong>Enable Slack Notifications</Text>
              </Space>

              <Divider />

              <Form.Item noStyle shouldUpdate>
                {() => {
                  const enabled = form.getFieldValue('slack_enabled');
                  return (
                    <>
                      <Form.Item
                        label="Webhook URL"
                        name="slack_webhook_url"
                        rules={[
                          { type: 'url', message: 'URL không hợp lệ' },
                          { required: enabled, message: 'Vui lòng nhập Webhook URL' },
                        ]}
                      >
                        <TextArea
                          rows={3}
                          placeholder="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
                          disabled={!enabled}
                        />
                      </Form.Item>

              <Divider />

              <Space direction="vertical" style={{ width: '100%' }} size="middle">
                <div>
                  <Text strong>🧪 Test Slack</Text>
                  <div style={{ marginTop: 8 }}>
                    <Button
                      onClick={() => handleTestChannel('slack')}
                      loading={testingChannel === 'slack'}
                      disabled={!form.getFieldValue('slack_enabled') || isSaving}
                    >
                      📤 Gửi tin nhắn test
                    </Button>
                    <Text type="secondary" style={{ marginLeft: 12, fontSize: 12 }}>
                      Gửi tin nhắn test đến Slack workspace
                    </Text>
                  </div>
                </div>
              </Space>

              <Divider />

              <Alert
                message="Hướng dẫn tạo Slack Webhook"
                description={
                  <div>
                    <ol style={{ marginLeft: 20 }}>
                      <li>Vào workspace settings</li>
                      <li>Chọn "Incoming Webhooks"</li>
                      <li>Click "Add New Webhook to Workspace"</li>
                      <li>Chọn channel và copy Webhook URL</li>
                    </ol>
                  </div>
                }
                type="info"
                showIcon
              />
                    </>
                  );
                }}
              </Form.Item>
            </Card>
          </Tabs.TabPane>

          {/* Log Tab */}
          <Tabs.TabPane tab="📝 Log" key="log">
            <Card>
              <Space align="center" style={{ marginBottom: 16 }}>
                <Form.Item name="log_enabled" valuePropName="checked" noStyle>
                  <Switch defaultChecked />
                </Form.Item>
                <Text strong>Enable File Logging</Text>
              </Space>

              <Divider />

              <Alert
                message="Log Settings"
                description={
                  <div>
                    <p>Logs sẽ được lưu tại: <code>wp-content/uploads/security-monitor/</code></p>
                    <p>File log được rotate hàng ngày để tránh quá lớn.</p>
                  </div>
                }
                type="info"
                showIcon
              />
            </Card>
          </Tabs.TabPane>
        </Tabs>

        {/* Action Buttons */}
        <Card style={{ marginTop: 24, textAlign: 'right' }}>
          <Space>
            <Button onClick={handleReset}>Reset</Button>
            <Button
              type="primary"
              onClick={handleSave}
              loading={settingsState.loading}
              icon={<SaveOutlined />}
            >
              Save All Settings
            </Button>
          </Space>
        </Card>
      </Form>
    </div>
  );
};

export default Settings;
