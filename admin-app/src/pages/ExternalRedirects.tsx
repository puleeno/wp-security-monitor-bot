import React, { useEffect, useState } from 'react';
import {
  Card, Table, Tag, Button, Space, Modal, Input, Typography,
  Alert, Descriptions, Drawer
} from 'antd';
import {
  CheckOutlined,
  CloseOutlined,
  EyeOutlined,
  ReloadOutlined,
  WarningOutlined,
} from '@ant-design/icons';
import { ajax } from 'rxjs/ajax';
import { buildUrl, getApiHeaders } from '../services/api';
import { addNotification } from '../reducers/uiReducer';
import { useDispatch } from 'react-redux';
import PageLoading from '../components/Loading/PageLoading';

const { Title, Text } = Typography;
const { TextArea } = Input;

interface PendingRedirect {
  domain: string;
  url: string;
  source_url: string;
  detected_count: number;
  first_detected: string;
  last_detected: string;
  status: 'pending' | 'approved' | 'rejected';
  user_agent?: string;
  ip_address?: string;
  contexts?: string;
  approved_by?: number;
  approved_at?: string;
  rejected_by?: number;
  rejected_at?: string;
  reject_reason?: string;
}

const ExternalRedirects: React.FC = () => {
  const dispatch = useDispatch();
  const [loading, setLoading] = useState(true);
  const [processing, setProcessing] = useState<string | null>(null);
  const [redirects, setRedirects] = useState<PendingRedirect[]>([]);
  const [selectedRedirect, setSelectedRedirect] = useState<PendingRedirect | null>(null);
  const [detailsVisible, setDetailsVisible] = useState(false);
  const [rejectReason, setRejectReason] = useState('');
  const [rejectModal, setRejectModal] = useState(false);
  const [activeTab, setActiveTab] = useState<'pending' | 'approved' | 'rejected'>('pending');

  useEffect(() => {
    loadRedirects();
  }, []);

  const loadRedirects = async (status?: string) => {
    try {
      setLoading(true);
      const queryParam = status ? `?status=${status}` : '';
      const url = buildUrl(`wp-security-monitor/v1/redirects${queryParam}`);

      const response = await ajax({
        url,
        method: 'GET',
        headers: getApiHeaders(),
      }).toPromise();

      const data = response?.response as any;
      setRedirects(data?.redirects || []);
    } catch (error: any) {
      console.error('❌ Failed to load redirects:', error);
      dispatch(addNotification({
        type: 'error',
        message: `Lỗi load domains: ${error.message}`,
      }));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRedirects(activeTab);
  }, [activeTab]);

  const handleApprove = async (redirect: PendingRedirect) => {
    if (!window.confirm(`✅ Approve domain "${redirect.domain}"?\n\nDomain này sẽ được thêm vào whitelist và không còn cảnh báo nữa.`)) {
      return;
    }

    try {
      setProcessing(redirect.domain);

      const response = await ajax({
        url: buildUrl(`wp-security-monitor/v1/redirects/${encodeURIComponent(redirect.domain)}/approve`),
        method: 'POST',
        headers: getApiHeaders(),
      }).toPromise();

      const data = response?.response as any;

      if (data?.success) {
        dispatch(addNotification({
          type: 'success',
          message: `✅ Domain "${redirect.domain}" đã được approve`,
        }));
        await loadRedirects();
      }
    } catch (error: any) {
      dispatch(addNotification({
        type: 'error',
        message: `Lỗi: ${error.message}`,
      }));
    } finally {
      setProcessing(null);
    }
  };

  const handleReject = async () => {
    if (!selectedRedirect) return;

    try {
      setProcessing(selectedRedirect.domain);

      const response = await ajax({
        url: buildUrl(`wp-security-monitor/v1/redirects/${encodeURIComponent(selectedRedirect.domain)}/reject`),
        method: 'POST',
        headers: getApiHeaders(),
        body: { reason: rejectReason },
      }).toPromise();

      const data = response?.response as any;

      if (data?.success) {
        dispatch(addNotification({
          type: 'success',
          message: `❌ Domain "${selectedRedirect.domain}" đã bị reject`,
        }));
        setRejectModal(false);
        setRejectReason('');
        await loadRedirects();
      }
    } catch (error: any) {
      dispatch(addNotification({
        type: 'error',
        message: `Lỗi: ${error.message}`,
      }));
    } finally {
      setProcessing(null);
    }
  };

  if (loading) {
    return <PageLoading message="Đang tải domains..." />;
  }

  const getStatusColor = (status: string): string => {
    const colors: Record<string, string> = {
      pending: 'orange',
      approved: 'green',
      rejected: 'red',
    };
    return colors[status] || 'default';
  };

  const columns = [
    {
      title: 'Domain',
      dataIndex: 'domain',
      key: 'domain',
      render: (domain: string, record: PendingRedirect) => (
        <Space direction="vertical" size={0}>
          <Text strong style={{ fontSize: 14 }}>{domain}</Text>
          <a href={record.url} target="_blank" rel="noopener noreferrer" style={{ fontSize: 12 }}>
            {record.url.length > 60 ? record.url.substring(0, 60) + '...' : record.url}
          </a>
        </Space>
      ),
    },
    {
      title: 'Source',
      dataIndex: 'source_url',
      key: 'source_url',
      width: 200,
      ellipsis: true,
      render: (url: string) => (
        <Text type="secondary" style={{ fontSize: 12 }}>{url || '-'}</Text>
      ),
    },
    {
      title: 'Detected',
      dataIndex: 'detected_count',
      key: 'detected_count',
      width: 100,
      render: (count: number) => <Tag color="blue">{count}x</Tag>,
    },
    {
      title: 'Last Seen',
      dataIndex: 'last_detected',
      key: 'last_detected',
      width: 160,
      render: (date: string) => new Date(date).toLocaleString('vi-VN'),
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 120,
      render: (status: string) => (
        <Tag color={getStatusColor(status)}>{status.toUpperCase()}</Tag>
      ),
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 260,
      render: (_: any, record: PendingRedirect) => (
        <Space size="small">
          <Button
            size="small"
            onClick={() => {
              setSelectedRedirect(record);
              setDetailsVisible(true);
            }}
            icon={<EyeOutlined />}
          >
            Details
          </Button>

          {record.status === 'pending' && (
            <>
              <Button
                size="small"
                type="primary"
                icon={<CheckOutlined />}
                onClick={() => handleApprove(record)}
                loading={processing === record.domain}
              >
                Approve
              </Button>
              <Button
                size="small"
                danger
                icon={<CloseOutlined />}
                onClick={() => {
                  setSelectedRedirect(record);
                  setRejectModal(true);
                }}
                loading={processing === record.domain}
              >
                Reject
              </Button>
            </>
          )}
        </Space>
      ),
    },
  ];

  const pendingCount = redirects.filter(r => r.status === 'pending').length;
  const approvedCount = redirects.filter(r => r.status === 'approved').length;
  const rejectedCount = redirects.filter(r => r.status === 'rejected').length;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <Title level={2} style={{ margin: 0 }}>🔀 External Redirects</Title>
        <Button icon={<ReloadOutlined />} onClick={() => loadRedirects(activeTab)}>
          Refresh
        </Button>
      </div>

      {activeTab === 'pending' && pendingCount > 0 && (
        <Alert
          message={`⚠️ Có ${pendingCount} domain(s) đang chờ review`}
          description="Kiểm tra và approve/reject các domain để bảo vệ website khỏi phishing và malware."
          type="warning"
          showIcon
          style={{ marginBottom: 24 }}
        />
      )}

      <Card
        tabList={[
          {
            key: 'pending',
            tab: (
              <Space>
                <WarningOutlined />
                Pending
                {pendingCount > 0 && <Tag color="orange">{pendingCount}</Tag>}
              </Space>
            ),
          },
          {
            key: 'approved',
            tab: (
              <Space>
                <CheckOutlined />
                Approved (Whitelist)
                {approvedCount > 0 && <Tag color="green">{approvedCount}</Tag>}
              </Space>
            ),
          },
          {
            key: 'rejected',
            tab: (
              <Space>
                <CloseOutlined />
                Rejected (Blacklist)
                {rejectedCount > 0 && <Tag color="red">{rejectedCount}</Tag>}
              </Space>
            ),
          },
        ]}
        activeTabKey={activeTab}
        onTabChange={(key) => setActiveTab(key as any)}
      >
        {redirects.length === 0 && (
          <Alert
            message={
              activeTab === 'pending'
                ? '✅ Không có pending domains'
                : activeTab === 'approved'
                ? 'Chưa có domain nào được approve'
                : 'Chưa có domain nào bị reject'
            }
            description={
              activeTab === 'pending'
                ? 'Tất cả external redirects đã được review. Website đang an toàn!'
                : undefined
            }
            type={activeTab === 'pending' ? 'success' : 'info'}
            showIcon
          />
        )}

        {redirects.length > 0 && (
          <Table
            columns={columns}
            dataSource={redirects}
            rowKey="domain"
            pagination={{ pageSize: 20 }}
            locale={{ emptyText: 'Không có redirects nào' }}
          />
        )}
      </Card>

      {/* Details Drawer */}
      <Drawer
        title="🔍 Redirect Details"
        placement="right"
        width={720}
        open={detailsVisible}
        onClose={() => setDetailsVisible(false)}
      >
        {selectedRedirect && (
          <Space direction="vertical" size="large" style={{ width: '100%' }}>
            <Descriptions bordered column={1} size="small">
              <Descriptions.Item label="Domain">
                <Text strong>{selectedRedirect.domain}</Text>
              </Descriptions.Item>
              <Descriptions.Item label="Full URL">
                <a href={selectedRedirect.url} target="_blank" rel="noopener noreferrer">
                  {selectedRedirect.url}
                </a>
              </Descriptions.Item>
              <Descriptions.Item label="Source URL">
                {selectedRedirect.source_url || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="Status">
                <Tag color={getStatusColor(selectedRedirect.status)}>
                  {selectedRedirect.status.toUpperCase()}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="Detection Count">
                {selectedRedirect.detected_count}
              </Descriptions.Item>
              <Descriptions.Item label="First Detected">
                {new Date(selectedRedirect.first_detected).toLocaleString('vi-VN')}
              </Descriptions.Item>
              <Descriptions.Item label="Last Detected">
                {new Date(selectedRedirect.last_detected).toLocaleString('vi-VN')}
              </Descriptions.Item>
              {selectedRedirect.ip_address && (
                <Descriptions.Item label="IP Address">
                  <Text code>{selectedRedirect.ip_address}</Text>
                </Descriptions.Item>
              )}
              {selectedRedirect.user_agent && (
                <Descriptions.Item label="User Agent">
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    {selectedRedirect.user_agent}
                  </Text>
                </Descriptions.Item>
              )}
            </Descriptions>

            <Alert
              message="🔍 Domain Analysis"
              description={
                <div>
                  <p><strong>Cách kiểm tra:</strong></p>
                  <ul style={{ marginLeft: 20 }}>
                    <li>Check domain có đáng tin cậy không (Google, VirusTotal)</li>
                    <li>Kiểm tra source URL - redirect có hợp lý không?</li>
                    <li>Nếu là domain của bạn → Approve</li>
                    <li>Nếu là spam/phishing → Reject</li>
                    <li>Nếu không chắc → Để pending và monitor thêm</li>
                  </ul>
                </div>
              }
              type="info"
              showIcon
            />

            {selectedRedirect.status === 'pending' && (
              <Space style={{ width: '100%', justifyContent: 'center' }}>
                <Button
                  type="primary"
                  icon={<CheckOutlined />}
                  onClick={() => handleApprove(selectedRedirect)}
                  loading={processing === selectedRedirect.domain}
                  size="large"
                >
                  Approve Domain
                </Button>
                <Button
                  danger
                  icon={<CloseOutlined />}
                  onClick={() => {
                    setDetailsVisible(false);
                    setRejectModal(true);
                  }}
                  loading={processing === selectedRedirect.domain}
                  size="large"
                >
                  Reject Domain
                </Button>
              </Space>
            )}
          </Space>
        )}
      </Drawer>

      {/* Reject Modal */}
      <Modal
        title="❌ Reject Domain"
        open={rejectModal}
        onOk={handleReject}
        onCancel={() => {
          setRejectModal(false);
          setRejectReason('');
        }}
        okText="Reject"
        okButtonProps={{ danger: true }}
        cancelText="Cancel"
      >
        {selectedRedirect && (
          <Space direction="vertical" style={{ width: '100%' }}>
            <Alert
              message={`Reject domain: ${selectedRedirect.domain}`}
              type="warning"
              showIcon
            />
            <Text>Lý do reject (optional):</Text>
            <TextArea
              rows={4}
              value={rejectReason}
              onChange={(e) => setRejectReason(e.target.value)}
              placeholder="VD: Spam domain, phishing site, malware..."
            />
          </Space>
        )}
      </Modal>
    </div>
  );
};

export default ExternalRedirects;

