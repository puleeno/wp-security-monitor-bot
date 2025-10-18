import React, { useEffect, useState } from 'react';
import {
  Card, Table, Tag, Button, Space, Modal, Input, Pagination,
  Drawer, Descriptions, Typography, Collapse, Alert
} from 'antd';
import {
  EyeOutlined,
  CheckOutlined,
  StopOutlined,
  ReloadOutlined,
} from '@ant-design/icons';
import { useDispatch, useSelector } from 'react-redux';
import { useTranslation } from 'react-i18next';
import type { RootState, AppDispatch } from '../store';
import {
  fetchIssues,
  markAsViewed,
  unmarkAsViewed,
  ignoreIssue,
  resolveIssue,
} from '../reducers/issuesReducer';
import type { Issue } from '../types';
import { getIssuerName } from '../utils/issuerNames';
import PageLoading from '../components/Loading/PageLoading';

const { TextArea } = Input;
const { Title, Text } = Typography;
const { Panel } = Collapse;

const Issues: React.FC = () => {
  const dispatch = useDispatch<AppDispatch>();
  const { t } = useTranslation();
  const { items, total, currentPage, perPage, loading, filters } = useSelector(
    (state: RootState) => state.issues
  );

  const [selectedIssue, setSelectedIssue] = useState<Issue | null>(null);
  const [detailsVisible, setDetailsVisible] = useState(false);
  const [ignoreModal, setIgnoreModal] = useState(false);
  const [resolveModal, setResolveModal] = useState(false);
  const [ignoreReason, setIgnoreReason] = useState('');
  const [resolutionNotes, setResolutionNotes] = useState('');
  const [initialLoading, setInitialLoading] = useState(true);
  const [isInitialized, setIsInitialized] = useState(false);

  // Initialize: Read page from URL on mount
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const pageFromUrl = parseInt(urlParams.get('paged') || '1', 10);

    dispatch(fetchIssues({ page: pageFromUrl, filters }));
    setIsInitialized(true);
  }, [dispatch]);

  // Update URL when page or filters change (skip on initial render)
  useEffect(() => {
    if (!isInitialized) return;

    dispatch(fetchIssues({ page: currentPage, filters }));

    // Update URL when page changes (preserve existing params like 'page')
    const urlParams = new URLSearchParams(window.location.search);

    if (currentPage > 1) {
      urlParams.set('paged', currentPage.toString());
    } else {
      urlParams.delete('paged'); // Remove param if page 1
    }

    // Keep hash (e.g., #issues)
    const newUrl = `${window.location.pathname}?${urlParams.toString()}${window.location.hash}`;
    window.history.replaceState({ page: currentPage }, '', newUrl);
  }, [currentPage, filters, isInitialized]);

  useEffect(() => {
    if (!loading && items) {
      setInitialLoading(false);
    }
  }, [loading, items]);

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

  const getStatusColor = (status: string): string => {
    const colors: Record<string, string> = {
      new: 'red',
      investigating: 'orange',
      resolved: 'green',
      ignored: 'default',
      false_positive: 'default',
    };
    return colors[status] || 'default';
  };

  const handleMarkViewed = (issueId: number, viewed: boolean): void => {
    if (viewed) {
      dispatch(unmarkAsViewed(issueId));
    } else {
      dispatch(markAsViewed(issueId));
    }
  };

  const handleIgnore = (): void => {
    if (selectedIssue) {
      dispatch(ignoreIssue({ issueId: selectedIssue.id, reason: ignoreReason }));
      setIgnoreModal(false);
      setIgnoreReason('');
    }
  };

  const handleResolve = (): void => {
    if (selectedIssue) {
      dispatch(resolveIssue({ issueId: selectedIssue.id, notes: resolutionNotes }));
      setResolveModal(false);
      setResolutionNotes('');
    }
  };

  const columns = [
    {
      title: 'ID',
      dataIndex: 'id',
      key: 'id',
      width: 70,
    },
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
          {record.file_path && (
            <Text type="secondary" style={{ fontSize: 12 }}>
              📁 {record.file_path}
            </Text>
          )}
          {record.ip_address && (
            <Text type="secondary" style={{ fontSize: 12 }}>
              🌐 {record.ip_address}
            </Text>
          )}
        </Space>
      ),
    },
    {
      title: 'Issuer',
      dataIndex: 'issuer_name',
      key: 'issuer_name',
      width: 200,
      render: (issuerName: string) => (
        <span style={{ fontSize: '13px' }}>{getIssuerName(issuerName)}</span>
      ),
    },
    {
      title: 'Count',
      dataIndex: 'detection_count',
      key: 'detection_count',
      width: 80,
      render: (count: number) => (
        <Tag color="blue">{count}</Tag>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 120,
      render: (status: string, record: Issue) => (
        <Space direction="vertical" size={0}>
          <Tag color={getStatusColor(status)}>{status}</Tag>
          {record.viewed && <Tag color="green">✅ {t('issues.viewed')}</Tag>}
        </Space>
      ),
    },
    {
      title: 'Actions',
      key: 'actions',
      width: 280,
      render: (_: any, record: Issue) => {
        const isProcessed = record.viewed || record.is_ignored || record.status === 'resolved';
        return (
          <Space wrap size="small">
            {/* Always show Details */}
            <Button
              size="small"
              onClick={() => {
                setSelectedIssue(record);
                setDetailsVisible(true);
              }}
            >
              {t('issues.details')}
            </Button>

            {/* Only show action buttons when NOT processed yet */}
            {!isProcessed && (
              <>
                <Button
                  size="small"
                  type={record.viewed ? 'default' : 'primary'}
                  icon={<EyeOutlined />}
                  onClick={() => handleMarkViewed(record.id, record.viewed)}
                >
                  {record.viewed ? t('issues.viewed') : t('issues.markViewed')}
                </Button>

                {!record.is_ignored && (
                  <>
                    <Button
                      size="small"
                      icon={<StopOutlined />}
                      onClick={() => {
                        setSelectedIssue(record);
                        setIgnoreModal(true);
                      }}
                    >
                      {t('issues.ignore')}
                    </Button>

                    {record.status !== 'resolved' && (
                      <Button
                        size="small"
                        type="primary"
                        icon={<CheckOutlined />}
                        onClick={() => {
                          setSelectedIssue(record);
                          setResolveModal(true);
                        }}
                      >
                        {t('issues.resolve')}
                      </Button>
                    )}
                  </>
                )}
              </>
            )}
          </Space>
        );
      },
    },
  ];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <Title level={2} style={{ margin: 0 }}>🔍 {t('issues.title')}</Title>
        <Button icon={<ReloadOutlined />} onClick={() => dispatch(fetchIssues({ page: currentPage, filters }))}>
          {t('issues.refresh')}
        </Button>
      </div>

      <Card>
        <Table
          columns={columns}
          dataSource={items}
          rowKey="id"
          loading={loading}
          pagination={false}
        />

        <Pagination
          current={currentPage}
          total={total}
          pageSize={perPage}
          onChange={(page) => dispatch(fetchIssues({ page, filters }))}
          style={{ marginTop: 16, textAlign: 'right' }}
          showSizeChanger={false}
          showTotal={(total) => t('issues.totalIssues', { count: total })}
        />
      </Card>

      {/* Issue Details Drawer */}
      <Drawer
        title={t('issues.issueDetails')}
        placement="right"
        width={720}
        open={detailsVisible}
        onClose={() => setDetailsVisible(false)}
      >
        {selectedIssue && (
          <Space direction="vertical" size="large" style={{ width: '100%' }}>
            <Descriptions bordered column={1} size="small">
              <Descriptions.Item label="Severity">
                <Tag color={getSeverityColor(selectedIssue.severity)}>
                  {selectedIssue.severity.toUpperCase()}
                </Tag>
              </Descriptions.Item>
              <Descriptions.Item label="Status">
                <Tag color={getStatusColor(selectedIssue.status)}>{selectedIssue.status}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="Issuer">{getIssuerName(selectedIssue.issuer_name)}</Descriptions.Item>
              <Descriptions.Item label="Detection Count">{selectedIssue.detection_count}</Descriptions.Item>
              <Descriptions.Item label="First Detected">
                {new Date(selectedIssue.first_detected).toLocaleString('vi-VN')}
              </Descriptions.Item>
              <Descriptions.Item label="Last Detected">
                {new Date(selectedIssue.last_detected).toLocaleString('vi-VN')}
              </Descriptions.Item>
              {selectedIssue.is_ignored && selectedIssue.ignored_at && (
                <>
                  <Descriptions.Item label={t('issues.ignoredBy')}>
                    User ID: {selectedIssue.ignored_by || 'Unknown'}
                  </Descriptions.Item>
                  <Descriptions.Item label={t('issues.ignoredAt')}>
                    {new Date(selectedIssue.ignored_at).toLocaleString()}
                  </Descriptions.Item>
                </>
              )}
              {selectedIssue.status === 'resolved' && selectedIssue.resolved_at && (
                <>
                  <Descriptions.Item label={t('issues.resolvedBy')}>
                    User ID: {selectedIssue.resolved_by || 'Unknown'}
                  </Descriptions.Item>
                  <Descriptions.Item label={t('issues.resolvedAt')}>
                    {new Date(selectedIssue.resolved_at).toLocaleString()}
                  </Descriptions.Item>
                </>
              )}
            </Descriptions>

            <div>
              <Title level={5}>📋 Description</Title>
              <Text>{selectedIssue.description}</Text>
            </div>

            {/* Ignore Reason */}
            {selectedIssue.is_ignored && selectedIssue.ignore_reason && (
              <Alert
                message={`🚫 ${t('issues.ignoreReasonLabel')}`}
                description={selectedIssue.ignore_reason}
                type="warning"
                showIcon
              />
            )}

            {/* Resolution Notes */}
            {selectedIssue.status === 'resolved' && selectedIssue.resolution_notes && (
              <Alert
                message={`✅ ${t('issues.resolutionNotesLabel')}`}
                description={selectedIssue.resolution_notes}
                type="success"
                showIcon
              />
            )}

            {/* Technical Details */}
            {selectedIssue.details && (
              <Collapse defaultActiveKey={[]}>
                <Panel header="🔍 Technical Details" key="details">
                  <pre style={{
                    background: '#f5f5f5',
                    padding: '12px',
                    borderRadius: '4px',
                    overflow: 'auto',
                    fontSize: '12px',
                    maxHeight: '300px'
                  }}>
                    {selectedIssue.details}
                  </pre>
                </Panel>
              </Collapse>
            )}

            {/* Backtrace */}
            {(() => {
              // Parse backtrace - có thể là string JSON hoặc array
              let backtraceData: any[] = [];

              try {
                if (typeof selectedIssue.backtrace === 'string') {
                  backtraceData = JSON.parse(selectedIssue.backtrace);
                } else if (Array.isArray(selectedIssue.backtrace)) {
                  backtraceData = selectedIssue.backtrace;
                }
              } catch (e) {
                console.error('Error parsing backtrace:', e);
              }

              return backtraceData && Array.isArray(backtraceData) && backtraceData.length > 0 && (
                <Collapse defaultActiveKey={['backtrace']}>
                  <Panel header="🗂️ Backtrace" key="backtrace">
                    <Table
                      columns={[
                        {
                          title: '#',
                          key: 'index',
                          width: 50,
                          render: (_: any, __: any, i: number) => (
                            <strong>{i + 1}</strong>
                          )
                        },
                        {
                          title: 'File',
                          dataIndex: 'file',
                          key: 'file',
                          render: (file: string) => {
                            // Extract filename from full path
                            if (!file) return '-';
                            const filename = file.split(/[/\\]/).pop() || file;
                            return (
                              <div>
                                <div><strong>{filename}</strong></div>
                                <div style={{ fontSize: '11px', color: '#999' }}>{file}</div>
                              </div>
                            );
                          }
                        },
                        {
                          title: 'Line',
                          dataIndex: 'line',
                          key: 'line',
                          width: 70,
                          render: (line: number) => <Tag color="blue">{line}</Tag>
                        },
                        {
                          title: 'Function',
                          dataIndex: 'function',
                          key: 'function',
                          width: 180,
                          render: (func: string) => <code style={{ fontSize: '12px' }}>{func}</code>
                        },
                        {
                          title: 'Class',
                          dataIndex: 'class',
                          key: 'class',
                          render: (cls: string | null) => cls ? (
                            <Text type="secondary" style={{ fontSize: '11px' }}>{cls}</Text>
                          ) : <Text type="secondary">-</Text>
                        },
                      ]}
                      dataSource={backtraceData}
                      pagination={false}
                      size="small"
                      rowKey={(_record, index) => `backtrace-${index}`}
                      bordered
                    />
                  </Panel>
                </Collapse>
              );
            })()}

            {/* Metadata */}
            {(() => {
              const hasMetadata = selectedIssue.metadata && Object.keys(selectedIssue.metadata).length > 0;
              const hasRawData = selectedIssue.raw_data && Object.keys(selectedIssue.raw_data).length > 0;

              if (!hasMetadata && !hasRawData) return null;

              return (
                <Collapse defaultActiveKey={['metadata']}>
                  <Panel header="📊 Metadata" key="metadata">
                    <Space direction="vertical" style={{ width: '100%' }} size="middle">
                      {/* Upload Metadata */}
                      {hasMetadata && selectedIssue.metadata && (
                        <div>
                          <Title level={5} style={{ marginBottom: 12 }}>🔍 Upload Information</Title>
                          <div style={{
                            background: '#f9f9f9',
                            padding: '16px',
                            borderRadius: '8px',
                            border: '1px solid #e8e8e8'
                          }}>
                            {selectedIssue.metadata?.uploader_id && (
                              <div style={{ marginBottom: 8 }}>
                                <Text strong>👤 Uploader:</Text>{' '}
                                <Text>
                                  {selectedIssue.metadata?.uploader_display_name} ({selectedIssue.metadata?.uploader_login})
                                </Text>
                              </div>
                            )}
                            {selectedIssue.metadata?.uploader_email && (
                              <div style={{ marginBottom: 8 }}>
                                <Text strong>📧 Email:</Text>{' '}
                                <Text copyable>{selectedIssue.metadata?.uploader_email}</Text>
                              </div>
                            )}
                            {selectedIssue.metadata?.ip_address && (
                              <div style={{ marginBottom: 8 }}>
                                <Text strong>🌐 IP Address:</Text>{' '}
                                <Text code>{selectedIssue.metadata?.ip_address}</Text>
                              </div>
                            )}
                            {selectedIssue.metadata?.user_agent && (
                              <div style={{ marginBottom: 8 }}>
                                <Text strong>💻 User Agent:</Text>{' '}
                                <Text style={{ fontSize: '11px', color: '#666' }}>
                                  {selectedIssue.metadata?.user_agent}
                                </Text>
                              </div>
                            )}
                            {selectedIssue.metadata?.upload_method && (
                              <div style={{ marginBottom: 8 }}>
                                <Text strong>📤 Upload Method:</Text>{' '}
                                <Tag color={
                                  selectedIssue.metadata?.upload_method === 'web' ? 'blue' :
                                  selectedIssue.metadata?.upload_method === 'cli' ? 'purple' : 'green'
                                }>
                                  {selectedIssue.metadata?.upload_method.toUpperCase()}
                                </Tag>
                              </div>
                            )}
                            {selectedIssue.metadata?.upload_time && (
                              <div style={{ marginBottom: 8 }}>
                                <Text strong>⏰ Upload Time:</Text>{' '}
                                <Text>{new Date(selectedIssue.metadata?.upload_time).toLocaleString('vi-VN')}</Text>
                              </div>
                            )}
                            {selectedIssue.metadata?.referer && (
                              <div>
                                <Text strong>🔗 Referer:</Text>{' '}
                                <Text code style={{ fontSize: '11px' }}>{selectedIssue.metadata?.referer}</Text>
                              </div>
                            )}
                          </div>
                        </div>
                      )}

                      {/* Raw Metadata JSON */}
                      {hasMetadata && (
                        <div>
                          <Title level={5} style={{ marginBottom: 12 }}>📝 Raw Metadata (JSON)</Title>
                          <pre style={{
                            background: '#f5f5f5',
                            padding: '12px',
                            borderRadius: '4px',
                            overflow: 'auto',
                            fontSize: '12px',
                            maxHeight: '300px',
                            border: '1px solid #e8e8e8'
                          }}>
                            {JSON.stringify(selectedIssue.metadata, null, 2)}
                          </pre>
                        </div>
                      )}

                      {/* Raw Data (if different from metadata) */}
                      {hasRawData && (
                        <div>
                          <Title level={5} style={{ marginBottom: 12 }}>🗃️ Additional Data</Title>
                          <pre style={{
                            background: '#f5f5f5',
                            padding: '12px',
                            borderRadius: '4px',
                            overflow: 'auto',
                            fontSize: '12px',
                            maxHeight: '300px',
                            border: '1px solid #e8e8e8'
                          }}>
                            {JSON.stringify(selectedIssue.raw_data, null, 2)}
                          </pre>
                        </div>
                      )}
                    </Space>
                  </Panel>
                </Collapse>
              );
            })()}
          </Space>
        )}
      </Drawer>

      {/* Ignore Modal */}
      <Modal
        title={`🚫 ${t('issues.ignoreIssue')}`}
        open={ignoreModal}
        onOk={handleIgnore}
        onCancel={() => setIgnoreModal(false)}
        okText={t('issues.ignore')}
        cancelText={t('common.cancel')}
      >
        <Space direction="vertical" style={{ width: '100%' }}>
          <Text>{t('issues.ignoreReason')}</Text>
          <TextArea
            rows={4}
            value={ignoreReason}
            onChange={(e) => setIgnoreReason(e.target.value)}
            placeholder={t('issues.optionalReason')}
          />
        </Space>
      </Modal>

      {/* Resolve Modal */}
      <Modal
        title={`✅ ${t('issues.resolveIssue')}`}
        open={resolveModal}
        onOk={handleResolve}
        onCancel={() => setResolveModal(false)}
        okText={t('issues.resolve')}
        cancelText={t('common.cancel')}
      >
        <Space direction="vertical" style={{ width: '100%' }}>
          <Text>{t('issues.resolutionNotes')}</Text>
          <TextArea
            rows={4}
            value={resolutionNotes}
            onChange={(e) => setResolutionNotes(e.target.value)}
            placeholder={t('issues.resolutionPlaceholder')}
          />
        </Space>
      </Modal>
    </div>
  );
};

export default Issues;

