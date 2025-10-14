import React from 'react';
import { Spin, Space } from 'antd';
import { LoadingOutlined } from '@ant-design/icons';

interface PageLoadingProps {
  message?: string;
  fullScreen?: boolean;
}

const PageLoading: React.FC<PageLoadingProps> = ({
  message = 'Đang tải...',
  fullScreen = false
}) => {
  const loadingIcon = <LoadingOutlined style={{ fontSize: 48 }} spin />;

  const content = (
    <Space direction="vertical" align="center" size="large">
      <Spin indicator={loadingIcon} />
      <div style={{ fontSize: 16, color: '#666' }}>{message}</div>
    </Space>
  );

  if (fullScreen) {
    return (
      <div style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'rgba(255, 255, 255, 0.9)',
        zIndex: 9999,
      }}>
        {content}
      </div>
    );
  }

  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: '400px',
      padding: '40px',
    }}>
      {content}
    </div>
  );
};

export default PageLoading;

