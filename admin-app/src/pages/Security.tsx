import React from 'react';
import { Card, Typography } from 'antd';

const { Title } = Typography;

const Security: React.FC = () => {
  return (
    <div>
      <Title level={2}>🔒 Security Status</Title>
      <Card>
        <p>Security status page - Coming soon with React UI</p>
      </Card>
    </div>
  );
};

export default Security;

