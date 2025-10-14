import React from 'react';
import { Card, Typography } from 'antd';

const { Title } = Typography;

const Settings: React.FC = () => {
  return (
    <div>
      <Title level={2}>⚙️ Settings</Title>
      <Card>
        <p>Settings page - Coming soon with React UI</p>
      </Card>
    </div>
  );
};

export default Settings;

