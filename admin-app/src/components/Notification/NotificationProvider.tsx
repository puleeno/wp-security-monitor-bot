import React, { useEffect } from 'react';
import { notification } from 'antd';
import { useDispatch, useSelector } from 'react-redux';
import type { RootState } from '../../store';
import { removeNotification } from '../../reducers/uiReducer';

const NotificationProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const dispatch = useDispatch();
  const notifications = useSelector((state: RootState) => state.ui.notifications);
  const [api, contextHolder] = notification.useNotification();

  useEffect(() => {
    notifications.forEach((notif) => {
      api[notif.type]({
        message: notif.message,
        duration: 4,
        onClose: () => {
          dispatch(removeNotification(notif.id));
        },
      });

      // Auto remove from store
      setTimeout(() => {
        dispatch(removeNotification(notif.id));
      }, 100);
    });
  }, [notifications, api, dispatch]);

  return (
    <>
      {contextHolder}
      {children}
    </>
  );
};

export default NotificationProvider;

