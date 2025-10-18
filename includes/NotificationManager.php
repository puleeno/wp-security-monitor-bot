<?php
namespace Puleeno\SecurityBot\WebMonitor;

/**
 * Notification Manager
 *
 * Quản lý notification queue và tracking
 */
class NotificationManager
{
    private static $instance = null;

    /**
     * @var int Last inserted notification ID
     */
    private $lastInsertedId = 0;

    private function __construct()
    {
        // Private constructor for singleton
    }

    public static function getInstance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Queue notification
     *
     * @param string $channelName
     * @param int $issueId
     * @param string $message
     * @param array $context
     * @return int|false Notification ID hoặc false nếu thất bại
     */
    public function queueNotification(string $channelName, int $issueId, string $message, array $context)
    {
        global $wpdb;

        $table = $wpdb->prefix . 'security_monitor_notifications';

        // Dedup: nếu đã có bản ghi pending cùng issue_id + channel + message thì không thêm nữa
        $existingId = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM $table WHERE issue_id = %d AND channel_name = %s AND status = 'pending' AND message = %s LIMIT 1",
            $issueId,
            $channelName,
            $message
        ));

        if ($existingId) {
            $this->lastInsertedId = (int) $existingId;
            return $this->lastInsertedId;
        }

        // Insert notification record
        $result = $wpdb->insert(
            $table,
            [
                'issue_id' => $issueId,
                'channel_name' => $channelName,
                'message' => $message,
                'context' => json_encode($context),
                'status' => 'pending',
                'created_at' => current_time('mysql'),
            ],
            ['%d', '%s', '%s', '%s', '%s', '%s']
        );

        if ($result) {
            $this->lastInsertedId = $wpdb->insert_id;
            return $this->lastInsertedId;
        }

        return false;
    }

    /**
     * Update notification status
     *
     * @param int $notificationId
     * @param string $status 'pending'|'sent'|'failed'
     * @param string $error Error message nếu failed
     * @return bool
     */
    public function updateNotificationStatus(int $notificationId, string $status, string $error = ''): bool
    {
        global $wpdb;

        $table = $wpdb->prefix . 'security_monitor_notifications';

        $data = [
            'status' => $status,
        ];
        $format = ['%s'];

        if ($status === 'sent') {
            $data['sent_at'] = current_time('mysql');
            $format[] = '%s';
        }

        if ($status === 'failed' && !empty($error)) {
            $data['error_message'] = $error;
            $format[] = '%s';
        }

        $result = $wpdb->update(
            $table,
            $data,
            ['id' => $notificationId],
            $format,
            ['%d']
        );

        return $result !== false;
    }

    /**
     * Get last inserted notification ID
     *
     * @return int
     */
    public function getLastInsertedNotificationId(): int
    {
        return $this->lastInsertedId;
    }

    /**
     * Get pending notifications
     *
     * @param int $limit
     * @return array
     */
    public function getPendingNotifications(int $limit = 10): array
    {
        global $wpdb;

        $table = $wpdb->prefix . 'security_monitor_notifications';

        $results = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM $table
                WHERE status = 'pending'
                GROUP BY issue_id, channel_name, message
                ORDER BY created_at ASC
                LIMIT %d",
                $limit
            ),
            ARRAY_A
        );

        return $results ?: [];
    }

    /**
     * Process pending notifications
     *
     * @return int Number of notifications processed
     */
    public function processPendingNotifications(): int
    {
        $notifications = $this->getPendingNotifications(20);
        $processed = 0;

        foreach ($notifications as $notification) {
            // Get channel
            $bot = Bot::getInstance();
            $channel = $bot->getChannel($notification['channel_name']);

            if (!$channel || !$channel->isAvailable()) {
                // Channel not available, mark as failed
                $this->updateNotificationStatus(
                    $notification['id'],
                    'failed',
                    'Channel not available'
                );
                continue;
            }

            // Try to send
            try {
                $context = json_decode($notification['context'], true) ?: [];
                $result = $channel->send($notification['message'], $context);

                if ($result) {
                    $this->updateNotificationStatus($notification['id'], 'sent');
                    $processed++;
                } else {
                    $this->updateNotificationStatus(
                        $notification['id'],
                        'failed',
                        'Channel send returned false'
                    );
                }
            } catch (\Exception $e) {
                $this->updateNotificationStatus(
                    $notification['id'],
                    'failed',
                    $e->getMessage()
                );
            }
        }

        return $processed;
    }
}

