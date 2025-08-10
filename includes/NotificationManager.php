<?php
namespace Puleeno\SecurityBot\WebMonitor;

use Puleeno\SecurityBot\WebMonitor\Database\Schema;

class NotificationManager
{
    /**
     * @var NotificationManager
     */
    private static $instance;

    /**
     * @var string
     */
    private $notificationsTable;

    private function __construct()
    {
        global $wpdb;
        $this->notificationsTable = $wpdb->prefix . Schema::TABLE_NOTIFICATIONS;
    }

    public static function getInstance(): NotificationManager
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Thêm notification vào queue
     *
     * @param string $channelName
     * @param int $issueId
     * @param string $message
     * @param array $context
     * @return int|false Notification ID hoặc false nếu lỗi
     */
    public function queueNotification(string $channelName, int $issueId, string $message, array $context = []): int|false
    {
        global $wpdb;

        $data = [
            'channel_name' => $channelName,
            'issue_id' => $issueId,
            'message' => $message,
            'context' => json_encode($context),
            'status' => 'pending',
            'created_at' => current_time('mysql')
        ];

        $inserted = $wpdb->insert($this->notificationsTable, $data);

        if (WP_DEBUG) {
            error_log("[NotificationManager] Queued notification for channel: {$channelName}, issue: {$issueId}");
        }

        return $inserted ? $wpdb->insert_id : false;
    }

    /**
     * Lấy danh sách notifications pending
     *
     * @param int $limit
     * @return array
     */
    public function getPendingNotifications(int $limit = 50): array
    {
        global $wpdb;

        $sql = $wpdb->prepare(
            "SELECT * FROM {$this->notificationsTable}
             WHERE status = 'pending'
             ORDER BY created_at ASC
             LIMIT %d",
            $limit
        );

        return $wpdb->get_results($sql, ARRAY_A);
    }

    /**
     * Cập nhật trạng thái notification
     *
     * @param int $notificationId
     * @param string $status
     * @param string|null $errorMessage
     * @return bool
     */
    public function updateNotificationStatus(int $notificationId, string $status, ?string $errorMessage = null): bool
    {
        global $wpdb;

        $data = [
            'status' => $status,
            'updated_at' => current_time('mysql')
        ];

        if ($status === 'sent') {
            $data['sent_at'] = current_time('mysql');
        } elseif ($status === 'failed' || $status === 'retry') {
            $data['last_attempt'] = current_time('mysql');
            $data['retry_count'] = $wpdb->prepare('retry_count + 1');
            if ($errorMessage) {
                $data['error_message'] = $errorMessage;
            }
        }

        $updated = $wpdb->update(
            $this->notificationsTable,
            $data,
            ['id' => $notificationId]
        );

        if (WP_DEBUG) {
            error_log("[NotificationManager] Updated notification {$notificationId} status to: {$status}");
        }

        return $updated !== false;
    }

    /**
     * Xóa notifications cũ (đã sent hoặc failed)
     *
     * @param int $daysToKeep
     * @return int Số notifications đã xóa
     */
    public function cleanupOldNotifications(int $daysToKeep = 7): int
    {
        global $wpdb;

        $cutoffDate = date('Y-m-d H:i:s', strtotime("-{$daysToKeep} days"));

        $deleted = $wpdb->query($wpdb->prepare(
            "DELETE FROM {$this->notificationsTable}
             WHERE (status = 'sent' OR status = 'failed')
             AND created_at < %s",
            $cutoffDate
        ));

        if (WP_DEBUG) {
            error_log("[NotificationManager] Cleaned up {$deleted} old notifications");
        }

        return $deleted;
    }

    /**
     * Lấy thống kê notifications
     *
     * @return array
     */
    public function getStats(): array
    {
        global $wpdb;

        $stats = $wpdb->get_results(
            "SELECT
                status,
                COUNT(*) as count,
                COUNT(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR) THEN 1 END) as last_24h
             FROM {$this->notificationsTable}
             GROUP BY status",
            ARRAY_A
        );

        $total = array_sum(array_column($stats, 'count'));
        $pending = $wpdb->get_var("SELECT COUNT(*) FROM {$this->notificationsTable} WHERE status = 'pending'");

        return [
            'total' => $total,
            'pending' => $pending,
            'by_status' => $stats
        ];
    }
}
