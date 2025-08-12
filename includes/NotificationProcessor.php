<?php
namespace Puleeno\SecurityBot\WebMonitor;

class NotificationProcessor
{
    /**
     * @var NotificationProcessor
     */
    private static $instance;

    /**
     * @var NotificationManager
     */
    private $notificationManager;

    /**
     * @var Bot
     */
    private $bot;

    private function __construct()
    {
        $this->notificationManager = NotificationManager::getInstance();
        $this->bot = Bot::getInstance();

        // Hook cho immediate processing
        add_action('wp_security_monitor_process_notifications_immediate', [$this, 'processNotificationsImmediate']);
    }

    public static function getInstance(): NotificationProcessor
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Xử lý tất cả notifications pending
     *
     * @return array Kết quả xử lý
     */
    public function processPendingNotifications(): array
    {
        $results = [
            'processed' => 0,
            'success' => 0,
            'failed' => 0,
            'retry' => 0
        ];

        // Lấy notifications pending
        $pendingNotifications = $this->notificationManager->getPendingNotifications(100);

        if (empty($pendingNotifications)) {
            if (WP_DEBUG) {
                error_log("[NotificationProcessor] No pending notifications to process");
            }
            return $results;
        }

        if (WP_DEBUG) {
            error_log("[NotificationProcessor] Processing " . count($pendingNotifications) . " pending notifications");
        }

        foreach ($pendingNotifications as $notification) {
            $result = $this->processNotification($notification);
            $results['processed']++;

            switch ($result['status']) {
                case 'success':
                    $results['success']++;
                    break;
                case 'failed':
                    $results['failed']++;
                    break;
                case 'retry':
                    $results['retry']++;
                    break;
            }
        }

        if (WP_DEBUG) {
            error_log("[NotificationProcessor] Processed {$results['processed']} notifications: " .
                     "{$results['success']} success, {$results['failed']} failed, {$results['retry']} retry");
        }

        return $results;
    }

    /**
     * Xử lý một notification cụ thể
     *
     * @param array $notification
     * @return array Kết quả xử lý
     */
    private function processNotification(array $notification): array
    {
        $notificationId = $notification['id'];
        $channelName = $notification['channel_name'];
        $message = $notification['message'];
        $context = json_decode($notification['context'], true) ?: [];

        // Debug logging
        if (WP_DEBUG) {
            error_log("[NotificationProcessor] Processing notification {$notificationId} for channel {$channelName}");
            error_log("[NotificationProcessor] Message: " . $message);
            error_log("[NotificationProcessor] Context: " . json_encode($context));
        }

        try {
            // Lấy channel từ bot
            $channel = $this->bot->getChannel($channelName);

            if (!$channel) {
                $errorMessage = "Channel {$channelName} not found";
                $this->notificationManager->updateNotificationStatus($notificationId, 'failed', $errorMessage);

                if (WP_DEBUG) {
                    error_log("[NotificationProcessor] Failed to process notification {$notificationId}: {$errorMessage}");
                }

                return ['status' => 'failed', 'error' => $errorMessage];
            }

            // Kiểm tra channel có available không
            if (!$channel->isAvailable()) {
                $errorMessage = "Channel {$channelName} is not available";
                $this->notificationManager->updateNotificationStatus($notificationId, 'retry', $errorMessage);

                if (WP_DEBUG) {
                    error_log("[NotificationProcessor] Channel {$channelName} not available, will retry later");
                }

                return ['status' => 'retry', 'error' => $errorMessage];
            }

            // Gửi notification
            $sent = $channel->send($message, $context);

            if ($sent) {
                $this->notificationManager->updateNotificationStatus($notificationId, 'sent');

                if (WP_DEBUG) {
                    error_log("[NotificationProcessor] Successfully sent notification {$notificationId} via {$channelName}");
                }

                return ['status' => 'success'];
            } else {
                $errorMessage = "Failed to send via channel {$channelName}";
                $this->notificationManager->updateNotificationStatus($notificationId, 'failed', $errorMessage);

                if (WP_DEBUG) {
                    error_log("[NotificationProcessor] Failed to send notification {$notificationId} via {$channelName}");
                }

                return ['status' => 'failed', 'error' => $errorMessage];
            }

        } catch (\Exception $e) {
            $errorMessage = "Exception: " . $e->getMessage();
            $this->notificationManager->updateNotificationStatus($notificationId, 'failed', $errorMessage);

            if (WP_DEBUG) {
                error_log("[NotificationProcessor] Exception processing notification {$notificationId}: " . $e->getMessage());
            }

            return ['status' => 'failed', 'error' => $errorMessage];
        }
    }

    /**
     * Xử lý notifications theo cron job
     *
     * @return void
     */
    public function processNotificationsCron(): void
    {
        if (WP_DEBUG) {
            error_log("[NotificationProcessor] Cron job triggered for processing notifications");
        }

        $results = $this->processPendingNotifications();

        // Cleanup old notifications
        $cleaned = $this->notificationManager->cleanupOldNotifications(7);

        if (WP_DEBUG) {
            error_log("[NotificationProcessor] Cron job completed. Cleaned up {$cleaned} old notifications");
        }
    }

    /**
     * Xử lý notifications ngay lập tức (cho testing)
     *
     * @return array
     */
    public function processNotificationsImmediate(): array
    {
        if (WP_DEBUG) {
            error_log("[NotificationProcessor] Immediate processing triggered");
        }

        return $this->processPendingNotifications();
    }
}
