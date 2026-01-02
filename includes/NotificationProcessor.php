<?php
namespace Puleeno\SecurityBot\WebMonitor;

/**
 * Notification Processor
 *
 * Xử lý notification queue via cron
 */
class NotificationProcessor
{
    private static $instance = null;

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
     * Process notifications cron job
     *
     * @return void
     */
    public function processNotificationsCron(): void
    {
        $manager = NotificationManager::getInstance();

        $processed = $manager->processPendingNotifications();

        if (WP_DEBUG && $processed > 0) {
            error_log("[WP Security Monitor] Processed {$processed} pending notifications");
        }
    }
}

