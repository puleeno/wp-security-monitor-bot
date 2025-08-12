<?php
namespace Puleeno\SecurityBot\WebMonitor\Abstracts;

use Puleeno\SecurityBot\WebMonitor\Interfaces\MonitorInterface;
use Puleeno\SecurityBot\WebMonitor\Interfaces\IssuerInterface;
use Puleeno\SecurityBot\WebMonitor\Interfaces\ChannelInterface;

abstract class MonitorAbstract implements MonitorInterface
{
    /**
     * @var IssuerInterface[]
     */
    protected $issuers = [];

    /**
     * @var ChannelInterface[]
     */
    protected $channels = [];

    /**
     * @var bool
     */
    protected $isRunning = false;

    /**
     * @var array
     */
    protected $config = [];

    public function addIssuer(IssuerInterface $issuer): void
    {
        $this->issuers[] = $issuer;
    }

    public function addChannel(ChannelInterface $channel): void
    {
        $this->channels[] = $channel;
    }

    public function isRunning(): bool
    {
        return $this->isRunning;
    }

    public function runCheck(): array
    {
        $issues = [];

        foreach ($this->issuers as $issuer) {
            if (!$issuer->isEnabled()) {
                continue;
            }

            try {
                $detectedIssues = $issuer->detect();
                if (!empty($detectedIssues)) {
                    $issues[$issuer->getName()] = $detectedIssues;
                    $this->sendNotifications($issuer->getName(), $detectedIssues);
                }
            } catch (\Exception $e) {
                error_log(sprintf('Error in issuer %s: %s', $issuer->getName(), $e->getMessage()));
            }
        }

        return $issues;
    }

    /**
     * Gửi thông báo qua tất cả các channel
     *
     * @param string $issuerName
     * @param array $issues
     * @return void
     */
    protected function sendNotifications(string $issuerName, array $issues): void
    {
        $message = $this->formatMessage($issuerName, $issues);

        // Debug: Log notification attempt
        if (WP_DEBUG) {
            error_log("[Monitor Debug] Attempting to send notifications for issuer: {$issuerName}");
            error_log("[Monitor Debug] Total channels available: " . count($this->channels));
            error_log("[Monitor Debug] Message content: " . substr($message, 0, 200) . "...");
        }

        foreach ($this->channels as $channel) {
            $channelName = $channel->getName();

            // Debug: Log channel check
            if (WP_DEBUG) {
                error_log("[Monitor Debug] Checking channel: {$channelName}");
            }

            if (!$channel->isAvailable()) {
                if (WP_DEBUG) {
                    error_log("[Monitor Debug] Channel {$channelName} is NOT available - skipping");
                }
                continue;
            }

            if (WP_DEBUG) {
                error_log("[Monitor Debug] Channel {$channelName} is available - attempting to send");
            }

            try {
                $result = $channel->send($message, [
                    'issuer' => $issuerName,
                    'issues' => $issues,
                    'timestamp' => time(),
                    'site_url' => home_url()
                ]);

                if (WP_DEBUG) {
                    error_log("[Monitor Debug] Channel {$channelName} send result: " . ($result ? 'SUCCESS' : 'FAILED'));
                }
            } catch (\Exception $e) {
                error_log(sprintf('Error sending notification via %s: %s', $channel->getName(), $e->getMessage()));
                if (WP_DEBUG) {
                    error_log("[Monitor Debug] Channel {$channelName} exception: " . $e->getMessage());
                }
            }
        }

        if (WP_DEBUG) {
            error_log("[Monitor Debug] Notification sending completed for issuer: {$issuerName}");
        }
    }

    /**
     * Format thông báo
     *
     * @param string $issuerName
     * @param array $issues
     * @return string
     */
    protected function formatMessage(string $issuerName, array $issues): string
    {
        $siteUrl = home_url();
        $siteName = get_bloginfo('name');

        $message = "🔒 *SECURITY ALERT*\n";
        $message .= str_repeat('─', 30) . "\n\n";

        $message .= "📋 *System Information*\n";
        $message .= "• *Website:* {$siteName}\n";
        $message .= "• *URL:* {$siteUrl}\n";
        $message .= "• *Detected by:* {$issuerName}\n";
        $message .= "• *Time:* " . date('d/m/Y H:i:s') . "\n\n";

        $message .= "🚨 *Security Issues Detected:*\n";
        foreach ($issues as $issue) {
            if (is_array($issue)) {
                $message .= "• " . ($issue['message'] ?? 'Unknown issue') . "\n";
                if (isset($issue['details'])) {
                    $message .= "  └ " . $issue['details'] . "\n";
                }
            } else {
                $message .= "• {$issue}\n";
            }
        }

        $message .= "\n⚠️ *Action Required:* Please review and take appropriate security measures.";

        return $message;
    }

    /**
     * Cấu hình monitor
     *
     * @param array $config
     * @return void
     */
    public function configure(array $config): void
    {
        $this->config = array_merge($this->config, $config);
    }
}
