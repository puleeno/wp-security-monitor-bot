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

        foreach ($this->channels as $channel) {
            if (!$channel->isAvailable()) {
                continue;
            }

            try {
                $channel->send($message, [
                    'issuer' => $issuerName,
                    'issues' => $issues,
                    'timestamp' => time(),
                    'site_url' => home_url()
                ]);
            } catch (\Exception $e) {
                error_log(sprintf('Error sending notification via %s: %s', $channel->getName(), $e->getMessage()));
            }
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

        $message = "🚨 *Cảnh báo bảo mật - {$siteName}*\n\n";
        $message .= "📍 *Website:* {$siteUrl}\n";
        $message .= "🔍 *Phát hiện bởi:* {$issuerName}\n";
        $message .= "⏰ *Thời gian:* " . date('d/m/Y H:i:s') . "\n\n";

        $message .= "📋 *Chi tiết vấn đề:*\n";
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
