<?php

namespace Puleeno\SecurityBot\WebMonitor\Channels;

use Puleeno\SecurityBot\WebMonitor\Abstracts\Channel;

/**
 * SlackChannel
 *
 * Gửi notifications tới Slack workspace qua Incoming Webhooks
 *
 * @package Puleeno\SecurityBot\WebMonitor\Channels
 */
class SlackChannel extends Channel
{
    /**
     * Slack webhook URL
     */
    private string $webhookUrl = '';

    /**
     * Default channel to send messages
     */
    private string $defaultChannel = '#security';

    /**
     * Bot username for messages
     */
    private string $botUsername = 'Security Monitor Bot';

    /**
     * Bot icon emoji
     */
    private string $iconEmoji = ':warning:';

    /**
     * Get channel name
     */
    public function getName(): string
    {
        return 'Slack';
    }

    /**
     * Send message to Slack
     */
    public function send(string $message, array $data = []): bool
    {
        if (!$this->isAvailable()) {
            $this->logError('Slack channel is not properly configured');
            return false;
        }

        try {
            $payload = $this->buildSlackPayload($message, $data);
            $response = $this->sendToSlack($payload);

            if ($response === false) {
                $this->logError('Failed to send message to Slack');
                return false;
            }

            return true;

        } catch (\Exception $e) {
            $this->logError('Slack send error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Check connection to Slack
     */
    protected function checkConnection(): bool
    {
        if (empty($this->webhookUrl)) {
            return false;
        }

        // Test với một message đơn giản
        $testPayload = [
            'text' => 'WP Security Monitor Bot - Connection Test',
            'channel' => $this->getConfig('channel', $this->defaultChannel),
            'username' => $this->botUsername,
            'icon_emoji' => $this->iconEmoji
        ];

        $response = $this->sendToSlack($testPayload);
        return $response !== false;
    }

    /**
     * Configure channel
     */
    public function configure(array $config): void
    {
        parent::configure($config);

        $this->webhookUrl = $this->getConfig('webhook_url', '');
        $this->defaultChannel = $this->getConfig('channel', '#security');
        $this->botUsername = $this->getConfig('username', 'Security Monitor Bot');
        $this->iconEmoji = $this->getConfig('icon_emoji', ':warning:');
    }

    /**
     * Build Slack payload từ message và data
     */
    private function buildSlackPayload(string $message, array $data): array
    {
        $issuer = $data['issuer'] ?? 'Unknown';
        $issues = $data['issues'] ?? [];
        $siteUrl = get_site_url();
        $siteName = get_bloginfo('name');

        // Base payload
        $payload = [
            'channel' => $this->getConfig('channel', $this->defaultChannel),
            'username' => $this->botUsername,
            'icon_emoji' => $this->iconEmoji,
            'text' => $this->formatMainMessage($issuer, count($issues), $siteName),
            'attachments' => []
        ];

        // Tạo attachment chính
        $mainAttachment = [
            'color' => $this->getColorForSeverity($issues),
            'title' => "🚨 Security Alert - {$siteName}",
            'title_link' => $siteUrl,
            'text' => $this->formatIssuesText($issues),
            'fields' => $this->buildFields($issuer, $issues, $siteUrl),
            'footer' => 'WP Security Monitor Bot',
            'footer_icon' => 'https://wordpress.org/favicon.ico',
            'ts' => time()
        ];

        $payload['attachments'][] = $mainAttachment;

        // Thêm individual issue attachments nếu có nhiều issues
        if (count($issues) > 1) {
            foreach (array_slice($issues, 0, 3) as $index => $issue) { // Limit to 3 để tránh spam
                $payload['attachments'][] = $this->buildIssueAttachment($issue, $index + 1);
            }

            if (count($issues) > 3) {
                $payload['attachments'][] = [
                    'color' => '#36a64f',
                    'text' => sprintf('... và %d issues khác. Kiểm tra admin dashboard để xem tất cả.', count($issues) - 3)
                ];
            }
        }

        return $payload;
    }

    /**
     * Format main message
     */
    private function formatMainMessage(string $issuer, int $issueCount, string $siteName): string
    {
        if ($issueCount === 1) {
            return "🚨 *Security alert detected* on *{$siteName}* by _{$issuer}_";
        } else {
            return "🚨 *{$issueCount} security alerts detected* on *{$siteName}* by _{$issuer}_";
        }
    }

    /**
     * Format issues text
     */
    private function formatIssuesText(array $issues): string
    {
        if (empty($issues)) {
            return 'No specific details available.';
        }

        $firstIssue = $issues[0];
        $text = "• *" . ($firstIssue['message'] ?? 'Security issue detected') . "*";

        if (isset($firstIssue['file_path'])) {
            $text .= "\n  📁 File: `" . $firstIssue['file_path'] . "`";
        }

        if (isset($firstIssue['ip_address'])) {
            $text .= "\n  🌐 IP: `" . $firstIssue['ip_address'] . "`";
        }

        if (count($issues) > 1) {
            $text .= "\n\n_And " . (count($issues) - 1) . " more issues..._";
        }

        return $text;
    }

    /**
     * Build fields array cho attachment
     */
    private function buildFields(string $issuer, array $issues, string $siteUrl): array
    {
        $fields = [
            [
                'title' => 'Issuer',
                'value' => $issuer,
                'short' => true
            ],
            [
                'title' => 'Issues Count',
                'value' => count($issues),
                'short' => true
            ]
        ];

        // Thêm severity nếu có
        $severities = array_column($issues, 'severity');
        $uniqueSeverities = array_unique(array_filter($severities));
        if (!empty($uniqueSeverities)) {
            $fields[] = [
                'title' => 'Severity',
                'value' => strtoupper(implode(', ', $uniqueSeverities)),
                'short' => true
            ];
        }

        // Thêm timestamp
        $fields[] = [
            'title' => 'Detected At',
            'value' => current_time('Y-m-d H:i:s'),
            'short' => true
        ];

        // Link tới admin dashboard
        $adminUrl = admin_url('tools.php?page=wp-security-monitor-issues');
        $fields[] = [
            'title' => 'Actions',
            'value' => "<{$adminUrl}|View in Dashboard> | <{$siteUrl}|Visit Site>",
            'short' => false
        ];

        return $fields;
    }

    /**
     * Build attachment cho individual issue
     */
    private function buildIssueAttachment(array $issue, int $index): array
    {
        $severity = $issue['severity'] ?? 'medium';
        $color = $this->getSeverityColor($severity);

        $attachment = [
            'color' => $color,
            'title' => "Issue #{$index}: " . ($issue['message'] ?? 'Security Issue'),
            'text' => $this->formatIssueDetails($issue),
            'fields' => []
        ];

        // Thêm fields cho issue details
        if (isset($issue['type'])) {
            $attachment['fields'][] = [
                'title' => 'Type',
                'value' => $issue['type'],
                'short' => true
            ];
        }

        if (isset($issue['severity'])) {
            $attachment['fields'][] = [
                'title' => 'Severity',
                'value' => strtoupper($issue['severity']),
                'short' => true
            ];
        }

        return $attachment;
    }

    /**
     * Format issue details
     */
    private function formatIssueDetails(array $issue): string
    {
        $details = [];

        if (isset($issue['details']) && !empty($issue['details'])) {
            // Truncate nếu quá dài
            $detailText = $issue['details'];
            if (strlen($detailText) > 200) {
                $detailText = substr($detailText, 0, 200) . '...';
            }
            $details[] = $detailText;
        }

        if (isset($issue['file_path'])) {
            $details[] = "📁 *File:* `{$issue['file_path']}`";
        }

        if (isset($issue['ip_address'])) {
            $details[] = "🌐 *IP:* `{$issue['ip_address']}`";
        }

        if (isset($issue['domain'])) {
            $details[] = "🔗 *Domain:* `{$issue['domain']}`";
        }

        return implode("\n", $details);
    }

    /**
     * Get color dựa trên severity của issues
     */
    private function getColorForSeverity(array $issues): string
    {
        if (empty($issues)) {
            return '#36a64f'; // good/green
        }

        $severities = array_column($issues, 'severity');

        if (in_array('critical', $severities)) {
            return '#ff0000'; // red
        } elseif (in_array('high', $severities)) {
            return '#ff6600'; // orange
        } elseif (in_array('medium', $severities)) {
            return '#ffcc00'; // yellow
        } else {
            return '#36a64f'; // green
        }
    }

    /**
     * Get color cho specific severity
     */
    private function getSeverityColor(string $severity): string
    {
        $colors = [
            'critical' => '#ff0000',
            'high' => '#ff6600',
            'medium' => '#ffcc00',
            'low' => '#36a64f'
        ];

        return $colors[$severity] ?? '#36a64f';
    }

    /**
     * Send payload tới Slack webhook
     */
    private function sendToSlack(array $payload): bool
    {
        $jsonPayload = json_encode($payload);

        $args = [
            'method' => 'POST',
            'headers' => [
                'Content-Type' => 'application/json',
            ],
            'body' => $jsonPayload,
            'timeout' => 30,
            'user-agent' => 'WP Security Monitor Bot/1.0'
        ];

        $response = wp_remote_post($this->webhookUrl, $args);

        if (is_wp_error($response)) {
            $this->logError('Slack API error: ' . $response->get_error_message());
            return false;
        }

        $responseCode = wp_remote_retrieve_response_code($response);
        $responseBody = wp_remote_retrieve_body($response);

        if ($responseCode !== 200) {
            $this->logError("Slack API returned {$responseCode}: {$responseBody}");
            return false;
        }

        // Slack trả về "ok" nếu thành công
        if (trim($responseBody) !== 'ok') {
            $this->logError("Slack API unexpected response: {$responseBody}");
            return false;
        }

        return true;
    }

    /**
     * Test connection method
     */
    public function testConnection(): array
    {
        if (!$this->isAvailable()) {
            return [
                'success' => false,
                'message' => 'Slack channel not properly configured. Check webhook URL.'
            ];
        }

        try {
            $testPayload = [
                'text' => '🧪 Test message from WP Security Monitor Bot',
                'channel' => $this->getConfig('channel', $this->defaultChannel),
                'username' => $this->botUsername,
                'icon_emoji' => ':white_check_mark:',
                'attachments' => [
                    [
                        'color' => '#36a64f',
                        'title' => 'Connection Test Successful',
                        'text' => 'Your Slack integration is working correctly!',
                        'fields' => [
                            [
                                'title' => 'Website',
                                'value' => get_bloginfo('name'),
                                'short' => true
                            ],
                            [
                                'title' => 'Test Time',
                                'value' => current_time('Y-m-d H:i:s'),
                                'short' => true
                            ]
                        ],
                        'footer' => 'WP Security Monitor Bot',
                        'ts' => time()
                    ]
                ]
            ];

            $success = $this->sendToSlack($testPayload);

            if ($success) {
                return [
                    'success' => true,
                    'message' => 'Test message sent successfully to Slack!'
                ];
            } else {
                return [
                    'success' => false,
                    'message' => 'Failed to send test message. Check your webhook URL and channel.'
                ];
            }

        } catch (\Exception $e) {
            return [
                'success' => false,
                'message' => 'Connection test failed: ' . $e->getMessage()
            ];
        }
    }

    /**
     * Get suggested configuration
     */
    public static function getSuggestedConfig(): array
    {
        return [
            'webhook_url' => [
                'type' => 'url',
                'label' => 'Slack Webhook URL',
                'description' => 'Create an Incoming Webhook at https://api.slack.com/apps',
                'required' => true,
                'placeholder' => 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'
            ],
            'channel' => [
                'type' => 'text',
                'label' => 'Slack Channel',
                'description' => 'Channel hoặc user để gửi notifications (có thể override webhook default)',
                'required' => false,
                'placeholder' => '#security, @username, hoặc để trống để dùng webhook default',
                'default' => '#security'
            ],
            'username' => [
                'type' => 'text',
                'label' => 'Bot Username',
                'description' => 'Tên hiển thị của bot trong Slack',
                'required' => false,
                'default' => 'Security Monitor Bot'
            ],
            'icon_emoji' => [
                'type' => 'text',
                'label' => 'Bot Icon Emoji',
                'description' => 'Emoji icon cho bot (e.g., :warning:, :shield:, :robot_face:)',
                'required' => false,
                'placeholder' => ':warning:',
                'default' => ':warning:'
            ]
        ];
    }

    /**
     * Validate configuration
     */
    public function validateConfig(array $config): array
    {
        $errors = [];

        // Check webhook URL
        if (empty($config['webhook_url'])) {
            $errors[] = 'Webhook URL is required';
        } elseif (!filter_var($config['webhook_url'], FILTER_VALIDATE_URL)) {
            $errors[] = 'Webhook URL must be a valid URL';
        } elseif (strpos($config['webhook_url'], 'hooks.slack.com') === false) {
            $errors[] = 'Webhook URL must be a Slack webhook URL';
        }

        // Check channel format
        if (!empty($config['channel'])) {
            $channel = trim($config['channel']);
            if (!preg_match('/^[#@]/', $channel)) {
                $errors[] = 'Channel must start with # (for channels) or @ (for users)';
            }
        }

        // Check emoji format
        if (!empty($config['icon_emoji'])) {
            $emoji = trim($config['icon_emoji']);
            if (!preg_match('/^:[a-z0-9_+-]+:$/', $emoji)) {
                $errors[] = 'Icon emoji must be in format :emoji_name:';
            }
        }

        return $errors;
    }
}
