<?php
namespace Puleeno\SecurityBot\WebMonitor;

use WP_REST_Controller;
use WP_REST_Server;
use WP_REST_Request;
use WP_REST_Response;
use WP_Error;
use Puleeno\SecurityBot\WebMonitor\Security\CredentialManager;

class RestApi extends WP_REST_Controller
{
    /**
     * @var string
     */
    protected $namespace = 'wp-security-monitor/v1';

    /**
     * @var IssueManager
     */
    private $issueManager;

    public function __construct()
    {
        $this->issueManager = IssueManager::getInstance();
    }

    /**
     * Register REST API routes
     *
     * @return void
     */
    public function registerRoutes(): void
    {
        // Issues endpoints
        register_rest_route($this->namespace, '/issues', [
            [
                'methods' => WP_REST_Server::READABLE,
                'callback' => [$this, 'getIssues'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
        ]);

        register_rest_route($this->namespace, '/issues/(?P<id>\d+)/viewed', [
            [
                'methods' => WP_REST_Server::CREATABLE,
                'callback' => [$this, 'markAsViewed'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
            [
                'methods' => WP_REST_Server::DELETABLE,
                'callback' => [$this, 'unmarkAsViewed'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
        ]);

        register_rest_route($this->namespace, '/issues/(?P<id>\d+)/ignore', [
            [
                'methods' => WP_REST_Server::CREATABLE,
                'callback' => [$this, 'ignoreIssue'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
        ]);

        register_rest_route($this->namespace, '/issues/(?P<id>\d+)/resolve', [
            [
                'methods' => WP_REST_Server::CREATABLE,
                'callback' => [$this, 'resolveIssue'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
        ]);

        // Stats endpoints
        register_rest_route($this->namespace, '/stats/security', [
            [
                'methods' => WP_REST_Server::READABLE,
                'callback' => [$this, 'getSecurityStats'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
        ]);

        register_rest_route($this->namespace, '/stats/bot', [
            [
                'methods' => WP_REST_Server::READABLE,
                'callback' => [$this, 'getBotStats'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
        ]);

        // Settings endpoints
        register_rest_route($this->namespace, '/settings', [
            [
                'methods' => WP_REST_Server::READABLE,
                'callback' => [$this, 'getSettings'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
            [
                'methods' => WP_REST_Server::CREATABLE,
                'callback' => [$this, 'updateSettings'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
        ]);

        // Test channel endpoints
        register_rest_route($this->namespace, '/test-channel/(?P<channel>[a-z]+)', [
            [
                'methods' => WP_REST_Server::CREATABLE,
                'callback' => [$this, 'testChannel'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
        ]);

        // Migration endpoints
        register_rest_route($this->namespace, '/migration/status', [
            [
                'methods' => WP_REST_Server::READABLE,
                'callback' => [$this, 'getMigrationStatus'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
        ]);

        register_rest_route($this->namespace, '/migration/run', [
            [
                'methods' => WP_REST_Server::CREATABLE,
                'callback' => [$this, 'runMigration'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
        ]);

        register_rest_route($this->namespace, '/migration/changelog', [
            [
                'methods' => WP_REST_Server::READABLE,
                'callback' => [$this, 'getMigrationChangelog'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
        ]);

        // External Redirects endpoints
        register_rest_route($this->namespace, '/redirects', [
            [
                'methods' => WP_REST_Server::READABLE,
                'callback' => [$this, 'getRedirects'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
        ]);

        register_rest_route($this->namespace, '/redirects/(?P<id>\d+)/approve', [
            [
                'methods' => WP_REST_Server::CREATABLE,
                'callback' => [$this, 'approveRedirect'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
        ]);

        register_rest_route($this->namespace, '/redirects/(?P<id>\d+)/reject', [
            [
                'methods' => WP_REST_Server::CREATABLE,
                'callback' => [$this, 'rejectRedirect'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
        ]);
    }

    /**
     * Check permissions
     *
     * @return bool
     */
    public function checkPermissions(): bool
    {
        return current_user_can('manage_options');
    }

    /**
     * Get issues
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response|WP_Error
     */
    public function getIssues(WP_REST_Request $request)
    {
        $page = $request->get_param('page') ?? 1;
        $per_page = $request->get_param('per_page') ?? 20;
        $status = $request->get_param('status') ?? '';
        $severity = $request->get_param('severity') ?? '';
        $issuer = $request->get_param('issuer') ?? '';
        $search = $request->get_param('search') ?? '';

        $args = [
            'page' => (int) $page,
            'per_page' => (int) $per_page,
            'status' => $status,
            'severity' => $severity,
            'issuer' => $issuer,
            'search' => $search,
        ];

        $result = $this->issueManager->getIssues($args);

        return new WP_REST_Response($result, 200);
    }

    /**
     * Mark issue as viewed
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response|WP_Error
     */
    public function markAsViewed(WP_REST_Request $request)
    {
        $issueId = (int) $request->get_param('id');

        if (!$issueId) {
            return new WP_Error('invalid_id', 'Invalid issue ID', ['status' => 400]);
        }

        $success = $this->issueManager->markAsViewed($issueId);

        if ($success) {
            return new WP_REST_Response([
                'success' => true,
                'message' => 'Issue marked as viewed',
            ], 200);
        }

        return new WP_Error('update_failed', 'Failed to mark as viewed', ['status' => 500]);
    }

    /**
     * Unmark issue as viewed
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response|WP_Error
     */
    public function unmarkAsViewed(WP_REST_Request $request)
    {
        $issueId = (int) $request->get_param('id');

        if (!$issueId) {
            return new WP_Error('invalid_id', 'Invalid issue ID', ['status' => 400]);
        }

        $success = $this->issueManager->unmarkAsViewed($issueId);

        if ($success) {
            return new WP_REST_Response([
                'success' => true,
                'message' => 'Unmarked as viewed',
            ], 200);
        }

        return new WP_Error('update_failed', 'Failed to unmark', ['status' => 500]);
    }

    /**
     * Ignore issue
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response|WP_Error
     */
    public function ignoreIssue(WP_REST_Request $request)
    {
        $issueId = (int) $request->get_param('id');
        $reason = sanitize_textarea_field($request->get_param('reason') ?? '');

        if (!$issueId) {
            return new WP_Error('invalid_id', 'Invalid issue ID', ['status' => 400]);
        }

        $success = $this->issueManager->ignoreIssue($issueId, $reason);

        if ($success) {
            return new WP_REST_Response([
                'success' => true,
                'message' => 'Issue ignored',
            ], 200);
        }

        return new WP_Error('update_failed', 'Failed to ignore issue', ['status' => 500]);
    }

    /**
     * Resolve issue
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response|WP_Error
     */
    public function resolveIssue(WP_REST_Request $request)
    {
        $issueId = (int) $request->get_param('id');
        $notes = sanitize_textarea_field($request->get_param('notes') ?? '');

        if (!$issueId) {
            return new WP_Error('invalid_id', 'Invalid issue ID', ['status' => 400]);
        }

        $success = $this->issueManager->resolveIssue($issueId, $notes);

        if ($success) {
            return new WP_REST_Response([
                'success' => true,
                'message' => 'Issue resolved',
            ], 200);
        }

        return new WP_Error('update_failed', 'Failed to resolve issue', ['status' => 500]);
    }

    /**
     * Get security stats
     *
     * @return WP_REST_Response
     */
    public function getSecurityStats()
    {
        $stats = $this->issueManager->getStats();
        return new WP_REST_Response($stats, 200);
    }

    /**
     * Get bot stats
     *
     * @return WP_REST_Response
     */
    public function getBotStats()
    {
        $bot = Bot::getInstance();
        $stats = $bot->getStats();
        return new WP_REST_Response($stats, 200);
    }

    /**
     * Get settings
     *
     * @return WP_REST_Response
     */
    public function getSettings()
    {
        // Load settings từ WordPress options và CredentialManager
        $settings = [
            'telegram' => [
                'enabled' => (bool) get_option('wp_security_monitor_telegram_enabled', false),
                'bot_token' => CredentialManager::getCredential(
                    CredentialManager::TYPE_TELEGRAM_TOKEN
                ) ?? '',
                'chat_id' => CredentialManager::getCredential(
                    CredentialManager::TYPE_TELEGRAM_CHAT_ID
                ) ?? '',
            ],
            'email' => [
                'enabled' => (bool) get_option('wp_security_monitor_email_enabled', false),
                'to' => get_option('wp_security_monitor_email_to', ''),
            ],
            'slack' => [
                'enabled' => (bool) get_option('wp_security_monitor_slack_enabled', false),
                'webhook_url' => CredentialManager::getCredential(
                    CredentialManager::TYPE_SLACK_WEBHOOK
                ) ?? '',
            ],
            'log' => [
                'enabled' => true, // Log always enabled
            ],
        ];

        return new WP_REST_Response($settings, 200);
    }

    /**
     * Update settings
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response
     */
    public function updateSettings(WP_REST_Request $request)
    {
        $settings = $request->get_json_params();

        // Update Telegram settings
        if (isset($settings['telegram'])) {
            update_option('wp_security_monitor_telegram_enabled', $settings['telegram']['enabled'] ?? false);

            if (!empty($settings['telegram']['bot_token'])) {
                CredentialManager::setCredential(
                    CredentialManager::TYPE_TELEGRAM_TOKEN,
                    sanitize_text_field($settings['telegram']['bot_token'])
                );
            }

            if (!empty($settings['telegram']['chat_id'])) {
                CredentialManager::setCredential(
                    CredentialManager::TYPE_TELEGRAM_CHAT_ID,
                    sanitize_text_field($settings['telegram']['chat_id'])
                );
            }
        }

        // Update Email settings
        if (isset($settings['email'])) {
            update_option('wp_security_monitor_email_enabled', $settings['email']['enabled'] ?? false);

            if (!empty($settings['email']['to'])) {
                update_option('wp_security_monitor_email_to', sanitize_email($settings['email']['to']));
            }
        }

        // Update Slack settings
        if (isset($settings['slack'])) {
            update_option('wp_security_monitor_slack_enabled', $settings['slack']['enabled'] ?? false);

            if (!empty($settings['slack']['webhook_url'])) {
                CredentialManager::setCredential(
                    CredentialManager::TYPE_SLACK_WEBHOOK,
                    esc_url_raw($settings['slack']['webhook_url'])
                );
            }
        }

        return new WP_REST_Response([
            'success' => true,
            'message' => 'Settings updated successfully',
        ], 200);
    }

    /**
     * Test channel connection
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response|WP_Error
     */
    public function testChannel(WP_REST_Request $request)
    {
        $channel = $request->get_param('channel');

        if (!in_array($channel, ['telegram', 'email', 'slack'])) {
            return new WP_Error('invalid_channel', 'Invalid channel type', ['status' => 400]);
        }

        try {
            $result = $this->testChannelSendMessage($channel);

            return new WP_REST_Response([
                'success' => $result['success'],
                'message' => $result['message'] ?? ($result['success'] ? 'Test thành công' : 'Test thất bại'),
            ], 200);
        } catch (\Exception $e) {
            return new WP_REST_Response([
                'success' => false,
                'message' => 'Test failed: ' . $e->getMessage(),
            ], 200);
        }
    }

    /**
     * Test gửi tin nhắn test cho channel
     *
     * @param string $channelType
     * @return array
     */
    private function testChannelSendMessage(string $channelType): array
    {
        switch ($channelType) {
            case 'telegram':
                return $this->testTelegramSendMessage();

            case 'email':
                return $this->testEmailSendMessage();

            case 'slack':
                return $this->testSlackSendMessage();

            default:
                return [
                    'success' => false,
                    'message' => 'Unknown channel type: ' . $channelType
                ];
        }
    }

    /**
     * Test Telegram send message
     */
    private function testTelegramSendMessage(): array
    {
        $botToken = CredentialManager::getCredential(CredentialManager::TYPE_TELEGRAM_TOKEN);
        $chatId = CredentialManager::getCredential(CredentialManager::TYPE_TELEGRAM_CHAT_ID);
        $enabled = get_option('wp_security_monitor_telegram_enabled', false);

        if (empty($botToken) || empty($chatId)) {
            return [
                'success' => false,
                'message' => 'Telegram config chưa đầy đủ. Vui lòng kiểm tra Bot Token và Chat ID.'
            ];
        }

        if (!$enabled) {
            return [
                'success' => false,
                'message' => 'Telegram channel chưa được bật. Vui lòng enable trước.'
            ];
        }

        $config = [
            'bot_token' => $botToken,
            'chat_id' => $chatId
        ];

        $telegram = new \Puleeno\SecurityBot\WebMonitor\Channels\TelegramChannel();
        $telegram->configure($config);

        $testMessage = "🧪 *Test Message*\n\n";
        $testMessage .= "Đây là tin nhắn test từ WP Security Monitor Bot\n";
        $testMessage .= "Time: " . date('Y-m-d H:i:s') . "\n";
        $testMessage .= "Status: ✅ Kết nối thành công!";

        $result = $telegram->send($testMessage);

        return [
            'success' => $result,
            'message' => $result ?
                '✅ Tin nhắn test đã được gửi thành công! Kiểm tra Telegram.' :
                '❌ Không thể gửi tin nhắn. Kiểm tra Bot Token và Chat ID.'
        ];
    }

    /**
     * Test Email send
     */
    private function testEmailSendMessage(): array
    {
        $to = get_option('wp_security_monitor_email_to', '');
        $enabled = get_option('wp_security_monitor_email_enabled', false);

        if (empty($to)) {
            return [
                'success' => false,
                'message' => 'Email config chưa đầy đủ. Vui lòng nhập địa chỉ email.'
            ];
        }

        if (!$enabled) {
            return [
                'success' => false,
                'message' => 'Email channel chưa được bật.'
            ];
        }

        $config = ['to' => $to];
        $email = new \Puleeno\SecurityBot\WebMonitor\Channels\EmailChannel();
        $email->configure($config);

        $testMessage = "Test email từ WP Security Monitor Bot\n\n";
        $testMessage .= "Time: " . date('Y-m-d H:i:s') . "\n";
        $testMessage .= "Status: Kết nối thành công!";

        $result = $email->send($testMessage);

        return [
            'success' => $result,
            'message' => $result ?
                '✅ Email test đã được gửi! Kiểm tra hộp thư.' :
                '❌ Không thể gửi email. Kiểm tra SMTP configuration.'
        ];
    }

    /**
     * Test Slack send
     */
    private function testSlackSendMessage(): array
    {
        $webhookUrl = CredentialManager::getCredential(CredentialManager::TYPE_SLACK_WEBHOOK);
        $enabled = get_option('wp_security_monitor_slack_enabled', false);

        if (empty($webhookUrl)) {
            return [
                'success' => false,
                'message' => 'Slack config chưa đầy đủ. Vui lòng nhập Webhook URL.'
            ];
        }

        if (!$enabled) {
            return [
                'success' => false,
                'message' => 'Slack channel chưa được bật.'
            ];
        }

        $config = ['webhook_url' => $webhookUrl];
        $slack = new \Puleeno\SecurityBot\WebMonitor\Channels\SlackChannel();
        $slack->configure($config);

        $testMessage = "🧪 *Test Message*\n\n";
        $testMessage .= "Đây là tin nhắn test từ WP Security Monitor Bot\n";
        $testMessage .= "Time: " . date('Y-m-d H:i:s') . "\n";
        $testMessage .= "Status: ✅ Kết nối thành công!";

        $result = $slack->send($testMessage);

        return [
            'success' => $result,
            'message' => $result ?
                '✅ Tin nhắn test đã được gửi đến Slack!' :
                '❌ Không thể gửi tin nhắn. Kiểm tra Webhook URL.'
        ];
    }

    /**
     * Get migration status
     *
     * @return WP_REST_Response
     */
    public function getMigrationStatus()
    {
        $currentVersion = get_option('wp_security_monitor_db_version', '0');
        $latestVersion = '1.3';
        $lastUpdated = get_option('wp_security_monitor_db_updated_at', null);

        $status = [
            'current_version' => $currentVersion,
            'latest_version' => $latestVersion,
            'needs_migration' => version_compare($currentVersion, $latestVersion, '<'),
            'last_updated' => $lastUpdated,
        ];

        return new WP_REST_Response($status, 200);
    }

    /**
     * Run migration
     *
     * @return WP_REST_Response
     */
    public function runMigration()
    {
        try {
            $schema = new \Puleeno\SecurityBot\WebMonitor\Database\Schema();

            // Run domain tables migration
            $domainMigrationResult = $schema->migrateDomainTables();

            // Run general schema update
            $schemaResult = $schema->updateSchema();

            if ($domainMigrationResult && $schemaResult) {
                return new WP_REST_Response([
                    'success' => true,
                    'message' => 'Migration completed successfully! Domain tables merged into redirect_domains.',
                    'new_version' => '1.3',
                ], 200);
            }

            return new WP_REST_Response([
                'success' => false,
                'message' => 'Migration failed. Check error logs.',
            ], 200);
        } catch (\Exception $e) {
            return new WP_REST_Response([
                'success' => false,
                'message' => 'Migration error: ' . $e->getMessage(),
            ], 200);
        }
    }

    /**
     * Get migration changelog
     *
     * @return WP_REST_Response
     */
    public function getMigrationChangelog()
    {
        $changelogDir = plugin_dir_path(__FILE__) . '../';
        $changelogFiles = glob($changelogDir . 'database-changelog-v*.txt');

        $changelog = [];

        foreach ($changelogFiles as $file) {
            $content = file_get_contents($file);
            if ($content) {
                $version = basename($file, '.txt');
                $version = str_replace('database-changelog-v', '', $version);

                $changelog[] = [
                    'version' => $version,
                    'content' => $content,
                    'file' => basename($file)
                ];
            }
        }

        // Sort by version (newest first)
        usort($changelog, function($a, $b) {
            return version_compare($b['version'], $a['version']);
        });

        return new WP_REST_Response([
            'changelog' => $changelog,
            'total' => count($changelog),
        ], 200);
    }

    /**
     * Get redirects (với filter theo status)
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response
     */
    public function getRedirects(WP_REST_Request $request)
    {
        global $wpdb;

        $status = $request->get_param('status') ?? 'pending';

        // Table for tracking redirect domains
        $table = $wpdb->prefix . 'security_monitor_redirect_domains';

        // Check if table exists, if not return empty
        $tableExists = $wpdb->get_var("SHOW TABLES LIKE '$table'") === $table;

        if (!$tableExists) {
            return new WP_REST_Response([
                'redirects' => [],
                'total' => 0,
            ], 200);
        }

        $redirects = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT
                    domain,
                    first_detected,
                    detection_count,
                    status,
                    contexts,
                    approved_by,
                    approved_at,
                    rejected_by,
                    rejected_at,
                    reject_reason,
                    first_detected as last_detected,
                    domain as url,
                    '' as source_url,
                    '' as user_agent,
                    '' as ip_address
                FROM $table
                WHERE status = %s
                ORDER BY first_detected DESC
                LIMIT 100",
                $status
            ),
            ARRAY_A
        );

        return new WP_REST_Response([
            'redirects' => $redirects ?: [],
            'total' => count($redirects ?: []),
            'status' => $status,
        ], 200);
    }

    /**
     * Approve redirect
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response
     */
    public function approveRedirect(WP_REST_Request $request)
    {
        global $wpdb;
        $domain = $request->get_param('id'); // Actually domain name
        $table = $wpdb->prefix . 'security_monitor_redirect_domains';

        $updated = $wpdb->update(
            $table,
            [
                'status' => 'approved',
                'approved_by' => get_current_user_id(),
                'approved_at' => current_time('mysql')
            ],
            ['domain' => $domain],
            ['%s', '%d', '%s'],
            ['%s']
        );

        if ($updated) {
            return new WP_REST_Response([
                'success' => true,
                'message' => 'Domain approved successfully',
            ], 200);
        }

        return new WP_REST_Response([
            'success' => false,
            'message' => 'Failed to approve domain',
        ], 200);
    }

    /**
     * Reject redirect
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response
     */
    public function rejectRedirect(WP_REST_Request $request)
    {
        global $wpdb;
        $domain = $request->get_param('id'); // Actually domain name
        $reason = sanitize_textarea_field($request->get_param('reason') ?? '');
        $table = $wpdb->prefix . 'security_monitor_redirect_domains';

        $updated = $wpdb->update(
            $table,
            [
                'status' => 'rejected',
                'reject_reason' => $reason,
                'rejected_by' => get_current_user_id(),
                'rejected_at' => current_time('mysql')
            ],
            ['domain' => $domain],
            ['%s', '%s', '%d', '%s'],
            ['%s']
        );

        if ($updated) {
            return new WP_REST_Response([
                'success' => true,
                'message' => 'Domain rejected successfully',
            ], 200);
        }

        return new WP_REST_Response([
            'success' => false,
            'message' => 'Failed to reject domain',
        ], 200);
    }
}


