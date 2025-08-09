<?php
namespace Puleeno\SecurityBot\WebMonitor;

use Puleeno\SecurityBot\WebMonitor\Abstracts\MonitorAbstract;
use Puleeno\SecurityBot\WebMonitor\Interfaces\ChannelInterface;
use Puleeno\SecurityBot\WebMonitor\Interfaces\IssuerInterface;
use Puleeno\SecurityBot\WebMonitor\Channels\TelegramChannel;
use Puleeno\SecurityBot\WebMonitor\Channels\EmailChannel;
use Puleeno\SecurityBot\WebMonitor\Channels\SlackChannel;
use Puleeno\SecurityBot\WebMonitor\Channels\LogChannel;
use Puleeno\SecurityBot\WebMonitor\Security\SecureConfigManager;
use Puleeno\SecurityBot\WebMonitor\Security\CredentialManager;
use Puleeno\SecurityBot\WebMonitor\Security\AccessControl;
use Puleeno\SecurityBot\WebMonitor\Security\TwoFactorAuth;
use Puleeno\SecurityBot\WebMonitor\Issuers\ExternalRedirectIssuer;
use Puleeno\SecurityBot\WebMonitor\Issuers\LoginAttemptIssuer;
use Puleeno\SecurityBot\WebMonitor\Issuers\FileChangeIssuer;
use Puleeno\SecurityBot\WebMonitor\Issuers\AdminUserCreatedIssuer;
use Puleeno\SecurityBot\WebMonitor\Issuers\EvalFunctionIssuer;
use Puleeno\SecurityBot\WebMonitor\Issuers\GitFileChangesIssuer;
use Puleeno\SecurityBot\WebMonitor\Issuers\SQLInjectionAttemptIssuer;
use Puleeno\SecurityBot\WebMonitor\Issuers\BackdoorDetectionIssuer;
use Puleeno\SecurityBot\WebMonitor\Issuers\FunctionOverrideIssuer;
use Puleeno\SecurityBot\WebMonitor\IssueManager;
use Puleeno\SecurityBot\WebMonitor\Database\Schema;

class Bot extends MonitorAbstract
{
    protected static $instance;

    /**
     * @var string
     */
    private $cronHook = 'wp_security_monitor_bot_check';

    protected function __construct()
    {
        $this->initializeHooks();
        $this->loadConfiguration();
        $this->setupDefaultChannelsAndIssuers();

        // Initialize security systems
        AccessControl::init();
        TwoFactorAuth::init();
    }

    public static function getInstance()
    {
        if (is_null(static::$instance)) {
            static::$instance = new static();
        }
        return static::$instance;
    }

    public function start(): void
    {
        if ($this->isRunning) {
            return;
        }

        $this->isRunning = true;

        // Schedule cron job để chạy kiểm tra định kỳ
        if (!wp_next_scheduled($this->cronHook)) {
            $interval = $this->getConfig('check_interval', 'hourly');
            wp_schedule_event(time(), $interval, $this->cronHook);
        }

        update_option('wp_security_monitor_bot_running', true);

        do_action('wp_security_monitor_bot_started');
    }

    public function stop(): void
    {
        if (!$this->isRunning) {
            return;
        }

        $this->isRunning = false;

        // Unschedule cron job
        $timestamp = wp_next_scheduled($this->cronHook);
        if ($timestamp) {
            wp_unschedule_event($timestamp, $this->cronHook);
        }

        update_option('wp_security_monitor_bot_running', false);

        do_action('wp_security_monitor_bot_stopped');
    }

    public function isRunning(): bool
    {
        $saved = get_option('wp_security_monitor_bot_running', false);
        return $this->isRunning || $saved;
    }

    /**
     * Khởi tạo WordPress hooks
     *
     * @return void
     */
    private function initializeHooks(): void
    {
        // Hook cho cron job
        add_action($this->cronHook, [$this, 'runScheduledCheck']);

        // Hook admin menu
        add_action('admin_menu', [$this, 'addAdminMenu']);

        // Hook for database schema
        add_action('init', [$this, 'checkDatabaseSchema']);

        // Hook cho AJAX
        add_action('wp_ajax_security_monitor_test_channel', [$this, 'ajaxTestChannel']);
        add_action('wp_ajax_security_monitor_run_check', [$this, 'ajaxRunCheck']);

        // Hook cho manual check từ admin
        add_action('admin_init', [$this, 'handleAdminActions']);
    }

    /**
     * Load cấu hình từ database
     *
     * @return void
     */
    private function loadConfiguration(): void
    {
        $config = get_option('wp_security_monitor_bot_config', []);
        $this->configure($config);

        // Cấu hình mặc định
        $defaultConfig = [
            'check_interval' => 'hourly',
            'auto_start' => true,
            'max_issues_per_notification' => 10,
            'notification_throttle' => 300 // 5 minutes
        ];

        $this->config = array_merge($defaultConfig, $this->config);
    }

    /**
     * Migrate credentials from plain storage to secure storage
     *
     * @return void
     */
    private function migrateCredentialsIfNeeded(): void
    {
        // Check if migration already done
        if (get_option('wp_security_monitor_credentials_migrated', false)) {
            return;
        }

        // Migrate Telegram credentials
        $telegramConfig = get_option('wp_security_monitor_telegram_config', []);
        if (!empty($telegramConfig['bot_token'])) {
            CredentialManager::setCredential(
                CredentialManager::TYPE_TELEGRAM_TOKEN,
                $telegramConfig['bot_token'],
                ['migrated_from' => 'wp_security_monitor_telegram_config']
            );
        }

        if (!empty($telegramConfig['chat_id'])) {
            CredentialManager::setCredential(
                CredentialManager::TYPE_TELEGRAM_CHAT_ID,
                $telegramConfig['chat_id'],
                ['migrated_from' => 'wp_security_monitor_telegram_config']
            );
        }

        // Migrate Slack credentials
        $slackConfig = get_option('wp_security_monitor_slack_config', []);
        if (!empty($slackConfig['webhook_url'])) {
            CredentialManager::setCredential(
                CredentialManager::TYPE_SLACK_WEBHOOK,
                $slackConfig['webhook_url'],
                ['migrated_from' => 'wp_security_monitor_slack_config']
            );
        }

        // Mark migration as complete
        update_option('wp_security_monitor_credentials_migrated', true);

        // Log migration
        if (WP_DEBUG) {
            error_log('[WP Security Monitor] Credentials migrated to secure storage');
        }
    }

    /**
     * Setup các channel và issuer mặc định
     *
     * @return void
     */
    private function setupDefaultChannelsAndIssuers(): void
    {
        // Migrate existing credentials to secure storage
        $this->migrateCredentialsIfNeeded();

        // Setup Telegram Channel với secure credentials
        $telegramToken = CredentialManager::getCredential(CredentialManager::TYPE_TELEGRAM_TOKEN);
        $telegramChatId = CredentialManager::getCredential(CredentialManager::TYPE_TELEGRAM_CHAT_ID);

        if ($telegramToken && $telegramChatId) {
            $telegram = new TelegramChannel();
            $telegram->configure([
                'bot_token' => $telegramToken,
                'chat_id' => $telegramChatId,
                'enabled' => true
            ]);
            $this->addChannel($telegram);
        }

        // Setup Email Channel
        $emailConfig = get_option('wp_security_monitor_email_config', []);
        if (!empty($emailConfig['to'])) {
            $email = new EmailChannel();
            $email->configure($emailConfig);
            $this->addChannel($email);
        }

        // Setup Slack Channel với secure credentials
        $slackWebhook = CredentialManager::getCredential(CredentialManager::TYPE_SLACK_WEBHOOK);
        if ($slackWebhook) {
            $slackConfig = get_option('wp_security_monitor_slack_config', []);
            $slackConfig['webhook_url'] = $slackWebhook;

            $slack = new SlackChannel();
            $slack->configure($slackConfig);
            $this->addChannel($slack);
        }

        // Setup Log Channel
        $logConfig = get_option('wp_security_monitor_log_config', []);
        if ($logConfig['enabled'] ?? true) { // Log channel enabled by default
            $log = new LogChannel();
            $log->configure($logConfig);
            $this->addChannel($log);
        }

        // Setup Default Issuers
        $issuersConfig = get_option('wp_security_monitor_issuers_config', []);

        // External Redirect Issuer
        $redirectIssuer = new ExternalRedirectIssuer();
        $redirectConfig = $issuersConfig['external_redirect'] ?? ['enabled' => true];
        $redirectIssuer->configure($redirectConfig);
        $this->addIssuer($redirectIssuer);

        // Login Attempt Issuer
        $loginIssuer = new LoginAttemptIssuer();
        $loginConfig = $issuersConfig['login_attempt'] ?? ['enabled' => true];
        $loginIssuer->configure($loginConfig);
        $this->addIssuer($loginIssuer);

        // File Change Issuer
        $fileIssuer = new FileChangeIssuer();
        $fileConfig = $issuersConfig['file_change'] ?? ['enabled' => true];
        $fileIssuer->configure($fileConfig);
        $this->addIssuer($fileIssuer);

        // Admin User Created Issuer
        $adminUserIssuer = new AdminUserCreatedIssuer();
        $adminUserConfig = $issuersConfig['admin_user_created'] ?? ['enabled' => true];
        $adminUserIssuer->configure($adminUserConfig);
        $this->addIssuer($adminUserIssuer);

        // Eval Function Issuer
        $evalIssuer = new EvalFunctionIssuer();
        $evalConfig = $issuersConfig['eval_function'] ?? [
            'enabled' => true,
            'max_files_per_scan' => 50,
            'max_scan_depth' => 3
        ];
        $evalIssuer->configure($evalConfig);
        $this->addIssuer($evalIssuer);

        // Setup Git File Changes Issuer (nếu Git available)
        $gitIssuer = new GitFileChangesIssuer();
        $gitConfig = $issuersConfig['git_file_changes'] ?? [
            'enabled' => true,
            'check_interval' => 300,
            'max_files_per_alert' => 10
        ];
        $gitIssuer->configure($gitConfig);
        if ($gitIssuer->isEnabled()) {
            $this->addIssuer($gitIssuer);
        }

        // Setup SQL Injection Attempt Issuer - HIGHEST PRIORITY
        $sqliIssuer = new SQLInjectionAttemptIssuer();
        $sqliConfig = $issuersConfig['sql_injection_attempt'] ?? [
            'enabled' => true,
            'block_suspicious_requests' => false,
            'max_alerts_per_hour' => 10
        ];
        $sqliIssuer->configure($sqliConfig);
        $this->addIssuer($sqliIssuer);

        // Setup Backdoor Detection Issuer - WP CRON ONLY
        $backdoorIssuer = new BackdoorDetectionIssuer();
        $backdoorConfig = $issuersConfig['backdoor_detection'] ?? [
            'enabled' => true,
            'max_file_size' => 1048576, // 1MB
            'max_files_per_scan' => 20,
            'scan_depth' => 3
        ];
        $backdoorIssuer->configure($backdoorConfig);
        $this->addIssuer($backdoorIssuer);

        // Setup Function Override Issuer - RUNKIT7 REQUIRED
        $overrideIssuer = new FunctionOverrideIssuer();
        $overrideConfig = $issuersConfig['function_override'] ?? [
            'enabled' => true,
            'block_calls' => false,
            'max_alerts_per_hour' => 20,
            'detailed_logging' => true
        ];
        $overrideIssuer->configure($overrideConfig);
        if ($overrideIssuer->isEnabled()) {
            $this->addIssuer($overrideIssuer);
        }

        do_action('wp_security_monitor_bot_setup_complete', $this);
    }

    /**
     * Chạy kiểm tra theo lịch
     *
     * @return void
     */
    public function runScheduledCheck(): void
    {
        if (!$this->isRunning()) {
            return;
        }

        $lastCheck = get_option('wp_security_monitor_last_check', 0);
        $throttle = $this->getConfig('notification_throttle', 300);

        // Throttle để tránh spam
        if (time() - $lastCheck < $throttle) {
            return;
        }

        try {
            $issues = $this->runCheck();

            update_option('wp_security_monitor_last_check', time());
            update_option('wp_security_monitor_last_issues', $issues);

            if (!empty($issues)) {
                do_action('wp_security_monitor_issues_detected', $issues);
            }

        } catch (\Exception $e) {
            error_log('WP Security Monitor Bot Error: ' . $e->getMessage());
        }
    }

        /**
     * Khi plugin được activate
     *
     * @return void
     */
    public static function onActivation(): void
    {
        // Tạo database tables
        Schema::createTables();

        // Tạo các options mặc định
        add_option('wp_security_monitor_bot_config', [
            'auto_start' => true,
            'check_interval' => 'hourly'
        ]);

        // Tạo cron job
        $cronHook = 'wp_security_monitor_bot_check';
        if (!wp_next_scheduled($cronHook)) {
            wp_schedule_event(time(), 'hourly', $cronHook);
        }
    }

    /**
     * Khi plugin được deactivate
     *
     * @return void
     */
    public static function onDeactivation(): void
    {
        // Clear cron job
        $cronHook = 'wp_security_monitor_bot_check';
        $timestamp = wp_next_scheduled($cronHook);
        if ($timestamp) {
            wp_unschedule_event($timestamp, $cronHook);
        }
    }

    /**
     * Thêm admin menu
     *
     * @return void
     */
            public function addAdminMenu(): void
    {
        // Main menu - Puleeno Security
        $menuSlug = add_menu_page(
            'Puleeno Security',           // Page title
            'Puleeno Security',           // Menu title
            'read',                       // Capability
            'puleeno-security',           // Menu slug
            [$this, 'renderMainSecurityPage'], // Callback
            'dashicons-shield-alt',       // Icon
            30                           // Position
        );

        // Security Monitor Settings - submenu
        add_submenu_page(
            'puleeno-security',
            'Security Monitor Settings',
            'Settings',
            AccessControl::CAP_MANAGE_SETTINGS,
            'wp-security-monitor-bot',
            [$this, 'renderAdminPage']
        );

        // Security Issues - submenu
        add_submenu_page(
            'puleeno-security',
            'Security Issues',
            'Issues',
            AccessControl::CAP_VIEW_ISSUES,
            'wp-security-monitor-issues',
            [$this, 'renderIssuesPage']
        );

        // Security Status - submenu
        add_submenu_page(
            'puleeno-security',
            'Security Status',
            'Status',
            AccessControl::CAP_VIEW_SECURITY_STATUS,
            'wp-security-monitor-security',
            [$this, 'renderSecurityPage']
        );

        // Access Control - submenu
        add_submenu_page(
            'puleeno-security',
            'Access Control',
            'Access Control',
            'read', // Basic permission, then check specific caps inside
            'wp-security-monitor-access-control',
            [$this, 'renderAccessControlPage']
        );
    }

        /**
     * Render admin page
     *
     * @return void
     */
    public function renderAdminPage(): void
    {
        $isRunning = $this->isRunning();
        $lastCheck = get_option('wp_security_monitor_last_check', 0);
        $lastIssues = get_option('wp_security_monitor_last_issues', []);

        include dirname(__FILE__) . '/../admin/settings-page.php';
    }

    /**
     * Render issues management page
     *
     * @return void
     */
    public function renderIssuesPage(): void
    {
        include dirname(__FILE__) . '/../admin/issues-page.php';
    }

    /**
     * Render security status page
     *
     * @return void
     */
    public function renderSecurityPage(): void
    {
        include dirname(__FILE__) . '/../admin/security-page.php';
    }

    /**
     * Render access control page
     *
     * @return void
     */
    public function renderAccessControlPage(): void
    {
        include dirname(__FILE__) . '/../admin/access-control-page.php';
    }

    /**
     * Render main security dashboard page
     *
     * @return void
     */
    public function renderMainSecurityPage(): void
    {
        include dirname(__FILE__) . '/../admin/main-security-page.php';
    }

    /**
     * Kiểm tra và cập nhật database schema
     *
     * @return void
     */
    public function checkDatabaseSchema(): void
    {
        Schema::updateSchema();
    }

    /**
     * Override runCheck để integrate với IssueManager
     *
     * @return array
     */
    public function runCheck(): array
    {
        $issues = [];
        $issueManager = IssueManager::getInstance();

        foreach ($this->issuers as $issuer) {
            if (!$issuer->isEnabled()) {
                continue;
            }

            try {
                $detectedIssues = $issuer->detect();
                if (!empty($detectedIssues)) {
                    $issues[$issuer->getName()] = $detectedIssues;

                    // Lưu từng issue vào database
                    foreach ($detectedIssues as $issueData) {
                        $issueId = $issueManager->recordIssue($issuer->getName(), $issueData);

                        // Chỉ gửi notification cho issues mới (không bị ignore)
                        if ($issueId !== false) {
                            $this->sendNotifications($issuer->getName(), [$issueData]);
                        }
                    }
                }
            } catch (\Exception $e) {
                error_log(sprintf('Error in issuer %s: %s', $issuer->getName(), $e->getMessage()));

                // Ghi lại lỗi như một issue
                $issueManager->recordIssue('System', [
                    'message' => 'Error in security check',
                    'details' => sprintf('Issuer %s failed: %s', $issuer->getName(), $e->getMessage()),
                    'type' => 'system_error'
                ]);
            }
        }

        return $issues;
    }

    /**
     * Xử lý actions từ admin
     *
     * @return void
     */
    public function handleAdminActions(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        if (isset($_POST['security_monitor_action'])) {
            $action = sanitize_text_field($_POST['security_monitor_action']);

            switch ($action) {
                case 'start':
                    $this->start();
                    add_action('admin_notices', function() {
                        echo '<div class="notice notice-success"><p>Security Monitor Bot đã được khởi động!</p></div>';
                    });
                    break;

                case 'stop':
                    $this->stop();
                    add_action('admin_notices', function() {
                        echo '<div class="notice notice-info"><p>Security Monitor Bot đã được dừng!</p></div>';
                    });
                    break;

                case 'run_check':
                    $issues = $this->runCheck();
                    $count = count($issues);
                    add_action('admin_notices', function() use ($count) {
                        $class = $count > 0 ? 'notice-warning' : 'notice-success';
                        $message = $count > 0 ? "Phát hiện {$count} vấn đề bảo mật!" : "Không phát hiện vấn đề nào.";
                        echo "<div class=\"notice {$class}\"><p>{$message}</p></div>";
                    });
                    break;
            }
        }
    }





        /**
     * Lấy thống kê
     *
     * @return array
     */
    public function getStats(): array
    {
        $issueManager = IssueManager::getInstance();
        $issueStats = $issueManager->getStats();

        return [
            'is_running' => $this->isRunning(),
            'channels_count' => count($this->channels),
            'issuers_count' => count($this->issuers),
            'last_check' => get_option('wp_security_monitor_last_check', 0),
            'total_issues_found' => $issueStats['total_issues'] ?? 0,
            'new_issues' => $issueStats['new_issues'] ?? 0,
            'next_scheduled_check' => wp_next_scheduled($this->cronHook)
        ];
    }

    /**
     * Lấy config value
     *
     * @param string $key
     * @param mixed $default
     * @return mixed
     */
    private function getConfig(string $key, $default = null)
    {
        return $this->config[$key] ?? $default;
    }

    /**
     * AJAX handler để test channel connections
     */
    public function ajaxTestChannel(): void
    {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'] ?? '', 'security_monitor_nonce')) {
            wp_send_json_error('Invalid nonce');
            return;
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
            return;
        }

        $channelType = sanitize_text_field($_POST['channel_type'] ?? '');

        if (empty($channelType)) {
            wp_send_json_error('Channel type is required');
            return;
        }

        try {
            $result = $this->testChannelConnection($channelType);

            if ($result['success']) {
                wp_send_json_success($result['message']);
            } else {
                wp_send_json_error($result['message']);
            }

        } catch (\Exception $e) {
            wp_send_json_error('Test failed: ' . $e->getMessage());
        }
    }

    /**
     * Test connection cho specific channel
     */
    private function testChannelConnection(string $channelType): array
    {
        switch ($channelType) {
            case 'telegram':
                return $this->testTelegramConnection();

            case 'email':
                return $this->testEmailConnection();

                        case 'slack':
                return $this->testSlackConnection();

            case 'log':
                return $this->testLogConnection();

            default:
                return [
                    'success' => false,
                    'message' => "Unknown channel type: {$channelType}"
                ];
        }
    }

    /**
     * Test Telegram connection
     */
    private function testTelegramConnection(): array
    {
        $config = get_option('wp_security_monitor_telegram_config', []);

        if (empty($config['bot_token']) || empty($config['chat_id'])) {
            return [
                'success' => false,
                'message' => 'Telegram config is incomplete. Please check bot token and chat ID.'
            ];
        }

        $telegram = new \Puleeno\SecurityBot\WebMonitor\Channels\TelegramChannel();
        $telegram->configure($config);

        return $telegram->testConnection();
    }

    /**
     * Test Email connection
     */
    private function testEmailConnection(): array
    {
        $config = get_option('wp_security_monitor_email_config', []);

        if (empty($config['to'])) {
            return [
                'success' => false,
                'message' => 'Email config is incomplete. Please check recipient email.'
            ];
        }

        $email = new \Puleeno\SecurityBot\WebMonitor\Channels\EmailChannel();
        $email->configure($config);

        return $email->testConnection();
    }

    /**
     * Test Slack connection
     */
    private function testSlackConnection(): array
    {
        $config = get_option('wp_security_monitor_slack_config', []);

        if (empty($config['webhook_url'])) {
            return [
                'success' => false,
                'message' => 'Slack config is incomplete. Please check webhook URL.'
            ];
        }

        $slack = new \Puleeno\SecurityBot\WebMonitor\Channels\SlackChannel();
        $slack->configure($config);

        return $slack->testConnection();
    }

        /**
     * Test Log connection
     */
    private function testLogConnection(): array
    {
        $config = get_option('wp_security_monitor_log_config', []);

        $log = new LogChannel();
        $log->configure($config);

        return $log->testConnection();
    }

    /**
     * AJAX handler để run manual check
     */
    public function ajaxRunCheck(): void
    {
        // Verify nonce
        if (!wp_verify_nonce($_POST['nonce'] ?? '', 'security_monitor_nonce')) {
            wp_send_json_error('Invalid nonce');
            return;
        }

        // Check permissions
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
            return;
        }

        try {
            $issues = $this->runCheck();
            $totalIssues = array_sum(array_map('count', $issues));

            wp_send_json_success([
                'message' => "Manual check completed. Found {$totalIssues} issues.",
                'issues' => $issues
            ]);

        } catch (\Exception $e) {
            wp_send_json_error('Check failed: ' . $e->getMessage());
        }
    }
}
