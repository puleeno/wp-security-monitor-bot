<?php
namespace Puleeno\SecurityBot\WebMonitor;

use Puleeno\SecurityBot\WebMonitor\Abstracts\MonitorAbstract;
use Puleeno\SecurityBot\WebMonitor\Admin\AdminMenuManager;
use Puleeno\SecurityBot\WebMonitor\Channels\TelegramChannel;
use Puleeno\SecurityBot\WebMonitor\Interfaces\ChannelInterface;
use Puleeno\SecurityBot\WebMonitor\Interfaces\IssuerInterface;
use Puleeno\SecurityBot\WebMonitor\Issuers\IssuerRegistry;
use Puleeno\SecurityBot\WebMonitor\Channels\EmailChannel;
use Puleeno\SecurityBot\WebMonitor\Channels\SlackChannel;
use Puleeno\SecurityBot\WebMonitor\Channels\LogChannel;
use Puleeno\SecurityBot\WebMonitor\Security\SecureConfigManager;
use Puleeno\SecurityBot\WebMonitor\Security\CredentialManager;
use Puleeno\SecurityBot\WebMonitor\Security\AccessControl;
use Puleeno\SecurityBot\WebMonitor\Issuers\ExternalRedirectIssuer;
use Puleeno\SecurityBot\WebMonitor\Issuers\LoginAttemptIssuer;
use Puleeno\SecurityBot\WebMonitor\Issuers\FileChangeIssuer;
use Puleeno\SecurityBot\WebMonitor\Issuers\AdminUserCreatedIssuer;
use Puleeno\SecurityBot\WebMonitor\Issuers\EvalFunctionIssuer;
use Puleeno\SecurityBot\WebMonitor\Issuers\SQLInjectionAttemptIssuer;
use Puleeno\SecurityBot\WebMonitor\Issuers\BackdoorDetectionIssuer;
use Puleeno\SecurityBot\WebMonitor\Issuers\RealtimeRedirectIssuer;
use Puleeno\SecurityBot\WebMonitor\Issuers\FunctionOverrideIssuer;
use Puleeno\SecurityBot\WebMonitor\Issuers\FatalErrorIssuer;
use Puleeno\SecurityBot\WebMonitor\Issuers\PluginThemeUploadIssuer;
use Puleeno\SecurityBot\WebMonitor\Issuers\PerformanceIssuer;
use Puleeno\SecurityBot\WebMonitor\IssueManager;
use Puleeno\SecurityBot\WebMonitor\Database\Schema;
use Exception;

class Bot extends MonitorAbstract
{
    protected static $instance;

    /**
     * @var string
     */
    private $cronHook = 'wp_security_monitor_bot_check';

    /**
     * @var IssueManager
     */
    private $issueManager;

    /**
     * @var AdminMenuManager
     */
    private $menuManager;

    /**
     * @var IssuerRegistry
     */
    private $issuerRegistry;

    protected function __construct()
    {
        // Initialize managers
        $this->menuManager = new AdminMenuManager();
        $this->issuerRegistry = new IssuerRegistry();

        $this->initializeHooks();
        $this->loadConfiguration();
        // Khởi tạo channels và issuers ngay lập tức để các hooks được đăng ký
        $this->setupDefaultChannelsAndIssuers();

        // Initialize managers
        $this->issueManager = IssueManager::getInstance();

        // Initialize security systems
        AccessControl::init();

        // NOTE: Không auto-start bot nữa
        // User phải manually start qua UI hoặc API để đảm bảo control rõ ràng
        // $this->maybeAutoStart();
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
        // Check DB flag - single source of truth
        if ($this->isRunning()) {
            return;
        }

        // Set DB flag FIRST
        update_option('wp_security_monitor_bot_running', true);

        // Sync property với DB
        $this->isRunning = true;

        // Schedule cron job để chạy kiểm tra định kỳ
        if (!wp_next_scheduled($this->cronHook)) {
            $interval = $this->getConfig('check_interval', 'hourly');
            wp_schedule_event(time(), $interval, $this->cronHook);
        }

        do_action('wp_security_monitor_bot_started');

        if (WP_DEBUG) {
            error_log('[WP Security Monitor] Bot started on ' . current_time('mysql'));
        }
    }

    public function stop(): void
    {
        // Check DB flag - single source of truth
        if (!$this->isRunning()) {
            return;
        }

        // Set DB flag FIRST
        update_option('wp_security_monitor_bot_running', false);

        // Sync property với DB
        $this->isRunning = false;

        // Unschedule cron job
        $timestamp = wp_next_scheduled($this->cronHook);
        if ($timestamp) {
            wp_unschedule_event($timestamp, $this->cronHook);
        }

        do_action('wp_security_monitor_bot_stopped');

        if (WP_DEBUG) {
            error_log('[WP Security Monitor] Bot stopped on ' . current_time('mysql'));
        }
    }

    public function isRunning(): bool
    {
        // DB option là single source of truth
        // Property chỉ dùng để cache trong memory
        $saved = get_option('wp_security_monitor_bot_running', false);

        // Sync property với DB để tránh inconsistency
        $this->isRunning = (bool) $saved;

        return (bool) $saved;
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

        // Register REST API routes
        add_action('rest_api_init', [$this, 'registerRestRoutes']);

        // Hook cho AJAX
        add_action('wp_ajax_security_monitor_test_channel', [$this, 'ajaxTestChannel']);
        add_action('wp_ajax_security_monitor_test_send_message', [$this, 'ajaxTestSendMessage']);
        add_action('wp_ajax_security_monitor_run_check', [$this, 'ajaxRunCheck']);
        add_action('wp_ajax_security_monitor_mark_viewed', [$this, 'ajaxMarkViewed']);
        add_action('wp_ajax_security_monitor_unmark_viewed', [$this, 'ajaxUnmarkViewed']);

        // Hook cho manual check từ admin
        add_action('admin_init', [$this, 'handleAdminActions']);

        // Hook cho notification processing
        add_action('wp_security_monitor_process_notifications', [$this, 'processNotificationsCron']);

        // Hook cho suspicious redirect detection
        add_action('wp_security_monitor_suspicious_redirect', [$this, 'handleSuspiciousRedirect']);

        // Hook cho user registration detection
        add_action('wp_security_monitor_user_registered', [$this, 'handleUserRegistration']);

        // Hook cho realtime failed login detection
        add_action('wp_security_monitor_realtime_failed_login', [$this, 'handleRealtimeFailedLogin']);

        // Hook cho realtime brute force detection
        add_action('wp_security_monitor_realtime_brute_force', [$this, 'handleRealtimeBruteForce']);

        // Hook cho fatal error detection
        add_action('wp_security_monitor_fatal_error', [$this, 'handleFatalError']);

        // Hook cho malicious upload detection
        add_action('wp_security_monitor_malicious_upload', [$this, 'handleMaliciousUpload']);

        // Hook cho slow performance detection
        add_action('wp_security_monitor_slow_performance', [$this, 'handleSlowPerformance']);
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
     * Tự động start bot nếu cấu hình auto_start = true
     *
     * @return void
     */
    private function maybeAutoStart(): void
    {
        // Chỉ auto start khi:
        // 1. Cấu hình auto_start = true
        // 2. Bot chưa đang chạy
        // 3. Không phải cron job (cho phép AJAX để UI có thể trigger)
        if (
            $this->getConfig('auto_start', true) &&
            !$this->isRunning() &&
            !wp_doing_cron()
        ) {
            $this->start();

            if (WP_DEBUG) {
                error_log('[WP Security Monitor] Bot auto-started on ' . current_time('mysql'));
            }
        }
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
     * Đảm bảo channels được khởi tạo khi cần thiết
     *
     * @return void
     */
    private function ensureChannelsInitialized(): void
    {
        // Debug logging
        if (WP_DEBUG) {
            error_log("[Bot Debug] ensureChannelsInitialized called");
            error_log("[Bot Debug] Current channels count: " . count($this->channels));
            error_log("[Bot Debug] Current issuers count: " . count($this->issuers));
        }

        // Kiểm tra cả channels và issuers
        $needsInitialization = empty($this->channels) || empty($this->issuers);

        if (!$needsInitialization) {
            if (WP_DEBUG) {
                error_log("[Bot Debug] Channels and issuers already initialized, skipping");
            }
            return;
        }

        if (WP_DEBUG) {
            error_log("[Bot Debug] Initializing channels and issuers...");
        }

        // Khởi tạo channels và issuers
        $this->setupDefaultChannelsAndIssuers();

        if (WP_DEBUG) {
            error_log("[Bot Debug] Initialization completed. Total channels: " . count($this->channels) . ", Total issuers: " . count($this->issuers));
            foreach ($this->channels as $index => $channel) {
                error_log("[Bot Debug] Channel {$index}: " . $channel->getName() . " - Available: " . ($channel->isAvailable() ? 'YES' : 'NO'));
            }
            foreach ($this->issuers as $index => $issuer) {
                error_log("[Bot Debug] Issuer {$index}: " . get_class($issuer) . " - Enabled: " . ($issuer->isEnabled() ? 'YES' : 'NO'));
            }
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
        $telegramEnabled = get_option('wp_security_monitor_telegram_enabled', false);

        if (WP_DEBUG) {
            error_log("[Bot Debug] Telegram setup - Token: " . (!empty($telegramToken) ? 'SET' : 'MISSING') .
                ", Chat ID: " . (!empty($telegramChatId) ? 'SET' : 'MISSING') .
                ", Enabled: " . ($telegramEnabled ? 'YES' : 'NO'));
        }

        if ($telegramToken && $telegramChatId && $telegramEnabled) {
            try {
                $telegram = new TelegramChannel();
                $telegram->configure([
                    'bot_token' => $telegramToken,
                    'chat_id' => $telegramChatId,
                    'enabled' => true
                ]);
                TelegramChannel::setInstance($telegram);
                $this->addChannel($telegram);

                if (WP_DEBUG) {
                    error_log("[Bot Debug] Telegram channel added successfully");
                }
            } catch (Exception $e) {
                if (WP_DEBUG) {
                    error_log("[Bot Debug] Error adding Telegram channel: " . $e->getMessage());
                }
            }
        } else {
            if (WP_DEBUG) {
                error_log("[Bot Debug] Telegram channel not added - missing credentials or disabled");
            }
        }

        // Setup Email Channel
        $emailConfig = get_option('wp_security_monitor_email_config', []);
        if (!empty($emailConfig['to']) && ($emailConfig['enabled'] ?? true)) {
            $email = new EmailChannel();
            $email->configure($emailConfig);
            $this->addChannel($email);
        }

        // Setup Slack Channel với secure credentials
        $slackWebhook = CredentialManager::getCredential(CredentialManager::TYPE_SLACK_WEBHOOK);
        $slackEnabled = get_option('wp_security_monitor_slack_enabled', false);

        if ($slackWebhook && $slackEnabled) {
            $slackConfig = get_option('wp_security_monitor_slack_config', []);
            $slackConfig['webhook_url'] = $slackWebhook;

            $slack = new SlackChannel();
            $slack->configure($slackConfig);
            $this->addChannel($slack);

            if (WP_DEBUG) {
                error_log("[Bot Debug] Slack channel added successfully");
            }
        }

        // Setup Log Channel
        $logConfig = get_option('wp_security_monitor_log_config', []);
        if (isset($logConfig['enabled']) ? $logConfig['enabled'] : true) { // Log channel enabled by default
            $log = new LogChannel();
            $log->configure($logConfig);
            $this->addChannel($log);
        }

        // Setup Default Issuers
        $issuersConfig = get_option('wp_security_monitor_issuers_config', []);

        // Chỉ khởi tạo issuers khi Bot đang chạy để tránh tạo object nặng không cần thiết
        if (!$this->isRunning()) {
            if (WP_DEBUG) {
                error_log('[Bot Debug] Skipping issuers initialization because bot is stopped');
            }
            return;
        }

        // External Redirect Issuer
        $redirectIssuer = new ExternalRedirectIssuer();
        $redirectConfig = $issuersConfig['external_redirect'] ?? ['enabled' => true];
        $redirectIssuer->configure($redirectConfig);
        if ($redirectIssuer->isEnabled()) {
            $this->addIssuer($redirectIssuer);
        }

        // Realtime Redirect Issuer
        $realtimeRedirectIssuer = new \Puleeno\SecurityBot\WebMonitor\Issuers\RealtimeRedirectIssuer();
        $realtimeRedirectConfig = $issuersConfig['realtime_redirect'] ?? ['enabled' => true];
        $realtimeRedirectIssuer->configure($realtimeRedirectConfig);
        if ($realtimeRedirectIssuer->isEnabled()) {
            $this->addIssuer($realtimeRedirectIssuer);
        }

        // Realtime User Registration Issuer
        $realtimeUserRegIssuer = new \Puleeno\SecurityBot\WebMonitor\Issuers\RealtimeUserRegistrationIssuer();
        $realtimeUserRegConfig = $issuersConfig['realtime_user_registration'] ?? ['enabled' => true];
        $realtimeUserRegIssuer->configure($realtimeUserRegConfig);
        if ($realtimeUserRegIssuer->isEnabled()) {
            $this->addIssuer($realtimeUserRegIssuer);
        }

        // Login Attempt Issuer
        $loginIssuer = new LoginAttemptIssuer();
        $loginConfig = $issuersConfig['login_attempt'] ?? ['enabled' => true];
        $loginIssuer->configure($loginConfig);
        if ($loginIssuer->isEnabled()) {
            $this->addIssuer($loginIssuer);
        }

        // File Change Issuer
        $fileIssuer = new FileChangeIssuer();
        $fileConfig = $issuersConfig['file_change'] ?? ['enabled' => true];
        $fileIssuer->configure($fileConfig);
        if ($fileIssuer->isEnabled()) {
            $this->addIssuer($fileIssuer);
        }

        // Admin User Created Issuer
        $adminUserIssuer = new AdminUserCreatedIssuer();
        $adminUserConfig = $issuersConfig['admin_user_created'] ?? ['enabled' => true];
        $adminUserIssuer->configure($adminUserConfig);
        if ($adminUserIssuer->isEnabled()) {
            $this->addIssuer($adminUserIssuer);
        }

        // Eval Function Issuer
        $evalIssuer = new EvalFunctionIssuer();
        $evalConfig = $issuersConfig['eval_function'] ?? [
            'enabled' => true,
            'max_files_per_scan' => 50,
            'max_scan_depth' => 3
        ];
        $evalIssuer->configure($evalConfig);
        if ($evalIssuer->isEnabled()) {
            $this->addIssuer($evalIssuer);
        }

        // Setup Git File Changes Issuer (chỉ nếu shell functions available)
        if (GitFileChangesIssuer::areShellFunctionsEnabled()) {
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
        }

        // Setup SQL Injection Attempt Issuer - HIGHEST PRIORITY
        $sqliIssuer = new SQLInjectionAttemptIssuer();
        $sqliConfig = $issuersConfig['sql_injection_attempt'] ?? [
            'enabled' => true,
            'block_suspicious_requests' => false,
            'max_alerts_per_hour' => 10
        ];
        $sqliIssuer->configure($sqliConfig);
        if ($sqliIssuer->isEnabled()) {
            $this->addIssuer($sqliIssuer);
        }

        // Setup Backdoor Detection Issuer - WP CRON ONLY
        $backdoorIssuer = new BackdoorDetectionIssuer();
        $backdoorConfig = $issuersConfig['backdoor_detection'] ?? [
            'enabled' => true,
            'max_file_size' => 1048576, // 1MB
            'max_files_per_scan' => 20,
            'scan_depth' => 3
        ];
        $backdoorIssuer->configure($backdoorConfig);
        if ($backdoorIssuer->isEnabled()) {
            $this->addIssuer($backdoorIssuer);
        }

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

        // Setup Fatal Error Issuer - REALTIME
        $fatalErrorIssuer = new FatalErrorIssuer();
        $fatalErrorConfig = $issuersConfig['fatal_error'] ?? [
            'enabled' => true,
            'monitor_levels' => ['error', 'warning'], // ['error', 'warning', 'notice']
        ];
        $fatalErrorIssuer->configure($fatalErrorConfig);
        if ($fatalErrorIssuer->isEnabled()) {
            $this->addIssuer($fatalErrorIssuer);
        }

        // Setup Plugin/Theme Upload Scanner - REALTIME
        $uploadScannerIssuer = new PluginThemeUploadIssuer();
        $uploadScannerConfig = $issuersConfig['plugin_theme_upload'] ?? [
            'enabled' => true,
            'max_files_per_scan' => 100,
            'max_file_size' => 1048576, // 1MB
            'block_suspicious_uploads' => true,
        ];
        $uploadScannerIssuer->configure($uploadScannerConfig);
        if ($uploadScannerIssuer->isEnabled()) {
            $this->addIssuer($uploadScannerIssuer);
        }

        // Setup Performance Monitor - REALTIME
        $performanceIssuer = new PerformanceIssuer();
        $performanceConfig = $issuersConfig['performance_monitor'] ?? [
            'enabled' => true,
            'threshold' => 30, // seconds
            'memory_threshold' => 134217728, // 128MB
            'track_queries' => true,
        ];
        $performanceIssuer->configure($performanceConfig);
        if ($performanceIssuer->isEnabled()) {
            $this->addIssuer($performanceIssuer);
        }

        if (WP_DEBUG) {
            error_log("[Bot Debug] setupDefaultChannelsAndIssuers completed");
            error_log("[Bot Debug] Total channels: " . count($this->channels));
            error_log("[Bot Debug] Total issuers: " . count($this->issuers));
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

        // Set flag OFF mặc định khi activate - user phải manually start
        // Điều này đảm bảo bot không tự động chạy khi vừa cài đặt
        add_option('wp_security_monitor_bot_running', false);

        // Tạo cron job cho security checks
        $cronHook = 'wp_security_monitor_bot_check';
        if (!wp_next_scheduled($cronHook)) {
            wp_schedule_event(time(), 'hourly', $cronHook);
        }

        // Tạo cron job cho notification processing (chạy mỗi 5 phút)
        $notificationCronHook = 'wp_security_monitor_process_notifications';
        if (!wp_next_scheduled($notificationCronHook)) {
            // WordPress không có 'every_5_minutes', sử dụng 'hourly' và custom interval
            wp_schedule_event(time(), 'hourly', $notificationCronHook);
        }

        // Thêm custom cron interval cho 5 phút
        add_filter('cron_schedules', function ($schedules) {
            $schedules['every_5_minutes'] = [
                'interval' => 300, // 5 phút = 300 giây
                'display' => 'Every 5 Minutes'
            ];
            return $schedules;
        });
    }

    /**
     * Khi plugin được deactivate
     *
     * @return void
     */
    public static function onDeactivation(): void
    {
        // Clear cron job cho security checks
        $cronHook = 'wp_security_monitor_bot_check';
        $timestamp = wp_next_scheduled($cronHook);
        if ($timestamp) {
            wp_unschedule_event($timestamp, $cronHook);
        }

        // Clear cron job cho notification processing
        $notificationCronHook = 'wp_security_monitor_process_notifications';
        $notificationTimestamp = wp_next_scheduled($notificationCronHook);
        if ($notificationTimestamp) {
            wp_unschedule_event($notificationTimestamp, $notificationCronHook);
        }
    }

    /**
     * Thêm admin menu
     *
     * @return void
     */
    public function addAdminMenu(): void
    {
        // Delegate to AdminMenuManager
        $this->menuManager->addMenus();
    }


    /**
     * Register REST API routes
     *
     * @return void
     */
    public function registerRestRoutes(): void
    {
        $restApi = new RestApi();
        $restApi->registerRoutes();
    }

    /**
     * Kiểm tra và cập nhật database schema
     *
     * @return void
     */
    public function checkDatabaseSchema(): void
    {
        $currentVersion = get_option('wp_security_monitor_db_version', '0');
        $latestVersion = '1.2';

        // Nếu cần migration
        if (version_compare($currentVersion, $latestVersion, '<')) {
            Schema::updateSchema();

            // Show admin notice sau khi migrate
            $newVersion = get_option('wp_security_monitor_db_version');
            if ($newVersion !== $currentVersion) {
                add_action('admin_notices', function () use ($currentVersion, $newVersion) {
                    echo '<div class="notice notice-success is-dismissible">';
                    echo '<p><strong>WP Security Monitor:</strong> Database đã được cập nhật từ version ' . esc_html($currentVersion) . ' lên ' . esc_html($newVersion) . '!</p>';
                    echo '</div>';
                });

                if (WP_DEBUG) {
                    error_log('[WP Security Monitor] Database migrated from ' . $currentVersion . ' to ' . $newVersion);
                }
            }
        }
    }

    /**
     * Override runCheck để integrate với IssueManager
     *
     * @return array
     */
    public function runCheck(): array
    {
        // CHECK FLAG FIRST - Nếu bot đã bị dừng, không chạy check
        if (!$this->isRunning()) {
            if (WP_DEBUG) {
                error_log('[WP Security Monitor] runCheck() skipped - Bot is stopped');
            }
            return [];
        }

        // Đảm bảo channels được khởi tạo trước khi chạy check
        $this->ensureChannelsInitialized();

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
                        $issueId = $issueManager->recordIssue($issuer->getName(), $issueData, $issuer);

                        // recordIssue có thể trả về:
                        //  - false: bị ignore hoặc lỗi → bỏ qua
                        //  - số dương: ID issue (mới hoặc cập nhật)
                        //  - số âm:  -ID issue (cần notify lại trên redetection)
                        if ($issueId === false) {
                            continue;
                        }

                        $actualIssueId = abs($issueId);
                        $shouldNotify = ($issueId < 0) || $this->isNewIssue($actualIssueId);

                        if ($shouldNotify) {
                            // Thêm vào notification queue (đã có cơ chế dedup ở NotificationManager)
                            $this->queueNotificationsForIssue($issuer->getName(), $actualIssueId, $issueData);
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
     * Tạo hash duy nhất cho issue
     *
     * @param string $issuerName
     * @param array $issueData
     * @return string
     */
    private function generateIssueHash(string $issuerName, array $issueData): string
    {
        // Tạo hash dựa trên issuer name và các thông tin cơ bản của issue
        $hashData = [
            'issuer' => $issuerName,
            'type' => $issueData['type'] ?? 'unknown',
            'message' => $issueData['message'] ?? '',
            'file_path' => $issueData['file_path'] ?? '',
            'ip_address' => $issueData['ip_address'] ?? ''
        ];

        // Loại bỏ các giá trị null/empty để tạo hash nhất quán
        $hashData = array_filter($hashData, function ($value) {
            return !empty($value);
        });

        return md5(serialize($hashData));
    }

    /**
     * Kiểm tra xem issue đã tồn tại trong database chưa
     *
     * @param string $issueHash
     * @return int|null Issue ID nếu tồn tại, null nếu chưa tồn tại
     */
    private function getExistingIssueId(string $issueHash): ?int
    {
        global $wpdb;
        $tableName = $wpdb->prefix . \Puleeno\SecurityBot\WebMonitor\Database\Schema::TABLE_ISSUES;

        $existingId = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM {$tableName} WHERE issue_hash = %s",
            $issueHash
        ));

        return $existingId ? (int) $existingId : null;
    }

    /**
     * Thêm notifications vào queue cho một issue
     *
     * @param string $issuerName
     * @param int $issueId
     * @param array $issueData
     * @return void
     */
    private function queueNotificationsForIssue(string $issuerName, int $issueId, array $issueData): void
    {
        $notificationManager = \Puleeno\SecurityBot\WebMonitor\NotificationManager::getInstance();

        // Tạo message cho notification
        $message = $this->formatNotificationMessage($issuerName, $issueData);
        $context = [
            'issuer' => $issuerName,
            'issue_data' => $issueData,
            'timestamp' => current_time('mysql')
        ];

        // Debug logging
        if (WP_DEBUG) {
            error_log("[Bot] queueNotificationsForIssue() - issuerName: " . $issuerName);
            error_log("[Bot] queueNotificationsForIssue() - issueId: " . $issueId);
            error_log("[Bot] queueNotificationsForIssue() - message: " . $message);
            error_log("[Bot] queueNotificationsForIssue() - context: " . json_encode($context));
        }

        // Thêm notification cho mỗi channel active
        foreach ($this->channels as $channel) {
            if ($channel->isAvailable()) {
                $notificationManager->queueNotification(
                    $channel->getName(),
                    $issueId,
                    $message,
                    $context
                );

                if (WP_DEBUG) {
                    error_log("[Bot] Queued notification for channel: " . $channel->getName() . ", issue: {$issueId}");
                }
            }
        }
    }

    /**
     * Format message cho notification
     *
     * @param string $issuerName
     * @param array $issueData
     * @return string
     */
    private function formatNotificationMessage(string $issuerName, array $issueData): string
    {
        // Debug logging - ALWAYS LOG for debugging
        error_log("[Bot] formatNotificationMessage() - issuerName: " . $issuerName);
        error_log("[Bot] formatNotificationMessage() - issueData: " . json_encode($issueData));

        $title = $issueData['title'] ?? 'Security Issue Detected';
        $description = $issueData['description'] ?? 'A security issue has been detected';
        $severity = $issueData['severity'] ?? 'medium';
        $type = $issueData['type'] ?? 'unknown';
        $filePath = $issueData['file_path'] ?? '';
        $ipAddress = $issueData['ip_address'] ?? '';
        $username = $issueData['username'] ?? '';
        $email = $issueData['email'] ?? '';
        $roles = $issueData['roles'] ?? '';
        $userAgent = $issueData['user_agent'] ?? '';
        $attemptCount = $issueData['attempt_count'] ?? 0;

        // Emoji cho severity
        $severityEmoji = [
            'low' => '🟢',
            'medium' => '🟡',
            'high' => '🔴',
            'critical' => '🚨'
        ];
        $severityIcon = $severityEmoji[$severity] ?? '🟡';

        // Emoji cho type
        $typeEmoji = [
            'failed_login_attempts' => '🔐',
            'brute_force_attack' => '⚠️',
            'suspicious_admin_login' => '👤',
            'off_hours_login' => '🌙',
            'redirect' => '🔀',
            'user_registration' => '👥',
            'file_change' => '📁',
            'malware' => '☠️'
        ];
        $typeIcon = $typeEmoji[$type] ?? '🔔';

        // Format message dựa vào type
        if ($type === 'redirect' || $issuerName === 'RealtimeRedirectIssuer') {
            // Redirect details
            $toUrl = $issueData['to_url'] ?? 'unknown';
            $fromUrl = $issueData['from_url'] ?? 'unknown';
            $method = $issueData['method'] ?? 'unknown';
            $statusCode = $issueData['status'] ?? 'unknown';
            $userId = $issueData['user_id'] ?? 0;
            $referer = $issueData['referer'] ?? '';

            $message = "🔀 *CẢNH BÁO REDIRECT*\n\n";
            $message .= "*Phát hiện redirect đáng ngờ*\n\n";
            $message .= "🎯 *Đích đến:*\n`{$toUrl}`\n\n";
            $message .= "📍 *Từ URL:* `{$fromUrl}`\n";
            $message .= "⚙️ *Phương thức:* `{$method}`\n";
            if ($statusCode && $statusCode !== 'unknown') {
                $message .= "📊 *HTTP Status:* `{$statusCode}`\n";
            }

            if ($userId > 0) {
                $user = get_userdata($userId);
                if ($user) {
                    $message .= "\n👤 *User:* {$user->display_name} (@{$user->user_login})\n";
                    $message .= "🔑 *Roles:* " . implode(', ', $user->roles) . "\n";
                }
            } else {
                $message .= "\n👤 *User:* Guest (chưa đăng nhập)\n";
            }

            if (!empty($ipAddress)) {
                $message .= "🌐 *IP Address:* `{$ipAddress}`\n";
            }

            if (!empty($referer) && $referer !== 'unknown') {
                $message .= "🔗 *Referer:* `{$referer}`\n";
            }

            $message .= "\n⚠️ *Mức độ:* {$severityIcon} *" . strtoupper($severity) . "*";
        } else if ($type === 'failed_login_attempts') {
            $message = "🚨 *CẢNH BÁO BẢO MẬT*\n\n";
            $message .= "🔐 *Phát hiện nhiều lần đăng nhập thất bại*\n\n";
            $message .= "👤 Username: *{$username}*\n";
            $message .= "🌐 IP Address: *{$ipAddress}*\n";
            if ($attemptCount > 0) {
                $message .= "🔢 Số lần thử: *{$attemptCount}*\n";
            }
            $message .= "⚠️ Mức độ: {$severityIcon} *" . strtoupper($severity) . "*\n\n";
            $message .= "📝 Chi tiết:\n_{$description}_\n";
        } elseif ($type === 'brute_force_attack') {
            $uniqueUsernames = $issueData['unique_usernames'] ?? 0;
            $totalAttempts = $issueData['total_attempts'] ?? 0;

            $message = "🚨 *CẢNH BÁO KHẨN CẤP*\n\n";
            $message .= "⚠️ *Phát hiện tấn công Brute Force*\n\n";
            $message .= "🌐 IP Address: *{$ipAddress}*\n";
            $message .= "🔢 Tổng số lần thử: *{$totalAttempts}*\n";
            $message .= "👥 Số username khác nhau: *{$uniqueUsernames}*\n";
            $message .= "🚨 Mức độ: {$severityIcon} *" . strtoupper($severity) . "*\n\n";
            $message .= "📝 Chi tiết:\n_{$description}_\n";
        } elseif ($type === 'user_registration' || strpos($issuerName, 'UserRegistration') !== false) {
            $message = "🔔 *THÔNG BÁO BẢO MẬT*\n\n";
            $message .= "👥 *User mới được tạo*\n\n";
            $message .= "👤 Username: *{$username}*\n";
            if (!empty($email)) {
                $message .= "📧 Email: *{$email}*\n";
            }
            if (!empty($roles)) {
                $rolesStr = is_array($roles) ? implode(', ', $roles) : $roles;
                $message .= "🔑 Roles: *{$rolesStr}*\n";
            }
            if (!empty($ipAddress)) {
                $message .= "🌐 IP Address: *{$ipAddress}*\n";
            }
            $message .= "⚠️ Mức độ: {$severityIcon} *" . strtoupper($severity) . "*\n\n";
            $message .= "📝 Chi tiết:\n_{$description}_\n";
        } elseif ($issuerName === 'File Change Monitor' || $type === 'file_change') {
            // File change details
            $message = "📁 *FILE CHANGE DETECTED*\n\n";
            $message .= "*" . ($title ?: 'File changed') . "*\n\n";
            // Extract file path from description if provided like '... File: path (Size: ..., Modified: ...)'
            $fileLine = '';
            if (!empty($description)) {
                $fileLine = $description;
            }
            if (!empty($filePath)) {
                $message .= "🗂 File: `{$filePath}`\n";
            }
            if (!empty($fileLine)) {
                $message .= "📝 Chi tiết: \n" . $fileLine . "\n";
            }
            $message .= "⚠️ Mức độ: {$severityIcon} *" . strtoupper($severity) . "*";
        } else {
            // Default format
            $message = "{$typeIcon} *CẢNH BÁO BẢO MẬT*\n\n";
            $message .= "*{$title}*\n\n";
            $message .= "📝 _{$description}_\n\n";
            $message .= "⚠️ Mức độ: {$severityIcon} *" . strtoupper($severity) . "*\n";

            // Thông tin bổ sung
            if (!empty($filePath)) {
                $message .= "📁 File: `{$filePath}`\n";
            }
            if (!empty($ipAddress)) {
                $message .= "🌐 IP: *{$ipAddress}*\n";
            }
            if (!empty($username)) {
                $message .= "👤 User: *{$username}*\n";
            }
            if (!empty($email)) {
                $message .= "📧 Email: *{$email}*\n";
            }
            if (!empty($roles)) {
                $rolesStr = is_array($roles) ? implode(', ', $roles) : $roles;
                $message .= "🔑 Roles: *{$rolesStr}*\n";
            }
        }

        // User Agent (nếu có và ngắn)
        if (!empty($userAgent) && strlen($userAgent) < 100) {
            $message .= "\n🔍 User Agent:\n`{$userAgent}`\n";
        }

        // Footer
        $message .= "\n⏰ " . current_time('d/m/Y H:i:s');
        $message .= "\n🌐 " . home_url();

        return $message;
    }

    /**
     * Lấy channel theo tên
     *
     * @param string $channelName
     * @return \Puleeno\SecurityBot\WebMonitor\Abstracts\Channel|null
     */
    public function getChannel(string $channelName): ?\Puleeno\SecurityBot\WebMonitor\Abstracts\Channel
    {
        foreach ($this->channels as $channel) {
            if ($channel->getName() === $channelName) {
                return $channel;
            }
        }
        return null;
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
                    add_action('admin_notices', function () {
                        echo '<div class="notice notice-success"><p>Security Monitor Bot đã được khởi động!</p></div>';
                    });
                    break;

                case 'stop':
                    $this->stop();
                    add_action('admin_notices', function () {
                        echo '<div class="notice notice-info"><p>Security Monitor Bot đã được dừng!</p></div>';
                    });
                    break;

                case 'run_check':
                    $issues = $this->runCheck();
                    $count = count($issues);
                    add_action('admin_notices', function () use ($count) {
                        $class = $count > 0 ? 'notice-warning' : 'notice-success';
                        $message = $count > 0 ? "Phát hiện {$count} vấn đề bảo mật!" : "Không phát hiện vấn đề nào.";
                        echo "<div class=\"notice {$class}\"><p>{$message}</p></div>";
                    });
                    break;
            }
        }

        // Handle database migration
        if (isset($_POST['action']) && $_POST['action'] === 'migrate_database' && wp_verify_nonce($_POST['_wpnonce'], 'security_monitor_migrate_db')) {
            $oldVersion = get_option('wp_security_monitor_db_version', '0');
            Schema::updateSchema();
            $newVersion = get_option('wp_security_monitor_db_version');

            add_action('admin_notices', function () use ($oldVersion, $newVersion) {
                echo '<div class="notice notice-success is-dismissible">';
                echo '<p><strong>✅ Migration hoàn tất!</strong> Database đã được cập nhật từ version <code>' . esc_html($oldVersion) . '</code> lên <code>' . esc_html($newVersion) . '</code></p>';
                echo '</div>';
            });

            if (WP_DEBUG) {
                error_log('[WP Security Monitor] Manual migration from ' . $oldVersion . ' to ' . $newVersion);
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
        // Đảm bảo khởi tạo channels/issuers theo trạng thái hiện tại
        $this->ensureChannelsInitialized();

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
     * Test gửi tin nhắn thực tế qua channel
     */
    public function ajaxTestSendMessage(): void
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
            $result = $this->testSendMessage($channelType);

            if ($result['success']) {
                wp_send_json_success($result['message']);
            } else {
                wp_send_json_error($result['message']);
            }

        } catch (\Exception $e) {
            wp_send_json_error('Send message test failed: ' . $e->getMessage());
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
        $botToken = CredentialManager::getCredential(CredentialManager::TYPE_TELEGRAM_TOKEN, false);
        $chatId = CredentialManager::getCredential(CredentialManager::TYPE_TELEGRAM_CHAT_ID, false);
        $enabled = get_option('wp_security_monitor_telegram_enabled', false);

        if (empty($botToken) || empty($chatId)) {
            return [
                'success' => false,
                'message' => 'Telegram config is incomplete. Please check bot token and chat ID.'
            ];
        }

        if (!$enabled) {
            return [
                'success' => false,
                'message' => 'Telegram channel is disabled. Please enable it first.'
            ];
        }

        $config = [
            'bot_token' => $botToken,
            'chat_id' => $chatId
        ];

        $telegram = new \Puleeno\SecurityBot\WebMonitor\Channels\TelegramChannel();
        $telegram->configure($config);

        // TelegramChannel::testConnection() đã cung cấp thông tin SSL và protocol
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

        if (!($config['enabled'] ?? true)) {
            return [
                'success' => false,
                'message' => 'Email channel is disabled. Please enable it first.'
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
        $webhookUrl = CredentialManager::getCredential(CredentialManager::TYPE_SLACK_WEBHOOK, false);
        $enabled = get_option('wp_security_monitor_slack_enabled', false);

        if (empty($webhookUrl)) {
            return [
                'success' => false,
                'message' => 'Slack config is incomplete. Please check webhook URL.'
            ];
        }

        if (!$enabled) {
            return [
                'success' => false,
                'message' => 'Slack channel is disabled. Please enable it first.'
            ];
        }

        $config = [
            'webhook_url' => $webhookUrl,
            'channel' => get_option('wp_security_monitor_slack_channel', '#general'),
            'username' => get_option('wp_security_monitor_slack_username', 'WP Security Monitor'),
            'icon_emoji' => get_option('wp_security_monitor_slack_icon', ':shield:')
        ];

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

        if (!($config['enabled'] ?? true)) {
            return [
                'success' => false,
                'message' => 'Log channel is disabled. Please enable it first.'
            ];
        }

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

    /**
     * Test gửi tin nhắn thực tế qua channel
     */
    private function testSendMessage(string $channelType): array
    {
        switch ($channelType) {
            case 'telegram':
                return $this->testTelegramSendMessage();

            case 'email':
                return $this->testEmailSendMessage();

            case 'slack':
                return $this->testSlackSendMessage();

            case 'log':
                return $this->testLogSendMessage();

            default:
                return [
                    'success' => false,
                    'message' => "Unknown channel type: {$channelType}"
                ];
        }
    }

    /**
     * Test gửi tin nhắn Telegram
     */
    private function testTelegramSendMessage(): array
    {
        $botToken = CredentialManager::getCredential(CredentialManager::TYPE_TELEGRAM_TOKEN, false);
        $chatId = CredentialManager::getCredential(CredentialManager::TYPE_TELEGRAM_CHAT_ID, false);
        $enabled = get_option('wp_security_monitor_telegram_enabled', false);

        if (empty($botToken) || empty($chatId)) {
            return [
                'success' => false,
                'message' => 'Telegram config is incomplete. Please check bot token and chat ID.'
            ];
        }

        if (!$enabled) {
            return [
                'success' => false,
                'message' => 'Telegram channel is disabled. Please enable it first.'
            ];
        }

        $config = [
            'bot_token' => $botToken,
            'chat_id' => $chatId,
            'enabled' => true
        ];

        $telegram = new \Puleeno\SecurityBot\WebMonitor\Channels\TelegramChannel();
        $telegram->configure($config);

        // Gửi tin nhắn Telegram test với thông tin site
        $siteName = get_bloginfo('name');
        $siteUrl = get_site_url();
        $currentTime = current_time('d/m/Y H:i:s');

        $testMessage = "🧪 *Test Tin Nhắn Telegram*\n\n" .
            "Đây là tin nhắn test từ Security Bot.\n\n" .
            "📱 *Thông tin Site:*\n" .
            "• Tên: {$siteName}\n" .
            "• URL: {$siteUrl}\n" .
            "• Thời gian: {$currentTime}\n\n" .
            "Nếu bạn nhận được tin nhắn này, có nghĩa là bot đã hoạt động bình thường!";

        try {
            $result = $telegram->send($testMessage);

            if ($result) {
                return [
                    'success' => true,
                    'message' => 'Tin nhắn Telegram test đã được gửi thành công! Hãy kiểm tra Telegram chat của bạn.'
                ];
            } else {
                return [
                    'success' => false,
                    'message' => 'Gửi tin nhắn Telegram test thất bại. Kiểm tra error log để xem chi tiết.'
                ];
            }
        } catch (\Exception $e) {
            return [
                'success' => false,
                'message' => 'Lỗi khi gửi tin nhắn Telegram: ' . $e->getMessage()
            ];
        }
    }

    /**
     * Test gửi tin nhắn Email
     */
    private function testEmailSendMessage(): array
    {
        $emailConfig = get_option('wp_security_monitor_email_config', []);
        $enabled = $emailConfig['enabled'] ?? true;

        if (empty($emailConfig['to']) || !$enabled) {
            return [
                'success' => false,
                'message' => 'Email config is incomplete or disabled. Please check email configuration.'
            ];
        }

        $email = new EmailChannel();
        $email->configure($emailConfig);

        // Gửi email test với thông tin site
        $siteName = get_bloginfo('name');
        $siteUrl = get_site_url();
        $currentTime = current_time('d/m/Y H:i:s');

        $testMessage = "🧪 Test Email\n\n" .
            "Đây là email test từ Security Bot.\n\n" .
            "📧 Thông tin Site:\n" .
            "• Tên: {$siteName}\n" .
            "• URL: {$siteUrl}\n" .
            "• Thời gian: {$currentTime}\n\n" .
            "Nếu bạn nhận được email này, có nghĩa là bot đã hoạt động bình thường!";

        try {
            $result = $email->send($testMessage);

            if ($result) {
                return [
                    'success' => true,
                    'message' => 'Email test đã được gửi thành công! Hãy kiểm tra hộp thư của bạn.'
                ];
            } else {
                return [
                    'success' => false,
                    'message' => 'Gửi email test thất bại. Kiểm tra error log để xem chi tiết.'
                ];
            }
        } catch (\Exception $e) {
            return [
                'success' => false,
                'message' => 'Lỗi khi gửi email: ' . $e->getMessage()
            ];
        }
    }

    /**
     * Test gửi tin nhắn Slack
     */
    private function testSlackSendMessage(): array
    {
        $webhookUrl = CredentialManager::getCredential(CredentialManager::TYPE_SLACK_WEBHOOK, false);
        $enabled = get_option('wp_security_monitor_slack_enabled', false);

        if (empty($webhookUrl)) {
            return [
                'success' => false,
                'message' => 'Slack config is incomplete. Please check webhook URL.'
            ];
        }

        if (!$enabled) {
            return [
                'success' => false,
                'message' => 'Slack channel is disabled. Please enable it first.'
            ];
        }

        $config = [
            'webhook_url' => $webhookUrl,
            'channel' => get_option('wp_security_monitor_slack_channel', '#general'),
            'username' => get_option('wp_security_monitor_slack_username', 'WP Security Monitor'),
            'icon_emoji' => get_option('wp_security_monitor_slack_icon', ':shield:')
        ];

        $slack = new \Puleeno\SecurityBot\WebMonitor\Channels\SlackChannel();
        $slack->configure($config);

        // Gửi tin nhắn Slack test với thông tin site
        $siteName = get_bloginfo('name');
        $siteUrl = get_site_url();
        $currentTime = current_time('d/m/Y H:i:s');

        $testMessage = "🧪 *Test Tin Nhắn Slack*\n\n" .
            "Đây là tin nhắn test từ Security Bot.\n\n" .
            "💬 *Thông tin Site:*\n" .
            "• Tên: {$siteName}\n" .
            "• URL: {$siteUrl}\n" .
            "• Thời gian: {$currentTime}\n\n" .
            "Nếu bạn nhận được tin nhắn này, có nghĩa là bot đã hoạt động bình thường!";

        try {
            $result = $slack->send($testMessage);

            if ($result) {
                return [
                    'success' => true,
                    'message' => 'Tin nhắn Slack test đã được gửi thành công! Hãy kiểm tra Slack channel của bạn.'
                ];
            } else {
                return [
                    'success' => false,
                    'message' => 'Gửi tin nhắn Slack test thất bại. Kiểm tra error log để xem chi tiết.'
                ];
            }
        } catch (\Exception $e) {
            return [
                'success' => false,
                'message' => 'Lỗi khi gửi tin nhắn Slack: ' . $e->getMessage()
            ];
        }
    }

    /**
     * Test gửi tin nhắn Log
     */
    private function testLogSendMessage(): array
    {
        $config = get_option('wp_security_monitor_log_config', []);

        if (!($config['enabled'] ?? true)) {
            return [
                'success' => false,
                'message' => 'Log channel is disabled. Please enable it first.'
            ];
        }

        $log = new LogChannel();
        $log->configure($config);

        // Gửi log test với thông tin site
        $siteName = get_bloginfo('name');
        $siteUrl = get_site_url();
        $currentTime = current_time('d/m/Y H:i:s');

        $testMessage = "🧪 Test Log\n\n" .
            "Đây là log test từ Security Bot.\n\n" .
            "📝 Thông tin Site:\n" .
            "• Tên: {$siteName}\n" .
            "• URL: {$siteUrl}\n" .
            "• Thời gian: {$currentTime}\n\n" .
            "Nếu bạn thấy log này, có nghĩa là bot đã hoạt động bình thường!";

        try {
            $result = $log->send($testMessage);

            if ($result) {
                return [
                    'success' => true,
                    'message' => 'Log test đã được ghi thành công! Kiểm tra log file để xem chi tiết.'
                ];
            } else {
                return [
                    'success' => false,
                    'message' => 'Ghi log test thất bại. Kiểm tra error log để xem chi tiết.'
                ];
            }
        } catch (\Exception $e) {
            return [
                'success' => false,
                'message' => 'Lỗi khi ghi log: ' . $e->getMessage()
            ];
        }
    }

    /**
     * Xử lý notifications theo cron job
     *
     * @return void
     */
    public function processNotificationsCron(): void
    {
        $processor = \Puleeno\SecurityBot\WebMonitor\NotificationProcessor::getInstance();
        $processor->processNotificationsCron();
    }

    /**
     * Xử lý suspicious redirect detection realtime
     *
     * @param array $issue
     * @return void
     */
    public function handleSuspiciousRedirect(array $issue): void
    {
        // CHECK FLAG FIRST - Nếu bot đã dừng, không xử lý
        if (!$this->isRunning()) {
            return;
        }

        try {
            // Thêm backtrace vào issue data nếu có
            $issueData = $issue['details'];
            if (isset($issue['details']['backtrace'])) {
                $issueData['backtrace'] = $issue['details']['backtrace'];
            }

            // Xử lý domain whitelist
            $this->handleRedirectDomainWhitelist($issueData);

            // Log issue ngay lập tức
            // Realtime redirect sẽ LUÔN notify vì không pass issuer instance
            $issueId = $this->issueManager->recordIssue(
                'realtime_redirect',
                $issueData
            );

            // Chỉ gửi notification nếu đây là issue mới (không phải update)
            if ($issueId && $this->isNewIssue($issueId)) {
                // Tạo notification records cho tất cả channels active
                $this->ensureChannelsInitialized();
                $notificationManager = \Puleeno\SecurityBot\WebMonitor\NotificationManager::getInstance();

                foreach ($this->channels as $channelName => $channel) {
                    if ($channel->isAvailable()) {
                        // Pass issueData (details) thay vì issue để có đầy đủ thông tin
                        $message = $this->formatNotificationMessage('RealtimeRedirectIssuer', $issueData);
                        $context = [
                            'issuer' => 'RealtimeRedirectIssuer',
                            'issue_data' => $issueData,
                            'timestamp' => current_time('mysql'),
                            'is_realtime' => true
                        ];

                        // Tạo notification record với status 'sent' ngay lập tức
                        $notificationManager->queueNotification(
                            $channelName,
                            $issueId,
                            $message,
                            $context
                        );

                        // Gửi notification trực tiếp
                        try {
                            $result = $channel->send($message, $context);

                            if ($result) {
                                // Cập nhật status thành 'sent'
                                $notificationManager->updateNotificationStatus(
                                    $notificationManager->getLastInsertedNotificationId(),
                                    'sent'
                                );
                                error_log("WP Security Monitor: Realtime notification sent successfully via {$channelName}");
                            } else {
                                // Cập nhật status thành 'failed'
                                $notificationManager->updateNotificationStatus(
                                    $notificationManager->getLastInsertedNotificationId(),
                                    'failed',
                                    'Failed to send notification'
                                );
                                error_log("WP Security Monitor: Failed to send realtime notification via {$channelName}");
                            }
                        } catch (\Exception $e) {
                            // Cập nhật status thành 'failed'
                            $notificationManager->updateNotificationStatus(
                                $notificationManager->getLastInsertedNotificationId(),
                                'failed',
                                'Exception: ' . $e->getMessage()
                            );
                            error_log("WP Security Monitor: Error sending realtime notification via {$channelName}: " . $e->getMessage());
                        }
                    }
                }
            } else if ($issueId) {
                // Issue đã tồn tại, chỉ log update
                error_log("WP Security Monitor: Updated existing redirect issue ID: {$issueId}");
            }

        } catch (\Exception $e) {
            error_log('WP Security Monitor: Error handling suspicious redirect - ' . $e->getMessage());
        }
    }

    /**
     * Kiểm tra xem issue có phải mới không
     *
     * @param int $issueId
     * @return bool
     */
    private function isNewIssue(int $issueId): bool
    {
        global $wpdb;

        $table = $wpdb->prefix . 'security_monitor_issues';
        $detectionCount = $wpdb->get_var($wpdb->prepare(
            "SELECT detection_count FROM {$table} WHERE id = %d",
            $issueId
        ));

        // Issue mới nếu detection_count = 1
        return $detectionCount == 1;
    }

    /**
     * Xử lý domain whitelist cho redirect
     *
     * @param array $issueData
     * @return void
     */
    private function handleRedirectDomainWhitelist(array $issueData): void
    {
        try {
            $whitelistManager = \Puleeno\SecurityBot\WebMonitor\WhitelistManager::getInstance();

            // Lấy redirect URL từ issue data
            $redirectUrl = $issueData['to_url'] ?? '';
            if (empty($redirectUrl)) {
                return;
            }

            // Trích xuất domain từ URL
            $domain = $whitelistManager->extractDomain($redirectUrl);
            if (empty($domain)) {
                return;
            }

            // Kiểm tra xem domain có trong whitelist không
            if ($whitelistManager->isDomainWhitelisted($domain)) {
                // Domain đã được whitelist, ghi lại usage
                $whitelistManager->recordDomainUsage($domain);
                return;
            }

            // Kiểm tra xem domain có bị reject không
            if ($whitelistManager->isDomainRejected($domain)) {
                // Domain đã bị reject, không cần thêm vào pending
                return;
            }

            // Kiểm tra xem domain có trong pending không
            if ($whitelistManager->isDomainPending($domain)) {
                // Domain đã trong pending, cập nhật detection count
                $whitelistManager->addPendingDomain($domain, [
                    'source' => 'realtime_redirect',
                    'redirect_url' => $redirectUrl,
                    'from_url' => $issueData['from_url'] ?? '',
                    'user_agent' => $issueData['user_agent'] ?? '',
                    'ip_address' => $issueData['ip_address'] ?? '',
                    'timestamp' => current_time('mysql')
                ]);
                return;
            }

            // Domain mới, thêm vào pending list để admin review
            $whitelistManager->addPendingDomain($domain, [
                'source' => 'realtime_redirect',
                'redirect_url' => $redirectUrl,
                'from_url' => $issueData['from_url'] ?? '',
                'user_agent' => $issueData['user_agent'] ?? '',
                'ip_address' => $issueData['ip_address'] ?? '',
                'timestamp' => current_time('mysql')
            ]);

            if (WP_DEBUG) {
                error_log("WP Security Monitor: Added domain '{$domain}' to pending list for review");
            }

        } catch (\Exception $e) {
            error_log('WP Security Monitor: Error handling redirect domain whitelist - ' . $e->getMessage());
        }
    }

    /**
     * Lấy danh sách tất cả issuers
     *
     * @return array
     */
    public function getIssuers(): array
    {
        return $this->issuers;
    }

    /**
     * Xử lý user registration detection realtime
     *
     * @param array $userData
     * @return void
     */
    public function handleUserRegistration(array $userData): void
    {
        // CHECK FLAG FIRST - Nếu bot đã dừng, không xử lý
        if (!$this->isRunning()) {
            return;
        }

        try {
            if (WP_DEBUG) {
                error_log("[Bot] Handling user registration: " . json_encode($userData));
            }

            // Tạo issue data với thông tin user
            $issueData = [
                'user_id' => $userData['user_id'],
                'username' => $userData['username'],
                'email' => $userData['email'],
                'display_name' => $userData['display_name'],
                'roles' => $userData['roles'],
                'registration_date' => $userData['registration_date'],
                'ip_address' => $userData['ip_address'],
                'user_agent' => $userData['user_agent'],
                'referer' => $userData['referer'],
                'backtrace' => $userData['backtrace'] ?? []
            ];

            // Log issue ngay lập tức
            // Realtime user registration sẽ LUÔN notify vì không pass issuer instance
            $issueId = $this->issueManager->recordIssue(
                'realtime_user_registration',
                $issueData
            );

            // Chỉ gửi notification nếu đây là issue mới (không phải update)
            if ($issueId && $this->isNewIssue($issueId)) {
                // Tạo notification records cho tất cả channels active
                $this->ensureChannelsInitialized();
                $notificationManager = \Puleeno\SecurityBot\WebMonitor\NotificationManager::getInstance();

                foreach ($this->channels as $channelName => $channel) {
                    if ($channel->isAvailable()) {
                        $message = $this->formatNotificationMessage('RealtimeUserRegistrationIssuer', $issueData);
                        $context = [
                            'issuer' => 'RealtimeUserRegistrationIssuer',
                            'issue_data' => $issueData,
                            'timestamp' => current_time('mysql'),
                            'is_realtime' => true
                        ];

                        // Tạo notification record với status 'sent' ngay lập tức
                        $notificationManager->queueNotification(
                            $channelName,
                            $issueId,
                            $message,
                            $context
                        );

                        // Gửi notification trực tiếp
                        try {
                            $result = $channel->send($message, $context);

                            if ($result) {
                                // Cập nhật status thành 'sent'
                                $notificationManager->updateNotificationStatus(
                                    $notificationManager->getLastInsertedNotificationId(),
                                    'sent'
                                );
                                error_log("WP Security Monitor: Realtime user registration notification sent successfully via {$channelName}");
                            } else {
                                // Cập nhật status thành 'failed'
                                $notificationManager->updateNotificationStatus(
                                    $notificationManager->getLastInsertedNotificationId(),
                                    'failed',
                                    'Failed to send notification'
                                );
                                error_log("WP Security Monitor: Failed to send realtime user registration notification via {$channelName}");
                            }
                        } catch (\Exception $e) {
                            // Cập nhật status thành 'failed'
                            $notificationManager->updateNotificationStatus(
                                $notificationManager->getLastInsertedNotificationId(),
                                'failed',
                                'Exception: ' . $e->getMessage()
                            );
                            error_log("WP Security Monitor: Error sending realtime user registration notification via {$channelName}: " . $e->getMessage());
                        }
                    }
                }
            } else if ($issueId) {
                // Issue đã tồn tại, chỉ log update
                error_log("WP Security Monitor: Updated existing user registration issue ID: {$issueId}");
            }

        } catch (\Exception $e) {
            error_log('WP Security Monitor: Error handling user registration - ' . $e->getMessage());
        }
    }

    /**
     * Xử lý realtime failed login detection
     *
     * @param array $issueData
     * @return void
     */
    public function handleRealtimeFailedLogin(array $issueData): void
    {
        // CHECK FLAG FIRST - Nếu bot đã dừng, không xử lý
        if (!$this->isRunning()) {
            return;
        }

        try {
            if (WP_DEBUG) {
                error_log("[Bot] Handling realtime failed login: " . json_encode($issueData));
            }

            // Log issue ngay lập tức
            $issueId = $this->issueManager->recordIssue(
                'realtime_failed_login',
                $issueData
            );

            // Chỉ gửi notification nếu đây là issue mới (không phải update)
            if ($issueId && $this->isNewIssue($issueId)) {
                // Tạo notification records cho tất cả channels active
                $this->ensureChannelsInitialized();
                $notificationManager = \Puleeno\SecurityBot\WebMonitor\NotificationManager::getInstance();

                foreach ($this->channels as $channelName => $channel) {
                    if ($channel->isAvailable()) {
                        $message = $this->formatNotificationMessage('LoginAttemptIssuer', $issueData);
                        $context = [
                            'issuer' => 'LoginAttemptIssuer',
                            'issue_data' => $issueData,
                            'timestamp' => current_time('mysql'),
                            'is_realtime' => true
                        ];

                        // Tạo notification record
                        $notificationManager->queueNotification(
                            $channelName,
                            $issueId,
                            $message,
                            $context
                        );

                        // Gửi notification trực tiếp
                        try {
                            $result = $channel->send($message, $context);

                            if ($result) {
                                // Cập nhật status thành 'sent'
                                $notificationManager->updateNotificationStatus(
                                    $notificationManager->getLastInsertedNotificationId(),
                                    'sent'
                                );
                                error_log("WP Security Monitor: Realtime failed login notification sent successfully via {$channelName}");
                            } else {
                                // Cập nhật status thành 'failed'
                                $notificationManager->updateNotificationStatus(
                                    $notificationManager->getLastInsertedNotificationId(),
                                    'failed',
                                    'Failed to send notification'
                                );
                                error_log("WP Security Monitor: Failed to send realtime failed login notification via {$channelName}");
                            }
                        } catch (\Exception $e) {
                            // Cập nhật status thành 'failed'
                            $notificationManager->updateNotificationStatus(
                                $notificationManager->getLastInsertedNotificationId(),
                                'failed',
                                'Exception: ' . $e->getMessage()
                            );
                            error_log("WP Security Monitor: Error sending realtime failed login notification via {$channelName}: " . $e->getMessage());
                        }
                    }
                }
            } else if ($issueId) {
                // Issue đã tồn tại, chỉ log update
                error_log("WP Security Monitor: Updated existing failed login issue ID: {$issueId}");
            }

        } catch (\Exception $e) {
            error_log('WP Security Monitor: Error handling realtime failed login - ' . $e->getMessage());
        }
    }

    /**
     * Xử lý realtime brute force detection
     *
     * @param array $issueData
     * @return void
     */
    public function handleRealtimeBruteForce(array $issueData): void
    {
        // CHECK FLAG FIRST - Nếu bot đã dừng, không xử lý
        if (!$this->isRunning()) {
            return;
        }

        try {
            if (WP_DEBUG) {
                error_log("[Bot] Handling realtime brute force: " . json_encode($issueData));
            }

            // Log issue ngay lập tức
            $issueId = $this->issueManager->recordIssue(
                'realtime_brute_force',
                $issueData
            );

            // Chỉ gửi notification nếu đây là issue mới (không phải update)
            if ($issueId && $this->isNewIssue($issueId)) {
                // Tạo notification records cho tất cả channels active
                $this->ensureChannelsInitialized();
                $notificationManager = \Puleeno\SecurityBot\WebMonitor\NotificationManager::getInstance();

                foreach ($this->channels as $channelName => $channel) {
                    if ($channel->isAvailable()) {
                        $message = $this->formatNotificationMessage('LoginAttemptIssuer', $issueData);
                        $context = [
                            'issuer' => 'LoginAttemptIssuer',
                            'issue_data' => $issueData,
                            'timestamp' => current_time('mysql'),
                            'is_realtime' => true
                        ];

                        // Tạo notification record
                        $notificationManager->queueNotification(
                            $channelName,
                            $issueId,
                            $message,
                            $context
                        );

                        // Gửi notification trực tiếp
                        try {
                            $result = $channel->send($message, $context);

                            if ($result) {
                                // Cập nhật status thành 'sent'
                                $notificationManager->updateNotificationStatus(
                                    $notificationManager->getLastInsertedNotificationId(),
                                    'sent'
                                );
                                error_log("WP Security Monitor: Realtime brute force notification sent successfully via {$channelName}");
                            } else {
                                // Cập nhật status thành 'failed'
                                $notificationManager->updateNotificationStatus(
                                    $notificationManager->getLastInsertedNotificationId(),
                                    'failed',
                                    'Failed to send notification'
                                );
                                error_log("WP Security Monitor: Failed to send realtime brute force notification via {$channelName}");
                            }
                        } catch (\Exception $e) {
                            // Cập nhật status thành 'failed'
                            $notificationManager->updateNotificationStatus(
                                $notificationManager->getLastInsertedNotificationId(),
                                'failed',
                                'Exception: ' . $e->getMessage()
                            );
                            error_log("WP Security Monitor: Error sending realtime brute force notification via {$channelName}: " . $e->getMessage());
                        }
                    }
                }
            } else if ($issueId) {
                // Issue đã tồn tại, chỉ log update
                error_log("WP Security Monitor: Updated existing brute force issue ID: {$issueId}");
            }

        } catch (\Exception $e) {
            error_log('WP Security Monitor: Error handling realtime brute force - ' . $e->getMessage());
        }
    }

    /**
     * AJAX handler: Đánh dấu issue đã xem
     *
     * @return void
     */
    public function ajaxMarkViewed(): void
    {
        check_ajax_referer('security_monitor_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized']);
            return;
        }

        $issueId = isset($_POST['issue_id']) ? intval($_POST['issue_id']) : 0;

        if (!$issueId) {
            wp_send_json_error(['message' => 'Invalid issue ID']);
            return;
        }

        $issueManager = IssueManager::getInstance();
        $success = $issueManager->markAsViewed($issueId);

        if ($success) {
            wp_send_json_success(['message' => 'Issue đã được đánh dấu là đã xem']);
        } else {
            wp_send_json_error(['message' => 'Không thể đánh dấu issue']);
        }
    }

    /**
     * AJAX handler: Bỏ đánh dấu đã xem
     *
     * @return void
     */
    public function ajaxUnmarkViewed(): void
    {
        check_ajax_referer('security_monitor_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Unauthorized']);
            return;
        }

        $issueId = isset($_POST['issue_id']) ? intval($_POST['issue_id']) : 0;

        if (!$issueId) {
            wp_send_json_error(['message' => 'Invalid issue ID']);
            return;
        }

        $issueManager = IssueManager::getInstance();
        $success = $issueManager->unmarkAsViewed($issueId);

        if ($success) {
            wp_send_json_success(['message' => 'Đã bỏ đánh dấu đã xem']);
        } else {
            wp_send_json_error(['message' => 'Không thể bỏ đánh dấu']);
        }
    }

    /**
     * Xử lý fatal error detection
     *
     * @param array $errorData
     * @return void
     */
    public function handleFatalError(array $errorData): void
    {
        // CHECK FLAG FIRST - Nếu bot đã dừng, không xử lý
        if (!$this->isRunning()) {
            return;
        }

        try {
            if (WP_DEBUG) {
                error_log("[Bot] Handling fatal error: " . json_encode($errorData));
            }

            // Log issue ngay lập tức
            $issueId = $this->issueManager->recordIssue(
                'fatal_error',
                $errorData
            );

            // Chỉ gửi notification nếu đây là issue mới
            if ($issueId && $this->isNewIssue($issueId)) {
                // Tạo notification records cho tất cả channels active
                $this->ensureChannelsInitialized();
                $notificationManager = \Puleeno\SecurityBot\WebMonitor\NotificationManager::getInstance();

                foreach ($this->channels as $channelName => $channel) {
                    if ($channel->isAvailable()) {
                        $message = $this->formatFatalErrorMessage($errorData);
                        $context = [
                            'issuer' => 'FatalErrorIssuer',
                            'issue_data' => $errorData,
                            'timestamp' => current_time('mysql'),
                            'is_realtime' => true
                        ];

                        // Tạo notification record
                        $notificationManager->queueNotification(
                            $channelName,
                            $issueId,
                            $message,
                            $context
                        );

                        // Gửi notification trực tiếp
                        try {
                            $result = $channel->send($message, $context);

                            if ($result) {
                                $notificationManager->updateNotificationStatus(
                                    $notificationManager->getLastInsertedNotificationId(),
                                    'sent'
                                );
                                error_log("WP Security Monitor: Fatal error notification sent via {$channelName}");
                            } else {
                                $notificationManager->updateNotificationStatus(
                                    $notificationManager->getLastInsertedNotificationId(),
                                    'failed',
                                    'Failed to send notification'
                                );
                                error_log("WP Security Monitor: Failed to send fatal error notification via {$channelName}");
                            }
                        } catch (\Exception $e) {
                            $notificationManager->updateNotificationStatus(
                                $notificationManager->getLastInsertedNotificationId(),
                                'failed',
                                'Exception: ' . $e->getMessage()
                            );
                            error_log("WP Security Monitor: Error sending fatal error notification via {$channelName}: " . $e->getMessage());
                        }
                    }
                }
            } else if ($issueId) {
                error_log("WP Security Monitor: Updated existing fatal error issue ID: {$issueId}");
            }

        } catch (\Exception $e) {
            error_log('WP Security Monitor: Error handling fatal error - ' . $e->getMessage());
        }
    }

    /**
     * Xử lý malicious upload detection
     *
     * @param array $uploadData
     * @return void
     */
    public function handleMaliciousUpload(array $uploadData): void
    {
        // CHECK FLAG FIRST - Nếu bot đã dừng, không xử lý
        if (!$this->isRunning()) {
            return;
        }

        try {
            if (WP_DEBUG) {
                error_log("[Bot] Handling malicious upload: " . json_encode($uploadData));
            }

            // Log issue ngay lập tức
            $issueId = $this->issueManager->recordIssue(
                'malicious_upload',
                $uploadData
            );

            // Chỉ gửi notification nếu đây là issue mới
            if ($issueId && $this->isNewIssue($issueId)) {
                // Tạo notification records cho tất cả channels active
                $this->ensureChannelsInitialized();
                $notificationManager = \Puleeno\SecurityBot\WebMonitor\NotificationManager::getInstance();

                foreach ($this->channels as $channelName => $channel) {
                    if ($channel->isAvailable()) {
                        $message = $this->formatMaliciousUploadMessage($uploadData);
                        $context = [
                            'issuer' => 'PluginThemeUploadIssuer',
                            'issue_data' => $uploadData,
                            'timestamp' => current_time('mysql'),
                            'is_realtime' => true
                        ];

                        // Tạo notification record
                        $notificationManager->queueNotification(
                            $channelName,
                            $issueId,
                            $message,
                            $context
                        );

                        // Gửi notification trực tiếp
                        try {
                            $result = $channel->send($message, $context);

                            if ($result) {
                                $notificationManager->updateNotificationStatus(
                                    $notificationManager->getLastInsertedNotificationId(),
                                    'sent'
                                );
                                error_log("WP Security Monitor: Malicious upload notification sent via {$channelName}");
                            } else {
                                $notificationManager->updateNotificationStatus(
                                    $notificationManager->getLastInsertedNotificationId(),
                                    'failed',
                                    'Failed to send notification'
                                );
                                error_log("WP Security Monitor: Failed to send malicious upload notification via {$channelName}");
                            }
                        } catch (\Exception $e) {
                            $notificationManager->updateNotificationStatus(
                                $notificationManager->getLastInsertedNotificationId(),
                                'failed',
                                'Exception: ' . $e->getMessage()
                            );
                            error_log("WP Security Monitor: Error sending malicious upload notification via {$channelName}: " . $e->getMessage());
                        }
                    }
                }
            } else if ($issueId) {
                error_log("WP Security Monitor: Updated existing malicious upload issue ID: {$issueId}");
            }

        } catch (\Exception $e) {
            error_log('WP Security Monitor: Error handling malicious upload - ' . $e->getMessage());
        }
    }

    /**
     * Format fatal error message cho notification
     *
     * @param array $errorData
     * @return string
     */
    private function formatFatalErrorMessage(array $errorData): string
    {
        $level = $errorData['level'] ?? 'error';
        $severity = $errorData['severity'] ?? 'critical';
        $title = $errorData['title'] ?? 'Fatal Error';
        $description = $errorData['description'] ?? '';
        $filePath = $errorData['file_path'] ?? '';
        $lineNumber = $errorData['line_number'] ?? 0;

        // Escape markdown special characters
        $title = $this->escapeMarkdown($title);
        $description = $this->escapeMarkdown($description);

        // Truncate if too long (Telegram limit)
        if (strlen($title) > 200) {
            $title = substr($title, 0, 200) . '...';
        }
        if (strlen($description) > 500) {
            $description = substr($description, 0, 500) . '...';
        }

        $icon = $level === 'error' ? '🚨' : ($level === 'warning' ? '⚠️' : '⚡');

        $message = "{$icon} *CẢNH BÁO LỖI HỆ THỐNG*\n\n";
        $message .= "*Error Type:* {$title}\n\n";
        $message .= "📝 *Chi tiết:*\n{$description}\n\n";
        $message .= "⚠️ Mức độ: *" . strtoupper($severity) . "*\n";
        $message .= "🔢 Level: *{$level}*\n";

        if (!empty($filePath)) {
            $message .= "📁 File: `" . basename($filePath) . ":{$lineNumber}`\n";
        }

        if (!empty($errorData['url'])) {
            $message .= "🌐 URL: {$errorData['url']}\n";
        }

        $message .= "\n⏰ " . current_time('d/m/Y H:i:s');
        $message .= "\n🌐 " . home_url();

        return $message;
    }

    /**
     * Format malicious upload message cho notification
     *
     * @param array $uploadData
     * @return string
     */
    private function formatMaliciousUploadMessage(array $uploadData): string
    {
        $title = $uploadData['title'] ?? 'Malicious Upload Detected';
        $description = $uploadData['description'] ?? '';
        $itemType = $uploadData['item_type'] ?? 'file';
        $itemName = $uploadData['item_name'] ?? 'unknown';

        $message = "🚨 *CẢNH BÁO BẢO MẬT NGHIÊM TRỌNG*\n\n";
        $message .= "☠️ *Phát hiện mã độc trong upload*\n\n";
        $message .= "*{$title}*\n\n";
        $message .= "📝 _{$description}_\n\n";
        $message .= "📦 Loại: *" . ucfirst($itemType) . "*\n";
        $message .= "📛 Tên: *{$itemName}*\n";
        $message .= "⚠️ Mức độ: 🔴 *CRITICAL*\n\n";

        if (isset($uploadData['findings']) && !empty($uploadData['findings'])) {
            $findingsCount = is_array($uploadData['findings']) ? count($uploadData['findings']) : 0;
            $message .= "🔍 Phát hiện: *{$findingsCount}* pattern(s) độc hại\n\n";

            if ($findingsCount > 0 && $findingsCount <= 5) {
                $message .= "⚠️ *Chi tiết patterns:*\n";
                $i = 1;
                foreach ($uploadData['findings'] as $file => $patterns) {
                    if ($i > 5)
                        break;
                    $patternCount = is_array($patterns) ? count($patterns) : 0;
                    $fileName = basename($file);
                    $message .= "{$i}. `{$fileName}` - {$patternCount} pattern(s)\n";
                    $i++;
                }
            }
        }

        if (isset($uploadData['username']) && !empty($uploadData['username'])) {
            $message .= "\n👤 Upload bởi: *{$uploadData['username']}*\n";
        }

        if (isset($uploadData['ip_address']) && !empty($uploadData['ip_address'])) {
            $message .= "🌐 IP: *{$uploadData['ip_address']}*\n";
        }

        $message .= "\n⏰ " . current_time('d/m/Y H:i:s');
        $message .= "\n🌐 " . home_url();
        $message .= "\n\n⚠️ *HÀNH ĐỘNG NGAY:* Kiểm tra và xóa {$itemType} này!";

        return $message;
    }

    /**
     * Xử lý slow performance detection
     *
     * @param array $performanceData
     * @return void
     */
    public function handleSlowPerformance(array $performanceData): void
    {
        // CHECK FLAG FIRST - Nếu bot đã dừng, không xử lý
        if (!$this->isRunning()) {
            return;
        }

        try {
            if (WP_DEBUG) {
                error_log("[Bot] Handling slow performance: " . json_encode($performanceData));
            }

            // Log issue ngay lập tức
            $issueId = $this->issueManager->recordIssue(
                'slow_performance',
                $performanceData
            );

            // Chỉ gửi notification nếu đây là issue mới
            if ($issueId && $this->isNewIssue($issueId)) {
                // Tạo notification records cho tất cả channels active
                $this->ensureChannelsInitialized();
                $notificationManager = \Puleeno\SecurityBot\WebMonitor\NotificationManager::getInstance();

                foreach ($this->channels as $channelName => $channel) {
                    if ($channel->isAvailable()) {
                        $message = $this->formatSlowPerformanceMessage($performanceData);
                        $context = [
                            'issuer' => 'PerformanceIssuer',
                            'issue_data' => $performanceData,
                            'timestamp' => current_time('mysql'),
                            'is_realtime' => true
                        ];

                        // Tạo notification record
                        $notificationManager->queueNotification(
                            $channelName,
                            $issueId,
                            $message,
                            $context
                        );

                        // Gửi notification trực tiếp
                        try {
                            $result = $channel->send($message, $context);

                            if ($result) {
                                $notificationManager->updateNotificationStatus(
                                    $notificationManager->getLastInsertedNotificationId(),
                                    'sent'
                                );
                                error_log("WP Security Monitor: Slow performance notification sent via {$channelName}");
                            } else {
                                $notificationManager->updateNotificationStatus(
                                    $notificationManager->getLastInsertedNotificationId(),
                                    'failed',
                                    'Failed to send notification'
                                );
                                error_log("WP Security Monitor: Failed to send slow performance notification via {$channelName}");
                            }
                        } catch (\Exception $e) {
                            $notificationManager->updateNotificationStatus(
                                $notificationManager->getLastInsertedNotificationId(),
                                'failed',
                                'Exception: ' . $e->getMessage()
                            );
                            error_log("WP Security Monitor: Error sending slow performance notification via {$channelName}: " . $e->getMessage());
                        }
                    }
                }
            } else if ($issueId) {
                error_log("WP Security Monitor: Updated existing slow performance issue ID: {$issueId}");
            }

        } catch (\Exception $e) {
            error_log('WP Security Monitor: Error handling slow performance - ' . $e->getMessage());
        }
    }

    /**
     * Format slow performance message cho notification
     *
     * @param array $performanceData
     * @return string
     */
    private function formatSlowPerformanceMessage(array $performanceData): string
    {
        $executionTime = $performanceData['execution_time'] ?? 0;
        $threshold = $performanceData['threshold'] ?? 30;
        $severity = $performanceData['severity'] ?? 'medium';
        $url = $performanceData['url'] ?? '';
        $method = $performanceData['method'] ?? 'GET';

        $icon = $severity === 'critical' ? '🔴' : ($severity === 'high' ? '🟠' : '🟡');

        $message = "{$icon} *CẢNH BÁO HIỆU NĂNG*\n\n";
        $message .= "🐌 *Request xử lý quá chậm*\n\n";
        $message .= "⏱️ Thời gian: *{$executionTime}s* (ngưỡng: {$threshold}s)\n";
        $message .= "⚠️ Mức độ: *" . strtoupper($severity) . "*\n\n";

        // Request info
        $message .= "🌐 *Request Details:*\n";
        $message .= "• Method: *{$method}*\n";
        $message .= "• URL: `{$url}`\n";

        // Memory usage
        if (isset($performanceData['memory_used'])) {
            $message .= "• Memory: {$performanceData['memory_used']}";
            if (isset($performanceData['peak_memory'])) {
                $message .= " (peak: {$performanceData['peak_memory']})";
            }
            $message .= "\n";
        }

        // Queries info
        if (isset($performanceData['total_queries']) && $performanceData['total_queries'] > 0) {
            $message .= "• Queries: {$performanceData['total_queries']} queries\n";

            if (isset($performanceData['slow_queries']) && !empty($performanceData['slow_queries'])) {
                $slowCount = count($performanceData['slow_queries']);
                $message .= "• Slow queries (>1s): *{$slowCount}*\n";
            }
        }

        // Server load (gắn nhãn: CPU/Memory/Diskspace theo yêu cầu hiển thị)
        if (isset($performanceData['server_load']) && !empty($performanceData['server_load'])) {
            $load = $performanceData['server_load'];
            $l1 = $load['1min'] ?? '-';
            $l5 = $load['5min'] ?? '-';
            $l15 = $load['15min'] ?? '-';
            $message .= "• Server load: {$l1} (CPU) / {$l5} (Memory) / {$l15} (Diskspace)\n";
        }

        // Backtrace (top 5)
        if (isset($performanceData['backtrace']) && !empty($performanceData['backtrace'])) {
            $message .= "\n🔍 *Backtrace (Top 5):*\n";
            $traces = array_slice($performanceData['backtrace'], 0, 5);
            foreach ($traces as $trace) {
                // Hỗ trợ cả dạng string và array {file,line,function,class}
                if (is_array($trace)) {
                    $file = $trace['file'] ?? '';
                    $line = $trace['line'] ?? '';
                    $func = $trace['function'] ?? '';
                    $cls = $trace['class'] ?? '';

                    $parts = [];
                    if (!empty($file)) {
                        $parts[] = $file . (!empty($line) ? ":{$line}" : '');
                    }
                    if (!empty($cls) || !empty($func)) {
                        $parts[] = trim(($cls ? $cls . '::' : '') . ($func ?: '')) . '()';
                    }
                    $lineStr = implode(' — ', $parts);
                    $message .= "```\n{$lineStr}\n```\n";
                } else {
                    $message .= "```\n{$trace}\n```\n";
                }
            }
        }

        // Slow queries detail (top 3)
        if (isset($performanceData['slow_queries']) && !empty($performanceData['slow_queries'])) {
            $message .= "\n⚡ *Slow Queries (Top 3):*\n";
            $slowQueries = array_slice($performanceData['slow_queries'], 0, 3);
            foreach ($slowQueries as $i => $query) {
                $message .= ($i + 1) . ". [{$query['time']}s] `{$query['query']}`\n";
            }
        }

        $message .= "\n⏰ " . current_time('d/m/Y H:i:s');
        $message .= "\n🌐 " . home_url();
        $message .= "\n\n💡 *Gợi ý:* Kiểm tra backtrace và queries để tối ưu performance";

        return $message;
    }

    /**
     * Escape special Markdown characters for Telegram
     *
     * @param string $text
     * @return string
     */
    private function escapeMarkdown(string $text): string
    {
        // Characters that need to be escaped in Telegram MarkdownV2
        // For simple Markdown mode, we need to escape: _ * [ ] ( ) ~ ` > # + - = | { } . !
        $specialChars = ['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!', '\\'];

        foreach ($specialChars as $char) {
            $text = str_replace($char, '\\' . $char, $text);
        }

        return $text;
    }
}
