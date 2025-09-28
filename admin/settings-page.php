<?php
if (!defined('ABSPATH')) {
    exit;
}

$bot = \Puleeno\SecurityBot\WebMonitor\Bot::getInstance();
$stats = $bot->getStats();

// Debug: Show current SSL verification setting
$currentSslVerify = get_option('wp_security_monitor_telegram_ssl_verify', 'NOT_SET');
error_log('Current SSL verify option value: ' . var_export($currentSslVerify, true));

// Import secure credential managers
use Puleeno\SecurityBot\WebMonitor\Security\SecureConfigManager;
use Puleeno\SecurityBot\WebMonitor\Security\CredentialManager;

// Get configs với secure credentials
$telegramConfig = [
    'enabled' => get_option('wp_security_monitor_telegram_enabled', false),
    'bot_token' => CredentialManager::getCredential(CredentialManager::TYPE_TELEGRAM_TOKEN, false),
    'chat_id' => CredentialManager::getCredential(CredentialManager::TYPE_TELEGRAM_CHAT_ID, false)
];
$emailConfig = get_option('wp_security_monitor_email_config', []);
$slackConfig = [
    'enabled' => get_option('wp_security_monitor_slack_enabled', false),
    'webhook_url' => CredentialManager::getCredential(CredentialManager::TYPE_SLACK_WEBHOOK, false),
    'channel' => get_option('wp_security_monitor_slack_channel', '#general'),
    'username' => get_option('wp_security_monitor_slack_username', 'WP Security Monitor'),
    'icon_emoji' => get_option('wp_security_monitor_slack_icon', ':shield:')
];
$logConfig = get_option('wp_security_monitor_log_config', []);

// Xử lý bot control actions
if (isset($_POST['security_monitor_action']) && wp_verify_nonce($_POST['_wpnonce'], 'security_monitor_action')) {
    $action = $_POST['security_monitor_action'];

    switch ($action) {
        case 'start':
            $bot->start();
            echo '<div class="notice notice-success"><p>Bot đã được khởi động!</p></div>';
            break;
        case 'stop':
            $bot->stop();
            echo '<div class="notice notice-success"><p>Bot đã được dừng!</p></div>';
            break;
        case 'run_check':
            $issues = $bot->runCheck();
            echo '<div class="notice notice-success"><p>Đã chạy kiểm tra! Phát hiện ' . count($issues) . ' vấn đề.</p></div>';
            break;
    }

    // Reload stats after bot actions
    $stats = $bot->getStats();
}

        // Xử lý settings form submit
    if (isset($_POST['submit']) && wp_verify_nonce($_POST['_wpnonce'], 'security_monitor_settings')) {

        // Debug: Log POST data for troubleshooting
        error_log('Settings form submitted. POST data: ' . print_r($_POST, true));
        error_log('Nonce verification passed');

        // Debug: Check if telegram data exists
        if (isset($_POST['telegram'])) {
            error_log('Telegram data found in POST: ' . print_r($_POST['telegram'], true));
        } else {
            error_log('No telegram data found in POST');
        }

    // Lưu Telegram config với secure storage
    if (isset($_POST['telegram'])) {
        $telegramData = $_POST['telegram'];

        // Debug: Log telegram data before processing
        error_log('Processing telegram data: ' . print_r($telegramData, true));

        // Save enabled status
        update_option('wp_security_monitor_telegram_enabled', isset($telegramData['enabled']));

        // Save SSL verification setting - handle unchecked checkbox properly
        $sslVerify = (bool) $telegramData['ssl_verify'];
        error_log('SSL verify value from POST: ' . var_export($telegramData['ssl_verify'], true));
        error_log('SSL verify after casting to bool: ' . var_export($sslVerify, true));
        update_option('wp_security_monitor_telegram_ssl_verify', $sslVerify);

        // Debug: Log the SSL verification setting
        error_log('Telegram SSL Verify setting: ' . ($sslVerify ? 'true' : 'false'));
        error_log('SSL verify option saved to database: ' . get_option('wp_security_monitor_telegram_ssl_verify', 'NOT_SET'));

        // Save credentials securely
        if (!empty($telegramData['bot_token'])) {
            $validation = CredentialManager::validateCredential(
                CredentialManager::TYPE_TELEGRAM_TOKEN,
                $telegramData['bot_token']
            );

            if ($validation['valid']) {
                CredentialManager::setCredential(
                    CredentialManager::TYPE_TELEGRAM_TOKEN,
                    sanitize_text_field($telegramData['bot_token'])
                );
            } else {
                echo '<div class="notice notice-error"><p>Telegram Token Error: ' .
                     implode(', ', $validation['errors']) . '</p></div>';
            }
        }

        if (!empty($telegramData['chat_id'])) {
            $validation = CredentialManager::validateCredential(
                CredentialManager::TYPE_TELEGRAM_CHAT_ID,
                $telegramData['chat_id']
            );

            if ($validation['valid']) {
                CredentialManager::setCredential(
                    CredentialManager::TYPE_TELEGRAM_CHAT_ID,
                    sanitize_text_field($telegramData['chat_id'])
                );
            } else {
                echo '<div class="notice notice-error"><p>Telegram Chat ID Error: ' .
                     implode(', ', $validation['errors']) . '</p></div>';
            }
        }
    }

    // Lưu Email config
    if (isset($_POST['email'])) {
        $emailData = $_POST['email'];
        update_option('wp_security_monitor_email_config', [
            'enabled' => isset($emailData['enabled']),
            'to' => sanitize_email($emailData['to']),
            'from' => sanitize_email($emailData['from']),
            'from_name' => sanitize_text_field($emailData['from_name'])
        ]);
    }

    // Lưu Slack config với secure storage
    if (isset($_POST['slack'])) {
        $slackData = $_POST['slack'];

        // Save enabled status
        update_option('wp_security_monitor_slack_enabled', isset($slackData['enabled']));

        // Save webhook URL securely
        if (!empty($slackData['webhook_url'])) {
            $validation = CredentialManager::validateCredential(
                CredentialManager::TYPE_SLACK_WEBHOOK,
                $slackData['webhook_url']
            );

            if ($validation['valid']) {
                CredentialManager::setCredential(
                    CredentialManager::TYPE_SLACK_WEBHOOK,
                    esc_url_raw($slackData['webhook_url'])
                );
            } else {
                echo '<div class="notice notice-error"><p>Slack Webhook Error: ' .
                     implode(', ', $validation['errors']) . '</p></div>';
            }
        }

        // Save other Slack settings
        if (isset($slackData['channel'])) {
            update_option('wp_security_monitor_slack_channel', sanitize_text_field($slackData['channel']));
        }
        if (isset($slackData['username'])) {
            update_option('wp_security_monitor_slack_username', sanitize_text_field($slackData['username']));
        }
        if (isset($slackData['icon'])) {
            update_option('wp_security_monitor_slack_icon', sanitize_text_field($slackData['icon']));
        }
    }

            // Lưu Log config
        if (isset($_POST['log'])) {
            $logData = $_POST['log'];
            update_option('wp_security_monitor_log_config', [
                'enabled' => isset($logData['enabled']),
                'log_directory' => sanitize_text_field($logData['log_directory']),
                'file_pattern' => sanitize_text_field($logData['file_pattern']),
                'max_file_size' => intval($logData['max_file_size']) * 1024 * 1024, // Convert MB to bytes
                'max_files' => intval($logData['max_files']),
                'include_debug_info' => isset($logData['include_debug_info'])
            ]);
        }

        // Show success message
        echo '<div class="notice notice-success"><p>Cấu hình đã được lưu thành công!</p></div>';

    } else {
        // Debug: Log why form submission failed
        if (!isset($_POST['submit'])) {
            error_log('Form not submitted - submit button not clicked');
        } else {
            error_log('Form submitted but nonce verification failed');
        }
    }



    // Reload configs after settings save
    $telegramConfig = [
        'enabled' => get_option('wp_security_monitor_telegram_enabled', false),
        'bot_token' => CredentialManager::getCredential(CredentialManager::TYPE_TELEGRAM_TOKEN, false),
        'chat_id' => CredentialManager::getCredential(CredentialManager::TYPE_TELEGRAM_CHAT_ID, false)
    ];
    $emailConfig = get_option('wp_security_monitor_email_config', []);
    $slackConfig = [
        'enabled' => get_option('wp_security_monitor_slack_enabled', false),
        'webhook_url' => CredentialManager::getCredential(CredentialManager::TYPE_SLACK_WEBHOOK, false),
        'channel' => get_option('wp_security_monitor_slack_channel', '#general'),
        'username' => get_option('wp_security_monitor_slack_username', 'WP Security Monitor'),
        'icon_emoji' => get_option('wp_security_monitor_slack_icon', ':shield:')
    ];
    $logConfig = get_option('wp_security_monitor_log_config', []);
?>

<div class="wrap">
    <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

    <!-- Status Dashboard -->
    <div class="card" style="margin-bottom: 20px;">
        <h2>📊 Trạng thái Bot</h2>
        <table class="form-table">
            <tr>
                <th>Trạng thái:</th>
                <td>
                    <span class="status-indicator <?php echo $stats['is_running'] ? 'active' : 'inactive'; ?>">
                        <?php echo $stats['is_running'] ? '🟢 Đang hoạt động' : '🔴 Đã dừng'; ?>
                    </span>
                </td>
            </tr>
            <tr>
                <th>Số channels:</th>
                <td><?php echo $stats['channels_count']; ?> kênh thông báo</td>
            </tr>
            <tr>
                <th>Số monitors:</th>
                <td><?php echo $stats['issuers_count']; ?> monitor đang hoạt động</td>
            </tr>
            <tr>
                <th>Lần check cuối:</th>
                <td>
                    <?php
                    if ($stats['last_check'] > 0) {
                        echo date('d/m/Y H:i:s', $stats['last_check']);
                    } else {
                        echo 'Chưa từng chạy';
                    }
                    ?>
                </td>
            </tr>
            <tr>
                <th>Check tiếp theo:</th>
                <td>
                    <?php
                    if ($stats['next_scheduled_check']) {
                        echo date('d/m/Y H:i:s', $stats['next_scheduled_check']);
                    } else {
                        echo 'Chưa lên lịch';
                    }
                    ?>
                </td>
            </tr>
            <tr>
                <th>Vấn đề phát hiện:</th>
                <td>
                    <strong><?php echo $stats['total_issues_found']; ?></strong> vấn đề
                    <?php if (isset($stats['new_issues']) && $stats['new_issues'] > 0): ?>
                        <span style="color: #dc3232; font-weight: bold;">
                            (<?php echo $stats['new_issues']; ?> mới)
                        </span>
                    <?php endif; ?>
                    <br>
                    <a href="<?php echo admin_url('tools.php?page=wp-security-monitor-issues'); ?>" class="button button-secondary" style="margin-top: 5px;">
                        📋 Quản lý Issues
                    </a>
                </td>
            </tr>
        </table>

        <!-- Debug Section -->
        <div class="card" style="background-color: #f0f0f0; border-left: 4px solid #0073aa;">
            <h3>🐛 Debug Information</h3>
            <p><strong>Current SSL Verify Option:</strong> <?php echo var_export($currentSslVerify, true); ?></p>
            <p><strong>Option Type:</strong> <?php echo gettype($currentSslVerify); ?></p>
            <p><strong>Raw Option Value:</strong> <?php echo var_export(get_option('wp_security_monitor_telegram_ssl_verify'), true); ?></p>
            <p><strong>Protocol sẽ được sử dụng:</strong> <strong style="color: #0073aa;">HTTPS</strong> (Telegram API chỉ hỗ trợ HTTPS)</p>
            <p><strong>SSL Options:</strong> sslverify=<?php echo ($currentSslVerify ? 'true' : 'false'); ?>, ssl=<?php echo ($currentSslVerify ? 'true' : 'false'); ?>, curl_ssl_verifypeer=<?php echo ($currentSslVerify ? 'true' : 'false'); ?>, curl_ssl_verifyhost=<?php echo ($currentSslVerify ? 'true' : 'false'); ?></p>
            <p><strong>Note:</strong> Khi SSL verification bị tắt, plugin sẽ sử dụng cURL options để bỏ qua SSL certificate check nhưng vẫn kết nối qua HTTPS.</p>
        </div>

        <p>
            <form method="post" style="display: inline;">
                <?php wp_nonce_field('security_monitor_action'); ?>
                <input type="hidden" name="security_monitor_action" value="<?php echo $stats['is_running'] ? 'stop' : 'start'; ?>">
                <button type="submit" class="button button-primary">
                    <?php echo $stats['is_running'] ? '⏹️ Dừng Bot' : '▶️ Khởi động Bot'; ?>
                </button>
            </form>

            <form method="post" style="display: inline; margin-left: 10px;">
                <?php wp_nonce_field('security_monitor_action'); ?>
                <input type="hidden" name="security_monitor_action" value="run_check">
                <button type="submit" class="button">🔍 Chạy kiểm tra ngay</button>
            </form>
        </p>
    </div>

    <!-- Settings Form -->
    <form method="post">
        <?php wp_nonce_field('security_monitor_settings'); ?>

        <!-- Telegram Settings -->
        <div class="card">
            <h2>📱 Cấu hình Telegram</h2>
            <table class="form-table">
                <tr>
                    <th scope="row">
                        <label for="telegram_enabled">Kích hoạt Telegram</label>
                    </th>
                    <td>
                        <input type="checkbox" id="telegram_enabled" name="telegram[enabled]" value="1"
                               <?php checked(isset($telegramConfig['enabled']) && $telegramConfig['enabled']); ?>>
                        <label for="telegram_enabled">Gửi thông báo qua Telegram</label>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="telegram_bot_token">Bot Token</label>
                    </th>
                    <td>
                        <input type="text" id="telegram_bot_token" name="telegram[bot_token]"
                               value="<?php echo esc_attr($telegramConfig['bot_token'] ?? ''); ?>"
                               class="regular-text" placeholder="123456789:ABCdefGHIjklMNOpqrsTUVwxyz">
                        <p class="description">
                            Lấy Bot Token từ <a href="https://t.me/BotFather" target="_blank">@BotFather</a> trên Telegram
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="telegram_chat_id">Chat ID</label>
                    </th>
                    <td>
                        <input type="text" id="telegram_chat_id" name="telegram[chat_id]"
                               value="<?php echo esc_attr($telegramConfig['chat_id'] ?? ''); ?>"
                               class="regular-text" placeholder="-1001234567890">
                        <p class="description">
                            ID của chat/group nhận thông báo. Có thể dùng <a href="https://t.me/userinfobot" target="_blank">@userinfobot</a> để lấy
                        </p>
                    </td>
                </tr>
                        <tr>
            <th scope="row">
                <label for="telegram_ssl_verify">SSL Verification</label>
            </th>
            <td>
                <input type="hidden" name="telegram[ssl_verify]" value="0">
                <input type="checkbox" id="telegram_ssl_verify" name="telegram[ssl_verify]" value="1"
                       <?php checked(get_option('wp_security_monitor_telegram_ssl_verify', true)); ?>>
                <label for="telegram_ssl_verify">Bật SSL certificate verification (bỏ chọn nếu gặp lỗi SSL)</label>
                <p class="description">Bỏ chọn nếu test trên môi trường local hoặc server có SSL self-signed</p>
            </td>
        </tr>
                <tr>
                    <th scope="row">Test kết nối</th>
                    <td>
                        <button type="button" class="button button-secondary" onclick="testChannel('telegram')">
                            🔗 Test kết nối
                        </button>
                        <span id="telegram-test-result"></span>
                        <p class="description">Kiểm tra kết nối với Telegram Bot API</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">Test gửi tin nhắn</th>
                    <td>
                        <button type="button" class="button button-secondary" onclick="testSendMessage('telegram')">
                            📤 Gửi tin nhắn test
                        </button>
                        <span id="telegram-send-result"></span>
                        <p class="description">Gửi tin nhắn test thực tế để kiểm tra bot có thể gửi tin nhắn hay không</p>
                    </td>
                </tr>
            </table>
        </div>

        <!-- Email Settings -->
        <div class="card">
            <h2>📧 Cấu hình Email</h2>
            <table class="form-table">
                <tr>
                    <th scope="row">
                        <label for="email_enabled">Kích hoạt Email</label>
                    </th>
                    <td>
                        <input type="checkbox" id="email_enabled" name="email[enabled]" value="1"
                               <?php checked(isset($emailConfig['enabled']) && $emailConfig['enabled']); ?>>
                        <label for="email_enabled">Gửi thông báo qua Email</label>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="email_to">Email nhận thông báo</label>
                    </th>
                    <td>
                        <input type="email" id="email_to" name="email[to]"
                               value="<?php echo esc_attr($emailConfig['to'] ?? get_option('admin_email')); ?>"
                               class="regular-text" required>
                        <p class="description">Email sẽ nhận các cảnh báo bảo mật</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="email_from">Email gửi</label>
                    </th>
                    <td>
                        <input type="email" id="email_from" name="email[from]"
                               value="<?php echo esc_attr($emailConfig['from'] ?? get_option('admin_email')); ?>"
                               class="regular-text">
                        <p class="description">Để trống để dùng email admin mặc định</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="email_from_name">Tên người gửi</label>
                    </th>
                    <td>
                        <input type="text" id="email_from_name" name="email[from_name]"
                               value="<?php echo esc_attr($emailConfig['from_name'] ?? get_bloginfo('name') . ' Security Monitor'); ?>"
                               class="regular-text">
                    </td>
                </tr>
                <tr>
                    <th scope="row">Test kết nối</th>
                    <td>
                        <button type="button" class="button button-secondary" onclick="testChannel('email')">
                            🔗 Test kết nối
                        </button>
                        <span id="email-test-result"></span>
                        <p class="description">Kiểm tra cấu hình email</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">Test gửi tin nhắn</th>
                    <td>
                        <button type="button" class="button button-secondary" onclick="testSendMessage('email')">
                            📤 Gửi email test
                        </button>
                        <span id="email-send-result"></span>
                        <p class="description">Gửi email test thực tế để kiểm tra khả năng gửi email</p>
                    </td>
                </tr>
            </table>
        </div>

        <!-- Slack Settings -->
        <div class="card">
            <h2>💬 Cấu hình Slack</h2>
            <table class="form-table">
                <tr>
                    <th scope="row">
                        <label for="slack_enabled">Kích hoạt Slack</label>
                    </th>
                    <td>
                        <input type="checkbox" id="slack_enabled" name="slack[enabled]" value="1"
                               <?php checked(isset($slackConfig['enabled']) && $slackConfig['enabled']); ?>>
                        <label for="slack_enabled">Gửi thông báo qua Slack</label>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="slack_webhook_url">Webhook URL</label>
                    </th>
                    <td>
                        <input type="url" id="slack_webhook_url" name="slack[webhook_url]"
                               value="<?php echo esc_attr($slackConfig['webhook_url'] ?? ''); ?>"
                               class="regular-text" placeholder="https://hooks.slack.com/services/...">
                        <p class="description">URL webhook từ Slack app settings</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="slack_channel">Channel</label>
                    </th>
                    <td>
                        <input type="text" id="slack_channel" name="slack[channel]"
                               value="<?php echo esc_attr($slackConfig['channel'] ?? '#general'); ?>"
                               class="regular-text" placeholder="#general">
                        <p class="description">Channel nhận thông báo (bắt đầu bằng #)</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="slack_username">Bot Username</label>
                    </th>
                    <td>
                        <input type="text" id="slack_username" name="slack[username]"
                               value="<?php echo esc_attr($slackConfig['username'] ?? 'WP Security Monitor'); ?>"
                               class="regular-text">
                        <p class="description">Tên hiển thị của bot trong Slack</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="slack_icon">Bot Icon</label>
                    </th>
                    <td>
                        <input type="text" id="slack_icon" name="slack[icon]"
                               value="<?php echo esc_attr($slackConfig['icon_emoji'] ?? ':shield:'); ?>"
                               class="regular-text" placeholder=":shield:">
                        <p class="description">Emoji icon cho bot (ví dụ: :shield:, :warning:)</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">Test kết nối</th>
                    <td>
                        <button type="button" class="button button-secondary" onclick="testChannel('slack')">
                            🔗 Test kết nối
                        </button>
                        <span id="slack-test-result"></span>
                        <p class="description">Kiểm tra kết nối với Slack webhook</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">Test gửi tin nhắn</th>
                    <td>
                        <button type="button" class="button button-secondary" onclick="testSendMessage('slack')">
                            📤 Gửi tin nhắn test
                        </button>
                        <span id="slack-send-result"></span>
                        <p class="description">Gửi tin nhắn test thực tế để kiểm tra khả năng gửi tin nhắn Slack</p>
                    </td>
                </tr>
            </table>


        <!-- Log Settings -->
        <div class="card">
            <h2>📄 Cấu hình Log File</h2>
            <table class="form-table">
                <tr>
                    <th scope="row">
                        <label for="log_enabled">Kích hoạt Log</label>
                    </th>
                    <td>
                        <input type="checkbox" id="log_enabled" name="log[enabled]" value="1"
                               <?php checked($logConfig['enabled'] ?? true); ?>>
                        <label for="log_enabled">Ghi logs vào file</label>
                        <p class="description">Log channel luôn được khuyến khích để audit và troubleshoot</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="log_directory">Log Directory</label>
                    </th>
                    <td>
                        <input type="text" id="log_directory" name="log[log_directory]"
                               value="<?php echo esc_attr($logConfig['log_directory'] ?? 'wp-content/uploads/security-logs'); ?>"
                               class="regular-text" placeholder="wp-content/uploads/security-logs">
                        <p class="description">
                            Directory để lưu log files (relative to WordPress root). Directory sẽ được tạo tự động với bảo vệ .htaccess.
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="log_file_pattern">File Pattern</label>
                    </th>
                    <td>
                        <input type="text" id="log_file_pattern" name="log[file_pattern]"
                               value="<?php echo esc_attr($logConfig['file_pattern'] ?? 'security-monitor-%Y-%m-%d.log'); ?>"
                               class="regular-text" placeholder="security-monitor-%Y-%m-%d.log">
                        <p class="description">
                            Pattern cho tên file log. Sử dụng date format: %Y (năm), %m (tháng), %d (ngày)
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="log_max_file_size">Max File Size (MB)</label>
                    </th>
                    <td>
                        <input type="number" id="log_max_file_size" name="log[max_file_size]"
                               value="<?php echo intval(($logConfig['max_file_size'] ?? 10485760) / 1024 / 1024); ?>"
                               min="1" max="100" class="small-text"> MB
                        <p class="description">
                            Kích thước tối đa của mỗi log file. Khi đạt giới hạn, file sẽ được rotate.
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="log_max_files">Max Files</label>
                    </th>
                    <td>
                        <input type="number" id="log_max_files" name="log[max_files]"
                               value="<?php echo intval($logConfig['max_files'] ?? 30); ?>"
                               min="1" max="365" class="small-text"> files
                        <p class="description">
                            Số lượng file log tối đa giữ lại. File cũ sẽ được xóa tự động.
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="log_include_debug">Include Debug Info</label>
                    </th>
                    <td>
                        <input type="checkbox" id="log_include_debug" name="log[include_debug_info]" value="1"
                               <?php checked($logConfig['include_debug_info'] ?? false); ?>>
                        <label for="log_include_debug">Bao gồm debug information trong log entries</label>
                        <p class="description">
                            Thêm call stack, memory usage và các thông tin debug khác (làm log file lớn hơn)
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">Test kết nối</th>
                    <td>
                        <button type="button" class="button button-secondary" onclick="testChannel('log')">
                            🔗 Test kết nối
                        </button>
                        <span id="log-test-result"></span>
                        <p class="description">Kiểm tra khả năng ghi log và hiển thị thông tin về log directory</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">Test gửi tin nhắn</th>
                    <td>
                        <button type="button" class="button button-secondary" onclick="testSendMessage('log')">
                            📄 Test ghi log
                        </button>
                        <span id="log-send-result"></span>
                        <p class="description">Ghi log test thực tế để kiểm tra khả năng ghi log</p>
                    </td>
                </tr>
            </table>
        </div>

        <?php submit_button('💾 Lưu cấu hình'); ?>
    </form>

    <!-- Issues Log -->
    <?php if (!empty($lastIssues)): ?>
    <div class="card" id="issues-log">
        <h2>⚠️ Vấn đề phát hiện gần đây</h2>
        <?php foreach ($lastIssues as $issuerName => $issues): ?>
            <h3><?php echo esc_html($issuerName); ?></h3>
            <ul>
                <?php foreach ($issues as $issue): ?>
                    <li>
                        <strong><?php echo esc_html(is_array($issue) ? $issue['message'] : $issue); ?></strong>
                        <?php if (is_array($issue) && isset($issue['details'])): ?>
                            <br><small><?php echo esc_html(is_string($issue['details']) ? $issue['details'] : var_export($issue['details'], true)); ?></small>
                        <?php endif; ?>
                    </li>
                <?php endforeach; ?>
            </ul>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>
</div>

<style>
.status-indicator.active {
    color: #46b450;
    font-weight: bold;
}
.status-indicator.inactive {
    color: #dc3232;
    font-weight: bold;
}
.card {
    background: #fff;
    border: 1px solid #ccd0d4;
    border-radius: 4px;
    padding: 20px;
    margin-bottom: 20px;
}
.card h2 {
    margin-top: 0;
}
#telegram-test-result, #email-test-result, #slack-test-result, #log-test-result,
#telegram-send-result, #email-send-result, #slack-send-result, #log-send-result {
    margin-left: 10px;
    font-weight: bold;
    display: block;
    margin-top: 5px;
    word-wrap: break-word;
    max-width: 400px;
}
.test-success {
    color: #46b450;
}
.test-error {
    color: #dc3232;
}
</style>

<script>
function testChannel(type) {
    const resultElement = document.getElementById(type + '-test-result');
    resultElement.innerHTML = '⏳ Đang test...';

    fetch(ajaxurl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            action: 'security_monitor_test_channel',
            channel_type: type,
            nonce: '<?php echo wp_create_nonce('security_monitor_nonce'); ?>'
        })
    })
    .then(response => response.json())
    .then(data => {
        console.log('AJAX Response:', data); // Debug log
        if (data.success) {
            resultElement.innerHTML = '<span class="test-success">✅ ' + data.data + '</span>';
        } else {
            resultElement.innerHTML = '<span class="test-error">❌ ' + (data.data || 'Test thất bại') + '</span>';
        }
    })
    .catch(error => {
        resultElement.innerHTML = '<span class="test-error">❌ Lỗi: ' + error.message + '</span>';
    });
}

function testSendMessage(type) {
    const resultElement = document.getElementById(type + '-send-result');
    resultElement.innerHTML = '⏳ Đang gửi tin nhắn test...';

    fetch(ajaxurl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            action: 'security_monitor_test_send_message',
            channel_type: type,
            nonce: '<?php echo wp_create_nonce('security_monitor_nonce'); ?>'
        })
    })
    .then(response => response.json())
    .then(data => {
        console.log('Send Message AJAX Response:', data); // Debug log
        if (data.success) {
            resultElement.innerHTML = '<span class="test-success">✅ ' + data.data + '</span>';
        } else {
            resultElement.innerHTML = '<span class="test-error">❌ ' + (data.data || 'Gửi tin nhắn thất bại') + '</span>';
        }
    })
    .catch(error => {
        resultElement.innerHTML = '<span class="test-error">❌ Lỗi: ' + error.message + '</span>';
    });
}
</script>
