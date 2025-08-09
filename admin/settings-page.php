<?php
if (!defined('ABSPATH')) {
    exit;
}

$bot = \Puleeno\SecurityBot\WebMonitor\Bot::getInstance();
$stats = $bot->getStats();

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

    // Lưu Telegram config với secure storage
    if (isset($_POST['telegram'])) {
        $telegramData = $_POST['telegram'];

        // Save enabled status
        update_option('wp_security_monitor_telegram_enabled', isset($telegramData['enabled']));

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
        update_option('wp_security_monitor_slack_channel', sanitize_text_field($slackData['channel']));
        update_option('wp_security_monitor_slack_username', sanitize_text_field($slackData['username']));
        update_option('wp_security_monitor_slack_icon', sanitize_text_field($slackData['icon_emoji']));
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

    echo '<div class="notice notice-success"><p>Cấu hình đã được lưu!</p></div>';

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
}
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
                    <th scope="row">Test kết nối</th>
                    <td>
                        <button type="button" class="button" onclick="testChannel('telegram')">
                            📤 Gửi tin nhắn test
                        </button>
                        <span id="telegram-test-result"></span>
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
                    <th scope="row">Test Email</th>
                    <td>
                        <button type="button" class="button" onclick="testChannel('email')">
                            📤 Gửi email test
                        </button>
                        <span id="email-test-result"></span>
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
                               class="regular-text" placeholder="https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX">
                        <p class="description">
                            Tạo Incoming Webhook tại <a href="https://api.slack.com/apps" target="_blank">https://api.slack.com/apps</a>
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="slack_channel">Channel</label>
                    </th>
                    <td>
                        <input type="text" id="slack_channel" name="slack[channel]"
                               value="<?php echo esc_attr($slackConfig['channel'] ?? '#security'); ?>"
                               class="regular-text" placeholder="#security">
                        <p class="description">
                            Channel hoặc user nhận thông báo (e.g., #security, @username). Để trống để dùng default của webhook.
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="slack_username">Bot Username</label>
                    </th>
                    <td>
                        <input type="text" id="slack_username" name="slack[username]"
                               value="<?php echo esc_attr($slackConfig['username'] ?? 'Security Monitor Bot'); ?>"
                               class="regular-text" placeholder="Security Monitor Bot">
                        <p class="description">Tên hiển thị của bot trong Slack</p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">
                        <label for="slack_icon_emoji">Icon Emoji</label>
                    </th>
                    <td>
                        <input type="text" id="slack_icon_emoji" name="slack[icon_emoji]"
                               value="<?php echo esc_attr($slackConfig['icon_emoji'] ?? ':warning:'); ?>"
                               class="regular-text" placeholder=":warning:">
                        <p class="description">
                            Emoji icon cho bot (e.g., :warning:, :shield:, :robot_face:)
                        </p>
                    </td>
                </tr>
                <tr>
                    <th scope="row">Test Slack</th>
                    <td>
                        <button type="button" class="button" onclick="testChannel('slack')">
                            💬 Gửi tin nhắn test
                        </button>
                        <span id="slack-test-result"></span>
                    </td>
                </tr>
            </table>
        </div>

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
                    <th scope="row">Test Log</th>
                    <td>
                        <button type="button" class="button" onclick="testChannel('log')">
                            📄 Test ghi log
                        </button>
                        <span id="log-test-result"></span>
                        <p class="description">
                            Test khả năng ghi log và hiển thị thông tin về log directory
                        </p>
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
                            <br><small><?php echo esc_html($issue['details']); ?></small>
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
#telegram-test-result, #email-test-result, #slack-test-result, #log-test-result {
    margin-left: 10px;
    font-weight: bold;
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
        if (data.success && data.data.success) {
            resultElement.innerHTML = '<span class="test-success">✅ Test thành công!</span>';
        } else {
            resultElement.innerHTML = '<span class="test-error">❌ Test thất bại!</span>';
        }
    })
    .catch(error => {
        resultElement.innerHTML = '<span class="test-error">❌ Lỗi: ' + error.message + '</span>';
    });
}
</script>
