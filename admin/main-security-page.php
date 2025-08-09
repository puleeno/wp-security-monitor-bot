<?php
if (!defined('ABSPATH')) {
    exit;
}

use Puleeno\SecurityBot\WebMonitor\Bot;
use Puleeno\SecurityBot\WebMonitor\IssueManager;
use Puleeno\SecurityBot\WebMonitor\Security\AccessControl;
use Puleeno\SecurityBot\WebMonitor\Security\TwoFactorAuth;
use Puleeno\SecurityBot\WebMonitor\Security\SecureConfigManager;
use Puleeno\SecurityBot\WebMonitor\Security\CredentialManager;

$bot = Bot::getInstance();
$stats = $bot->getStats();
$issueManager = IssueManager::getInstance();

// Get recent activity
$issuesData = $issueManager->getIssues(['per_page' => 5]);
$recentIssues = $issuesData['issues'] ?? [];
$recentLogs = AccessControl::getAuditLogs([], 10);

// Get system health - simple encryption test
$encryptionStatus = true;
try {
    $testData = 'test';
    $encrypted = SecureConfigManager::encrypt($testData);
    $decrypted = SecureConfigManager::decrypt($encrypted);
    $encryptionStatus = ($testData === $decrypted);
} catch (Exception $e) {
    $encryptionStatus = false;
}

$twoFactorStatus = TwoFactorAuth::isEnabled(get_current_user_id());
$ipWhitelistActive = !empty(get_option('wp_security_monitor_ip_whitelist', []));

// Get channels status - estimate based on config
$channelStatus = [
    'TelegramChannel' => !empty(CredentialManager::getCredential(CredentialManager::TYPE_TELEGRAM_TOKEN)),
    'EmailChannel' => !empty(get_option('wp_security_monitor_email_config')),
    'SlackChannel' => !empty(CredentialManager::getCredential(CredentialManager::TYPE_SLACK_WEBHOOK)),
    'LogChannel' => get_option('wp_security_monitor_log_config')['enabled'] ?? true
];

// Get issuers status - estimate based on config
$issuersConfig = get_option('wp_security_monitor_issuers_config', []);
$issuerStatus = [
    'ExternalRedirectIssuer' => $issuersConfig['external_redirect']['enabled'] ?? true,
    'LoginAttemptIssuer' => $issuersConfig['login_attempt']['enabled'] ?? true,
    'FileChangeIssuer' => $issuersConfig['file_change']['enabled'] ?? true,
    'AdminUserCreatedIssuer' => $issuersConfig['admin_user_created']['enabled'] ?? true,
    'EvalFunctionIssuer' => $issuersConfig['eval_function']['enabled'] ?? true,
];

?>

<div class="wrap">
    <h1>🛡️ Puleeno Security Dashboard</h1>
    <p>Tổng quan bảo mật website và quản lý các component security</p>

    <!-- System Status Overview -->
    <div class="dashboard-widgets-wrap">
        <div class="metabox-holder">

            <!-- Security Status Widget -->
            <div class="postbox">
                <div class="postbox-header">
                    <h2 class="hndle">📊 Trạng thái Bảo mật</h2>
                </div>
                <div class="inside">
                    <div class="security-status-grid">
                        <div class="status-item">
                            <div class="status-icon <?php echo $stats['is_running'] ? 'status-good' : 'status-warning'; ?>">
                                <?php echo $stats['is_running'] ? '🟢' : '🔴'; ?>
                            </div>
                            <div class="status-content">
                                <h4>Security Monitor</h4>
                                <p><?php echo $stats['is_running'] ? 'Đang hoạt động' : 'Đã dừng'; ?></p>
                            </div>
                        </div>

                        <div class="status-item">
                            <div class="status-icon <?php echo $encryptionStatus ? 'status-good' : 'status-error'; ?>">
                                <?php echo $encryptionStatus ? '🔐' : '🚨'; ?>
                            </div>
                            <div class="status-content">
                                <h4>Encryption</h4>
                                <p><?php echo $encryptionStatus ? 'Đang hoạt động' : 'Có lỗi'; ?></p>
                            </div>
                        </div>

                        <div class="status-item">
                            <div class="status-icon <?php echo $twoFactorStatus ? 'status-good' : 'status-warning'; ?>">
                                <?php echo $twoFactorStatus ? '✅' : '⚠️'; ?>
                            </div>
                            <div class="status-content">
                                <h4>Two-Factor Auth</h4>
                                <p><?php echo $twoFactorStatus ? 'Đã kích hoạt' : 'Chưa kích hoạt'; ?></p>
                            </div>
                        </div>

                        <div class="status-item">
                            <div class="status-icon <?php echo $ipWhitelistActive ? 'status-good' : 'status-neutral'; ?>">
                                <?php echo $ipWhitelistActive ? '🌐' : '🔓'; ?>
                            </div>
                            <div class="status-content">
                                <h4>IP Whitelist</h4>
                                <p><?php echo $ipWhitelistActive ? 'Đang áp dụng' : 'Không hạn chế'; ?></p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Quick Stats Widget -->
            <div class="postbox">
                <div class="postbox-header">
                    <h2 class="hndle">📈 Thống kê Nhanh</h2>
                </div>
                <div class="inside">
                    <div class="stats-grid">
                        <div class="stat-item">
                            <div class="stat-number"><?php echo $stats['total_issues_found']; ?></div>
                            <div class="stat-label">Tổng Issues</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-number"><?php echo isset($stats['new_issues']) ? $stats['new_issues'] : 0; ?></div>
                            <div class="stat-label">Issues Mới</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-number"><?php echo count($channelStatus); ?></div>
                            <div class="stat-label">Channels</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-number"><?php echo count($issuerStatus); ?></div>
                            <div class="stat-label">Monitors</div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Recent Issues Widget -->
            <div class="postbox">
                <div class="postbox-header">
                    <h2 class="hndle">⚠️ Issues Gần đây</h2>
                </div>
                <div class="inside">
                    <?php if (empty($recentIssues)): ?>
                        <p><em>Không có issues mới nào.</em></p>
                    <?php else: ?>
                        <div class="recent-issues-list">
                            <?php foreach (array_slice($recentIssues, 0, 5) as $issue): ?>
                                <div class="issue-item severity-<?php echo esc_attr($issue['severity'] ?? 'low'); ?>">
                                    <div class="issue-severity">
                                        <?php
                                        $severity = $issue['severity'] ?? 'low';
                                        switch ($severity) {
                                            case 'critical': echo '🔴'; break;
                                            case 'high': echo '🟠'; break;
                                            case 'medium': echo '🟡'; break;
                                            default: echo '🔵'; break;
                                        }
                                        ?>
                                    </div>
                                    <div class="issue-content">
                                        <strong><?php echo esc_html($issue['issuer_name'] ?? 'Unknown Issuer'); ?></strong>
                                        <?php
                                        $debugInfo = json_decode($issue['raw_data'] ?? '{}', true);
                                        $issuerType = $debugInfo['issuer_type'] ?? 'Unknown';
                                        $typeIcon = $issuerType === 'TRIGGER' ? '⚡' : ($issuerType === 'SCAN' ? '🔍' : '🔄');
                                        ?>
                                        <span style="color: #666; font-size: 0.9em;"><?php echo $typeIcon; ?> <?php echo $issuerType; ?></span>
                                        <p><?php echo esc_html($issue['title'] ?? $issue['description'] ?? 'No message available'); ?></p>
                                        <small><?php echo esc_html($issue['last_detected'] ?? $issue['created_at'] ?? 'Unknown date'); ?></small>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                        <p style="margin-top: 15px;">
                            <a href="<?php echo admin_url('admin.php?page=wp-security-monitor-issues'); ?>" class="button">
                                📋 Xem tất cả Issues
                            </a>
                        </p>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Quick Actions Widget -->
            <div class="postbox">
                <div class="postbox-header">
                    <h2 class="hndle">⚡ Thao tác Nhanh</h2>
                </div>
                <div class="inside">
                    <div class="quick-actions">
                        <a href="<?php echo admin_url('admin.php?page=wp-security-monitor-bot'); ?>" class="action-button settings">
                            ⚙️ Cấu hình Channels
                        </a>
                        <a href="<?php echo admin_url('admin.php?page=wp-security-monitor-issues'); ?>" class="action-button issues">
                            📋 Quản lý Issues
                        </a>
                        <a href="<?php echo admin_url('admin.php?page=wp-security-monitor-access-control'); ?>" class="action-button access">
                            🔐 Access Control
                        </a>
                        <a href="<?php echo admin_url('admin.php?page=wp-security-monitor-security'); ?>" class="action-button status">
                            📊 Security Status
                        </a>
                    </div>

                    <div style="margin-top: 20px;">
                        <form method="post" style="display: inline;">
                            <?php wp_nonce_field('security_monitor_action'); ?>
                            <input type="hidden" name="security_monitor_action" value="run_check">
                            <button type="submit" class="button button-primary">
                                🔍 Chạy kiểm tra ngay
                            </button>
                        </form>

                        <?php if (!$encryptionStatus): ?>
                        <form method="post" style="display: inline; margin-left: 10px;">
                            <?php wp_nonce_field('security_monitor_action'); ?>
                            <input type="hidden" name="security_monitor_action" value="clear_corrupted_data">
                            <button type="submit" class="button button-secondary"
                                    onclick="return confirm('This will clear encrypted credentials. You will need to re-enter them. Continue?')">
                                🗑️ Clear Encrypted Data
                            </button>
                        </form>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <!-- Channels Status Widget -->
            <div class="postbox">
                <div class="postbox-header">
                    <h2 class="hndle">📡 Trạng thái Channels</h2>
                </div>
                <div class="inside">
                    <div class="channels-status">
                        <?php foreach ($channelStatus as $channelClass => $enabled): ?>
                            <?php
                            $channelName = str_replace('Channel', '', $channelClass);
                            $icon = '📡'; // Default icon
                            switch($channelName) {
                                case 'Telegram': $icon = '📱'; break;
                                case 'Email': $icon = '📧'; break;
                                case 'Slack': $icon = '💬'; break;
                                case 'Log': $icon = '📄'; break;
                            }
                            ?>
                            <div class="channel-item">
                                <span class="channel-icon"><?php echo $icon; ?></span>
                                <span class="channel-name"><?php echo esc_html($channelName); ?></span>
                                <span class="channel-status <?php echo $enabled ? 'enabled' : 'disabled'; ?>">
                                    <?php echo $enabled ? '✅ Enabled' : '❌ Disabled'; ?>
                                </span>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>

            <!-- Recent Activity Widget -->
            <div class="postbox">
                <div class="postbox-header">
                    <h2 class="hndle">📋 Hoạt động Gần đây</h2>
                </div>
                <div class="inside">
                    <?php if (empty($recentLogs)): ?>
                        <p><em>Chưa có hoạt động nào được ghi nhận.</em></p>
                    <?php else: ?>
                        <div class="activity-list">
                            <?php foreach (array_slice($recentLogs, 0, 5) as $log): ?>
                                <div class="activity-item">
                                    <div class="activity-time"><?php echo esc_html($log['created_at']); ?></div>
                                    <div class="activity-content">
                                        <strong><?php echo esc_html(ucwords(str_replace('_', ' ', $log['event_type']))); ?></strong>
                                        <?php if ($log['user']): ?>
                                            by <?php echo esc_html($log['user']->display_name); ?>
                                        <?php endif; ?>
                                        <small>(<?php echo esc_html($log['ip_address']); ?>)</small>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                        <p style="margin-top: 15px;">
                            <a href="<?php echo admin_url('admin.php?page=wp-security-monitor-access-control'); ?>" class="button">
                                📋 Xem Audit Logs
                            </a>
                        </p>
                    <?php endif; ?>
                </div>
            </div>

        </div>
    </div>
</div>

<style>
.dashboard-widgets-wrap {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
    gap: 20px;
    margin-top: 20px;
}

.security-status-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 15px;
}

.status-item {
    display: flex;
    align-items: center;
    padding: 15px;
    background: #f9f9f9;
    border-radius: 8px;
    border-left: 4px solid #ddd;
}

.status-item.status-good {
    border-left-color: #46b450;
}

.status-item.status-warning {
    border-left-color: #ffb900;
}

.status-item.status-error {
    border-left-color: #dc3232;
}

.status-icon {
    font-size: 24px;
    margin-right: 15px;
}

.status-content h4 {
    margin: 0 0 5px 0;
    font-size: 14px;
    font-weight: 600;
}

.status-content p {
    margin: 0;
    font-size: 13px;
    color: #666;
}

.stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 20px;
    text-align: center;
}

.stat-item .stat-number {
    font-size: 28px;
    font-weight: bold;
    color: #0073aa;
    margin-bottom: 5px;
}

.stat-item .stat-label {
    font-size: 13px;
    color: #666;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.recent-issues-list {
    max-height: 300px;
    overflow-y: auto;
}

.issue-item {
    display: flex;
    align-items: flex-start;
    padding: 12px;
    margin-bottom: 10px;
    background: #f9f9f9;
    border-radius: 6px;
    border-left: 4px solid #ddd;
}

.issue-item.severity-critical {
    border-left-color: #dc3232;
}

.issue-item.severity-high {
    border-left-color: #ff8800;
}

.issue-item.severity-medium {
    border-left-color: #ffb900;
}

.issue-item.severity-low {
    border-left-color: #0073aa;
}

.issue-severity {
    font-size: 18px;
    margin-right: 12px;
}

.issue-content h4 {
    margin: 0 0 5px 0;
    font-size: 13px;
    font-weight: 600;
}

.issue-content p {
    margin: 0 0 5px 0;
    font-size: 12px;
    line-height: 1.4;
}

.issue-content small {
    color: #666;
    font-size: 11px;
}

.quick-actions {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 10px;
}

.action-button {
    display: block;
    padding: 15px 20px;
    text-align: center;
    text-decoration: none;
    border-radius: 6px;
    font-weight: 500;
    transition: all 0.2s ease;
}

.action-button.settings {
    background: #0073aa;
    color: white;
}

.action-button.issues {
    background: #dc3232;
    color: white;
}

.action-button.access {
    background: #46b450;
    color: white;
}

.action-button.status {
    background: #ff8800;
    color: white;
}

.action-button:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 8px rgba(0,0,0,0.1);
    color: white;
}

.channels-status {
    display: grid;
    gap: 10px;
}

.channel-item {
    display: flex;
    align-items: center;
    padding: 10px;
    background: #f9f9f9;
    border-radius: 6px;
}

.channel-icon {
    font-size: 18px;
    margin-right: 12px;
}

.channel-name {
    flex: 1;
    font-weight: 500;
}

.channel-status.enabled {
    color: #46b450;
    font-weight: 500;
}

.channel-status.disabled {
    color: #dc3232;
    font-weight: 500;
}

.activity-list {
    max-height: 250px;
    overflow-y: auto;
}

.activity-item {
    padding: 10px 0;
    border-bottom: 1px solid #f0f0f0;
}

.activity-item:last-child {
    border-bottom: none;
}

.activity-time {
    font-size: 11px;
    color: #666;
    margin-bottom: 3px;
}

.activity-content {
    font-size: 13px;
    line-height: 1.4;
}
</style>

<?php
// Handle manual check action
if (isset($_POST['security_monitor_action']) && wp_verify_nonce($_POST['_wpnonce'], 'security_monitor_action')) {
    $action = $_POST['security_monitor_action'];

    switch ($action) {
        case 'run_check':
            $issues = $bot->runCheck();
            echo '<div class="notice notice-success"><p>✅ Đã chạy kiểm tra! Phát hiện ' . count($issues) . ' vấn đề mới.</p></div>';
            echo '<script>setTimeout(function(){ location.reload(); }, 2000);</script>';
            break;

        case 'clear_corrupted_data':
            SecureConfigManager::clearCorruptedData();
            echo '<div class="notice notice-success"><p>✅ Đã xóa dữ liệu encryption cũ. Vui lòng nhập lại credentials.</p></div>';
            echo '<script>setTimeout(function(){ location.reload(); }, 2000);</script>';
            break;
    }
}
?>
