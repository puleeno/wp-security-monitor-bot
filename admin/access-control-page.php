<?php
if (!defined('ABSPATH')) {
    exit;
}

use Puleeno\SecurityBot\WebMonitor\Security\AccessControl;
use Puleeno\SecurityBot\WebMonitor\Security\TwoFactorAuth;

// Handle actions
if (isset($_POST['action']) && wp_verify_nonce($_POST['_wpnonce'], 'security_monitor_access_control')) {
    switch ($_POST['action']) {
        case 'update_ip_whitelist':
            $whitelist = array_filter(array_map('trim', explode("\n", $_POST['ip_whitelist'])));
            update_option('wp_security_monitor_ip_whitelist', $whitelist);
            echo '<div class="notice notice-success"><p>IP whitelist updated successfully!</p></div>';
            break;

        case 'setup_2fa':
            $method = sanitize_text_field($_POST['2fa_method']);
            $userId = get_current_user_id();

            if ($method === 'email') {
                TwoFactorAuth::enable($userId, 'email');
                echo '<div class="notice notice-success"><p>Email 2FA enabled successfully!</p></div>';
            } elseif ($method === 'totp') {
                // This will be handled via AJAX
                echo '<div class="notice notice-info"><p>Please complete TOTP setup below.</p></div>';
            }
            break;

        case 'disable_2fa':
            $userId = get_current_user_id();
            TwoFactorAuth::disable($userId);
            echo '<div class="notice notice-success"><p>2FA disabled successfully!</p></div>';
            break;
    }
}

$currentUser = wp_get_current_user();
$ipWhitelist = get_option('wp_security_monitor_ip_whitelist', []);
$userIP = AccessControl::getUserIP();
$twoFactorEnabled = TwoFactorAuth::isEnabled($currentUser->ID);
$twoFactorMethod = get_user_meta($currentUser->ID, 'wp_security_monitor_2fa_method', true);

// Get recent audit logs
$recentLogs = AccessControl::getAuditLogs([], 20);

?>

<div class="wrap">
    <h1>🔐 Access Control & Security</h1>
    <p>Quản lý permissions, 2FA, IP whitelist và audit logs cho WP Security Monitor</p>

    <!-- Current User Info -->
    <div class="card" style="margin-top: 20px;">
        <h2 class="title">👤 Current User Information</h2>
        <table class="widefat fixed striped">
            <tbody>
                <tr>
                    <td style="width: 200px;"><strong>Username</strong></td>
                    <td><?php echo esc_html($currentUser->user_login); ?></td>
                </tr>
                <tr>
                    <td><strong>Display Name</strong></td>
                    <td><?php echo esc_html($currentUser->display_name); ?></td>
                </tr>
                <tr>
                    <td><strong>Email</strong></td>
                    <td><?php echo esc_html($currentUser->user_email); ?></td>
                </tr>
                <tr>
                    <td><strong>Roles</strong></td>
                    <td><?php echo implode(', ', $currentUser->roles); ?></td>
                </tr>
                <tr>
                    <td><strong>Your IP Address</strong></td>
                    <td>
                        <code><?php echo esc_html($userIP); ?></code>
                        <?php if (AccessControl::isIPWhitelisted()): ?>
                            <span style="color: green;">✅ Whitelisted</span>
                        <?php else: ?>
                            <span style="color: red;">❌ Not Whitelisted</span>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <td><strong>Session Status</strong></td>
                    <td>
                        <?php if (AccessControl::isSessionValid()): ?>
                            <span style="color: green;">✅ Valid</span>
                        <?php else: ?>
                            <span style="color: orange;">⚠️ Timeout Soon</span>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <td><strong>Account Status</strong></td>
                    <td>
                        <?php if (AccessControl::isAccountLocked()): ?>
                            <span style="color: red;">🔒 Locked</span>
                        <?php else: ?>
                            <span style="color: green;">✅ Active</span>
                        <?php endif; ?>
                    </td>
                </tr>
            </tbody>
        </table>
    </div>

    <!-- IP Whitelist Management -->
    <div class="card" style="margin-top: 20px;">
        <h2 class="title">🌐 IP Address Whitelist</h2>
        <p>Chỉ các IP addresses trong whitelist mới có thể access security operations. Để trống để allow tất cả IPs.</p>

        <form method="post">
            <?php wp_nonce_field('security_monitor_access_control'); ?>
            <input type="hidden" name="action" value="update_ip_whitelist">

            <table class="form-table">
                <tr>
                    <th scope="row">Allowed IP Addresses</th>
                    <td>
                        <textarea name="ip_whitelist" rows="8" cols="50" class="large-text"><?php
                            echo esc_textarea(implode("\n", $ipWhitelist));
                        ?></textarea>
                        <p class="description">
                            Một IP per line. Supports CIDR notation (e.g., 192.168.1.0/24).<br>
                            Examples: 192.168.1.100, 10.0.0.0/8, 172.16.0.0/12
                        </p>
                    </td>
                </tr>
            </table>

            <p class="submit">
                <input type="submit" class="button-primary" value="Update IP Whitelist">
            </p>
        </form>
    </div>

    <!-- Two-Factor Authentication -->
    <div class="card" style="margin-top: 20px;">
        <h2 class="title">🔒 Two-Factor Authentication (2FA)</h2>

        <?php if ($twoFactorEnabled): ?>
            <div style="background: #d1f2eb; padding: 15px; border-left: 4px solid #27ae60; margin-bottom: 20px;">
                <h4>✅ 2FA Enabled</h4>
                <p><strong>Method:</strong> <?php echo esc_html(ucfirst($twoFactorMethod)); ?></p>
                <p>Your account is protected with two-factor authentication.</p>
            </div>

            <form method="post" style="display: inline;">
                <?php wp_nonce_field('security_monitor_access_control'); ?>
                <input type="hidden" name="action" value="disable_2fa">
                <button type="submit" class="button button-secondary"
                        onclick="return confirm('Are you sure you want to disable 2FA? This will reduce your account security.')">
                    Disable 2FA
                </button>
            </form>

            <button type="button" class="button" onclick="generateBackupCodes()">
                Generate New Backup Codes
            </button>

        <?php else: ?>
            <div style="background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin-bottom: 20px;">
                <h4>⚠️ 2FA Not Enabled</h4>
                <p>Enable two-factor authentication để enhance security cho sensitive operations.</p>
            </div>

            <h3>Choose 2FA Method:</h3>

            <!-- Email OTP -->
            <div style="border: 1px solid #ddd; padding: 15px; margin: 10px 0;">
                <h4>📧 Email OTP</h4>
                <p>Receive verification codes via email. Simple và không requires additional apps.</p>

                <form method="post" style="display: inline;">
                    <?php wp_nonce_field('security_monitor_access_control'); ?>
                    <input type="hidden" name="action" value="setup_2fa">
                    <input type="hidden" name="2fa_method" value="email">
                    <button type="submit" class="button button-primary">Enable Email 2FA</button>
                </form>
            </div>

            <!-- TOTP -->
            <div style="border: 1px solid #ddd; padding: 15px; margin: 10px 0;">
                <h4>📱 Authenticator App (TOTP)</h4>
                <p>Use apps như Google Authenticator, Authy, or 1Password. More secure than email.</p>

                <button type="button" class="button button-primary" onclick="setupTOTP()">
                    Setup Authenticator App
                </button>

                <div id="totp-setup" style="display: none; margin-top: 20px;">
                    <h4>TOTP Setup</h4>
                    <div id="totp-qr-code"></div>
                    <p>Scan the QR code với your authenticator app, then enter verification code:</p>
                    <input type="text" id="totp-verification" placeholder="Enter 6-digit code" maxlength="6">
                    <button type="button" class="button" onclick="verifyTOTP()">Verify & Enable</button>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <!-- User Capabilities -->
    <div class="card" style="margin-top: 20px;">
        <h2 class="title">🔑 Your Security Permissions</h2>

        <table class="widefat fixed striped">
            <thead>
                <tr>
                    <th style="width: 300px;">Permission</th>
                    <th>Status</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td><strong>View Issues</strong></td>
                    <td>
                        <?php if (current_user_can(AccessControl::CAP_VIEW_ISSUES)): ?>
                            <span style="color: green;">✅ Granted</span>
                        <?php else: ?>
                            <span style="color: red;">❌ Denied</span>
                        <?php endif; ?>
                    </td>
                    <td>View security issues và reports</td>
                </tr>
                <tr>
                    <td><strong>Manage Issues</strong></td>
                    <td>
                        <?php if (current_user_can(AccessControl::CAP_MANAGE_ISSUES)): ?>
                            <span style="color: green;">✅ Granted</span>
                        <?php else: ?>
                            <span style="color: red;">❌ Denied</span>
                        <?php endif; ?>
                    </td>
                    <td>Resolve, ignore, và manage security issues</td>
                </tr>
                <tr>
                    <td><strong>Manage Settings</strong></td>
                    <td>
                        <?php if (current_user_can(AccessControl::CAP_MANAGE_SETTINGS)): ?>
                            <span style="color: green;">✅ Granted</span>
                        <?php else: ?>
                            <span style="color: red;">❌ Denied</span>
                        <?php endif; ?>
                    </td>
                    <td>Configure plugin settings và channels</td>
                </tr>
                <tr>
                    <td><strong>Manage Credentials</strong></td>
                    <td>
                        <?php if (current_user_can(AccessControl::CAP_MANAGE_CREDENTIALS)): ?>
                            <span style="color: green;">✅ Granted</span>
                        <?php else: ?>
                            <span style="color: red;">❌ Denied</span>
                        <?php endif; ?>
                    </td>
                    <td>Manage API tokens và sensitive credentials</td>
                </tr>
                <tr>
                    <td><strong>View Security Status</strong></td>
                    <td>
                        <?php if (current_user_can(AccessControl::CAP_VIEW_SECURITY_STATUS)): ?>
                            <span style="color: green;">✅ Granted</span>
                        <?php else: ?>
                            <span style="color: red;">❌ Denied</span>
                        <?php endif; ?>
                    </td>
                    <td>View encryption status và security health</td>
                </tr>
                <tr>
                    <td><strong>Manage Whitelist</strong></td>
                    <td>
                        <?php if (current_user_can(AccessControl::CAP_MANAGE_WHITELIST)): ?>
                            <span style="color: green;">✅ Granted</span>
                        <?php else: ?>
                            <span style="color: red;">❌ Denied</span>
                        <?php endif; ?>
                    </td>
                    <td>Approve/reject domains trong external redirect monitoring</td>
                </tr>
                <tr>
                    <td><strong>Emergency Actions</strong></td>
                    <td>
                        <?php if (current_user_can(AccessControl::CAP_EMERGENCY_ACTIONS)): ?>
                            <span style="color: green;">✅ Granted</span>
                        <?php else: ?>
                            <span style="color: red;">❌ Denied</span>
                        <?php endif; ?>
                    </td>
                    <td>Perform emergency lockdown và key rotation</td>
                </tr>
                <tr>
                    <td><strong>Audit Logs</strong></td>
                    <td>
                        <?php if (current_user_can(AccessControl::CAP_AUDIT_LOGS)): ?>
                            <span style="color: green;">✅ Granted</span>
                        <?php else: ?>
                            <span style="color: red;">❌ Denied</span>
                        <?php endif; ?>
                    </td>
                    <td>View và analyze audit trails</td>
                </tr>
            </tbody>
        </table>
    </div>

    <!-- Recent Activity -->
    <div class="card" style="margin-top: 20px;">
        <h2 class="title">📋 Recent Security Activity</h2>

        <?php if (empty($recentLogs)): ?>
            <p><em>No recent security activity recorded.</em></p>
        <?php else: ?>
            <table class="widefat fixed striped">
                <thead>
                    <tr>
                        <th style="width: 140px;">Timestamp</th>
                        <th style="width: 120px;">Event</th>
                        <th style="width: 100px;">User</th>
                        <th style="width: 120px;">IP Address</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach (array_slice($recentLogs, 0, 10) as $log): ?>
                        <tr>
                            <td><?php echo esc_html($log['created_at']); ?></td>
                            <td>
                                <span class="event-type-<?php echo esc_attr($log['event_type']); ?>">
                                    <?php echo esc_html(ucwords(str_replace('_', ' ', $log['event_type']))); ?>
                                </span>
                            </td>
                            <td>
                                <?php
                                if ($log['user']) {
                                    echo esc_html($log['user']->display_name);
                                } else {
                                    echo 'System';
                                }
                                ?>
                            </td>
                            <td><code><?php echo esc_html($log['ip_address']); ?></code></td>
                            <td>
                                <?php
                                if (!empty($log['event_data'])) {
                                    $details = [];
                                    foreach ($log['event_data'] as $key => $value) {
                                        if (is_string($value) || is_numeric($value)) {
                                            $details[] = esc_html($key . ': ' . $value);
                                        }
                                    }
                                    echo implode(', ', array_slice($details, 0, 3));
                                    if (count($details) > 3) {
                                        echo '...';
                                    }
                                }
                                ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</div>

<style>
.card {
    background: #fff;
    border: 1px solid #ccd0d4;
    border-radius: 4px;
    padding: 20px;
    box-shadow: 0 1px 1px rgba(0,0,0,.04);
}

.card .title {
    margin-top: 0;
    padding-bottom: 10px;
    border-bottom: 1px solid #eee;
}

.event-type-user_login { color: #27ae60; }
.event-type-user_logout { color: #95a5a6; }
.event-type-access_denied_ip { color: #e74c3c; }
.event-type-session_timeout { color: #f39c12; }
.event-type-2fa_enabled { color: #3498db; }
.event-type-2fa_verified { color: #27ae60; }
.event-type-2fa_failed { color: #e74c3c; }
</style>

<script>
function setupTOTP() {
    const setupDiv = document.getElementById('totp-setup');
    setupDiv.style.display = 'block';

    // AJAX call để get QR code
    jQuery.post(ajaxurl, {
        action: 'security_monitor_setup_2fa',
        method: 'totp',
        nonce: '<?php echo wp_create_nonce('security_monitor_2fa'); ?>'
    }, function(response) {
        if (response.success) {
            document.getElementById('totp-qr-code').innerHTML =
                '<img src="' + response.data.qr_code + '" alt="QR Code">' +
                '<p><strong>Manual Entry:</strong> <code>' + response.data.secret + '</code></p>';
        }
    });
}

function verifyTOTP() {
    const code = document.getElementById('totp-verification').value;

    if (!code || code.length !== 6) {
        alert('Please enter a 6-digit verification code');
        return;
    }

    jQuery.post(ajaxurl, {
        action: 'security_monitor_verify_2fa',
        code: code,
        nonce: '<?php echo wp_create_nonce('security_monitor_2fa'); ?>'
    }, function(response) {
        if (response.success) {
            alert('TOTP 2FA enabled successfully!');
            location.reload();
        } else {
            alert('Verification failed: ' + response.data);
        }
    });
}

function generateBackupCodes() {
    if (!confirm('Generate new backup codes? This will invalidate existing backup codes.')) {
        return;
    }

    jQuery.post(ajaxurl, {
        action: 'security_monitor_generate_backup_codes',
        nonce: '<?php echo wp_create_nonce('security_monitor_2fa'); ?>'
    }, function(response) {
        if (response.success) {
            let codesList = response.data.codes.join('\n');
            alert('New backup codes generated:\n\n' + codesList + '\n\nPlease save these codes in a secure location.');
        } else {
            alert('Failed to generate backup codes: ' + response.data);
        }
    });
}
</script>
