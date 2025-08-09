<?php
if (!defined('ABSPATH')) {
    exit;
}

use Puleeno\SecurityBot\WebMonitor\Security\SecureConfigManager;
use Puleeno\SecurityBot\WebMonitor\Security\CredentialManager;

// Handle actions
if (isset($_POST['action']) && wp_verify_nonce($_POST['_wpnonce'], 'security_monitor_security_action')) {
    switch ($_POST['action']) {
        case 'test_encryption':
            $validation = SecureConfigManager::validateEncryption();
            if ($validation['encryption_test']) {
                echo '<div class="notice notice-success"><p>✅ Encryption test successful! Performance: ' .
                     ($validation['performance_test'] ?? 'N/A') . 'ms for 100 operations.</p></div>';
            } else {
                echo '<div class="notice notice-error"><p>❌ Encryption test failed: ' .
                     ($validation['error'] ?? 'Unknown error') . '</p></div>';
            }
            break;

        case 'rotate_keys':
            if (SecureConfigManager::rotateKeys()) {
                echo '<div class="notice notice-success"><p>🔄 Encryption keys rotated successfully!</p></div>';
            } else {
                echo '<div class="notice notice-error"><p>❌ Key rotation failed!</p></div>';
            }
            break;

        case 'test_credential':
            $credentialType = sanitize_text_field($_POST['credential_type']);
            $result = CredentialManager::testCredential($credentialType);

            if ($result['success']) {
                echo '<div class="notice notice-success"><p>✅ ' . esc_html($result['message']);
                if (!empty($result['details'])) {
                    echo ' - ' . esc_html(json_encode($result['details']));
                }
                echo '</p></div>';
            } else {
                echo '<div class="notice notice-error"><p>❌ ' . esc_html($result['message']) . '</p></div>';
            }
            break;
    }
}

$securityStatus = SecureConfigManager::getSecurityStatus();
$encryptionValidation = SecureConfigManager::validateEncryption();
$credentialsList = CredentialManager::listCredentials();

?>

<div class="wrap">
    <h1>🔒 Security Status</h1>
    <p>Monitor encryption status và credential security trong WP Security Monitor Bot</p>

    <!-- Security Overview -->
    <div class="card" style="margin-top: 20px;">
        <h2 class="title">🛡️ Security Overview</h2>
        <table class="widefat fixed striped">
            <tbody>
                <tr>
                    <td style="width: 200px;"><strong>Encryption Status</strong></td>
                    <td>
                        <?php if ($securityStatus['encryption_ready']): ?>
                            <span style="color: green;">✅ Ready</span>
                        <?php else: ?>
                            <span style="color: red;">❌ Not Available</span>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <td><strong>Security Level</strong></td>
                    <td>
                        <?php
                        $level = $securityStatus['security_level'];
                        $color = strpos($level, 'HIGH') !== false ? 'green' :
                                (strpos($level, 'MEDIUM') !== false ? 'orange' : 'red');
                        ?>
                        <span style="color: <?php echo $color; ?>;">
                            <?php echo esc_html($level); ?>
                        </span>
                    </td>
                </tr>
                <tr>
                    <td><strong>Protected Configs</strong></td>
                    <td><?php echo count($securityStatus['protected_configs']); ?> items</td>
                </tr>
                <tr>
                    <td><strong>Last Key Rotation</strong></td>
                    <td><?php echo esc_html($securityStatus['last_key_rotation']); ?></td>
                </tr>
                <tr>
                    <td><strong>Encryption Performance</strong></td>
                    <td><?php echo esc_html($securityStatus['encryption_performance']); ?>ms</td>
                </tr>
            </tbody>
        </table>
    </div>

    <!-- Encryption Details -->
    <div class="card" style="margin-top: 20px;">
        <h2 class="title">🔐 Encryption Details</h2>
        <table class="widefat fixed striped">
            <thead>
                <tr>
                    <th>Component</th>
                    <th>Status</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>OpenSSL Extension</td>
                    <td>
                        <?php if ($encryptionValidation['openssl_available']): ?>
                            <span style="color: green;">✅ Available</span>
                        <?php else: ?>
                            <span style="color: red;">❌ Missing</span>
                        <?php endif; ?>
                    </td>
                    <td><?php echo $encryptionValidation['openssl_available'] ? 'AES-256-CBC supported' : 'Required for encryption'; ?></td>
                </tr>
                <tr>
                    <td>AES-256-CBC Cipher</td>
                    <td>
                        <?php if ($encryptionValidation['cipher_available']): ?>
                            <span style="color: green;">✅ Supported</span>
                        <?php else: ?>
                            <span style="color: red;">❌ Not Supported</span>
                        <?php endif; ?>
                    </td>
                    <td>Strong encryption method</td>
                </tr>
                <tr>
                    <td>WordPress Salts</td>
                    <td>
                        <?php if ($encryptionValidation['wp_salts_defined']): ?>
                            <span style="color: green;">✅ Defined</span>
                        <?php else: ?>
                            <span style="color: red;">❌ Missing</span>
                        <?php endif; ?>
                    </td>
                    <td>Required for key derivation</td>
                </tr>
                <tr>
                    <td>Encryption Test</td>
                    <td>
                        <?php if ($encryptionValidation['encryption_test']): ?>
                            <span style="color: green;">✅ Passed</span>
                        <?php else: ?>
                            <span style="color: red;">❌ Failed</span>
                        <?php endif; ?>
                    </td>
                    <td>
                        <?php
                        if ($encryptionValidation['encryption_test']) {
                            echo 'Encrypt/decrypt working properly';
                        } else {
                            echo isset($encryptionValidation['error']) ? esc_html($encryptionValidation['error']) : 'Unknown error';
                        }
                        ?>
                    </td>
                </tr>
            </tbody>
        </table>

        <p style="margin-top: 15px;">
            <form method="post" style="display: inline;">
                <?php wp_nonce_field('security_monitor_security_action'); ?>
                <input type="hidden" name="action" value="test_encryption">
                <button type="submit" class="button">🧪 Test Encryption</button>
            </form>

            <form method="post" style="display: inline; margin-left: 10px;">
                <?php wp_nonce_field('security_monitor_security_action'); ?>
                <input type="hidden" name="action" value="rotate_keys">
                <button type="submit" class="button button-secondary"
                        onclick="return confirm('Are you sure? This will re-encrypt all credentials with new keys.')">
                    🔄 Rotate Keys
                </button>
            </form>
        </p>
    </div>

    <!-- Credentials Status -->
    <div class="card" style="margin-top: 20px;">
        <h2 class="title">🔑 Stored Credentials</h2>

        <?php if (empty($credentialsList)): ?>
            <p><em>No credentials stored yet.</em></p>
        <?php else: ?>
            <table class="widefat fixed striped">
                <thead>
                    <tr>
                        <th style="width: 200px;">Credential Type</th>
                        <th style="width: 120px;">Created</th>
                        <th style="width: 120px;">Last Used</th>
                        <th style="width: 80px;">Use Count</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($credentialsList as $type => $metadata): ?>
                        <tr>
                            <td>
                                <strong><?php echo esc_html(ucwords(str_replace('_', ' ', $type))); ?></strong>
                                <?php if ($metadata['created_by']): ?>
                                    <br><small>by User #<?php echo esc_html($metadata['created_by']); ?></small>
                                <?php endif; ?>
                            </td>
                            <td><?php echo $metadata['created_at'] ? esc_html($metadata['created_at']) : 'Unknown'; ?></td>
                            <td><?php echo $metadata['last_used'] ? esc_html($metadata['last_used']) : 'Never'; ?></td>
                            <td style="text-align: center;"><?php echo esc_html($metadata['use_count']); ?></td>
                            <td>
                                <?php if (in_array($type, ['telegram_token', 'slack_webhook'])): ?>
                                    <form method="post" style="display: inline;">
                                        <?php wp_nonce_field('security_monitor_security_action'); ?>
                                        <input type="hidden" name="action" value="test_credential">
                                        <input type="hidden" name="credential_type" value="<?php echo esc_attr($type); ?>">
                                        <button type="submit" class="button button-small">🧪 Test</button>
                                    </form>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

    <!-- Security Recommendations -->
    <div class="card" style="margin-top: 20px;">
        <h2 class="title">💡 Security Recommendations</h2>

        <div style="background: #f9f9f9; padding: 15px; border-left: 4px solid #0073aa;">
            <h4>🔒 Credential Protection Best Practices:</h4>
            <ul>
                <li><strong>Strong WordPress Salts:</strong> Ensure all WordPress authentication salts are defined and unique</li>
                <li><strong>Regular Key Rotation:</strong> Rotate encryption keys periodically (quarterly recommended)</li>
                <li><strong>Monitor Access:</strong> Review credential usage patterns for suspicious activity</li>
                <li><strong>Test Connections:</strong> Regularly test credential functionality to detect issues early</li>
                <li><strong>Backup Strategy:</strong> Document credential recovery procedures for emergency situations</li>
            </ul>
        </div>

        <?php if (!$encryptionValidation['wp_salts_defined']): ?>
            <div style="background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin-top: 15px;">
                <h4>⚠️ Warning: WordPress Salts Not Properly Configured</h4>
                <p>Your WordPress installation is using default or missing authentication salts. This significantly reduces the security of encrypted credentials.</p>
                <p><strong>Action Required:</strong> Update your <code>wp-config.php</code> file with unique salts from
                   <a href="https://api.wordpress.org/secret-key/1.1/salt/" target="_blank">WordPress Salt Generator</a></p>
            </div>
        <?php endif; ?>

        <?php if (!$encryptionValidation['openssl_available']): ?>
            <div style="background: #f8d7da; padding: 15px; border-left: 4px solid #dc3545; margin-top: 15px;">
                <h4>🚨 Critical: OpenSSL Extension Missing</h4>
                <p>The OpenSSL extension is not available on your server. Credential encryption is disabled.</p>
                <p><strong>Action Required:</strong> Contact your hosting provider to enable the OpenSSL PHP extension.</p>
            </div>
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

.widefat td, .widefat th {
    padding: 12px;
}

.button-small {
    font-size: 11px;
    height: auto;
    line-height: 1.5;
    padding: 2px 6px;
}
</style>
