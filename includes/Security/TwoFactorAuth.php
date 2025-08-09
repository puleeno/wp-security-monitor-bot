<?php

namespace Puleeno\SecurityBot\WebMonitor\Security;

/**
 * Two-Factor Authentication Manager
 *
 * Provides 2FA functionality cho sensitive operations
 * - Email-based OTP
 * - TOTP support (Google Authenticator compatible)
 * - Backup codes
 * - Session management
 */
class TwoFactorAuth
{
    /**
     * OTP validity duration (seconds)
     */
    const OTP_VALIDITY = 300; // 5 minutes

    /**
     * Backup codes count
     */
    const BACKUP_CODES_COUNT = 10;

    /**
     * TOTP window (30 seconds)
     */
    const TOTP_WINDOW = 30;

    /**
     * TOTP digits
     */
    const TOTP_DIGITS = 6;

    /**
     * Initialize 2FA system
     */
    public static function init(): void
    {
        add_action('wp_ajax_security_monitor_setup_2fa', [__CLASS__, 'ajaxSetup2FA']);
        add_action('wp_ajax_security_monitor_verify_2fa', [__CLASS__, 'ajaxVerify2FA']);
        add_action('wp_ajax_security_monitor_disable_2fa', [__CLASS__, 'ajaxDisable2FA']);
        add_action('wp_ajax_security_monitor_generate_backup_codes', [__CLASS__, 'ajaxGenerateBackupCodes']);
    }

    /**
     * Check if user has 2FA enabled
     *
     * @param int $userId User ID
     * @return bool
     */
    public static function isEnabled(int $userId): bool
    {
        return (bool) get_user_meta($userId, 'wp_security_monitor_2fa_enabled', true);
    }

    /**
     * Enable 2FA for user
     *
     * @param int $userId User ID
     * @param string $method Method (email, totp)
     * @return bool
     */
    public static function enable(int $userId, string $method = 'email'): bool
    {
        update_user_meta($userId, 'wp_security_monitor_2fa_enabled', true);
        update_user_meta($userId, 'wp_security_monitor_2fa_method', $method);
        update_user_meta($userId, 'wp_security_monitor_2fa_setup_at', current_time('mysql'));

        // Generate backup codes
        self::generateBackupCodes($userId);

        // Log event
        AccessControl::logSecurityEvent('2fa_enabled', [
            'user_id' => $userId,
            'method' => $method
        ]);

        return true;
    }

    /**
     * Disable 2FA for user
     *
     * @param int $userId User ID
     * @return bool
     */
    public static function disable(int $userId): bool
    {
        // Clear all 2FA related metadata
        delete_user_meta($userId, 'wp_security_monitor_2fa_enabled');
        delete_user_meta($userId, 'wp_security_monitor_2fa_method');
        delete_user_meta($userId, 'wp_security_monitor_2fa_secret');
        delete_user_meta($userId, 'wp_security_monitor_2fa_backup_codes');
        delete_user_meta($userId, 'wp_security_monitor_2fa_verified');
        delete_user_meta($userId, 'wp_security_monitor_2fa_setup_at');

        // Log event
        AccessControl::logSecurityEvent('2fa_disabled', [
            'user_id' => $userId
        ]);

        return true;
    }

    /**
     * Generate OTP for email-based 2FA
     *
     * @param int $userId User ID
     * @return string OTP code
     */
    public static function generateEmailOTP(int $userId): string
    {
        $otp = wp_generate_password(6, false, false); // 6 digit numeric

        // Store OTP với expiration
        update_user_meta($userId, 'wp_security_monitor_2fa_otp', [
            'code' => $otp,
            'expires' => time() + self::OTP_VALIDITY,
            'attempts' => 0
        ]);

        return $otp;
    }

    /**
     * Send OTP via email
     *
     * @param int $userId User ID
     * @param string $operation Operation description
     * @return bool Success status
     */
    public static function sendEmailOTP(int $userId, string $operation = 'security operation'): bool
    {
        $user = get_userdata($userId);
        if (!$user) {
            return false;
        }

        $otp = self::generateEmailOTP($userId);

        $subject = 'WP Security Monitor - Verification Code';
        $message = self::buildOTPEmail($user->display_name, $otp, $operation);

        $headers = [
            'Content-Type: text/html; charset=UTF-8',
            'From: ' . get_bloginfo('name') . ' <' . get_option('admin_email') . '>'
        ];

        $sent = wp_mail($user->user_email, $subject, $message, $headers);

        if ($sent) {
            AccessControl::logSecurityEvent('2fa_otp_sent', [
                'user_id' => $userId,
                'operation' => $operation,
                'email' => $user->user_email
            ]);
        }

        return $sent;
    }

    /**
     * Build OTP email content
     *
     * @param string $userName User name
     * @param string $otp OTP code
     * @param string $operation Operation description
     * @return string Email HTML
     */
    private static function buildOTPEmail(string $userName, string $otp, string $operation): string
    {
        return "
        <html>
        <head>
            <meta charset='UTF-8'>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                .header { background: #0073aa; color: white; padding: 20px; text-align: center; }
                .content { background: #f9f9f9; padding: 20px; }
                .otp-code { font-size: 24px; font-weight: bold; color: #0073aa; text-align: center;
                           letter-spacing: 5px; margin: 20px 0; padding: 15px; background: white;
                           border: 2px dashed #0073aa; }
                .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 20px 0; }
                .footer { text-align: center; font-size: 12px; color: #666; margin-top: 30px; }
            </style>
        </head>
        <body>
            <div class='container'>
                <div class='header'>
                    <h1>🔐 WP Security Monitor</h1>
                    <p>Two-Factor Authentication</p>
                </div>

                <div class='content'>
                    <h2>Hello {$userName},</h2>

                    <p>You are attempting to perform a security-sensitive operation: <strong>{$operation}</strong></p>

                    <p>Please use the following verification code to complete this action:</p>

                    <div class='otp-code'>{$otp}</div>

                    <div class='warning'>
                        <strong>⚠️ Security Notice:</strong>
                        <ul>
                            <li>This code expires in 5 minutes</li>
                            <li>Never share this code with anyone</li>
                            <li>If you didn't request this, please contact your administrator immediately</li>
                        </ul>
                    </div>

                    <p><strong>Request Details:</strong></p>
                    <ul>
                        <li><strong>Time:</strong> " . current_time('Y-m-d H:i:s') . "</li>
                        <li><strong>IP Address:</strong> " . AccessControl::getUserIP() . "</li>
                        <li><strong>User Agent:</strong> " . esc_html($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown') . "</li>
                    </ul>
                </div>

                <div class='footer'>
                    <p>This is an automated message from WP Security Monitor Bot</p>
                    <p>Website: " . get_site_url() . "</p>
                </div>
            </div>
        </body>
        </html>";
    }

    /**
     * Verify OTP code
     *
     * @param int $userId User ID
     * @param string $code OTP code
     * @return bool Valid or not
     */
    public static function verifyOTP(int $userId, string $code): bool
    {
        $storedOTP = get_user_meta($userId, 'wp_security_monitor_2fa_otp', true);

        if (!$storedOTP || !is_array($storedOTP)) {
            return false;
        }

        // Check expiration
        if (time() > $storedOTP['expires']) {
            delete_user_meta($userId, 'wp_security_monitor_2fa_otp');
            return false;
        }

        // Check attempt limit
        if ($storedOTP['attempts'] >= 3) {
            delete_user_meta($userId, 'wp_security_monitor_2fa_otp');
            AccessControl::logSecurityEvent('2fa_max_attempts', ['user_id' => $userId]);
            return false;
        }

        // Increment attempts
        $storedOTP['attempts']++;
        update_user_meta($userId, 'wp_security_monitor_2fa_otp', $storedOTP);

        // Verify code
        if (hash_equals($storedOTP['code'], $code)) {
            // Success - clean up and mark as verified
            delete_user_meta($userId, 'wp_security_monitor_2fa_otp');
            update_user_meta($userId, 'wp_security_monitor_2fa_verified', time());

            AccessControl::logSecurityEvent('2fa_verified', [
                'user_id' => $userId,
                'method' => 'email_otp'
            ]);

            return true;
        }

        AccessControl::logSecurityEvent('2fa_failed', [
            'user_id' => $userId,
            'attempts' => $storedOTP['attempts']
        ]);

        return false;
    }

    /**
     * Generate TOTP secret
     *
     * @param int $userId User ID
     * @return string Base32 secret
     */
    public static function generateTOTPSecret(int $userId): string
    {
        $secret = '';
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; // Base32 alphabet

        for ($i = 0; $i < 32; $i++) {
            $secret .= $chars[random_int(0, 31)];
        }

        update_user_meta($userId, 'wp_security_monitor_2fa_totp_secret', $secret);

        return $secret;
    }

    /**
     * Get QR code URL for TOTP setup
     *
     * @param int $userId User ID
     * @return string QR code URL
     */
    public static function getTOTPQRCode(int $userId): string
    {
        $user = get_userdata($userId);
        $secret = get_user_meta($userId, 'wp_security_monitor_2fa_totp_secret', true);

        if (!$secret) {
            $secret = self::generateTOTPSecret($userId);
        }

        $siteName = get_bloginfo('name');
        $accountName = $user->user_email;

        $otpauth = sprintf(
            'otpauth://totp/%s:%s?secret=%s&issuer=%s',
            urlencode($siteName),
            urlencode($accountName),
            $secret,
            urlencode($siteName)
        );

        // Use Google Charts API for QR code
        return 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=' . urlencode($otpauth);
    }

    /**
     * Verify TOTP code
     *
     * @param int $userId User ID
     * @param string $code TOTP code
     * @return bool Valid or not
     */
    public static function verifyTOTP(int $userId, string $code): bool
    {
        $secret = get_user_meta($userId, 'wp_security_monitor_2fa_totp_secret', true);

        if (!$secret) {
            return false;
        }

        // Check current time window and adjacent windows for clock drift
        $currentTime = floor(time() / self::TOTP_WINDOW);

        for ($window = -1; $window <= 1; $window++) {
            $timeSlice = $currentTime + $window;
            $expectedCode = self::generateTOTPCode($secret, $timeSlice);

            if (hash_equals($expectedCode, $code)) {
                update_user_meta($userId, 'wp_security_monitor_2fa_verified', time());

                AccessControl::logSecurityEvent('2fa_verified', [
                    'user_id' => $userId,
                    'method' => 'totp'
                ]);

                return true;
            }
        }

        AccessControl::logSecurityEvent('2fa_failed', [
            'user_id' => $userId,
            'method' => 'totp'
        ]);

        return false;
    }

    /**
     * Generate TOTP code for specific time slice
     *
     * @param string $secret Base32 secret
     * @param int $timeSlice Time slice
     * @return string TOTP code
     */
    private static function generateTOTPCode(string $secret, int $timeSlice): string
    {
        // Convert Base32 secret to binary
        $secretBinary = self::base32Decode($secret);

        // Pack time slice as 64-bit big-endian
        $time = pack('N*', 0) . pack('N*', $timeSlice);

        // Generate HMAC-SHA1
        $hash = hash_hmac('sha1', $time, $secretBinary, true);

        // Dynamic truncation
        $offset = ord($hash[19]) & 0xf;
        $code = (
            ((ord($hash[$offset]) & 0x7f) << 24) |
            ((ord($hash[$offset + 1]) & 0xff) << 16) |
            ((ord($hash[$offset + 2]) & 0xff) << 8) |
            (ord($hash[$offset + 3]) & 0xff)
        ) % pow(10, self::TOTP_DIGITS);

        return str_pad($code, self::TOTP_DIGITS, '0', STR_PAD_LEFT);
    }

    /**
     * Decode Base32 string
     *
     * @param string $input Base32 string
     * @return string Binary data
     */
    private static function base32Decode(string $input): string
    {
        $input = strtoupper($input);
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $output = '';
        $v = 0;
        $vbits = 0;

        for ($i = 0, $j = strlen($input); $i < $j; $i++) {
            $v <<= 5;
            $v += strpos($alphabet, $input[$i]);
            $vbits += 5;

            if ($vbits >= 8) {
                $output .= chr($v >> ($vbits - 8));
                $vbits -= 8;
            }
        }

        return $output;
    }

    /**
     * Generate backup codes
     *
     * @param int $userId User ID
     * @return array Backup codes
     */
    public static function generateBackupCodes(int $userId): array
    {
        $codes = [];

        for ($i = 0; $i < self::BACKUP_CODES_COUNT; $i++) {
            $codes[] = wp_generate_password(8, false, false);
        }

        // Hash codes before storing
        $hashedCodes = array_map('wp_hash_password', $codes);
        update_user_meta($userId, 'wp_security_monitor_2fa_backup_codes', $hashedCodes);

        AccessControl::logSecurityEvent('2fa_backup_codes_generated', [
            'user_id' => $userId,
            'codes_count' => count($codes)
        ]);

        return $codes;
    }

    /**
     * Verify backup code
     *
     * @param int $userId User ID
     * @param string $code Backup code
     * @return bool Valid or not
     */
    public static function verifyBackupCode(int $userId, string $code): bool
    {
        $storedCodes = get_user_meta($userId, 'wp_security_monitor_2fa_backup_codes', true);

        if (!$storedCodes || !is_array($storedCodes)) {
            return false;
        }

        foreach ($storedCodes as $index => $hashedCode) {
            if (wp_check_password($code, $hashedCode)) {
                // Remove used code
                unset($storedCodes[$index]);
                update_user_meta($userId, 'wp_security_monitor_2fa_backup_codes', array_values($storedCodes));

                update_user_meta($userId, 'wp_security_monitor_2fa_verified', time());

                AccessControl::logSecurityEvent('2fa_verified', [
                    'user_id' => $userId,
                    'method' => 'backup_code',
                    'remaining_codes' => count($storedCodes)
                ]);

                return true;
            }
        }

        AccessControl::logSecurityEvent('2fa_failed', [
            'user_id' => $userId,
            'method' => 'backup_code'
        ]);

        return false;
    }

    /**
     * Check if 2FA verification is required and valid
     *
     * @param string $operation Operation requiring 2FA
     * @return array Status and challenge data
     */
    public static function checkRequired(string $operation): array
    {
        $userId = get_current_user_id();

        if (!self::isEnabled($userId)) {
            return ['required' => false, 'verified' => true];
        }

        // Check if already verified in this session
        $lastVerification = get_user_meta($userId, 'wp_security_monitor_2fa_verified', true);

        // 2FA valid for 15 minutes
        if ($lastVerification && (time() - $lastVerification) < 900) {
            return ['required' => true, 'verified' => true];
        }

        // Need fresh verification
        $method = get_user_meta($userId, 'wp_security_monitor_2fa_method', true);

        return [
            'required' => true,
            'verified' => false,
            'method' => $method,
            'challenge' => self::initializeChallenge($userId, $operation)
        ];
    }

    /**
     * Initialize 2FA challenge
     *
     * @param int $userId User ID
     * @param string $operation Operation description
     * @return array Challenge data
     */
    private static function initializeChallenge(int $userId, string $operation): array
    {
        $method = get_user_meta($userId, 'wp_security_monitor_2fa_method', true);

        switch ($method) {
            case 'email':
                $sent = self::sendEmailOTP($userId, $operation);
                return [
                    'type' => 'email_otp',
                    'sent' => $sent,
                    'message' => $sent ? 'Verification code sent to your email' : 'Failed to send verification code'
                ];

            case 'totp':
                return [
                    'type' => 'totp',
                    'message' => 'Enter code from your authenticator app'
                ];

            default:
                return [
                    'type' => 'unknown',
                    'message' => '2FA method not configured'
                ];
        }
    }

    /**
     * AJAX handler để setup 2FA
     */
    public static function ajaxSetup2FA(): void
    {
        if (!wp_verify_nonce($_POST['nonce'] ?? '', 'security_monitor_2fa')) {
            wp_send_json_error('Invalid nonce');
            return;
        }

        if (!current_user_can('read')) {
            wp_send_json_error('Insufficient permissions');
            return;
        }

        $method = sanitize_text_field($_POST['method'] ?? 'email');
        $userId = get_current_user_id();

        switch ($method) {
            case 'email':
                self::enable($userId, 'email');
                wp_send_json_success([
                    'message' => '2FA enabled successfully',
                    'backup_codes' => self::generateBackupCodes($userId)
                ]);
                break;

            case 'totp':
                $secret = self::generateTOTPSecret($userId);
                wp_send_json_success([
                    'message' => 'TOTP setup initialized',
                    'secret' => $secret,
                    'qr_code' => self::getTOTPQRCode($userId)
                ]);
                break;

            default:
                wp_send_json_error('Invalid 2FA method');
        }
    }

    /**
     * AJAX handler để verify 2FA
     */
    public static function ajaxVerify2FA(): void
    {
        if (!wp_verify_nonce($_POST['nonce'] ?? '', 'security_monitor_2fa')) {
            wp_send_json_error('Invalid nonce');
            return;
        }

        $code = sanitize_text_field($_POST['code'] ?? '');
        $userId = get_current_user_id();

        if (empty($code)) {
            wp_send_json_error('Verification code is required');
            return;
        }

        $method = get_user_meta($userId, 'wp_security_monitor_2fa_method', true);
        $verified = false;

        switch ($method) {
            case 'email':
                $verified = self::verifyOTP($userId, $code);
                break;

            case 'totp':
                $verified = self::verifyTOTP($userId, $code);
                if ($verified && !self::isEnabled($userId)) {
                    // Complete TOTP setup
                    self::enable($userId, 'totp');
                }
                break;
        }

        // Try backup code if primary method failed
        if (!$verified) {
            $verified = self::verifyBackupCode($userId, $code);
        }

        if ($verified) {
            wp_send_json_success(['message' => 'Verification successful']);
        } else {
            wp_send_json_error('Invalid verification code');
        }
    }

    /**
     * AJAX handler để disable 2FA
     */
    public static function ajaxDisable2FA(): void
    {
        if (!wp_verify_nonce($_POST['nonce'] ?? '', 'security_monitor_2fa')) {
            wp_send_json_error('Invalid nonce');
            return;
        }

        $userId = get_current_user_id();

        if (self::disable($userId)) {
            wp_send_json_success(['message' => '2FA disabled successfully']);
        } else {
            wp_send_json_error('Failed to disable 2FA');
        }
    }

    /**
     * AJAX handler để generate backup codes
     */
    public static function ajaxGenerateBackupCodes(): void
    {
        if (!wp_verify_nonce($_POST['nonce'] ?? '', 'security_monitor_2fa')) {
            wp_send_json_error('Invalid nonce');
            return;
        }

        $userId = get_current_user_id();

        if (!self::isEnabled($userId)) {
            wp_send_json_error('2FA is not enabled');
            return;
        }

        $codes = self::generateBackupCodes($userId);
        wp_send_json_success([
            'message' => 'New backup codes generated',
            'codes' => $codes
        ]);
    }
}
