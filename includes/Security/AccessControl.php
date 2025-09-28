<?php

namespace Puleeno\SecurityBot\WebMonitor\Security;

/**
 * Access Control Manager
 *
 * Quản lý permissions system nâng cao cho plugin
 * - Custom capabilities cho các operations khác nhau
 * - Role-based access control
 * - IP whitelisting
 * - Session management
 * - Activity logging
 */
class AccessControl
{
    /**
     * Custom capabilities
     */
    const CAP_VIEW_ISSUES = 'wp_security_monitor_view_issues';
    const CAP_MANAGE_ISSUES = 'wp_security_monitor_manage_issues';
    const CAP_MANAGE_SETTINGS = 'wp_security_monitor_manage_settings';
    const CAP_MANAGE_CREDENTIALS = 'wp_security_monitor_manage_credentials';
    const CAP_VIEW_SECURITY_STATUS = 'wp_security_monitor_view_security';
    const CAP_MANAGE_WHITELIST = 'wp_security_monitor_manage_whitelist';
    const CAP_EMERGENCY_ACTIONS = 'wp_security_monitor_emergency';
    const CAP_AUDIT_LOGS = 'wp_security_monitor_audit_logs';

    /**
     * Security roles
     */
    const ROLE_SECURITY_VIEWER = 'wp_security_monitor_viewer';
    const ROLE_SECURITY_OPERATOR = 'wp_security_monitor_operator';
    const ROLE_SECURITY_ADMIN = 'wp_security_monitor_admin';

    /**
     * Session timeout (seconds)
     */
    const SESSION_TIMEOUT = 86400; // 24 hours

    /**
     * Max failed attempts before lockout
     */
    const MAX_FAILED_ATTEMPTS = 5;

    /**
     * Lockout duration (seconds)
     */
    const LOCKOUT_DURATION = 1800; // 30 minutes

    /**
     * Initialize access control system
     */
    public static function init(): void
    {
        add_action('init', [__CLASS__, 'setupRolesAndCapabilities']);
        add_action('wp_login', [__CLASS__, 'onUserLogin'], 10, 2);
        add_action('wp_logout', [__CLASS__, 'onUserLogout']);
        add_action('admin_init', [__CLASS__, 'checkAccess']);
        add_filter('user_has_cap', [__CLASS__, 'filterUserCapabilities'], 10, 4);
    }

    /**
     * Setup custom roles and capabilities
     */
    public static function setupRolesAndCapabilities(): void
    {
        // Only setup once
        if (get_option('wp_security_monitor_roles_setup', false)) {
            return;
        }

        // Get WordPress roles
        $wp_roles = wp_roles();

        // Add capabilities to Administrator
        $admin_caps = [
            self::CAP_VIEW_ISSUES => true,
            self::CAP_MANAGE_ISSUES => true,
            self::CAP_MANAGE_SETTINGS => true,
            self::CAP_MANAGE_CREDENTIALS => true,
            self::CAP_VIEW_SECURITY_STATUS => true,
            self::CAP_MANAGE_WHITELIST => true,
            self::CAP_EMERGENCY_ACTIONS => true,
            self::CAP_AUDIT_LOGS => true,
        ];

        $wp_roles->add_cap('administrator', self::CAP_VIEW_ISSUES);
        $wp_roles->add_cap('administrator', self::CAP_MANAGE_ISSUES);
        $wp_roles->add_cap('administrator', self::CAP_MANAGE_SETTINGS);
        $wp_roles->add_cap('administrator', self::CAP_MANAGE_CREDENTIALS);
        $wp_roles->add_cap('administrator', self::CAP_VIEW_SECURITY_STATUS);
        $wp_roles->add_cap('administrator', self::CAP_MANAGE_WHITELIST);
        $wp_roles->add_cap('administrator', self::CAP_EMERGENCY_ACTIONS);
        $wp_roles->add_cap('administrator', self::CAP_AUDIT_LOGS);

        // Create Security Viewer role
        $wp_roles->add_role(
            self::ROLE_SECURITY_VIEWER,
            'Security Monitor Viewer',
            [
                'read' => true,
                self::CAP_VIEW_ISSUES => true,
                self::CAP_VIEW_SECURITY_STATUS => true,
            ]
        );

        // Create Security Operator role
        $wp_roles->add_role(
            self::ROLE_SECURITY_OPERATOR,
            'Security Monitor Operator',
            [
                'read' => true,
                self::CAP_VIEW_ISSUES => true,
                self::CAP_MANAGE_ISSUES => true,
                self::CAP_VIEW_SECURITY_STATUS => true,
                self::CAP_MANAGE_WHITELIST => true,
            ]
        );

        // Create Security Admin role
        $wp_roles->add_role(
            self::ROLE_SECURITY_ADMIN,
            'Security Monitor Admin',
            [
                'read' => true,
                self::CAP_VIEW_ISSUES => true,
                self::CAP_MANAGE_ISSUES => true,
                self::CAP_MANAGE_SETTINGS => true,
                self::CAP_MANAGE_CREDENTIALS => true,
                self::CAP_VIEW_SECURITY_STATUS => true,
                self::CAP_MANAGE_WHITELIST => true,
                self::CAP_EMERGENCY_ACTIONS => true,
                self::CAP_AUDIT_LOGS => true,
            ]
        );

        // Mark setup as complete
        update_option('wp_security_monitor_roles_setup', true);
    }

    /**
     * Check if current user has specific capability
     *
     * @param string $capability Capability to check
     * @return bool
     */
    public static function currentUserCan(string $capability): bool
    {
        return current_user_can($capability);
    }

    /**
     * Check access và apply security policies
     */
    public static function checkAccess(): void
    {
        // Skip if not our admin pages
        if (!self::isSecurityMonitorPage()) {
            return;
        }

        // Check IP whitelist
        if (!self::isIPWhitelisted()) {
            self::logSecurityEvent('access_denied_ip', [
                'ip' => self::getUserIP(),
                'user_id' => get_current_user_id(),
                'page' => $_GET['page'] ?? '',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
            ]);

            wp_die('Access denied: IP address not whitelisted for security operations.', 'Access Denied', ['response' => 403]);
        }

        // Check session timeout - only for sensitive operations
        if (self::isSensitiveOperation() && !self::isSessionValid()) {
            self::logSecurityEvent('session_timeout', [
                'user_id' => get_current_user_id(),
                'page' => $_GET['page'] ?? ''
            ]);

            wp_logout();
            wp_redirect(wp_login_url());
            exit;
        }

        // Check account lockout
        if (self::isAccountLocked()) {
            self::logSecurityEvent('access_denied_locked', [
                'user_id' => get_current_user_id(),
                'ip' => self::getUserIP()
            ]);

            wp_die('Account temporarily locked due to security policy.', 'Account Locked', ['response' => 423]);
        }

        // Update session activity - only when needed
        if (self::shouldUpdateSession()) {
            self::updateSessionActivity();
        }
    }

    /**
     * Check if current page is security monitor page
     *
     * @return bool
     */
    private static function isSecurityMonitorPage(): bool
    {
        $page = $_GET['page'] ?? '';
        return strpos($page, 'wp-security-monitor') === 0;
    }

    /**
     * Check if current operation is sensitive (requires strict session validation)
     *
     * @return bool
     */
    private static function isSensitiveOperation(): bool
    {
        $page = $_GET['page'] ?? '';
        $action = $_GET['action'] ?? '';

        // Only require strict session validation for sensitive operations
        $sensitivePages = [
            'wp-security-monitor-access-control',  // Access control settings
            'wp-security-monitor-credentials',     // Credential management
        ];

        $sensitiveActions = [
            'delete_issue',
            'ignore_issue',
            'clear_encrypted_data',
            'test_channel',
            'run_check'
        ];

        return in_array($page, $sensitivePages) || in_array($action, $sensitiveActions);
    }

    /**
     * Check if session should be updated (throttled to avoid excessive DB writes)
     *
     * @return bool
     */
    private static function shouldUpdateSession(): bool
    {
        if (!is_user_logged_in()) {
            return false;
        }

        $userId = get_current_user_id();
        $lastUpdate = get_user_meta($userId, 'wp_security_monitor_session_last_update', true);

        // Only update session every 5 minutes to reduce DB load
        return !$lastUpdate || (time() - $lastUpdate) >= 300;
    }

    /**
     * Check IP whitelist
     *
     * @return bool
     */
    public static function isIPWhitelisted(): bool
    {
        $whitelist = get_option('wp_security_monitor_ip_whitelist', []);

        // If no whitelist configured, allow all (default behavior)
        if (empty($whitelist)) {
            return true;
        }

        $userIP = self::getUserIP();

        foreach ($whitelist as $allowedIP) {
            if (self::ipMatches($userIP, $allowedIP)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get user's real IP address
     *
     * @return string
     */
    public static function getUserIP(): string
    {
        // Check for various proxy headers
        $headers = [
            'HTTP_CF_CONNECTING_IP',     // Cloudflare
            'HTTP_X_REAL_IP',            // Nginx proxy
            'HTTP_X_FORWARDED_FOR',      // Standard forwarded header
            'HTTP_X_FORWARDED',          // Alternative
            'HTTP_FORWARDED_FOR',        // Alternative
            'HTTP_FORWARDED',            // Alternative
            'REMOTE_ADDR'                // Standard
        ];

        foreach ($headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ips = explode(',', $_SERVER[$header]);
                return trim($ips[0]);
            }
        }

        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    /**
     * Check if IP matches pattern (supports CIDR)
     *
     * @param string $ip IP to check
     * @param string $pattern Pattern (IP or CIDR)
     * @return bool
     */
    private static function ipMatches(string $ip, string $pattern): bool
    {
        // Exact match
        if ($ip === $pattern) {
            return true;
        }

        // CIDR notation
        if (strpos($pattern, '/') !== false) {
            list($subnet, $bits) = explode('/', $pattern);
            $ip_long = ip2long($ip);
            $subnet_long = ip2long($subnet);
            $mask = -1 << (32 - (int)$bits);

            return ($ip_long & $mask) === ($subnet_long & $mask);
        }

        return false;
    }

    /**
     * Check session validity
     *
     * @return bool
     */
    public static function isSessionValid(): bool
    {
        if (!is_user_logged_in()) {
            return false;
        }

        $userId = get_current_user_id();
        $lastActivity = get_user_meta($userId, 'wp_security_monitor_last_activity', true);

        if (!$lastActivity) {
            return true; // First time, allow
        }

        return (time() - $lastActivity) <= self::SESSION_TIMEOUT;
    }

    /**
     * Update session activity timestamp
     */
    public static function updateSessionActivity(): void
    {
        if (is_user_logged_in()) {
            $userId = get_current_user_id();
            $currentTime = time();

            update_user_meta($userId, 'wp_security_monitor_last_activity', $currentTime);
            update_user_meta($userId, 'wp_security_monitor_session_last_update', $currentTime);
        }
    }

    /**
     * Check if account is locked
     *
     * @return bool
     */
    public static function isAccountLocked(): bool
    {
        if (!is_user_logged_in()) {
            return false;
        }

        $userId = get_current_user_id();
        $lockTime = get_user_meta($userId, 'wp_security_monitor_locked_until', true);

        if (!$lockTime) {
            return false;
        }

        if (time() > $lockTime) {
            // Lock expired, remove it
            delete_user_meta($userId, 'wp_security_monitor_locked_until');
            delete_user_meta($userId, 'wp_security_monitor_failed_attempts');
            return false;
        }

        return true;
    }

    /**
     * Record failed attempt
     *
     * @param int $userId User ID
     */
    public static function recordFailedAttempt(int $userId): void
    {
        $attempts = (int) get_user_meta($userId, 'wp_security_monitor_failed_attempts', true);
        $attempts++;

        update_user_meta($userId, 'wp_security_monitor_failed_attempts', $attempts);

        if ($attempts >= self::MAX_FAILED_ATTEMPTS) {
            $lockUntil = time() + self::LOCKOUT_DURATION;
            update_user_meta($userId, 'wp_security_monitor_locked_until', $lockUntil);

            self::logSecurityEvent('account_locked', [
                'user_id' => $userId,
                'attempts' => $attempts,
                'locked_until' => $lockUntil,
                'ip' => self::getUserIP()
            ]);
        }
    }

    /**
     * Clear failed attempts
     *
     * @param int $userId User ID
     */
    public static function clearFailedAttempts(int $userId): void
    {
        delete_user_meta($userId, 'wp_security_monitor_failed_attempts');
        delete_user_meta($userId, 'wp_security_monitor_locked_until');
    }

    /**
     * Handle user login
     *
     * @param string $userLogin Username
     * @param WP_User $user User object
     */
    public static function onUserLogin(string $userLogin, $user): void
    {
        // Clear failed attempts on successful login
        self::clearFailedAttempts($user->ID);

        // Update session activity
        self::updateSessionActivity();

        // Log login
        self::logSecurityEvent('user_login', [
            'user_id' => $user->ID,
            'username' => $userLogin,
            'ip' => self::getUserIP(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
        ]);
    }

    /**
     * Handle user logout
     */
    public static function onUserLogout(): void
    {
        $userId = get_current_user_id();

        if ($userId) {
            // Clear session data
            delete_user_meta($userId, 'wp_security_monitor_last_activity');

            // Log logout
            self::logSecurityEvent('user_logout', [
                'user_id' => $userId,
                'ip' => self::getUserIP()
            ]);
        }
    }

    /**
     * Filter user capabilities for additional security
     *
     * @param array $allcaps All capabilities
     * @param array $caps Required capabilities
     * @param array $args Arguments
     * @param WP_User $user User object
     * @return array
     */
    public static function filterUserCapabilities($allcaps, $caps, $args, $user): array
    {
        // Security monitor specific capabilities
        $securityCaps = [
            self::CAP_VIEW_ISSUES,
            self::CAP_MANAGE_ISSUES,
            self::CAP_MANAGE_SETTINGS,
            self::CAP_MANAGE_CREDENTIALS,
            self::CAP_VIEW_SECURITY_STATUS,
            self::CAP_MANAGE_WHITELIST,
            self::CAP_EMERGENCY_ACTIONS,
            self::CAP_AUDIT_LOGS
        ];

        foreach ($caps as $cap) {
            if (in_array($cap, $securityCaps)) {
                // Additional security checks
                if (self::isAccountLocked()) {
                    $allcaps[$cap] = false;
                    continue;
                }

                // IP whitelist check for sensitive operations
                $sensitiveCaps = [
                    self::CAP_MANAGE_CREDENTIALS,
                    self::CAP_EMERGENCY_ACTIONS
                ];

                if (in_array($cap, $sensitiveCaps) && !self::isIPWhitelisted()) {
                    $allcaps[$cap] = false;
                    continue;
                }
            }
        }

        return $allcaps;
    }

    /**
     * Require 2FA for sensitive operations
     *
     * @param string $operation Operation type
     * @return bool
     */
    public static function require2FA(string $operation): bool
    {
        $twoFactorOperations = [
            'credential_management',
            'key_rotation',
            'emergency_lockdown',
            'user_role_change'
        ];

        if (!in_array($operation, $twoFactorOperations)) {
            return true; // No 2FA required
        }

        // 2FA feature has been removed. For backward compatibility we allow the
        // operation but log that a previously-sensitive operation was executed
        // without 2FA enforcement.
        $userId = get_current_user_id();
        self::logSecurityEvent('2fa_removed', [
            'user_id' => $userId,
            'operation' => $operation,
            'message' => '2FA enforcement removed by plugin configuration'
        ]);

        return true;
    }

    /**
     * Verify 2FA token
     *
     * @return bool
     */
    private static function verify2FAToken(): bool
    {
        // 2FA has been removed. Always return true to avoid blocking operations
        return true;
    }

    /**
     * Generate 2FA challenge
     *
     * @return array Challenge data
     */
    public static function generate2FAChallenge(): array
    {
        // 2FA has been removed. Return a no-op challenge payload so callers
        // that expect an array still receive a valid structure.
        $userId = get_current_user_id();
        $user = get_userdata($userId);

        return [
            'method' => 'none',
            'destination' => $user->user_email ?? '',
            'challenge_id' => wp_generate_password(32, false)
        ];
    }

    /**
     * Generate TOTP secret
     *
     * @return string
     */
    private static function generateTOTPSecret(): string
    {
        // 2FA removed: keep function available but generate a random token
        return wp_generate_password(32, true, true);
    }

    /**
     * Log security events
     *
     * @param string $event Event type
     * @param array $data Event data
     */
    public static function logSecurityEvent(string $event, array $data = []): void
    {
        global $wpdb;

        $logData = [
            'event_type' => $event,
            'user_id' => get_current_user_id(),
            'ip_address' => self::getUserIP(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'event_data' => json_encode($data),
            'created_at' => current_time('mysql')
        ];

        $wpdb->insert(
            $wpdb->prefix . 'security_monitor_audit_log',
            $logData,
            ['%s', '%d', '%s', '%s', '%s', '%s']
        );

        // Also log to WordPress error log if debugging enabled
        if (WP_DEBUG) {
            error_log(sprintf(
                '[WP Security Monitor] %s: %s (User: %d, IP: %s)',
                $event,
                json_encode($data),
                get_current_user_id(),
                self::getUserIP()
            ));
        }
    }

    /**
     * Get audit logs
     *
     * @param array $filters Filters
     * @param int $limit Limit
     * @param int $offset Offset
     * @return array
     */
    public static function getAuditLogs(array $filters = [], int $limit = 50, int $offset = 0): array
    {
        global $wpdb;

        $where = ['1=1'];
        $values = [];

        if (!empty($filters['event_type'])) {
            $where[] = 'event_type = %s';
            $values[] = $filters['event_type'];
        }

        if (!empty($filters['user_id'])) {
            $where[] = 'user_id = %d';
            $values[] = $filters['user_id'];
        }

        if (!empty($filters['ip_address'])) {
            $where[] = 'ip_address = %s';
            $values[] = $filters['ip_address'];
        }

        if (!empty($filters['date_from'])) {
            $where[] = 'created_at >= %s';
            $values[] = $filters['date_from'];
        }

        if (!empty($filters['date_to'])) {
            $where[] = 'created_at <= %s';
            $values[] = $filters['date_to'];
        }

        $values[] = $limit;
        $values[] = $offset;

        $sql = "SELECT * FROM {$wpdb->prefix}security_monitor_audit_log
                WHERE " . implode(' AND ', $where) . "
                ORDER BY created_at DESC
                LIMIT %d OFFSET %d";

        $results = $wpdb->get_results($wpdb->prepare($sql, $values), ARRAY_A);

        // Decode event data
        foreach ($results as &$result) {
            $result['event_data'] = json_decode($result['event_data'], true);
            $result['user'] = get_userdata($result['user_id']);
        }

        return $results;
    }

    /**
     * Clean up old audit logs
     *
     * @param int $days Days to keep
     * @return int Deleted count
     */
    public static function cleanupAuditLogs(int $days = 90): int
    {
        global $wpdb;

        $cutoff = date('Y-m-d H:i:s', strtotime("-{$days} days"));

        $deleted = $wpdb->query($wpdb->prepare(
            "DELETE FROM {$wpdb->prefix}security_monitor_audit_log WHERE created_at < %s",
            $cutoff
        ));

        return $deleted ?: 0;
    }

    /**
     * Remove custom roles and capabilities
     */
    public static function cleanup(): void
    {
        $wp_roles = wp_roles();

        // Remove custom roles
        $wp_roles->remove_role(self::ROLE_SECURITY_VIEWER);
        $wp_roles->remove_role(self::ROLE_SECURITY_OPERATOR);
        $wp_roles->remove_role(self::ROLE_SECURITY_ADMIN);

        // Remove capabilities from administrator
        $caps = [
            self::CAP_VIEW_ISSUES,
            self::CAP_MANAGE_ISSUES,
            self::CAP_MANAGE_SETTINGS,
            self::CAP_MANAGE_CREDENTIALS,
            self::CAP_VIEW_SECURITY_STATUS,
            self::CAP_MANAGE_WHITELIST,
            self::CAP_EMERGENCY_ACTIONS,
            self::CAP_AUDIT_LOGS
        ];

        foreach ($caps as $cap) {
            $wp_roles->remove_cap('administrator', $cap);
        }

        delete_option('wp_security_monitor_roles_setup');
    }
}
