<?php

namespace Puleeno\SecurityBot\WebMonitor\Issuers;

use Puleeno\SecurityBot\WebMonitor\Interfaces\IssuerInterface;
use Puleeno\SecurityBot\WebMonitor\DebugHelper;
use Puleeno\SecurityBot\WebMonitor\ForensicHelper;
use Puleeno\SecurityBot\WebMonitor\Enums\IssuerType;

/**
 * RealtimeUserRegistrationIssuer
 *
 * Phát hiện realtime khi có user mới được tạo thông qua action hook user_register
 *
 * @package Puleeno\SecurityBot\WebMonitor\Issuers
 */
class RealtimeUserRegistrationIssuer implements IssuerInterface
{
    private array $config = [];

    public function __construct()
    {
        $this->initializeHooks();
    }

    /**
     * Khởi tạo WordPress hooks
     */
    private function initializeHooks(): void
    {
        // Hook khi user mới được tạo
        add_action('user_register', [$this, 'onUserRegistered'], 10, 1);

        if (WP_DEBUG) {
            error_log('[RealtimeUserRegistrationIssuer] Hooks initialized - user_register action registered');
        }
    }

    /**
     * Implement detection method (không sử dụng cho realtime)
     */
    public function detect(): array
    {
        // Không sử dụng method này vì đây là realtime issuer
        return [];
    }

    /**
     * Handle khi user mới được register
     */
    public function onUserRegistered(int $userId): void
    {
        if (WP_DEBUG) {
            error_log("[RealtimeUserRegistrationIssuer] User registered: ID {$userId}");
        }

        $user = get_userdata($userId);
        if (!$user) {
            if (WP_DEBUG) {
                error_log("[RealtimeUserRegistrationIssuer] Failed to get user data for ID: {$userId}");
            }
            return;
        }

        // Chỉ trigger notification cho user có quyền quản lý trở lên
        if ($this->hasManagementRole($user)) {
            if (WP_DEBUG) {
                error_log("[RealtimeUserRegistrationIssuer] High-privilege user registered: {$user->user_login} with roles: " . implode(', ', $user->roles));
            }
            $this->createUserRegistrationIssue($user);
        } else {
            if (WP_DEBUG) {
                error_log("[RealtimeUserRegistrationIssuer] Low-privilege user registered: {$user->user_login} with roles: " . implode(', ', $user->roles) . " - skipping notification");
            }
        }
    }

    /**
     * Tạo security issue cho user registration
     */
    private function createUserRegistrationIssue(\WP_User $user): void
    {
        $userData = [
            'user_id' => $user->ID,
            'username' => $user->user_login,
            'email' => $user->user_email,
            'display_name' => $user->display_name,
            'roles' => $user->roles,
            'registration_date' => $user->user_registered,
            'timestamp' => current_time('mysql'),
            'ip_address' => $this->getUserIP(),
            'user_agent' => $this->getUserAgent(),
            'referer' => $this->getReferer(),
            'backtrace' => $this->getBacktrace()
        ];

        if (WP_DEBUG) {
            error_log("[RealtimeUserRegistrationIssuer] Creating issue for user: {$user->user_login}");
        }

        // Trigger action để Bot có thể xử lý
        do_action('wp_security_monitor_user_registered', $userData);
    }

    /**
     * Lấy IP address của user
     */
    private function getUserIP(): string
    {
        $ipKeys = ['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR'];

        foreach ($ipKeys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                        return $ip;
                    }
                }
            }
        }

        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }

    /**
     * Lấy User Agent
     */
    private function getUserAgent(): string
    {
        return $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    }

    /**
     * Lấy Referer
     */
    private function getReferer(): string
    {
        return $_SERVER['HTTP_REFERER'] ?? 'unknown';
    }

    /**
     * Lấy backtrace để forensic analysis
     */
    private function getBacktrace(): array
    {
        $backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 10);
        $filteredBacktrace = [];

        foreach ($backtrace as $frame) {
            // Bỏ qua frames từ RealtimeUserRegistrationIssuer
            if (isset($frame['class']) && strpos($frame['class'], 'RealtimeUserRegistrationIssuer') !== false) {
                continue;
            }

            $filteredBacktrace[] = [
                'file' => $frame['file'] ?? 'unknown',
                'line' => $frame['line'] ?? 0,
                'function' => $frame['function'] ?? 'unknown',
                'class' => $frame['class'] ?? null,
                'type' => $frame['type'] ?? 'unknown'
            ];
        }

        return $filteredBacktrace;
    }

    /**
     * Kiểm tra xem user có quyền quản lý trở lên không
     */
    private function hasManagementRole(\WP_User $user): bool
    {
        $managementRoles = ['administrator', 'editor', 'author'];

        foreach ($user->roles as $role) {
            if (in_array($role, $managementRoles)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get issuer name
     */
    public function getName(): string
    {
        return 'RealtimeUserRegistrationIssuer';
    }

    /**
     * Get issuer priority
     */
    public function getPriority(): int
    {
        return 100; // High priority for realtime detection
    }

    /**
     * Check if issuer is enabled
     */
    public function isEnabled(): bool
    {
        return true; // Always enabled for realtime detection
    }

    /**
     * Configure issuer
     */
    public function configure(array $config): void
    {
        $this->config = array_merge($this->config, $config);
    }
}
