<?php

namespace Puleeno\SecurityBot\WebMonitor\Issuers;

use Puleeno\SecurityBot\WebMonitor\Interfaces\IssuerInterface;
use Puleeno\SecurityBot\WebMonitor\DebugHelper;
use Puleeno\SecurityBot\WebMonitor\ForensicHelper;
use Puleeno\SecurityBot\WebMonitor\Enums\IssuerType;

/**
 * AdminUserCreatedIssuer
 *
 * Monitors khi có user mới được tạo với role admin hoặc user existing được promote lên admin
 *
 * @package Puleeno\SecurityBot\WebMonitor\Issuers
 */
class AdminUserCreatedIssuer implements IssuerInterface
{
    private array $config = [];
    private array $pendingUsers = [];

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

        // Hook khi user role được update
        add_action('set_user_role', [$this, 'onUserRoleChanged'], 10, 3);
        add_action('add_user_role', [$this, 'onUserRoleAdded'], 10, 2);

        // Hook khi profile được update (backup method)
        add_action('profile_update', [$this, 'onProfileUpdated'], 10, 2);

        // Hook khi user capabilities được changed
        add_action('added_user_meta', [$this, 'onUserMetaAdded'], 10, 4);
    }

    /**
     * Implement detection method
     */
    public function detect(): array
    {
        $issues = [];

        // Kiểm tra pending users từ hooks
        foreach ($this->pendingUsers as $userData) {
            $issues[] = $this->createAdminUserIssue($userData);
        }

        // Clear pending users sau khi process
        $this->pendingUsers = [];

        return $issues;
    }

    /**
     * Handle khi user mới được register
     */
    public function onUserRegistered(int $userId): void
    {
        $user = get_userdata($userId);
        if (!$user) return;

        // Kiểm tra nếu user được tạo với admin role ngay lập tức
        if (user_can($userId, 'manage_options')) {
            $this->trackAdminUserCreation($userId, 'new_user_with_admin_role');
        }
    }

    /**
     * Handle khi user role được set
     */
    public function onUserRoleChanged(int $userId, string $role, array $oldRoles): void
    {
        // Kiểm tra nếu role mới là admin
        if ($this->isAdminRole($role)) {
            // Kiểm tra nếu user không có admin capabilities trước đó
            $hadAdminAccess = false;
            foreach ($oldRoles as $oldRole) {
                if ($this->isAdminRole($oldRole)) {
                    $hadAdminAccess = true;
                    break;
                }
            }

            if (!$hadAdminAccess) {
                $this->trackAdminUserCreation($userId, 'role_promoted_to_admin', [
                    'old_roles' => $oldRoles,
                    'new_role' => $role
                ]);
            }
        }
    }

    /**
     * Handle khi user role được add (multiple roles)
     */
    public function onUserRoleAdded(int $userId, string $role): void
    {
        if ($this->isAdminRole($role)) {
            $this->trackAdminUserCreation($userId, 'admin_role_added', [
                'added_role' => $role
            ]);
        }
    }

    /**
     * Handle khi profile được update
     */
    public function onProfileUpdated(int $userId, \WP_User $oldUser): void
    {
        $newUser = get_userdata($userId);
        if (!$newUser) return;

        // So sánh capabilities cũ và mới
        $oldCanManage = user_can($oldUser, 'manage_options');
        $newCanManage = user_can($newUser, 'manage_options');

        // Nếu user không có admin quyền trước đó nhưng giờ có
        if (!$oldCanManage && $newCanManage) {
            $this->trackAdminUserCreation($userId, 'capabilities_updated_to_admin', [
                'old_roles' => $oldUser->roles,
                'new_roles' => $newUser->roles
            ]);
        }
    }

    /**
     * Handle khi user meta được add (backup cho capabilities changes)
     */
    public function onUserMetaAdded(int $metaId, int $userId, string $metaKey, $metaValue): void
    {
        // Kiểm tra nếu meta key là capabilities
        if (strpos($metaKey, 'capabilities') !== false && user_can($userId, 'manage_options')) {
            $this->trackAdminUserCreation($userId, 'admin_capabilities_added', [
                'meta_key' => $metaKey,
                'meta_value' => $metaValue
            ]);
        }
    }

    /**
     * Track admin user creation
     */
    private function trackAdminUserCreation(int $userId, string $method, array $context = []): void
    {
        $user = get_userdata($userId);
        if (!$user) return;

        // Lấy thông tin về user hiện tại (người thực hiện action)
        $currentUser = wp_get_current_user();
        $requestInfo = $this->getRequestInfo();

        $userData = [
            'user_id' => $userId,
            'username' => $user->user_login,
            'user_email' => $user->user_email,
            'display_name' => $user->display_name,
            'roles' => $user->roles,
            'method' => $method,
            'context' => $context,
            'created_by' => [
                'id' => $currentUser->ID,
                'login' => $currentUser->user_login,
                'ip' => $requestInfo['ip'],
                'user_agent' => $requestInfo['user_agent']
            ],
            'request_info' => $requestInfo,
            'timestamp' => current_time('mysql')
        ];

        // Thêm vào pending users để process trong detect()
        $this->pendingUsers[] = $userData;
    }

    /**
     * Tạo issue cho admin user creation
     */
    private function createAdminUserIssue(array $userData): array
    {
        $severity = $this->determineSeverity($userData);
        $title = $this->generateTitle($userData);
        $description = $this->generateDescription($userData);

        return [
            'message' => $title,
            'details' => $description,
            'type' => 'admin_user_created',
            'severity' => $severity,
            'user_id' => $userData['user_id'],
            'username' => $userData['username'],
            'method' => $userData['method'],
            'ip_address' => $userData['request_info']['ip'],
            'user_agent' => $userData['request_info']['user_agent'],
            'created_by_user_id' => $userData['created_by']['id'],
            'debug_info' => DebugHelper::createIssueDebugInfo($this->getName(), [
                'admin_user_data' => $userData,
                'detection_method' => $userData['method']
            ])
        ];
    }

    /**
     * Xác định severity dựa vào context
     */
    private function determineSeverity(array $userData): string
    {
        $method = $userData['method'];
        $requestInfo = $userData['request_info'];

        // Critical: Admin user được tạo từ bên ngoài office hours
        if (!$this->isOfficeHours()) {
            return 'critical';
        }

        // High: User được tạo bằng programmatic method
        if ($method === 'admin_capabilities_added' || $requestInfo['is_ajax']) {
            return 'high';
        }

        // High: User được tạo từ external IP
        if (!$this->isInternalIP($requestInfo['ip'])) {
            return 'high';
        }

        // Medium: Normal admin user creation
        return 'medium';
    }

    /**
     * Generate title cho issue
     */
    private function generateTitle(array $userData): string
    {
        $method = $userData['method'];
        $username = $userData['username'];

        $titles = [
            'new_user_with_admin_role' => "New user '{$username}' created with admin role",
            'role_promoted_to_admin' => "User '{$username}' promoted to admin role",
            'admin_role_added' => "Admin role added to user '{$username}'",
            'capabilities_updated_to_admin' => "User '{$username}' granted admin capabilities",
            'admin_capabilities_added' => "Admin capabilities programmatically added to '{$username}'"
        ];

        return $titles[$method] ?? "Admin user activity detected for '{$username}'";
    }

    /**
     * Generate description cho issue
     */
    private function generateDescription(array $userData): string
    {
        $lines = [];
        $lines[] = "**Admin User Activity Detected**";
        $lines[] = "";
        $lines[] = "**User Information:**";
        $lines[] = "- Username: {$userData['username']}";
        $lines[] = "- Email: {$userData['user_email']}";
        $lines[] = "- Display Name: {$userData['display_name']}";
        $lines[] = "- User ID: {$userData['user_id']}";
        $lines[] = "- Roles: " . implode(', ', $userData['roles']);
        $lines[] = "";
        $lines[] = "**Activity Details:**";
        $lines[] = "- Method: {$userData['method']}";
        $lines[] = "- Timestamp: {$userData['timestamp']}";

        if (!empty($userData['context'])) {
            $lines[] = "- Context: " . json_encode($userData['context'], JSON_PRETTY_PRINT);
        }

        $lines[] = "";
        $lines[] = "**Created By:**";
        $lines[] = "- User ID: {$userData['created_by']['id']}";
        $lines[] = "- Login: {$userData['created_by']['login']}";
        $lines[] = "- IP Address: {$userData['created_by']['ip']}";
        $lines[] = "- User Agent: {$userData['created_by']['user_agent']}";

        $requestInfo = $userData['request_info'];
        $lines[] = "";
        $lines[] = "**Request Information:**";
        $lines[] = "- Request URI: {$requestInfo['request_uri']}";
        $lines[] = "- Request Method: {$requestInfo['request_method']}";
        $lines[] = "- Is AJAX: " . ($requestInfo['is_ajax'] ? 'Yes' : 'No');
        $lines[] = "- Is Admin: " . ($requestInfo['is_admin'] ? 'Yes' : 'No');

        return implode("\n", $lines);
    }

    /**
     * Kiểm tra nếu role là admin role
     */
    private function isAdminRole(string $role): bool
    {
        $adminRoles = ['administrator', 'super_admin'];
        return in_array($role, $adminRoles) || $this->roleHasAdminCapabilities($role);
    }

    /**
     * Kiểm tra nếu role có admin capabilities
     */
    private function roleHasAdminCapabilities(string $role): bool
    {
        $roleObj = get_role($role);
        return $roleObj && $roleObj->has_cap('manage_options');
    }

    /**
     * Lấy request information
     */
    private function getRequestInfo(): array
    {
        return [
            'ip' => $this->getUserIP(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
            'request_uri' => $_SERVER['REQUEST_URI'] ?? '/',
            'request_method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
            'is_ajax' => wp_doing_ajax(),
            'is_admin' => is_admin(),
            'referer' => wp_get_referer() ?: 'Direct'
        ];
    }

    /**
     * Lấy IP address của user
     */
    private function getUserIP(): string
    {
        $ipKeys = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR'];

        foreach ($ipKeys as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = trim($_SERVER[$key]);
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }

        return $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
    }

    /**
     * Kiểm tra nếu đang trong office hours
     */
    private function isOfficeHours(): bool
    {
        $config = $this->getConfig('office_hours', [9, 18]);
        $currentHour = (int) current_time('H');

        return $currentHour >= $config[0] && $currentHour <= $config[1];
    }

    /**
     * Kiểm tra nếu IP là internal
     */
    private function isInternalIP(string $ip): bool
    {
        // Kiểm tra private IP ranges
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    }

    /**
     * Get configuration value
     */
    private function getConfig(string $key, $default = null)
    {
        return $this->config[$key] ?? $default;
    }

    /**
     * Get issuer name
     */
    public function getName(): string
    {
        return 'Admin User Monitor';
    }

    /**
     * Get priority
     */
    public function getPriority(): int
    {
        return 20; // High priority vì admin user creation rất quan trọng
    }

    /**
     * Check if enabled
     */
    public function isEnabled(): bool
    {
        return $this->getConfig('enabled', true);
    }

    /**
     * Configure issuer
     */
    public function configure(array $config): void
    {
        $this->config = array_merge($this->config, $config);
    }
}
