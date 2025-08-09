<?php
namespace Puleeno\SecurityBot\WebMonitor\Issuers;

use Puleeno\SecurityBot\WebMonitor\Interfaces\IssuerInterface;
use Puleeno\SecurityBot\WebMonitor\DebugHelper;

class LoginAttemptIssuer implements IssuerInterface
{
    /**
     * @var array
     */
    private $config = [];

    /**
     * @var bool
     */
    private $enabled = true;

    /**
     * @var string
     */
    private $optionKey = 'wp_security_monitor_failed_logins';

    public function __construct()
    {
        // Hook vào WordPress login events
        add_action('wp_login_failed', [$this, 'recordFailedLogin']);
        add_action('wp_login', [$this, 'recordSuccessfulLogin'], 10, 2);
    }

    public function getName(): string
    {
        return 'Login Attempt Monitor';
    }

    public function getPriority(): int
    {
        return 8; // Mức độ ưu tiên cao
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function configure(array $config): void
    {
        $this->config = array_merge($this->config, $config);

        if (isset($config['enabled'])) {
            $this->enabled = (bool) $config['enabled'];
        }
    }

    public function detect(): array
    {
        $issues = [];

        try {
            // Kiểm tra failed login attempts
            $failedLoginIssues = $this->checkFailedLogins();
            if (!empty($failedLoginIssues)) {
                $issues = array_merge($issues, $failedLoginIssues);
            }

            // Kiểm tra brute force attacks
            $bruteForceIssues = $this->checkBruteForceAttacks();
            if (!empty($bruteForceIssues)) {
                $issues = array_merge($issues, $bruteForceIssues);
            }

            // Kiểm tra suspicious login patterns
            $suspiciousIssues = $this->checkSuspiciousLoginPatterns();
            if (!empty($suspiciousIssues)) {
                $issues = array_merge($issues, $suspiciousIssues);
            }

        } catch (\Exception $e) {
            $issues[] = [
                'message' => 'Lỗi khi kiểm tra login attempts',
                'details' => $e->getMessage()
            ];
        }

        return $issues;
    }

    /**
     * Ghi lại failed login
     *
     * @param string $username
     * @return void
     */
    public function recordFailedLogin(string $username): void
    {
        $ip = $this->getUserIP();
        $attempts = get_option($this->optionKey, []);

        $key = md5($ip . $username);
        $now = time();

        if (!isset($attempts[$key])) {
            $attempts[$key] = [
                'username' => $username,
                'ip' => $ip,
                'attempts' => [],
                'total_attempts' => 0
            ];
        }

        $attempts[$key]['attempts'][] = $now;
        $attempts[$key]['total_attempts']++;
        $attempts[$key]['last_attempt'] = $now;

        // Cleanup old attempts (older than 24 hours)
        $attempts[$key]['attempts'] = array_filter(
            $attempts[$key]['attempts'],
            function($timestamp) {
                return $timestamp > (time() - 86400);
            }
        );

        // Cleanup old records
        $attempts = array_filter($attempts, function($record) {
            return isset($record['last_attempt']) && $record['last_attempt'] > (time() - 86400);
        });

        update_option($this->optionKey, $attempts);
    }

    /**
     * Ghi lại successful login
     *
     * @param string $user_login
     * @param \WP_User $user
     * @return void
     */
    public function recordSuccessfulLogin(string $user_login, $user): void
    {
        $ip = $this->getUserIP();

        // Clear failed attempts for this IP/username combination
        $attempts = get_option($this->optionKey, []);
        $key = md5($ip . $user_login);

        if (isset($attempts[$key])) {
            unset($attempts[$key]);
            update_option($this->optionKey, $attempts);
        }

        // Record successful login for admin users
        if (in_array('administrator', $user->roles)) {
            $successfulLogins = get_option('wp_security_monitor_admin_logins', []);
            $successfulLogins[] = [
                'user_id' => $user->ID,
                'username' => $user_login,
                'ip' => $ip,
                'timestamp' => time(),
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? ''
            ];

            // Keep only last 50 admin logins
            $successfulLogins = array_slice($successfulLogins, -50);
            update_option('wp_security_monitor_admin_logins', $successfulLogins);
        }
    }

    /**
     * Kiểm tra failed logins
     *
     * @return array
     */
    private function checkFailedLogins(): array
    {
        $issues = [];
        $attempts = get_option($this->optionKey, []);
        $threshold = $this->getConfig('failed_login_threshold', 5);
        $timeWindow = $this->getConfig('failed_login_time_window', 900); // 15 minutes

        foreach ($attempts as $record) {
            $recentAttempts = array_filter(
                $record['attempts'],
                function($timestamp) use ($timeWindow) {
                    return $timestamp > (time() - $timeWindow);
                }
            );

            if (count($recentAttempts) >= $threshold) {
                $debugContext = [
                    'ip_address' => $record['ip'],
                    'username' => $record['username'],
                    'attempt_count' => count($recentAttempts),
                    'time_window_minutes' => $timeWindow / 60,
                    'total_attempts' => $record['total_attempts'],
                    'source' => 'failed_login_attempts'
                ];

                $issues[] = [
                    'message' => 'Phát hiện nhiều lần đăng nhập thất bại',
                    'details' => sprintf(
                        'IP %s đã thử đăng nhập thất bại %d lần với username "%s" trong %d phút qua',
                        $record['ip'],
                        count($recentAttempts),
                        $record['username'],
                        $timeWindow / 60
                    ),
                    'type' => 'failed_login_attempts',
                    'ip_address' => $record['ip'],
                    'username' => $record['username'],
                    'attempt_count' => count($recentAttempts),
                    'debug_info' => DebugHelper::createIssueDebugInfo($this->getName(), $debugContext)
                ];
            }
        }

        return $issues;
    }

    /**
     * Kiểm tra brute force attacks
     *
     * @return array
     */
    private function checkBruteForceAttacks(): array
    {
        $issues = [];
        $attempts = get_option($this->optionKey, []);
        $threshold = $this->getConfig('brute_force_threshold', 20);

        // Group by IP
        $ipAttempts = [];
        foreach ($attempts as $record) {
            $ip = $record['ip'];
            if (!isset($ipAttempts[$ip])) {
                $ipAttempts[$ip] = [
                    'total_attempts' => 0,
                    'usernames' => [],
                    'last_attempt' => 0
                ];
            }

            $ipAttempts[$ip]['total_attempts'] += $record['total_attempts'];
            $ipAttempts[$ip]['usernames'][] = $record['username'];
            $ipAttempts[$ip]['last_attempt'] = max($ipAttempts[$ip]['last_attempt'], $record['last_attempt']);
        }

        foreach ($ipAttempts as $ip => $data) {
            if ($data['total_attempts'] >= $threshold) {
                $debugContext = [
                    'ip_address' => $ip,
                    'total_attempts' => $data['total_attempts'],
                    'unique_usernames' => count(array_unique($data['usernames'])),
                    'usernames_tried' => array_unique($data['usernames']),
                    'last_attempt' => date('Y-m-d H:i:s', $data['last_attempt']),
                    'source' => 'brute_force_detection'
                ];

                $issues[] = [
                    'message' => 'Phát hiện cuộc tấn công brute force',
                    'details' => sprintf(
                        'IP %s đã thực hiện %d lần đăng nhập thất bại với %d username khác nhau',
                        $ip,
                        $data['total_attempts'],
                        count(array_unique($data['usernames']))
                    ),
                    'type' => 'brute_force_attack',
                    'ip_address' => $ip,
                    'total_attempts' => $data['total_attempts'],
                    'unique_usernames' => count(array_unique($data['usernames'])),
                    'debug_info' => DebugHelper::createIssueDebugInfo($this->getName(), $debugContext)
                ];
            }
        }

        return $issues;
    }

    /**
     * Kiểm tra suspicious login patterns
     *
     * @return array
     */
    private function checkSuspiciousLoginPatterns(): array
    {
        $issues = [];
        $adminLogins = get_option('wp_security_monitor_admin_logins', []);

        if (empty($adminLogins)) {
            return $issues;
        }

        // Kiểm tra đăng nhập admin từ IP lạ
        $recentLogins = array_filter($adminLogins, function($login) {
            return $login['timestamp'] > (time() - 3600); // Last hour
        });

        if (!empty($recentLogins)) {
            $ips = array_unique(array_column($recentLogins, 'ip'));

            if (count($ips) > 1) {
                $debugContext = [
                    'unique_ips' => $ips,
                    'ip_count' => count($ips),
                    'time_window' => '1 hour',
                    'login_attempts' => count($recentLogins),
                    'source' => 'multiple_ip_admin_login'
                ];

                $issues[] = [
                    'message' => 'Phát hiện đăng nhập admin từ nhiều IP khác nhau',
                    'details' => sprintf(
                        'Trong 1 giờ qua có %d IP khác nhau đăng nhập admin: %s',
                        count($ips),
                        implode(', ', $ips)
                    ),
                    'type' => 'suspicious_admin_login',
                    'ip_addresses' => $ips,
                    'ip_count' => count($ips),
                    'debug_info' => DebugHelper::createIssueDebugInfo($this->getName(), $debugContext)
                ];
            }
        }

        // Kiểm tra đăng nhập vào giờ bất thường
        $currentHour = (int) date('H');
        $officeHours = $this->getConfig('office_hours', [9, 18]); // 9 AM to 6 PM

        if ($currentHour < $officeHours[0] || $currentHour > $officeHours[1]) {
            $recentNightLogins = array_filter($adminLogins, function($login) use ($officeHours) {
                $loginHour = (int) date('H', $login['timestamp']);
                return $login['timestamp'] > (time() - 3600) &&
                       ($loginHour < $officeHours[0] || $loginHour > $officeHours[1]);
            });

            if (!empty($recentNightLogins)) {
                $debugContext = [
                    'current_hour' => $currentHour,
                    'office_hours' => $officeHours,
                    'night_logins_count' => count($recentNightLogins),
                    'login_details' => array_map(function($login) {
                        return [
                            'user' => $login['username'],
                            'ip' => $login['ip'],
                            'time' => date('H:i:s', $login['timestamp'])
                        ];
                    }, $recentNightLogins),
                    'source' => 'off_hours_login'
                ];

                $issues[] = [
                    'message' => 'Phát hiện đăng nhập admin ngoài giờ làm việc',
                    'details' => sprintf(
                        'Có %d lần đăng nhập admin trong giờ %d:00',
                        count($recentNightLogins),
                        $currentHour
                    ),
                    'type' => 'off_hours_login',
                    'current_hour' => $currentHour,
                    'login_count' => count($recentNightLogins),
                    'debug_info' => DebugHelper::createIssueDebugInfo($this->getName(), $debugContext)
                ];
            }
        }

        return $issues;
    }

    /**
     * Lấy IP của user
     *
     * @return string
     */
    private function getUserIP(): string
    {
        $ipKeys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_FORWARDED', 'REMOTE_ADDR'];

        foreach ($ipKeys as $key) {
            if (!empty($_SERVER[$key])) {
                $ips = explode(',', $_SERVER[$key]);
                return trim($ips[0]);
            }
        }

        return '127.0.0.1';
    }

    /**
     * Lấy giá trị config
     *
     * @param string $key
     * @param mixed $default
     * @return mixed
     */
    private function getConfig(string $key, $default = null)
    {
        return $this->config[$key] ?? $default;
    }
}
