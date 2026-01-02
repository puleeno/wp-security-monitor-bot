<?php
namespace Puleeno\SecurityBot\WebMonitor\Issuers;

use Puleeno\SecurityBot\WebMonitor\Interfaces\IssuerInterface;
use Puleeno\SecurityBot\WebMonitor\Interfaces\RealtimeIssuerInterface;
use Puleeno\SecurityBot\WebMonitor\WhitelistManager;
use Puleeno\SecurityBot\WebMonitor\DebugHelper;
use Puleeno\SecurityBot\WebMonitor\ForensicHelper;
use Puleeno\SecurityBot\WebMonitor\Enums\IssuerType;

class RealtimeRedirectIssuer implements RealtimeIssuerInterface
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
    private $optionKey = 'wp_security_monitor_realtime_redirects';

    /**
     * @var array
     */
    private $redirectLog = [];

    public function __construct()
    {
        // Hook vào wp_redirect filter để detect realtime redirects
        add_filter('wp_redirect', [$this, 'interceptRedirect'], 10, 2);

        // Hook vào wp_die để catch redirects that might not use wp_redirect
        add_action('wp_die_handler', [$this, 'interceptWpDie'], 10, 2);

        // Hook vào shutdown để log redirects
        add_action('shutdown', [$this, 'logRedirects']);
    }

    public function getName(): string
    {
        return 'Realtime Redirect Monitor';
    }

    public function getPriority(): int
    {
        return 9; // Mức độ ưu tiên cao
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
        if (!$this->isEnabled()) {
            return [];
        }

        $issues = [];

        // Kiểm tra redirects từ log
        $redirectLog = get_option($this->optionKey, []);

        if (!empty($redirectLog)) {
            foreach ($redirectLog as $redirect) {
                if ($this->isSuspiciousRedirect($redirect)) {
                    $issues[] = [
                        'type' => 'suspicious_redirect',
                        'severity' => 'medium',
                        'message' => 'Suspicious redirect detected',
                        'details' => [
                            'from_url' => $redirect['from_url'] ?? 'unknown',
                            'to_url' => $redirect['to_url'],
                            'user_agent' => $redirect['user_agent'] ?? 'unknown',
                            'ip_address' => $redirect['ip_address'] ?? 'unknown',
                            'user_id' => $redirect['user_id'] ?? 0,
                            'timestamp' => $redirect['timestamp'],
                            'referer' => $redirect['referer'] ?? 'unknown',
                            'method' => $redirect['method'] ?? 'unknown',
                            'backtrace' => $redirect['backtrace'] ?? 'unknown',
                        ],
                        'timestamp' => $redirect['timestamp'],
                    ];
                }
            }
        }

        return $issues;
    }

    /**
     * Intercept wp_redirect calls
     */
    public function interceptRedirect($location, $status)
    {
        if (!$this->isEnabled()) {
            return $location;
        }

        // Log redirect
        $this->logRedirect($location, 'wp_redirect', $status);

        // Check if suspicious
        if ($this->isSuspiciousRedirectUrl($location)) {
            $this->recordSuspiciousRedirect($location, 'wp_redirect', $status);
        }

        return $location;
    }

    /**
     * Intercept wp_die calls
     *
     * @param mixed $handler The wp_die handler
     * @param string|null $title Optional title (not always passed by WordPress)
     * @return mixed
     */
    public function interceptWpDie($handler, $title = null)
    {
        if (!$this->isEnabled()) {
            return $handler;
        }

        // Log wp_die
        $titleText = $title ? $title : 'unknown';
        $this->logRedirect('wp_die: ' . $titleText, 'wp_die', 0);

        return $handler;
    }

    /**
     * Log redirect information
     */
    private function logRedirect($location, $method, $status)
    {
        $redirect = [
            'to_url' => $location,
            'method' => $method,
            'status' => $status,
            'timestamp' => current_time('mysql'),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'ip_address' => $this->getClientIP(),
            'user_id' => get_current_user_id(),
            'referer' => $_SERVER['HTTP_REFERER'] ?? 'unknown',
            'from_url' => $_SERVER['REQUEST_URI'] ?? 'unknown'
        ];

        $this->redirectLog[] = $redirect;

        // Lưu vào WordPress option
        $existingLog = get_option($this->optionKey, []);
        $existingLog[] = $redirect;

        // Giữ chỉ 100 redirects gần nhất
        if (count($existingLog) > 100) {
            $existingLog = array_slice($existingLog, -100);
        }

        update_option($this->optionKey, $existingLog);
    }

    /**
     * Log redirects on shutdown
     */
    public function logRedirects()
    {
        // Không cần trigger action ở đây nữa vì đã trigger trong recordSuspiciousRedirect()
        // Chỉ log redirects thông thường, không phải suspicious redirects
        if (!empty($this->redirectLog)) {
            // Log redirects thông thường nếu cần
            if (WP_DEBUG) {
                error_log('[RealtimeRedirectIssuer] Logged ' . count($this->redirectLog) . ' redirects on shutdown');
            }
        }
    }

    /**
     * Check if URL is suspicious
     */
    private function isSuspiciousRedirectUrl($url): bool
    {
        if (empty($url)) {
            return false;
        }

        // Check external URLs
        if ($this->isExternalUrl($url)) {
            return true;
        }

        // Check JavaScript redirects
        if (strpos($url, 'javascript:') === 0) {
            return true;
        }

        // Check data URLs
        if (strpos($url, 'data:') === 0) {
            return true;
        }

        // Check suspicious patterns
        $suspiciousPatterns = [
            'eval(',
            'base64_decode(',
            'gzinflate(',
            'str_rot13(',
            'file_get_contents(',
            'include(',
            'require(',
            'system(',
            'exec(',
            'shell_exec('
        ];

        foreach ($suspiciousPatterns as $pattern) {
            if (stripos($url, $pattern) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if redirect is suspicious
     */
    private function isSuspiciousRedirect($redirect): bool
    {
        if (!isset($redirect['to_url'])) {
            return false;
        }

        $url = $redirect['to_url'];

        // Check external URLs
        if ($this->isExternalUrl($url)) {
            return true;
        }

        // Check suspicious query parameters
        if (isset($redirect['from_url']) && $this->hasSuspiciousQueryParams($redirect['from_url'])) {
            return true;
        }

        // Check suspicious patterns in URL
        return $this->isSuspiciousRedirectUrl($url);
    }

    /**
     * Check if URL is external
     */
    private function isExternalUrl($url): bool
    {
        if (empty($url)) {
            return false;
        }

        $siteUrl = get_site_url();
        $siteHost = parse_url($siteUrl, PHP_URL_HOST);
        $urlHost = parse_url($url, PHP_URL_HOST);

        if ($urlHost && $urlHost !== $siteHost) {
            // Check whitelist trong database table
            global $wpdb;
            $table = $wpdb->prefix . 'security_monitor_redirect_domains';

            $approved = $wpdb->get_var($wpdb->prepare(
                "SELECT COUNT(*) FROM $table WHERE domain = %s AND status = 'approved'",
                $urlHost
            ));

            if ($approved > 0) {
                return false; // Domain đã approved (trong whitelist)
            }

            return true; // External URL chưa approved
        }

        return false; // Internal URL
    }

    /**
     * Check for suspicious query parameters
     */
    private function hasSuspiciousQueryParams($url): bool
    {
        $queryString = parse_url($url, PHP_URL_QUERY);
        if (!$queryString) {
            return false;
        }

        $suspiciousParams = [
            'redirect',
            'url',
            'goto',
            'link',
            'target',
            'destination',
            'next',
            'continue'
        ];

        parse_str($queryString, $params);
        foreach ($suspiciousParams as $param) {
            if (isset($params[$param]) && !empty($params[$param])) {
                $value = $params[$param];
                if ($this->isSuspiciousRedirectUrl($value)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Record suspicious redirect
     */
    private function recordSuspiciousRedirect($location, $method, $status)
    {
        $redirect = [
            'to_url' => $location,
            'method' => $method,
            'status' => $status,
            'timestamp' => current_time('mysql'),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
            'ip_address' => $this->getClientIP(),
            'user_id' => get_current_user_id(),
            'referer' => $_SERVER['HTTP_REFERER'] ?? 'unknown',
            'from_url' => $_SERVER['REQUEST_URI'] ?? 'unknown'
        ];

        // Thêm backtrace để debug
        ob_start();
        debug_print_backtrace();
        $redirect['backtrace'] = ob_get_clean();

        // Track domain vào database
        $domainStatus = $this->trackDomainToDatabase($location, $redirect);

        // Chỉ trigger action khi:
        // 1. Domain chưa được approve (không trong whitelist)
        // 2. Chưa có issue với cùng domain + backtrace
        if ($domainStatus['status'] !== 'approved' && $this->shouldCreateIssue($location, $redirect['backtrace'])) {
            do_action('wp_security_monitor_suspicious_redirect', [
                'details' => $redirect,
                'message' => 'Suspicious redirect detected in realtime'
            ]);
        }
    }

    /**
     * Track domain to database table
     *
     * @return array Domain info with status
     */
    private function trackDomainToDatabase($url, $context): array
    {
        global $wpdb;

        // Extract domain from URL
        $parsedUrl = parse_url($url);
        if (!isset($parsedUrl['host'])) {
            return ['status' => 'unknown', 'is_new' => false];
        }

        $domain = $parsedUrl['host'];
        $table = $wpdb->prefix . 'security_monitor_redirect_domains';

        // Check if domain already exists
        $existing = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM $table WHERE domain = %s",
            $domain
        ));

        $contextData = [
            'source' => 'realtime_redirect',
            'redirect_url' => $url,
            'from_url' => $context['from_url'] ?? '',
            'user_agent' => $context['user_agent'] ?? '',
            'ip_address' => $context['ip_address'] ?? '',
            'timestamp' => $context['timestamp'] ?? current_time('mysql')
        ];

        if ($existing) {
            // Domain đã tồn tại - chỉ update detection count
            $existingContexts = json_decode($existing->contexts, true) ?: [];
            $existingContexts[] = $contextData;

            // Keep only last 50 contexts
            if (count($existingContexts) > 50) {
                $existingContexts = array_slice($existingContexts, -50);
            }

            $wpdb->update(
                $table,
                [
                    'detection_count' => $existing->detection_count + 1,
                    'contexts' => json_encode($existingContexts),
                    'last_used' => current_time('mysql'),
                    'usage_count' => $existing->usage_count + 1
                ],
                ['domain' => $domain],
                ['%d', '%s', '%s', '%d'],
                ['%s']
            );

            return [
                'status' => $existing->status,
                'is_new' => false,
                'domain' => $domain
            ];
        } else {
            // Domain mới - insert vào database
            $wpdb->insert(
                $table,
                [
                    'domain' => $domain,
                    'first_detected' => current_time('mysql'),
                    'detection_count' => 1,
                    'status' => 'pending',
                    'contexts' => json_encode([$contextData]),
                    'usage_count' => 1,
                    'last_used' => current_time('mysql')
                ],
                ['%s', '%s', '%d', '%s', '%s', '%d', '%s']
            );

            return [
                'status' => 'pending',
                'is_new' => true,
                'domain' => $domain
            ];
        }
    }

    /**
     * Check if should create issue based on domain + backtrace
     *
     * Logic:
     * - Nếu chưa có issue với cùng domain + line code → TẠO issue mới
     * - Nếu đã có issue:
     *   + Chưa xử lý (status='new' và viewed=0) → KHÔNG tạo (tránh spam)
     *   + Đã xử lý (viewed=1 hoặc resolved/ignored) → TẠO issue mới (báo lại)
     *
     * @param string $url Redirect URL
     * @param string $backtrace Backtrace string
     * @return bool True if should create issue, false if duplicate
     */
    private function shouldCreateIssue($url, $backtrace): bool
    {
        global $wpdb;

        // Extract domain from URL
        $parsedUrl = parse_url($url);
        if (!isset($parsedUrl['host'])) {
            return false;
        }

        $domain = $parsedUrl['host'];

        // Extract relevant line from backtrace (first meaningful line)
        $backtraceHash = $this->getBacktraceHash($backtrace);

        if (empty($backtraceHash)) {
            return true; // Không có backtrace hash → tạo issue
        }

        // Check if issue already exists with same domain and similar backtrace
        $issuesTable = $wpdb->prefix . 'security_monitor_issues';

        // Search for existing issue with same domain + backtrace
        $existingIssue = $wpdb->get_row($wpdb->prepare(
            "SELECT id, status, viewed, viewed_at, resolved_at, ignored_at, backtrace
             FROM $issuesTable
             WHERE issuer_name = %s
             AND metadata LIKE %s
             AND backtrace LIKE %s
             ORDER BY created_at DESC
             LIMIT 1",
            'Realtime Redirect Monitor',
            '%' . $wpdb->esc_like($domain) . '%',
            '%' . $wpdb->esc_like($backtraceHash) . '%'
        ));

        // Debug logging
        if (WP_DEBUG) {
            error_log('[Redirect Anti-Spam] Domain: ' . $domain);
            error_log('[Redirect Anti-Spam] Backtrace Hash: ' . $backtraceHash);
            error_log('[Redirect Anti-Spam] Existing Issue: ' . ($existingIssue ? $existingIssue->id : 'NONE'));
            if ($existingIssue) {
                error_log('[Redirect Anti-Spam] Issue Status: ' . $existingIssue->status . ', Viewed: ' . $existingIssue->viewed);
            }
        }

        // Nếu không có issue nào → tạo mới
        if ($existingIssue === null) {
            if (WP_DEBUG) {
                error_log('[Redirect Anti-Spam] Decision: CREATE (no existing issue)');
            }
            return true;
        }

        // Nếu có issue rồi → kiểm tra đã xử lý chưa
        $isProcessed = (
            $existingIssue->viewed == 1 || // Đã xem
            $existingIssue->status === 'resolved' || // Đã resolve
            $existingIssue->status === 'ignored' || // Đã ignore
            !empty($existingIssue->viewed_at) ||
            !empty($existingIssue->resolved_at) ||
            !empty($existingIssue->ignored_at)
        );

        if (WP_DEBUG) {
            error_log('[Redirect Anti-Spam] Is Processed: ' . ($isProcessed ? 'YES' : 'NO'));
            error_log('[Redirect Anti-Spam] Decision: ' . ($isProcessed ? 'CREATE (re-notify)' : 'SKIP (duplicate)'));
        }

        // Nếu đã xử lý → tạo issue mới để báo lại
        // Nếu chưa xử lý → không tạo (tránh spam)
        return $isProcessed;
    }

    /**
     * Get hash/signature from backtrace to identify unique code location
     *
     * @param string $backtrace Full backtrace
     * @return string Backtrace signature
     */
    private function getBacktraceHash($backtrace): string
    {
        // Extract first meaningful line (ignore internal redirect calls)
        $lines = explode("\n", $backtrace);

        foreach ($lines as $line) {
            // Skip internal security monitor and WordPress core redirects
            if (stripos($line, 'RealtimeRedirectIssuer') !== false) continue;
            if (stripos($line, 'wp_redirect') !== false) continue;
            if (stripos($line, 'wp-includes') !== false) continue;

            // Find theme or plugin file line
            if (preg_match('#(wp-content/(?:themes|plugins)/[^:]+):(\d+)#', $line, $matches)) {
                return $matches[1] . ':' . $matches[2]; // file:line
            }
        }

        // Fallback to first line
        return substr($backtrace, 0, 200);
    }

    /**
     * Get client IP address
     */
    private function getClientIP(): string
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
     * Cleanup old logs
     */
    public function cleanup()
    {
        $existingLog = get_option($this->optionKey, []);

        // Xóa logs cũ hơn 7 ngày
        $cutoff = date('Y-m-d H:i:s', strtotime('-7 days'));
        $filteredLog = array_filter($existingLog, function($log) use ($cutoff) {
            return isset($log['timestamp']) && $log['timestamp'] > $cutoff;
        });

        update_option($this->optionKey, array_values($filteredLog));
    }
}
