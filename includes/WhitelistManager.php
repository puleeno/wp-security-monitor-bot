<?php
namespace Puleeno\SecurityBot\WebMonitor;

class WhitelistManager
{
    /**
     * @var WhitelistManager
     */
    private static $instance;

    /**
     * @var string
     */
    private $optionKey = 'wp_security_monitor_whitelist_domains';

    /**
     * @var string
     */
    private $pendingKey = 'wp_security_monitor_pending_domains';

    private function __construct()
    {
    }

    public static function getInstance(): WhitelistManager
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Kiểm tra domain có trong whitelist không
     *
     * @param string $domain
     * @return bool
     */
    public function isDomainWhitelisted(string $domain): bool
    {
        $whitelist = $this->getWhitelistedDomains();

        // Exact match
        if (in_array($domain, $whitelist)) {
            return true;
        }

        // Wildcard match (*.example.com)
        foreach ($whitelist as $whitelistedDomain) {
            if (strpos($whitelistedDomain, '*') !== false) {
                $pattern = str_replace('*', '.*', preg_quote($whitelistedDomain, '/'));
                if (preg_match('/^' . $pattern . '$/', $domain)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Thêm domain vào whitelist
     *
     * @param string $domain
     * @param string $reason
     * @param int|null $addedBy
     * @return bool
     */
    public function addToWhitelist(string $domain, string $reason = '', ?int $addedBy = null): bool
    {
        if ($this->isDomainWhitelisted($domain)) {
            return true; // Already whitelisted
        }

        $whitelist = get_option($this->optionKey, []);
        $userId = $addedBy ?: get_current_user_id();

        $whitelist[$domain] = [
            'domain' => $domain,
            'reason' => $reason,
            'added_by' => $userId,
            'added_at' => current_time('mysql'),
            'usage_count' => 0,
            'last_used' => null
        ];

        $updated = update_option($this->optionKey, $whitelist);

        if ($updated) {
            // Xóa khỏi pending nếu có
            $this->removePendingDomain($domain);

            do_action('wp_security_monitor_domain_whitelisted', $domain, $reason, $userId);
        }

        return $updated;
    }

    /**
     * Xóa domain khỏi whitelist
     *
     * @param string $domain
     * @return bool
     */
    public function removeFromWhitelist(string $domain): bool
    {
        $whitelist = get_option($this->optionKey, []);

        if (isset($whitelist[$domain])) {
            unset($whitelist[$domain]);
            $updated = update_option($this->optionKey, $whitelist);

            if ($updated) {
                do_action('wp_security_monitor_domain_removed_from_whitelist', $domain);
            }

            return $updated;
        }

        return false;
    }

    /**
     * Ghi nhận domain pending (lần đầu phát hiện)
     *
     * @param string $domain
     * @param array $context Thông tin về redirect
     * @return bool
     */
    public function addPendingDomain(string $domain, array $context = []): bool
    {
        $pending = get_option($this->pendingKey, []);

        if (!isset($pending[$domain])) {
            $pending[$domain] = [
                'domain' => $domain,
                'first_detected' => current_time('mysql'),
                'detection_count' => 1,
                'contexts' => [$context],
                'status' => 'pending' // pending, approved, rejected
            ];
        } else {
            $pending[$domain]['detection_count']++;
            $pending[$domain]['contexts'][] = $context;
            $pending[$domain]['last_detected'] = current_time('mysql');
        }

        return update_option($this->pendingKey, $pending);
    }

    /**
     * Kiểm tra domain có trong pending không
     *
     * @param string $domain
     * @return bool
     */
    public function isDomainPending(string $domain): bool
    {
        $pending = get_option($this->pendingKey, []);
        return isset($pending[$domain]) && $pending[$domain]['status'] === 'pending';
    }

    /**
     * Lấy số lần domain đã được phát hiện
     *
     * @param string $domain
     * @return int
     */
    public function getDomainDetectionCount(string $domain): int
    {
        $pending = get_option($this->pendingKey, []);
        return $pending[$domain]['detection_count'] ?? 0;
    }

    /**
     * Xóa domain khỏi pending
     *
     * @param string $domain
     * @return bool
     */
    public function removePendingDomain(string $domain): bool
    {
        $pending = get_option($this->pendingKey, []);

        if (isset($pending[$domain])) {
            unset($pending[$domain]);
            return update_option($this->pendingKey, $pending);
        }

        return false;
    }

    /**
     * Approve pending domain (thêm vào whitelist)
     *
     * @param string $domain
     * @param string $reason
     * @return bool
     */
    public function approvePendingDomain(string $domain, string $reason = ''): bool
    {
        $pending = get_option($this->pendingKey, []);

        if (!isset($pending[$domain])) {
            return false;
        }

        // Thêm vào whitelist
        $success = $this->addToWhitelist($domain, $reason ?: 'Approved from pending domains');

        if ($success) {
            // Cập nhật status thành approved
            $pending[$domain]['status'] = 'approved';
            $pending[$domain]['approved_at'] = current_time('mysql');
            $pending[$domain]['approved_by'] = get_current_user_id();
            update_option($this->pendingKey, $pending);
        }

        return $success;
    }

    /**
     * Reject pending domain
     *
     * @param string $domain
     * @param string $reason
     * @return bool
     */
    public function rejectPendingDomain(string $domain, string $reason = ''): bool
    {
        global $wpdb;

        $pending = get_option($this->pendingKey, []);

        if (!isset($pending[$domain])) {
            return false;
        }

        $domainData = $pending[$domain];

        // Thêm vào rejected table
        $rejectedTable = $wpdb->prefix . 'security_monitor_redirect_domains';
        $result = $wpdb->insert(
            $rejectedTable,
            [
                'domain' => $domain,
                'first_detected' => $domainData['first_detected'] ?? current_time('mysql'),
                'detection_count' => $domainData['detection_count'] ?? 1,
                'last_detected' => $domainData['last_detected'] ?? current_time('mysql'),
                'rejected_at' => current_time('mysql'),
                'rejected_by' => get_current_user_id(),
                'reject_reason' => $reason,
                'contexts' => json_encode($domainData['contexts'] ?? []),
            ],
            [
                '%s', // domain
                '%s', // first_detected
                '%d', // detection_count
                '%s', // last_detected
                '%s', // rejected_at
                '%d', // rejected_by
                '%s', // reject_reason
                '%s'  // contexts
            ]
        );

        if ($result !== false) {
            // Xóa khỏi pending list
            unset($pending[$domain]);
            update_option($this->pendingKey, $pending);

            do_action('wp_security_monitor_domain_rejected', $domain, $reason);
            return true;
        }

        return false;
    }

    /**
     * Cập nhật usage count khi domain được sử dụng
     *
     * @param string $domain
     * @return void
     */
    public function recordDomainUsage(string $domain): void
    {
        $whitelist = get_option($this->optionKey, []);

        if (isset($whitelist[$domain])) {
            $whitelist[$domain]['usage_count']++;
            $whitelist[$domain]['last_used'] = current_time('mysql');
            update_option($this->optionKey, $whitelist);
        }
    }

    /**
     * Lấy danh sách domains trong whitelist
     *
     * @return array
     */
    public function getWhitelistedDomains(): array
    {
        $whitelist = get_option($this->optionKey, []);
        return array_keys($whitelist);
    }

    /**
     * Lấy chi tiết whitelist với metadata
     *
     * @return array
     */
    public function getWhitelistDetails(): array
    {
        return get_option($this->optionKey, []);
    }

    /**
     * Lấy danh sách pending domains
     *
     * @return array
     */
    public function getPendingDomains(): array
    {
        return get_option($this->pendingKey, []);
    }

    /**
     * Validate domain format
     *
     * @param string $domain
     * @return bool
     */
    public function isValidDomain(string $domain): bool
    {
        // Allow wildcards
        $domain = str_replace('*', 'test', $domain);

        return filter_var($domain, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
    }

    /**
     * Extract domain từ URL
     *
     * @param string $url
     * @return string|null
     */
    public function extractDomain(string $url): ?string
    {
        $parsed = parse_url($url);
        return $parsed['host'] ?? null;
    }

    /**
     * Bulk import domains vào whitelist
     *
     * @param array $domains
     * @param string $reason
     * @return array Results
     */
    public function bulkImportDomains(array $domains, string $reason = ''): array
    {
        $results = [
            'success' => 0,
            'failed' => 0,
            'duplicates' => 0,
            'errors' => []
        ];

        foreach ($domains as $domain) {
            $domain = trim($domain);

            if (empty($domain)) {
                continue;
            }

            if (!$this->isValidDomain($domain)) {
                $results['failed']++;
                $results['errors'][] = "Invalid domain: {$domain}";
                continue;
            }

            if ($this->isDomainWhitelisted($domain)) {
                $results['duplicates']++;
                continue;
            }

            if ($this->addToWhitelist($domain, $reason)) {
                $results['success']++;
            } else {
                $results['failed']++;
                $results['errors'][] = "Failed to add: {$domain}";
            }
        }

        return $results;
    }

    /**
     * Export whitelist domains
     *
     * @param string $format csv|json
     * @return string
     */
    public function exportDomains(string $format = 'csv'): string
    {
        $details = $this->getWhitelistDetails();

        if ($format === 'json') {
            return json_encode($details, JSON_PRETTY_PRINT);
        }

        // CSV format
        $csv = "Domain,Reason,Added By,Added At,Usage Count,Last Used\n";

        foreach ($details as $domain => $data) {
            $addedBy = get_userdata($data['added_by']);
            $addedByName = $addedBy ? $addedBy->display_name : 'Unknown';

            $csv .= sprintf(
                '"%s","%s","%s","%s",%d,"%s"' . "\n",
                $domain,
                str_replace('"', '""', $data['reason']),
                $addedByName,
                $data['added_at'],
                $data['usage_count'],
                $data['last_used'] ?: 'Never'
            );
        }

        return $csv;
    }

    /**
     * Cleanup old pending domains
     *
     * @param int $days
     * @return int Number of cleaned domains
     */
    public function cleanupOldPendingDomains(int $days = 30): int
    {
        $pending = get_option($this->pendingKey, []);
        $cutoffDate = date('Y-m-d H:i:s', strtotime("-{$days} days"));
        $cleaned = 0;

        foreach ($pending as $domain => $data) {
            if (isset($data['first_detected']) && $data['first_detected'] < $cutoffDate) {
                if ($data['status'] === 'rejected' ||
                    ($data['status'] === 'pending' && $data['detection_count'] < 2)) {
                    unset($pending[$domain]);
                    $cleaned++;
                }
            }
        }

        if ($cleaned > 0) {
            update_option($this->pendingKey, $pending);
        }

        return $cleaned;
    }

    /**
     * Lấy danh sách rejected domains
     *
     * @param int $limit
     * @param int $offset
     * @return array
     */
    public function getRejectedDomains(int $limit = 20, int $offset = 0): array
    {
        global $wpdb;

        $rejectedTable = $wpdb->prefix . 'security_monitor_redirect_domains';

        $results = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$rejectedTable}
             ORDER BY rejected_at DESC
             LIMIT %d OFFSET %d",
            $limit, $offset
        ), ARRAY_A);

        // Decode contexts JSON
        foreach ($results as &$domain) {
            $domain['contexts'] = json_decode($domain['contexts'] ?? '[]', true);
            $domain['rejected_by_user'] = get_userdata($domain['rejected_by']);
        }

        return $results;
    }

    /**
     * Kiểm tra domain có bị reject không
     *
     * @param string $domain
     * @return bool
     */
    public function isDomainRejected(string $domain): bool
    {
        global $wpdb;

        $rejectedTable = $wpdb->prefix . 'security_monitor_redirect_domains';

        $count = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$rejectedTable} WHERE domain = %s",
            $domain
        ));

        return $count > 0;
    }

    /**
     * Xóa domain khỏi rejected list (cho phép lại)
     *
     * @param string $domain
     * @return bool
     */
    public function removeFromRejected(string $domain): bool
    {
        global $wpdb;

        $rejectedTable = $wpdb->prefix . 'security_monitor_redirect_domains';

        $result = $wpdb->delete(
            $rejectedTable,
            ['domain' => $domain],
            ['%s']
        );

        if ($result !== false) {
            do_action('wp_security_monitor_domain_removed_from_rejected', $domain);
            return true;
        }

        return false;
    }

    /**
     * Lấy thống kê
     *
     * @return array
     */
    public function getStats(): array
    {
        global $wpdb;

        $whitelist = $this->getWhitelistDetails();
        $pending = $this->getPendingDomains();

        // Đếm rejected domains từ database table
        $rejectedTable = $wpdb->prefix . 'security_monitor_redirect_domains';
        $rejectedCount = $wpdb->get_var("SELECT COUNT(*) FROM {$rejectedTable}");

        $stats = [
            'whitelisted_count' => count($whitelist),
            'pending_count' => count(array_filter($pending, function($item) {
                return $item['status'] === 'pending';
            })),
            'approved_count' => count(array_filter($pending, function($item) {
                return $item['status'] === 'approved';
            })),
            'rejected_count' => (int) $rejectedCount,
            'total_usage' => array_sum(array_column($whitelist, 'usage_count')),
            'most_used_domains' => []
        ];

        // Top 5 most used domains
        uasort($whitelist, function($a, $b) {
            return $b['usage_count'] - $a['usage_count'];
        });

        $stats['most_used_domains'] = array_slice(
            array_map(function($domain, $data) {
                return ['domain' => $domain, 'count' => $data['usage_count']];
            }, array_keys($whitelist), $whitelist),
            0,
            5
        );

        return $stats;
    }
}
