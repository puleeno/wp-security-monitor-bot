<?php
namespace Puleeno\SecurityBot\WebMonitor;

use Puleeno\SecurityBot\WebMonitor\Database\Schema;

class IssueManager
{
    /**
     * @var IssueManager
     */
    private static $instance;

    /**
     * @var string
     */
    private $issuesTable;

    /**
     * @var string
     */
    private $ignoreTable;

    private function __construct()
    {
        global $wpdb;
        $this->issuesTable = $wpdb->prefix . Schema::TABLE_ISSUES;
        $this->ignoreTable = $wpdb->prefix . Schema::TABLE_IGNORE_RULES;
    }

    public static function getInstance(): IssueManager
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Ghi nhận một issue mới hoặc cập nhật existing
     *
     * @param string $issuerName
     * @param array $issueData
     * @return int|false Issue ID hoặc false nếu lỗi
     */
    public function recordIssue(string $issuerName, array $issueData)
    {
        global $wpdb;

        // Tạo hash duy nhất cho issue
        $issueHash = $this->generateIssueHash($issuerName, $issueData);

        // Tạo hash cho line code cụ thể
        $lineCodeHash = $this->generateLineCodeHash($issuerName, $issueData);

        // Kiểm tra ignore rules trước
        if ($this->isIgnored($issuerName, $issueData, $issueHash)) {
            return false;
        }

        // Tạo file .malware ngay lập tức khi phát hiện issue (không bị ignore)
        $this->createMalwareFlagFile();

        // Kiểm tra issue đã tồn tại chưa (theo line_code_hash)
        $existingId = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM {$this->issuesTable} WHERE line_code_hash = %s",
            $lineCodeHash
        ));

        $now = current_time('mysql');

        if ($existingId) {
            // Cập nhật existing issue
            // Sử dụng raw SQL để tăng detection_count
            $wpdb->query($wpdb->prepare(
                "UPDATE {$this->issuesTable}
                 SET last_detected = %s,
                     detection_count = detection_count + 1,
                     updated_at = %s
                 WHERE id = %d",
                $now, $now, $existingId
            ));

            $updated = $wpdb->rows_affected > 0;

            return $updated ? $existingId : false;
        } else {
            // Tạo issue mới
            $data = [
                'issue_hash' => $issueHash,
                'line_code_hash' => $lineCodeHash,
                'issuer_name' => $issuerName,
                'issue_type' => $this->extractIssueType($issueData),
                'severity' => $this->determineSeverity($issuerName, $issueData),
                'title' => $this->extractTitle($issueData),
                'description' => $this->extractDescription($issueData),
                'details' => $this->extractDetails($issueData),
                'raw_data' => json_encode($issueData),
                'backtrace' => $this->extractBacktrace($issueData),
                'file_path' => $this->extractFilePath($issueData),
                'ip_address' => $this->extractIPAddress($issueData),
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
                'first_detected' => $now,
                'last_detected' => $now,
                'metadata' => json_encode($this->extractMetadata($issueData))
            ];

            $inserted = $wpdb->insert($this->issuesTable, $data);

            return $inserted ? $wpdb->insert_id : false;
        }
    }

    /**
     * Lấy danh sách issues với pagination và filters
     *
     * @param array $args
     * @return array
     */
    public function getIssues(array $args = []): array
    {
        global $wpdb;

        $defaults = [
            'per_page' => 20,
            'page' => 1,
            'status' => '',
            'severity' => '',
            'issuer' => '',
            'search' => '',
            'order_by' => 'last_detected',
            'order' => 'DESC',
            'include_ignored' => false,
            'include_plugin_files' => false
        ];

        $args = wp_parse_args($args, $defaults);

        $where = ['1=1'];
        $params = [];

        // Filters
        if (!empty($args['status'])) {
            $where[] = 'status = %s';
            $params[] = $args['status'];
        }

        if (!empty($args['severity'])) {
            $where[] = 'severity = %s';
            $params[] = $args['severity'];
        }

        if (!empty($args['issuer'])) {
            $where[] = 'issuer_name = %s';
            $params[] = $args['issuer'];
        }

        if (!empty($args['search'])) {
            $where[] = '(title LIKE %s OR description LIKE %s OR file_path LIKE %s)';
            $searchTerm = '%' . $wpdb->esc_like($args['search']) . '%';
            $params[] = $searchTerm;
            $params[] = $searchTerm;
            $params[] = $searchTerm;
        }

        if (!$args['include_ignored']) {
            $where[] = 'is_ignored = 0';
        }

        // Filter out plugin files (avoid false positives)
        $pluginDir = dirname(dirname(__DIR__));
        $pluginPath = wp_normalize_path($pluginDir);
        $where[] = '(file_path IS NULL OR file_path NOT LIKE %s)';
        $params[] = $pluginPath . '%';

        // Pagination
        $offset = ($args['page'] - 1) * $args['per_page'];
        $limit = $args['per_page'];

        // Order
        $orderBy = sanitize_sql_orderby($args['order_by'] . ' ' . $args['order']);

        $whereClause = implode(' AND ', $where);

        // Get total count
        $totalQuery = "SELECT COUNT(*) FROM {$this->issuesTable} WHERE $whereClause";
        $total = $wpdb->get_var(
            empty($params) ? $totalQuery : $wpdb->prepare($totalQuery, $params)
        );

        // Get issues
        $query = "SELECT * FROM {$this->issuesTable}
                  WHERE $whereClause
                  ORDER BY $orderBy
                  LIMIT $offset, $limit";

        $issues = $wpdb->get_results(
            empty($params) ? $query : $wpdb->prepare($query, $params),
            ARRAY_A
        );

        // Decode JSON fields
        foreach ($issues as &$issue) {
            $issue['raw_data'] = is_array($issue['raw_data']) ? $issue['raw_data'] : json_decode($issue['raw_data'], true);
            $issue['metadata'] = is_array($issue['metadata']) ? $issue['metadata'] : json_decode($issue['metadata'], true);
        }

        return [
            'issues' => $issues,
            'total' => (int) $total,
            'pages' => ceil($total / $args['per_page']),
            'current_page' => $args['page'],
            'per_page' => $args['per_page']
        ];
    }

    /**
     * Ignore một issue
     *
     * @param int $issueId
     * @param string $reason
     * @param int|null $userId
     * @return bool
     */
    public function ignoreIssue(int $issueId, string $reason = '', ?int $userId = null): bool
    {
        global $wpdb;

        $userId = $userId ?: get_current_user_id();

        $updated = $wpdb->update(
            $this->issuesTable,
            [
                'is_ignored' => 1,
                'status' => 'ignored',
                'ignored_by' => $userId,
                'ignored_at' => current_time('mysql'),
                'ignore_reason' => $reason,
                'updated_at' => current_time('mysql')
            ],
            ['id' => $issueId],
            ['%d', '%s', '%d', '%s', '%s', '%s'],
            ['%d']
        );

        return $updated !== false;
    }

    /**
     * Unignore một issue
     *
     * @param int $issueId
     * @return bool
     */
    public function unignoreIssue(int $issueId): bool
    {
        global $wpdb;

        $updated = $wpdb->update(
            $this->issuesTable,
            [
                'is_ignored' => 0,
                'status' => 'new',
                'ignored_by' => null,
                'ignored_at' => null,
                'ignore_reason' => null,
                'updated_at' => current_time('mysql')
            ],
            ['id' => $issueId],
            ['%d', '%s', '%s', '%s', '%s', '%s'],
            ['%d']
        );

        return $updated !== false;
    }

    /**
     * Đánh dấu issue đã resolve
     *
     * @param int $issueId
     * @param string $notes
     * @param int|null $userId
     * @return bool
     */
    public function resolveIssue(int $issueId, string $notes = '', ?int $userId = null): bool
    {
        global $wpdb;

        $userId = $userId ?: get_current_user_id();

        $updated = $wpdb->update(
            $this->issuesTable,
            [
                'status' => 'resolved',
                'resolved_by' => $userId,
                'resolved_at' => current_time('mysql'),
                'resolution_notes' => $notes,
                'updated_at' => current_time('mysql')
            ],
            ['id' => $issueId],
            ['%s', '%d', '%s', '%s', '%s'],
            ['%d']
        );

        return $updated !== false;
    }

    /**
     * Tạo ignore rule từ issue
     *
     * @param int $issueId
     * @param string $ruleType
     * @param array $options
     * @return bool
     */
    public function createIgnoreRuleFromIssue(int $issueId, string $ruleType, array $options = []): bool
    {
        global $wpdb;

        $issue = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$this->issuesTable} WHERE id = %d",
            $issueId
        ), ARRAY_A);

        if (!$issue) {
            return false;
        }

        $ruleValue = '';
        $ruleName = '';

        switch ($ruleType) {
            case 'hash':
                $ruleValue = $issue['issue_hash'];
                $ruleName = 'Ignore specific issue: ' . substr($issue['title'], 0, 50);
                break;

            case 'file':
                $ruleValue = $issue['file_path'];
                $ruleName = 'Ignore file: ' . basename($issue['file_path']);
                break;

            case 'ip':
                $ruleValue = $issue['ip_address'];
                $ruleName = 'Ignore IP: ' . $issue['ip_address'];
                break;

            case 'issuer':
                $ruleValue = $issue['issuer_name'];
                $ruleName = 'Disable issuer: ' . $issue['issuer_name'];
                break;

            case 'pattern':
                $ruleValue = $options['pattern'] ?? $issue['title'];
                $ruleName = 'Ignore pattern: ' . substr($ruleValue, 0, 50);
                break;

            default:
                return false;
        }

        $ruleData = [
            'rule_name' => $ruleName,
            'rule_type' => $ruleType,
            'rule_value' => $ruleValue,
            'issuer_name' => $issue['issuer_name'],
            'issue_type' => $issue['issue_type'],
            'description' => $options['description'] ?? "Auto-generated from issue #{$issueId}",
            'created_by' => get_current_user_id(),
            'expires_at' => isset($options['expires_days']) ?
                date('Y-m-d H:i:s', strtotime("+{$options['expires_days']} days")) : null
        ];

        $inserted = $wpdb->insert($this->ignoreTable, $ruleData);

        if ($inserted) {
            // Ignore the original issue
            $this->ignoreIssue($issueId, "Ignored by rule: {$ruleName}");
            return true;
        }

        return false;
    }

    /**
     * Kiểm tra issue có bị ignore không
     *
     * @param string $issuerName
     * @param array $issueData
     * @param string $issueHash
     * @return bool
     */
    private function isIgnored(string $issuerName, array $issueData, string $issueHash): bool
    {
        global $wpdb;

        $rules = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$this->ignoreTable}
             WHERE is_active = 1
             AND (expires_at IS NULL OR expires_at > %s)
             ORDER BY rule_type",
            current_time('mysql')
        ), ARRAY_A);

        foreach ($rules as $rule) {
            $isMatch = false;

            switch ($rule['rule_type']) {
                case 'hash':
                    $isMatch = ($rule['rule_value'] === $issueHash);
                    break;

                case 'issuer':
                    $isMatch = ($rule['rule_value'] === $issuerName);
                    break;

                case 'file':
                    $filePath = $this->extractFilePath($issueData);
                    $isMatch = ($filePath && strpos($filePath, $rule['rule_value']) !== false);
                    break;

                case 'ip':
                    $ip = $this->extractIPAddress($issueData);
                    $isMatch = ($ip === $rule['rule_value']);
                    break;

                case 'pattern':
                    $title = $this->extractTitle($issueData);
                    $description = $this->extractDescription($issueData);
                    $isMatch = (strpos($title, $rule['rule_value']) !== false ||
                               strpos($description, $rule['rule_value']) !== false);
                    break;

                case 'regex':
                    $title = $this->extractTitle($issueData);
                    $isMatch = preg_match('/' . $rule['rule_value'] . '/i', $title);
                    break;
            }

            if ($isMatch) {
                // Cập nhật usage count
                // Sử dụng raw SQL để tăng usage_count
                $wpdb->query($wpdb->prepare(
                    "UPDATE {$this->ignoreTable}
                     SET usage_count = usage_count + 1,
                         last_used_at = %s
                     WHERE id = %d",
                    current_time('mysql'), $rule['id']
                ));

                return true;
            }
        }

        return false;
    }

    /**
     * Tạo hash duy nhất cho issue
     *
     * @param string $issuerName
     * @param array $issueData
     * @return string
     */
    private function generateIssueHash(string $issuerName, array $issueData): string
    {
        $hashData = [
            'issuer' => $issuerName,
            'message' => $this->extractTitle($issueData),
            'file' => $this->extractFilePath($issueData),
            'details' => $this->extractDetails($issueData)
        ];

        return md5(serialize($hashData));
    }

    /**
     * Tạo hash cho line code cụ thể
     *
     * @param string $issuerName
     * @param array $issueData
     * @return string
     */
    private function generateLineCodeHash(string $issuerName, array $issueData): string
    {
        $backtrace = $this->extractBacktrace($issueData);

        if (empty($backtrace)) {
            // Nếu không có backtrace, sử dụng issue_hash
            return $this->generateIssueHash($issuerName, $issueData);
        }

        // Tìm line code đầu tiên từ backtrace (không phải từ internal classes)
        $backtraceArray = is_string($backtrace) ? json_decode($backtrace, true) : $backtrace;

        if (is_array($backtraceArray)) {
            foreach ($backtraceArray as $frame) {
                if (isset($frame['file']) && isset($frame['line'])) {
                    // Loại bỏ các frames từ internal classes
                    $excludeClasses = ['IssueManager', 'Bot', 'RealtimeRedirectIssuer', 'RealtimeUserRegistrationIssuer'];
                    $excludePaths = ['wp-content/plugins/wp-security-monitor-bot'];

                    $isExcluded = false;
                    foreach ($excludePaths as $excludePath) {
                        if (strpos($frame['file'], $excludePath) !== false) {
                            $isExcluded = true;
                            break;
                        }
                    }

                    if (!$isExcluded) {
                        // Tạo hash từ file path và line number
                        $lineCodeData = [
                            'file' => $frame['file'],
                            'line' => $frame['line'],
                            'issuer' => $issuerName
                        ];
                        return md5(serialize($lineCodeData));
                    }
                }
            }
        }

        // Fallback: sử dụng issue_hash
        return $this->generateIssueHash($issuerName, $issueData);
    }

    /**
     * Extract methods
     */
    private function extractTitle(array $issueData): string
    {
        return $issueData['message'] ?? $issueData['title'] ?? 'Unknown Issue';
    }

    private function extractDescription(array $issueData): string
    {
        if (isset($issueData['description'])) {
            return is_string($issueData['description']) ? $issueData['description'] : json_encode($issueData['description'], JSON_UNESCAPED_UNICODE);
        }

        if (isset($issueData['details'])) {
            // Nếu details là array, convert thành JSON string
            if (is_array($issueData['details'])) {
                return json_encode($issueData['details'], JSON_UNESCAPED_UNICODE);
            }
            // Nếu details là string, return trực tiếp
            if (is_string($issueData['details'])) {
                return $issueData['details'];
            }
            // Nếu details là kiểu dữ liệu khác, convert thành string
            return (string) $issueData['details'];
        }

        return '';
    }

    private function extractDetails(array $issueData): string
    {
        if (isset($issueData['details'])) {
            // Nếu details là array, convert thành JSON string
            if (is_array($issueData['details'])) {
                return json_encode($issueData['details'], JSON_UNESCAPED_UNICODE);
            }
            // Nếu details là string, return trực tiếp
            if (is_string($issueData['details'])) {
                return $issueData['details'];
            }
            // Nếu details là kiểu dữ liệu khác, convert thành string
            return (string) $issueData['details'];
        }

        // Fallback: convert toàn bộ issueData thành JSON string
        return json_encode($issueData, JSON_UNESCAPED_UNICODE);
    }

    /**
     * Lấy backtrace từ issue data
     *
     * @param array $issueData
     * @return string|null
     */
    private function extractBacktrace(array $issueData): ?string
    {
        // Nếu có backtrace trong issue data
        if (isset($issueData['backtrace'])) {
            return is_string($issueData['backtrace']) ? $issueData['backtrace'] : json_encode($issueData['backtrace']);
        }

        // Nếu không có, tạo backtrace từ current stack
        if (function_exists('debug_backtrace')) {
            $backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 10);

            // Lọc bỏ các frames không cần thiết
            $filteredBacktrace = array_filter($backtrace, function($frame) {
                // Loại bỏ các frames từ IssueManager và các class internal
                $excludeClasses = ['IssueManager', 'Bot', 'RealtimeRedirectIssuer'];
                $excludeFunctions = ['recordIssue', 'handleSuspiciousRedirect'];

                if (isset($frame['class']) && in_array($frame['class'], $excludeClasses)) {
                    return false;
                }

                if (isset($frame['function']) && in_array($frame['function'], $excludeFunctions)) {
                    return false;
                }

                return true;
            });

            if (!empty($filteredBacktrace)) {
                return json_encode($filteredBacktrace, JSON_PRETTY_PRINT);
            }
        }

        return null;
    }

    private function extractFilePath(array $issueData): ?string
    {
        return $issueData['file_path'] ?? $issueData['file'] ?? null;
    }

    private function extractIPAddress(array $issueData): ?string
    {
        if (isset($issueData['ip'])) {
            return $issueData['ip'];
        }

        // Extract from details array or string
        if (isset($issueData['details'])) {
            // Nếu details là array, tìm ip_address
            if (is_array($issueData['details'])) {
                if (isset($issueData['details']['ip_address'])) {
                    return $issueData['details']['ip_address'];
                }
                // Nếu không có ip_address, tìm trong các key khác
                foreach ($issueData['details'] as $key => $value) {
                    if (is_string($value) && preg_match('/^(\d{1,3}\.){3}\d{1,3}$/', $value)) {
                        return $value;
                    }
                }
            }
            // Nếu details là string, extract bằng regex
            elseif (is_string($issueData['details']) && preg_match('/IP\s+([0-9.]+)/', $issueData['details'], $matches)) {
                return $matches[1];
            }
        }

        return $_SERVER['REMOTE_ADDR'] ?? null;
    }

    private function extractIssueType(array $issueData): string
    {
        if (isset($issueData['type'])) {
            return $issueData['type'];
        }

        // Infer from message
        $message = strtolower($this->extractTitle($issueData));

        if (strpos($message, 'redirect') !== false) return 'redirect';
        if (strpos($message, 'login') !== false) return 'login';
        if (strpos($message, 'file') !== false) return 'file_change';
        if (strpos($message, 'malware') !== false) return 'malware';
        if (strpos($message, 'brute') !== false) return 'brute_force';

        return 'unknown';
    }

    private function determineSeverity(string $issuerName, array $issueData): string
    {
        $message = strtolower($this->extractTitle($issueData));

        // Critical issues
        if (strpos($message, 'malware') !== false ||
            strpos($message, 'backdoor') !== false ||
            strpos($message, 'eval') !== false) {
            return 'critical';
        }

        // High severity
        if (strpos($message, 'brute force') !== false ||
            strpos($message, 'admin') !== false ||
            strpos($message, 'wp-config') !== false) {
            return 'high';
        }

        // Medium severity (default)
        return 'medium';
    }

    private function extractMetadata(array $issueData): array
    {
        $metadata = [];

        foreach ($issueData as $key => $value) {
            if (!in_array($key, ['message', 'details', 'file', 'ip'])) {
                $metadata[$key] = $value;
            }
        }

        return $metadata;
    }

    /**
     * Lấy thống kê
     *
     * @return array
     */
    public function getStats(): array
    {
        return Schema::getStats();
    }

    /**
     * Cleanup dữ liệu cũ
     *
     * @param int $days
     * @return array
     */
    public function cleanup(int $days = 90): array
    {
        return Schema::cleanupOldData($days);
    }

    /**
     * Lấy ID của issue vừa được insert
     *
     * @return int|null
     */
    public function getLastInsertId(): ?int
    {
        global $wpdb;
        return $wpdb->insert_id;
    }

    /**
     * Tạo file .malware trong ABSPATH để đánh dấu có issue
     *
     * @return void
     */
    private function createMalwareFlagFile(): void
    {
        try {
            // Chỉ tạo file nếu constant WP_SECURITY_MONITOR_MALWARE_FLAG được bật
            if (!defined('WP_SECURITY_MONITOR_MALWARE_FLAG') || !WP_SECURITY_MONITOR_MALWARE_FLAG) {
                return;
            }

            if (!defined('ABSPATH')) {
                return;
            }

            $flagFile = ABSPATH . '.malware';

            // Tạo file rỗng nếu chưa tồn tại
            if (!file_exists($flagFile)) {
                $result = touch($flagFile);

                if ($result && WP_DEBUG) {
                    error_log('[WP Security Monitor] Created malware flag file: ' . $flagFile);
                }
            }
        } catch (\Exception $e) {
            if (WP_DEBUG) {
                error_log('[WP Security Monitor] Error creating malware flag file: ' . $e->getMessage());
            }
        }
    }
}
