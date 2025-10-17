<?php
namespace Puleeno\SecurityBot\WebMonitor\Issuers;

use Puleeno\SecurityBot\WebMonitor\Abstracts\RealtimeIssuerAbstract;

/**
 * Performance Monitor Issuer
 *
 * Monitors website execution time và memory usage
 * Cảnh báo khi request xử lý quá chậm (>30s default)
 * Capture backtrace để debug performance bottlenecks
 *
 * ⚠️ QUAN TRỌNG - BẬT SQL QUERY TRACKING:
 * Để có thể tracking slow SQL queries, cần enable SAVEQUERIES trong wp-config.php:
 *
 *   define('SAVEQUERIES', true);
 *
 * Sau khi thêm dòng này, issuer sẽ tự động:
 * - Track tất cả database queries
 * - Phát hiện queries > 1s
 * - Hiển thị top slow queries trong alert
 * - Show query caller/backtrace
 *
 * Nếu không enable SAVEQUERIES, issuer vẫn hoạt động nhưng chỉ có:
 * - Execution time
 * - Memory usage
 * - Code backtrace
 * (Không có slow query details)
 */
class PerformanceIssuer extends RealtimeIssuerAbstract
{
    /**
     * @var string
     */
    protected $name = 'Performance Monitor';

    /**
     * @var string
     */
    protected $description = 'Monitors execution time and reports slow requests';

    /**
     * @var float Request start time
     */
    private $startTime;

    /**
     * @var int Start memory usage
     */
    private $startMemory;

    /**
     * @var array Query log
     */
    private $queries = [];

    /**
     * @var bool Đã ghi log chưa
     */
    private $logged = false;

    public function __construct()
    {
        // Record start time và memory
        $this->startTime = defined('WP_START_TIMESTAMP') ? WP_START_TIMESTAMP : microtime(true);
        $this->startMemory = memory_get_usage(true);

        // Register hooks
        $this->registerHooks();
    }

    /**
     * Register WordPress hooks
     */
    protected function registerHooks(): void
    {
        // Hook vào shutdown để đo execution time
        add_action('shutdown', [$this, 'monitorPerformance'], 999);

        // Hook vào wpdb để track queries nếu SAVEQUERIES enabled
        if (defined('SAVEQUERIES') && SAVEQUERIES) {
            add_filter('query', [$this, 'logQuery'], 10, 1);
        }
    }

    /**
     * Log query
     */
    public function logQuery($query)
    {
        if (count($this->queries) < 100) { // Limit to 100 queries
            $this->queries[] = [
                'query' => $query,
                'time' => microtime(true),
            ];
        }
        return $query;
    }

    /**
     * Monitor performance on shutdown
     */
    public function monitorPerformance(): void
    {
        if (!$this->isEnabled() || $this->logged) {
            return;
        }

        $this->logged = true;

        // Calculate execution time
        $executionTime = microtime(true) - $this->startTime;
        $threshold = $this->getConfig('threshold', 30); // Default 30s

        // Check if execution time exceeds threshold
        if ($executionTime < $threshold) {
            return;
        }

        // Calculate memory usage
        $peakMemory = memory_get_peak_usage(true);
        $memoryUsed = $peakMemory - $this->startMemory;

        // Get slow queries
        $slowQueries = $this->getSlowQueries();

        // Get backtrace
        $backtrace = $this->captureBacktrace();

        // Build issue data
        $issueData = [
            'type' => 'slow_performance',
            'severity' => $this->calculateSeverity($executionTime),
            'title' => sprintf('Slow Request: %.2fs execution time', $executionTime),
            'description' => sprintf(
                'Request took %.2f seconds to complete (threshold: %ds)',
                $executionTime,
                $threshold
            ),
            'execution_time' => round($executionTime, 2),
            'threshold' => $threshold,
            'memory_used' => $this->formatBytes($memoryUsed),
            'memory_used_bytes' => $memoryUsed,
            'peak_memory' => $this->formatBytes($peakMemory),
            'peak_memory_bytes' => $peakMemory,
            'url' => $_SERVER['REQUEST_URI'] ?? '',
            'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? '',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'user_id' => get_current_user_id(),
            'referer' => $_SERVER['HTTP_REFERER'] ?? '',
            'timestamp' => current_time('mysql'),
            'backtrace' => $backtrace,
            'slow_queries' => $slowQueries,
            'total_queries' => count($this->queries),
            'server_load' => $this->getServerLoad(),
        ];

        // Trigger action để Bot xử lý
        do_action('wp_security_monitor_slow_performance', $issueData);
    }

    /**
     * Calculate severity based on execution time
     */
    private function calculateSeverity(float $executionTime): string
    {
        $threshold = $this->getConfig('threshold', 30);

        if ($executionTime >= $threshold * 3) {
            return 'critical'; // 90s+
        } elseif ($executionTime >= $threshold * 2) {
            return 'high'; // 60s+
        } elseif ($executionTime >= $threshold * 1.5) {
            return 'medium'; // 45s+
        } else {
            return 'low'; // 30s+
        }
    }

    /**
     * Capture backtrace
     */
    private function captureBacktrace(): array
    {
        $backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 20);
        $formatted = [];

        foreach ($backtrace as $i => $trace) {
            // Skip internal issuer calls
            if (isset($trace['class']) && strpos($trace['class'], 'PerformanceIssuer') !== false) {
                continue;
            }

            $line = '';

            if (isset($trace['file'])) {
                $file = str_replace(ABSPATH, '', $trace['file']);
                $line .= "#{$i} {$file}";

                if (isset($trace['line'])) {
                    $line .= ":{$trace['line']}";
                }
                $line .= "\n";
            }

            if (isset($trace['class'])) {
                $line .= "    {$trace['class']}{$trace['type']}{$trace['function']}()";
            } elseif (isset($trace['function'])) {
                $line .= "    {$trace['function']}()";
            }

            if (!empty($line)) {
                $formatted[] = trim($line);
            }
        }

        return $formatted;
    }

    /**
     * Get slow queries (>1s)
     *
     * ⚠️ YÊU CẦU: define('SAVEQUERIES', true) trong wp-config.php
     * Nếu không enable SAVEQUERIES, function này sẽ return empty array
     */
    private function getSlowQueries(): array
    {
        global $wpdb;

        $slowQueries = [];

        // Nếu SAVEQUERIES enabled, analyze queries
        if (defined('SAVEQUERIES') && SAVEQUERIES && isset($wpdb->queries)) {
            foreach ($wpdb->queries as $query) {
                // $query format: [0 => query, 1 => time, 2 => backtrace]
                $queryTime = isset($query[1]) ? (float) $query[1] : 0;

                if ($queryTime > 1.0) { // Queries > 1s
                    $slowQueries[] = [
                        'query' => isset($query[0]) ? substr($query[0], 0, 200) : '',
                        'time' => round($queryTime, 3),
                        'caller' => isset($query[2]) ? $query[2] : '',
                    ];
                }
            }
        }

        // Sort by time descending
        usort($slowQueries, function($a, $b) {
            return $b['time'] <=> $a['time'];
        });

        // Return top 10
        return array_slice($slowQueries, 0, 10);
    }

    /**
     * Get server load (Linux only)
     */
    private function getServerLoad(): array
    {
        if (function_exists('sys_getloadavg')) {
            $load = sys_getloadavg();
            return [
                '1min' => round($load[0], 2),
                '5min' => round($load[1], 2),
                '15min' => round($load[2], 2),
            ];
        }

        return [];
    }

    /**
     * Format bytes to human readable
     */
    private function formatBytes(int $bytes, int $precision = 2): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];

        for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
            $bytes /= 1024;
        }

        return round($bytes, $precision) . ' ' . $units[$i];
    }

    /**
     * Get issuer name
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Detect issues (for scheduled checks)
     */
    public function detect(): array
    {
        // Realtime issuer, không cần scheduled detection
        return [];
    }

    /**
     * Get default config
     */
    public function getDefaultConfig(): array
    {
        return [
            'enabled' => true,
            'threshold' => 30, // seconds - Thời gian xử lý tối đa cho phép
            'memory_threshold' => 134217728, // 128MB - Memory usage tối đa
            'track_queries' => true, // ⚠️ YÊU CẦU: define('SAVEQUERIES', true) trong wp-config.php
        ];
    }
}

/*
 * ═══════════════════════════════════════════════════════════════════
 * HƯỚNG DẪN ENABLE QUERY TRACKING
 * ═══════════════════════════════════════════════════════════════════
 *
 * Để bật tracking SQL queries, thêm dòng sau vào wp-config.php:
 *
 *   define('SAVEQUERIES', true);
 *
 * Đặt ngay TRƯỚC dòng: require_once ABSPATH . 'wp-settings.php';
 *
 * ⚠️ CHÚ Ý: SAVEQUERIES làm tăng memory usage, chỉ nên bật khi:
 * - Debugging performance issues
 * - Development/staging environment
 * - Production với monitoring cần chi tiết
 *
 * Sau khi debug xong, có thể tắt lại bằng cách:
 *   define('SAVEQUERIES', false);
 * hoặc xóa dòng define đó đi.
 *
 * ═══════════════════════════════════════════════════════════════════
 */


