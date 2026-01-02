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

    /**
     * @var array Context information (route, ajax action, screen, template)
     */
    private $context = [];

    /**
     * @var array Last hooks executed (name, t)
     */
    private $lastHooks = [];

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

        // Track route/context
        add_action('init', [$this, 'detectContext'], 1);
        add_filter('template_include', function($template) {
            $this->context['template'] = $template;
            return $template;
        }, 1);
        if (function_exists('rest_get_server')) {
            add_filter('rest_pre_dispatch', function($result, $server, $request) {
                $this->context['rest_route'] = method_exists($request, 'get_route') ? $request->get_route() : '';
                return $result;
            }, 10, 3);
        }

        // Track last hooks (best-effort, capped)
        add_filter('all', [$this, 'trackHookTimings'], 9999);
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

        // Build absolute URL if possible
        $reqUri = $_SERVER['REQUEST_URI'] ?? '';
        $host = $_SERVER['HTTP_HOST'] ?? '';
        $scheme = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
        $fullUrl = (!empty($host) && !empty($reqUri)) ? ($scheme . '://' . $host . $reqUri) : ($reqUri ?: '');

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
            'url' => $fullUrl,
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
            'context' => $this->context,
            'last_hooks' => array_slice($this->lastHooks, -10),
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
        // Lấy backtrace dạng thô và chuẩn hoá về mảng các object có trường: file, line, function, class
        $backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 20);
        $frames = [];

        foreach ($backtrace as $trace) {
            // Bỏ qua các frame nội bộ của issuer để tập trung vào call-site thật
            if (isset($trace['class']) && strpos($trace['class'], 'PerformanceIssuer') !== false) {
                continue;
            }

            $filePath = $trace['file'] ?? null;
            if ($filePath && defined('ABSPATH')) {
                // Rút gọn path cho dễ đọc
                $filePath = str_replace(ABSPATH, '', $filePath);
            }

            $frames[] = [
                'file' => $filePath ?: null,
                'line' => isset($trace['line']) ? (int) $trace['line'] : null,
                'function' => isset($trace['function']) ? (string) $trace['function'] : '',
                'class' => isset($trace['class']) ? (string) $trace['class'] : null,
            ];

            if (count($frames) >= 15) {
                break; // Giới hạn số frame để tránh payload quá lớn
            }
        }

        return $frames;
    }

    /**
     * Detect request context (admin/rest/ajax/cron/frontend)
     */
    public function detectContext(): void
    {
        $this->context['is_admin'] = function_exists('is_admin') ? is_admin() : false;
        $this->context['is_ajax'] = function_exists('wp_doing_ajax') ? wp_doing_ajax() : (defined('DOING_AJAX') && DOING_AJAX);
        $this->context['is_cron'] = (defined('DOING_CRON') && DOING_CRON);
        $this->context['is_rest'] = (defined('REST_REQUEST') && REST_REQUEST);

        if (function_exists('get_current_screen')) {
            try {
                $screen = get_current_screen();
                if ($screen) {
                    $this->context['screen'] = $screen->id;
                }
            } catch (\Exception $e) {
                // ignore
            }
        }

        if (!empty($_REQUEST['action'])) {
            $this->context['ajax_action'] = sanitize_text_field($_REQUEST['action']);
        }
    }

    /**
     * Track last hooks executed for context
     */
    public function trackHookTimings($tag): void
    {
        // Avoid recording too many entries
        if (count($this->lastHooks) > 100) {
            array_shift($this->lastHooks);
        }
        $this->lastHooks[] = [ 'hook' => (string)$tag, 't' => microtime(true) ];
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


