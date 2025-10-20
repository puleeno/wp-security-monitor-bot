<?php

namespace Puleeno\SecurityBot\WebMonitor;

use Puleeno\SecurityBot\WebMonitor\Enums\IssuerType;

/**
 * ForensicHelper - Centralized forensic tracking for all Issuers
 *
 * Provides context-aware forensic data collection based on issuer type:
 * - TRIGGER issuers: Full backtrace + real-time context
 * - SCAN issuers: Minimal backtrace + scan context
 * - HYBRID issuers: Adaptive based on detection phase
 */
class ForensicHelper
{
    /**
     * Get comprehensive execution context
     */
    public static function getExecutionContext(): array
    {
        $context = [
            'context_type' => 'unknown',
            'source' => 'unknown',
            'ip_address' => 'unknown',
            'user_agent' => 'unknown',
            'request_uri' => 'unknown',
            'user_id' => null,
            'session_id' => null,
            'is_admin' => false,
            'is_ajax' => false,
            'is_rest' => false,
            'is_cron' => false,
            'is_cli' => false
        ];

        // Detect execution context
        if (defined('WP_CLI') && WP_CLI) {
            $context['context_type'] = 'CLI';
            $context['is_cli'] = true;
            $context['source'] = 'WP-CLI';
            $context['user_agent'] = 'WP-CLI';
        } elseif (wp_doing_cron()) {
            $context['context_type'] = 'CRON';
            $context['is_cron'] = true;
            $context['source'] = 'WordPress Cron';
            $context['user_agent'] = 'WP-Cron';
        } elseif (wp_doing_ajax()) {
            $context['context_type'] = 'AJAX';
            $context['is_ajax'] = true;
            $context['source'] = 'AJAX Request';
        } elseif (defined('REST_REQUEST') && REST_REQUEST) {
            $context['context_type'] = 'REST_API';
            $context['is_rest'] = true;
            $context['source'] = 'REST API';
        } elseif (is_admin()) {
            $context['context_type'] = 'ADMIN';
            $context['is_admin'] = true;
            $context['source'] = 'WordPress Admin';
        } elseif (isset($_SERVER['HTTP_HOST'])) {
            $context['context_type'] = 'FRONTEND';
            $context['source'] = 'Frontend Request';
        } else {
            $context['context_type'] = 'SCRIPT';
            $context['source'] = 'Direct Script Execution';
        }

        // Get request information (if available)
        if (!$context['is_cli'] && !$context['is_cron']) {
            $context['ip_address'] = self::getRealIPAddress();
            $context['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
            $context['request_uri'] = $_SERVER['REQUEST_URI'] ?? 'unknown';
            $context['request_method'] = $_SERVER['REQUEST_METHOD'] ?? 'unknown';
            $context['http_host'] = $_SERVER['HTTP_HOST'] ?? 'unknown';
            $context['server_port'] = $_SERVER['SERVER_PORT'] ?? 'unknown';
            $context['https'] = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';

            // Get referer if available
            if (isset($_SERVER['HTTP_REFERER'])) {
                $context['http_referer'] = $_SERVER['HTTP_REFERER'];
            }
        }

        // Get user information
        if (function_exists('get_current_user_id')) {
            $context['user_id'] = get_current_user_id() ?: null;

            if ($context['user_id'] && is_int($context['user_id'])) {
                $user = get_userdata($context['user_id']);
                if ($user) {
                    $context['username'] = $user->user_login;
                    $context['user_roles'] = $user->roles;
                    $context['user_email'] = $user->user_email;
                }
            }
        }

        // Get session information
        if (session_id()) {
            $context['session_id'] = session_id();
        }

        return $context;
    }

    /**
     * Get detailed backtrace with intelligent parsing
     */
    public static function getDetailedBacktrace(int $skipFrames = 0): array
    {
        $backtrace = debug_backtrace(DEBUG_BACKTRACE_PROVIDE_OBJECT, 20);

        $backtraceInfo = [
            'total_frames' => count($backtrace),
            'source_summary' => 'unknown',
            'call_chain' => [],
            'files_involved' => [],
            'likely_source' => 'unknown',
            'plugin_theme_info' => [],
            'wordpress_core' => false
        ];

        $callChain = [];
        $filesInvolved = [];
        $pluginThemeInfo = [];

        foreach ($backtrace as $index => $frame) {
            // Skip specified frames plus this helper function
            if ($index <= $skipFrames + 1) continue;

            $frameInfo = [
                'frame' => $index,
                'function' => $frame['function'] ?? 'unknown',
                'class' => $frame['class'] ?? null,
                'file' => $frame['file'] ?? 'unknown',
                'line' => $frame['line'] ?? 0,
                'type' => $frame['type'] ?? ''
            ];

            // Analyze file location
            if (isset($frame['file'])) {
                $file = $frame['file'];
                $frameInfo['file_relative'] = str_replace(ABSPATH, '', $file);
                $filesInvolved[] = $frameInfo['file_relative'];

                // Categorize source
                if (strpos($file, '/wp-content/plugins/') !== false) {
                    preg_match('/\/wp-content\/plugins\/([^\/]+)/', $file, $matches);
                    $plugin = $matches[1] ?? 'unknown';
                    $frameInfo['source_type'] = 'plugin';
                    $frameInfo['plugin_name'] = $plugin;
                    $pluginThemeInfo['plugins'][] = $plugin;
                } elseif (strpos($file, '/wp-content/themes/') !== false) {
                    preg_match('/\/wp-content\/themes\/([^\/]+)/', $file, $matches);
                    $theme = $matches[1] ?? 'unknown';
                    $frameInfo['source_type'] = 'theme';
                    $frameInfo['theme_name'] = $theme;
                    $pluginThemeInfo['themes'][] = $theme;
                } elseif (strpos($file, '/wp-admin/') !== false || strpos($file, '/wp-includes/') !== false) {
                    $frameInfo['source_type'] = 'wordpress_core';
                    $backtraceInfo['wordpress_core'] = true;
                } elseif (strpos($file, '/wp-content/') !== false) {
                    $frameInfo['source_type'] = 'wp_content';
                } else {
                    $frameInfo['source_type'] = 'external';
                }
            }

            $callChain[] = $frameInfo;
        }

        // Determine likely source
        $likelySource = self::determineLikelySource($callChain);

        $backtraceInfo['call_chain'] = array_slice($callChain, 0, 10); // Limit to 10 frames
        $backtraceInfo['files_involved'] = array_unique($filesInvolved);
        $backtraceInfo['likely_source'] = $likelySource;
        $backtraceInfo['plugin_theme_info'] = $pluginThemeInfo;
        $backtraceInfo['source_summary'] = self::createSourceSummary($likelySource, $pluginThemeInfo);

        return $backtraceInfo;
    }

    /**
     * Create context-aware forensic data based on issuer type
     */
    public static function createForensicData(int $skipFrames = 0, string $issuerClass = ''): array
    {
        $issuerType = IssuerType::getIssuerType($issuerClass);
        $contextNeeds = IssuerType::getContextNeeds($issuerClass);

        $forensicData = [
            'issuer_type' => $issuerType,
            'detection_method' => self::getDetectionMethod($issuerType),
            'context_level' => self::getContextLevel($issuerType),
            'timestamp' => current_time('mysql')
        ];

        // Always include execution context
        $forensicData['execution_context'] = self::getExecutionContext();

        // Backtrace based on issuer type
        if (IssuerType::needsFullBacktrace($issuerClass)) {
            $forensicData['backtrace_info'] = self::getDetailedBacktrace($skipFrames);
        } else {
            $forensicData['backtrace_info'] = self::getMinimalBacktrace($skipFrames);
        }

        // Additional context based on needs
        if (in_array('memory_usage', $contextNeeds)) {
            $forensicData['memory_usage'] = memory_get_usage(true);
            $forensicData['peak_memory'] = memory_get_peak_usage(true);
        }

        if (in_array('timing_patterns', $contextNeeds)) {
            $forensicData['timing_info'] = self::getTimingInfo();
        }

        if (in_array('scan_context', $contextNeeds)) {
            $forensicData['scan_context'] = self::getScanContext();
        }

        return $forensicData;
    }

    /**
     * Get detection method description
     */
    private static function getDetectionMethod(string $issuerType): string
    {
        $methods = [
            IssuerType::TRIGGER => 'Real-time Attack Detection',
            IssuerType::SCAN => 'Proactive Security Scan',
            IssuerType::HYBRID => 'Combined Detection Method'
        ];

        return $methods[$issuerType] ?? 'Unknown Detection Method';
    }

    /**
     * Get context level based on issuer type
     */
    private static function getContextLevel(string $issuerType): string
    {
        switch ($issuerType) {
            case IssuerType::TRIGGER:
                return 'full_forensic';
            case IssuerType::HYBRID:
                return 'selective_forensic';
            case IssuerType::SCAN:
                return 'minimal_forensic';
            default:
                return 'basic_forensic';
        }
    }

    /**
     * Determine likely source of function call
     */
    private static function determineLikelySource(array $callChain): string
    {
        // Prioritize non-core sources
        foreach ($callChain as $frame) {
            if (isset($frame['source_type'])) {
                switch ($frame['source_type']) {
                    case 'plugin':
                        return "Plugin: {$frame['plugin_name']}";
                    case 'theme':
                        return "Theme: {$frame['theme_name']}";
                    case 'wp_content':
                        return "WP Content: {$frame['file_relative']}";
                    case 'external':
                        return "External: {$frame['file_relative']}";
                }
            }
        }

        // Fallback to WordPress core
        foreach ($callChain as $frame) {
            if (isset($frame['source_type']) && $frame['source_type'] === 'wordpress_core') {
                return "WordPress Core: {$frame['file_relative']}";
            }
        }

        return 'Unknown source';
    }

    /**
     * Create human-readable source summary
     */
    private static function createSourceSummary(string $likelySource, array $pluginThemeInfo): string
    {
        $summary = $likelySource;

        if (!empty($pluginThemeInfo['plugins'])) {
            $plugins = array_unique($pluginThemeInfo['plugins']);
            $summary .= ' (Plugins: ' . implode(', ', $plugins) . ')';
        }

        if (!empty($pluginThemeInfo['themes'])) {
            $themes = array_unique($pluginThemeInfo['themes']);
            $summary .= ' (Themes: ' . implode(', ', $themes) . ')';
        }

        return $summary;
    }

    /**
     * Get real IP address behind proxies
     */
    public static function getRealIPAddress(): string
    {
        // Check for various proxy headers
        $headers = [
            'HTTP_CF_CONNECTING_IP',     // Cloudflare
            'HTTP_X_REAL_IP',            // Nginx
            'HTTP_X_FORWARDED_FOR',      // General proxy
            'HTTP_X_FORWARDED',          // General proxy
            'HTTP_X_CLUSTER_CLIENT_IP',  // Cluster
            'HTTP_FORWARDED_FOR',        // General proxy
            'HTTP_FORWARDED',            // General proxy
            'REMOTE_ADDR'                // Standard
        ];

        foreach ($headers as $header) {
            if (isset($_SERVER[$header]) && !empty($_SERVER[$header])) {
                $ips = explode(',', $_SERVER[$header]);
                $ip = trim($ips[0]);

                // Validate IP
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }

        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }

    /**
     * Enhanced logging with full context
     */
    public static function logSecurityEvent(string $eventType, string $message, array $additionalData = []): void
    {
        $forensicData = self::createForensicData(1); // Skip this function frame

        $logData = [
            'event_type' => $eventType,
            'message' => $message,
            'additional_data' => $additionalData,
            'forensic_data' => $forensicData
        ];

        error_log(sprintf(
            '[WP Security Monitor] %s: %s - Context: %s - Source: %s',
            $eventType,
            $message,
            $forensicData['execution_context']['context_type'],
            $forensicData['backtrace_info']['source_summary']
        ));
    }

    /**
     * Get minimal backtrace for SCAN issuers
     */
    public static function getMinimalBacktrace(int $skipFrames = 0): array
    {
        $backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 5); // Only 5 frames, no args

        $backtraceInfo = [
            'total_frames' => count($backtrace),
            'context_type' => 'scan_context',
            'scan_trigger' => 'scheduled_scan',
            'limited_trace' => true
        ];

        // Only get the immediate calling context
        foreach (array_slice($backtrace, $skipFrames + 1, 3) as $index => $frame) {
            $backtraceInfo['call_chain'][] = [
                'frame' => $index,
                'function' => $frame['function'] ?? 'unknown',
                'file' => isset($frame['file']) ? str_replace(ABSPATH, '', $frame['file']) : 'unknown',
                'line' => $frame['line'] ?? 0
            ];
        }

        return $backtraceInfo;
    }

    /**
     * Get timing information for pattern analysis
     */
    private static function getTimingInfo(): array
    {
        return [
            'request_time' => $_SERVER['REQUEST_TIME_FLOAT'] ?? microtime(true),
            'current_time' => microtime(true),
            'execution_time' => microtime(true) - ($_SERVER['REQUEST_TIME_FLOAT'] ?? microtime(true)),
            'hour_of_day' => (int) date('H'),
            'day_of_week' => (int) date('w'),
            'timezone' => wp_timezone_string()
        ];
    }

    /**
     * Get scan context information
     */
    private static function getScanContext(): array
    {
        return [
            'scan_type' => wp_doing_cron() ? 'cron_scan' : 'manual_scan',
            'is_background' => wp_doing_cron(),
            'scan_timestamp' => current_time('mysql'),
            'scan_environment' => self::getScanEnvironment()
        ];
    }

    /**
     * Get scan environment details
     */
    private static function getScanEnvironment(): array
    {
        return [
            'php_version' => PHP_VERSION,
            'wp_version' => get_bloginfo('version'),
            'active_plugins' => get_option('active_plugins', []),
            'active_theme' => get_option('stylesheet'),
            'multisite' => is_multisite(),
            'debug_mode' => defined('WP_DEBUG') && WP_DEBUG
        ];
    }

    /**
     * Create standardized issue structure với issuer-aware context
     */
    public static function createSecurityIssue(
        string $type,
        string $severity,
        string $message,
        array $details = [],
        int $skipFrames = 0,
        string $issuerClass = ''
    ): array {
        // Auto-detect issuer class từ backtrace nếu không provided
        if (empty($issuerClass)) {
            $issuerClass = self::detectIssuerClass($skipFrames + 1);
        }

        $forensicData = self::createForensicData($skipFrames + 1, $issuerClass);

        return [
            'type' => $type,
            'severity' => $severity,
            'message' => $message,
            'details' => array_merge($details, $forensicData),
            'debug_info' => DebugHelper::createIssueDebugInfo($issuerClass ?: 'Unknown Issuer')
        ];
    }

    /**
     * Auto-detect issuer class từ backtrace
     */
    private static function detectIssuerClass(int $skipFrames): string
    {
        $backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 10);

        foreach (array_slice($backtrace, $skipFrames) as $frame) {
            if (isset($frame['class']) && strpos($frame['class'], 'Issuer') !== false) {
                return $frame['class'];
            }
        }

        return '';
    }
}
