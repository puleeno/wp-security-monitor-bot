<?php
namespace Puleeno\SecurityBot\WebMonitor;

class DebugHelper
{
    /**
     * Tạo debug backtrace info để trace callback code
     *
     * @param int $skipFrames Số frames bỏ qua (default 1 để skip chính function này)
     * @param int $limit Giới hạn số frames (default 10)
     * @return array
     */
    public static function getDebugTrace(int $skipFrames = 1, int $limit = 10): array
    {
        $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, $limit + $skipFrames);

        // Bỏ qua $skipFrames frames đầu tiên
        $trace = array_slice($trace, $skipFrames);

        $debugInfo = [];

        foreach ($trace as $index => $frame) {
            $file = $frame['file'] ?? 'unknown';
            $line = $frame['line'] ?? 0;
            $function = $frame['function'] ?? 'unknown';
            $class = $frame['class'] ?? null;
            $type = $frame['type'] ?? '';

            // Rút gọn đường dẫn file
            if (defined('ABSPATH')) {
                $file = str_replace(ABSPATH, '', $file);
            }

            $call = $class ? "{$class}{$type}{$function}" : $function;

            $debugInfo[] = [
                'index' => $index,
                'file' => $file,
                'line' => $line,
                'function' => $call,
                'readable' => "#{$index} {$call}() called at {$file}:{$line}"
            ];
        }

        return $debugInfo;
    }

    /**
     * Tạo debug info cho issues
     *
     * @param string $issuerName
     * @param array $additionalContext
     * @return array
     */
    public static function createIssueDebugInfo(string $issuerName, array $additionalContext = []): array
    {
        $debug = [
            'issuer' => $issuerName,
            'timestamp' => current_time('mysql'),
            'memory_usage' => self::formatBytes(memory_get_usage(true)),
            'peak_memory' => self::formatBytes(memory_get_peak_usage(true)),
            'request_uri' => $_SERVER['REQUEST_URI'] ?? 'CLI',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
            'ip_address' => self::getRealIPAddress(),
            'wordpress_version' => get_bloginfo('version'),
            'php_version' => PHP_VERSION,
            'backtrace' => self::getDebugTrace(2, 8), // Skip 2 frames: this function và caller
            'context' => $additionalContext
        ];

        // WordPress specific info
        if (function_exists('wp_get_current_user')) {
            $user = wp_get_current_user();
            $debug['current_user'] = [
                'id' => $user->ID,
                'login' => $user->user_login,
                'roles' => $user->roles
            ];
        }

        // Hook và filter info
        if (isset($GLOBALS['wp_filter'])) {
            $debug['active_hooks'] = self::getActiveHooks();
        }

        // Plugin info
        $debug['active_plugins'] = self::getActivePluginsInfo();

        return $debug;
    }

    /**
     * Format bytes thành human readable
     *
     * @param int $bytes
     * @return string
     */
    private static function formatBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];

        for ($i = 0; $bytes >= 1024 && $i < count($units) - 1; $i++) {
            $bytes /= 1024;
        }

        return round($bytes, 2) . ' ' . $units[$i];
    }

    /**
     * Lấy real IP address
     *
     * @return string
     */
    private static function getRealIPAddress(): string
    {
        $ipHeaders = [
            'HTTP_CF_CONNECTING_IP',     // CloudFlare
            'HTTP_CLIENT_IP',            // Proxy
            'HTTP_X_FORWARDED_FOR',      // Load balancer/proxy
            'HTTP_X_FORWARDED',          // Proxy
            'HTTP_X_CLUSTER_CLIENT_IP',  // Cluster
            'HTTP_FORWARDED_FOR',        // Proxy
            'HTTP_FORWARDED',            // Proxy
            'REMOTE_ADDR'                // Standard
        ];

        foreach ($ipHeaders as $header) {
            if (!empty($_SERVER[$header])) {
                $ips = explode(',', $_SERVER[$header]);
                $ip = trim($ips[0]);

                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }

        return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    }

    /**
     * Lấy thông tin active hooks
     *
     * @return array
     */
    private static function getActiveHooks(): array
    {
        global $wp_filter;

        $hooks = [];
        $current_filter = current_filter();

        if ($current_filter && isset($wp_filter[$current_filter])) {
            $hooks['current_filter'] = $current_filter;
            $hooks['current_priority'] = $wp_filter[$current_filter]->current_priority();

            // Lấy callbacks đang active
            $callbacks = $wp_filter[$current_filter]->callbacks;
            $hooks['active_callbacks'] = [];

            foreach ($callbacks as $priority => $callbacks_at_priority) {
                foreach ($callbacks_at_priority as $callback) {
                    $function_name = 'unknown';

                    if (is_string($callback['function'])) {
                        $function_name = $callback['function'];
                    } elseif (is_array($callback['function'])) {
                        if (is_object($callback['function'][0])) {
                            $function_name = get_class($callback['function'][0]) . '::' . $callback['function'][1];
                        } else {
                            $function_name = $callback['function'][0] . '::' . $callback['function'][1];
                        }
                    }

                    $hooks['active_callbacks'][] = [
                        'priority' => $priority,
                        'function' => $function_name,
                        'accepted_args' => $callback['accepted_args']
                    ];
                }
            }
        }

        return $hooks;
    }

    /**
     * Lấy thông tin active plugins
     *
     * @return array
     */
    private static function getActivePluginsInfo(): array
    {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        $active_plugins = get_option('active_plugins', []);
        $all_plugins = get_plugins();
        $plugin_info = [];

        foreach ($active_plugins as $plugin_file) {
            if (isset($all_plugins[$plugin_file])) {
                $plugin = $all_plugins[$plugin_file];
                $plugin_info[] = [
                    'file' => $plugin_file,
                    'name' => $plugin['Name'],
                    'version' => $plugin['Version'],
                    'author' => $plugin['Author']
                ];
            }
        }

        return $plugin_info;
    }

    /**
     * Tạo readable debug summary
     *
     * @param array $debugInfo
     * @return string
     */
    public static function formatDebugSummary(array $debugInfo): string
    {
        $summary = "🔍 Debug Info:\n";
        $summary .= "Issuer: {$debugInfo['issuer']}\n";
        $summary .= "Time: {$debugInfo['timestamp']}\n";
        $summary .= "Memory: {$debugInfo['memory_usage']} (Peak: {$debugInfo['peak_memory']})\n";
        $summary .= "Request: {$debugInfo['request_uri']}\n";
        $summary .= "IP: {$debugInfo['ip_address']}\n";

        if (isset($debugInfo['current_user'])) {
            $user = $debugInfo['current_user'];
            $summary .= "User: {$user['login']} (ID: {$user['id']})\n";
        }

        $summary .= "\n📍 Call Stack:\n";
        foreach ($debugInfo['backtrace'] as $frame) {
            $summary .= "  {$frame['readable']}\n";
        }

        if (!empty($debugInfo['context'])) {
            $summary .= "\n📋 Context:\n";
            foreach ($debugInfo['context'] as $key => $value) {
                if (is_array($value) || is_object($value)) {
                    $value = json_encode($value, JSON_UNESCAPED_UNICODE);
                }
                $summary .= "  {$key}: {$value}\n";
            }
        }

        return $summary;
    }

    /**
     * Log debug info to file (for development)
     *
     * @param array $debugInfo
     * @param string $filename
     * @return void
     */
    public static function logDebugInfo(array $debugInfo, string $filename = 'security-monitor-debug.log'): void
    {
        if (!WP_DEBUG || !WP_DEBUG_LOG) {
            return;
        }

        $logFile = WP_CONTENT_DIR . '/debug/' . $filename;
        $logDir = dirname($logFile);

        if (!is_dir($logDir)) {
            wp_mkdir_p($logDir);
        }

        $summary = self::formatDebugSummary($debugInfo);
        $timestamp = current_time('Y-m-d H:i:s');

        $logEntry = "\n" . str_repeat('=', 80) . "\n";
        $logEntry .= "[{$timestamp}] Security Monitor Debug\n";
        $logEntry .= str_repeat('-', 80) . "\n";
        $logEntry .= $summary;
        $logEntry .= str_repeat('=', 80) . "\n";

        error_log($logEntry, 3, $logFile);
    }

    /**
     * Tạo debug context cho file operations
     *
     * @param string $filePath
     * @param string $operation
     * @return array
     */
    public static function createFileDebugContext(string $filePath, string $operation = 'scan'): array
    {
        $context = [
            'operation' => $operation,
            'file_path' => $filePath,
            'file_exists' => file_exists($filePath),
            'file_readable' => is_readable($filePath),
            'file_writable' => is_writable($filePath)
        ];

        if (file_exists($filePath)) {
            $context['file_size'] = filesize($filePath);
            $context['file_modified'] = date('Y-m-d H:i:s', filemtime($filePath));
            $context['file_permissions'] = substr(sprintf('%o', fileperms($filePath)), -4);
            $context['file_owner'] = function_exists('posix_getpwuid') && function_exists('fileowner')
                ? posix_getpwuid(fileowner($filePath))['name'] ?? 'unknown'
                : 'unknown';
        }

        return $context;
    }

    /**
     * Tạo debug context cho network operations
     *
     * @param string $url
     * @param array $additionalData
     * @return array
     */
    public static function createNetworkDebugContext(string $url, array $additionalData = []): array
    {
        $parsed = parse_url($url);

        $context = [
            'url' => $url,
            'scheme' => $parsed['scheme'] ?? 'unknown',
            'host' => $parsed['host'] ?? 'unknown',
            'port' => $parsed['port'] ?? 'default',
            'path' => $parsed['path'] ?? '/',
            'query' => $parsed['query'] ?? null,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
            'referer' => $_SERVER['HTTP_REFERER'] ?? null
        ];

        // DNS lookup nếu có thể
        if (function_exists('gethostbyname') && isset($parsed['host'])) {
            $context['resolved_ip'] = gethostbyname($parsed['host']);
        }

        return array_merge($context, $additionalData);
    }
}
