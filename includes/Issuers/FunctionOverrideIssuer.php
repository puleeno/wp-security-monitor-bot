<?php

namespace Puleeno\SecurityBot\WebMonitor\Issuers;

use Puleeno\SecurityBot\WebMonitor\Interfaces\IssuerInterface;
use Puleeno\SecurityBot\WebMonitor\DebugHelper;

/**
 * FunctionOverrideIssuer - Override dangerous functions với runkit7
 *
 * REQUIREMENTS:
 * - runkit7 extension phải được cài đặt
 * - runkit.internal_override = On trong php.ini
 *
 * STRATEGY:
 * 1. Rename original function to `_functionname`
 * 2. Create new function with original name
 * 3. Log/notify before calling original function
 * 4. Call original function với same parameters
 */
class FunctionOverrideIssuer implements IssuerInterface
{
    /**
     * @var array
     */
    private $config = [
        'enabled' => true,
        'priority' => 15, // Highest priority - setup trước
        'block_calls' => false, // Chỉ log, không block
        'max_alerts_per_hour' => 20,
        'detailed_logging' => true
    ];

    /**
     * @var array Functions to override
     */
    private $dangerousFunctions = [
        'eval',
        'exec',
        'system',
        'shell_exec',
        'passthru',
        'assert',
        'create_function',
        'file_get_contents', // Khi used với URLs
        'file_put_contents', // Khi used với user input
        'preg_replace'       // Khi dùng /e modifier
    ];

    /**
     * @var array Already overridden functions
     */
    private $overriddenFunctions = [];

    /**
     * @var string
     */
    private $alertCountKey = 'wp_security_monitor_function_override_alerts';

    /**
     * @var bool
     */
    private $runkitAvailable = false;

    public function __construct()
    {
        $this->runkitAvailable = $this->checkRunkitAvailability();

        if ($this->runkitAvailable) {
            // Override functions ngay khi class được load
            add_action('plugins_loaded', [$this, 'overrideDangerousFunctions'], 1);
        }
    }

    public function detect(): array
    {
        // Function override detection không cần scheduled checks
        // Chỉ cần setup một lần khi plugin load
        return [];
    }

    /**
     * Check runkit7 extension availability
     */
    private function checkRunkitAvailability(): bool
    {
        if (!extension_loaded('runkit7') && !extension_loaded('runkit')) {
            return false;
        }

        // Check if runkit.internal_override is enabled
        $internalOverride = ini_get('runkit.internal_override');
        if (!$internalOverride) {
            return false;
        }

        // Check if required functions exist
        $requiredFunctions = ['runkit_function_rename', 'runkit_function_add'];
        foreach ($requiredFunctions as $func) {
            if (!function_exists($func)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Override dangerous functions
     */
    public function overrideDangerousFunctions(): void
    {
        if (!$this->runkitAvailable) {
            return;
        }

        foreach ($this->dangerousFunctions as $functionName) {
            if (!function_exists($functionName)) {
                continue;
            }

            if (in_array($functionName, $this->overriddenFunctions)) {
                continue;
            }

            $this->overrideFunction($functionName);
        }
    }

    /**
     * Override single function
     */
    private function overrideFunction(string $functionName): bool
    {
        try {
            $backupName = '_' . $functionName;

            // Step 1: Rename original function
            if (!runkit_function_rename($functionName, $backupName)) {
                return false;
            }

            // Step 2: Create new function với same signature
            $newFunctionCode = $this->generateOverrideFunction($functionName, $backupName);

            if (!runkit_function_add($functionName, '', $newFunctionCode)) {
                // Rollback nếu failed
                runkit_function_rename($backupName, $functionName);
                return false;
            }

            $this->overriddenFunctions[] = $functionName;

            // Log successful override
            error_log("[WP Security Monitor] Successfully overridden function: {$functionName}");

            return true;

        } catch (\Exception $e) {
            error_log("[WP Security Monitor] Failed to override function {$functionName}: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Generate override function code
     */
    private function generateOverrideFunction(string $functionName, string $backupName): string
    {
        switch ($functionName) {
            case 'eval':
                return $this->generateEvalOverride($backupName);

            case 'exec':
                return $this->generateExecOverride($backupName);

            case 'system':
                return $this->generateSystemOverride($backupName);

            case 'shell_exec':
                return $this->generateShellExecOverride($backupName);

            case 'passthru':
                return $this->generatePassthruOverride($backupName);

            case 'assert':
                return $this->generateAssertOverride($backupName);

            case 'create_function':
                return $this->generateCreateFunctionOverride($backupName);

            case 'file_get_contents':
                return $this->generateFileGetContentsOverride($backupName);

            case 'file_put_contents':
                return $this->generateFilePutContentsOverride($backupName);

            case 'preg_replace':
                return $this->generatePregReplaceOverride($backupName);

            default:
                return $this->generateGenericOverride($functionName, $backupName);
        }
    }

    /**
     * Generate eval() override
     */
    private function generateEvalOverride(string $backupName): string
    {
        return "
        \$code = func_get_arg(0);

        // Log eval attempt
        \$this->logFunctionCall('eval', [\$code], [
            'code_preview' => substr(\$code, 0, 200),
            'code_hash' => md5(\$code),
            'severity' => 'critical'
        ]);

        // Call original function
        return {$backupName}(\$code);
        ";
    }

    /**
     * Generate exec() override
     */
    private function generateExecOverride(string $backupName): string
    {
        return "
        \$args = func_get_args();
        \$command = \$args[0] ?? '';

        // Log exec attempt
        \$this->logFunctionCall('exec', \$args, [
            'command' => \$command,
            'severity' => 'critical'
        ]);

        // Call original function with all args
        switch (func_num_args()) {
            case 1: return {$backupName}(\$args[0]);
            case 2: return {$backupName}(\$args[0], \$args[1]);
            case 3: return {$backupName}(\$args[0], \$args[1], \$args[2]);
            default: return {$backupName}(\$command);
        }
        ";
    }

    /**
     * Generate system() override
     */
    private function generateSystemOverride(string $backupName): string
    {
        return "
        \$args = func_get_args();
        \$command = \$args[0] ?? '';

        // Log system attempt
        \$this->logFunctionCall('system', \$args, [
            'command' => \$command,
            'severity' => 'critical'
        ]);

        // Call original function
        switch (func_num_args()) {
            case 1: return {$backupName}(\$args[0]);
            case 2: return {$backupName}(\$args[0], \$args[1]);
            default: return {$backupName}(\$command);
        }
        ";
    }

    /**
     * Generate shell_exec() override
     */
    private function generateShellExecOverride(string $backupName): string
    {
        return "
        \$command = func_get_arg(0);

        // Log shell_exec attempt
        \$this->logFunctionCall('shell_exec', [\$command], [
            'command' => \$command,
            'severity' => 'critical'
        ]);

        // Call original function
        return {$backupName}(\$command);
        ";
    }

    /**
     * Generate passthru() override
     */
    private function generatePassthruOverride(string $backupName): string
    {
        return "
        \$args = func_get_args();
        \$command = \$args[0] ?? '';

        // Log passthru attempt
        \$this->logFunctionCall('passthru', \$args, [
            'command' => \$command,
            'severity' => 'critical'
        ]);

        // Call original function
        switch (func_num_args()) {
            case 1: return {$backupName}(\$args[0]);
            case 2: return {$backupName}(\$args[0], \$args[1]);
            default: return {$backupName}(\$command);
        }
        ";
    }

    /**
     * Generate assert() override
     */
    private function generateAssertOverride(string $backupName): string
    {
        return "
        \$args = func_get_args();
        \$assertion = \$args[0] ?? '';

        // Check if assertion contains suspicious code
        if (is_string(\$assertion)) {
            \$this->logFunctionCall('assert', \$args, [
                'assertion' => \$assertion,
                'severity' => 'high'
            ]);
        }

        // Call original function
        switch (func_num_args()) {
            case 1: return {$backupName}(\$args[0]);
            case 2: return {$backupName}(\$args[0], \$args[1]);
            case 3: return {$backupName}(\$args[0], \$args[1], \$args[2]);
            default: return {$backupName}(\$assertion);
        }
        ";
    }

    /**
     * Generate create_function() override
     */
    private function generateCreateFunctionOverride(string $backupName): string
    {
        return "
        \$args = func_get_args();
        \$params = \$args[0] ?? '';
        \$body = \$args[1] ?? '';

        // Log create_function attempt
        \$this->logFunctionCall('create_function', \$args, [
            'params' => \$params,
            'body_preview' => substr(\$body, 0, 200),
            'severity' => 'high'
        ]);

        // Call original function
        return {$backupName}(\$params, \$body);
        ";
    }

    /**
     * Generate file_get_contents() override
     */
    private function generateFileGetContentsOverride(string $backupName): string
    {
        return "
        \$args = func_get_args();
        \$filename = \$args[0] ?? '';

        // Check if accessing URL (potential SSRF)
        if (filter_var(\$filename, FILTER_VALIDATE_URL)) {
            \$this->logFunctionCall('file_get_contents', \$args, [
                'url' => \$filename,
                'severity' => 'medium',
                'note' => 'URL access detected'
            ]);
        }

        // Call original function with all args
        switch (func_num_args()) {
            case 1: return {$backupName}(\$args[0]);
            case 2: return {$backupName}(\$args[0], \$args[1]);
            case 3: return {$backupName}(\$args[0], \$args[1], \$args[2]);
            case 4: return {$backupName}(\$args[0], \$args[1], \$args[2], \$args[3]);
            case 5: return {$backupName}(\$args[0], \$args[1], \$args[2], \$args[3], \$args[4]);
            default: return {$backupName}(\$filename);
        }
        ";
    }

    /**
     * Generate file_put_contents() override
     */
    private function generateFilePutContentsOverride(string $backupName): string
    {
        return "
        \$args = func_get_args();
        \$filename = \$args[0] ?? '';
        \$data = \$args[1] ?? '';

        // Check for suspicious file writes
        \$ext = strtolower(pathinfo(\$filename, PATHINFO_EXTENSION));
        if (in_array(\$ext, ['php', 'asp', 'jsp', 'py'])) {
            \$this->logFunctionCall('file_put_contents', \$args, [
                'filename' => \$filename,
                'data_preview' => substr(\$data, 0, 200),
                'severity' => 'high',
                'note' => 'Executable file write detected'
            ]);
        }

        // Call original function with all args
        switch (func_num_args()) {
            case 2: return {$backupName}(\$args[0], \$args[1]);
            case 3: return {$backupName}(\$args[0], \$args[1], \$args[2]);
            case 4: return {$backupName}(\$args[0], \$args[1], \$args[2], \$args[3]);
            default: return {$backupName}(\$filename, \$data);
        }
        ";
    }

    /**
     * Generate preg_replace() override
     */
    private function generatePregReplaceOverride(string $backupName): string
    {
        return "
        \$args = func_get_args();
        \$pattern = \$args[0] ?? '';

        // Check for /e modifier (deprecated but dangerous)
        if (is_string(\$pattern) && preg_match('/.*e[^\/]*$/', \$pattern)) {
            \$this->logFunctionCall('preg_replace', \$args, [
                'pattern' => \$pattern,
                'severity' => 'critical',
                'note' => '/e modifier detected - code execution possible'
            ]);
        }

        // Call original function with all args
        switch (func_num_args()) {
            case 3: return {$backupName}(\$args[0], \$args[1], \$args[2]);
            case 4: return {$backupName}(\$args[0], \$args[1], \$args[2], \$args[3]);
            case 5: return {$backupName}(\$args[0], \$args[1], \$args[2], \$args[3], \$args[4]);
            default: return {$backupName}(\$pattern, \$args[1], \$args[2]);
        }
        ";
    }

    /**
     * Generate generic override
     */
    private function generateGenericOverride(string $functionName, string $backupName): string
    {
        return "
        \$args = func_get_args();

        // Log function call
        \$this->logFunctionCall('{$functionName}', \$args, [
            'severity' => 'medium'
        ]);

        // Call original function
        return call_user_func_array('{$backupName}', \$args);
        ";
    }

        /**
     * Log function call và create issue với full context tracing
     */
    private function logFunctionCall(string $functionName, array $args, array $metadata = []): void
    {
        // Rate limiting
        if (!$this->checkRateLimit()) {
            return;
        }

        $severity = $metadata['severity'] ?? 'medium';

        // Get comprehensive execution context
        $executionContext = $this->getExecutionContext();
        $backtraceInfo = $this->getDetailedBacktrace();

        // Create issue
        $issueManager = new \Puleeno\SecurityBot\WebMonitor\IssueManager();

        $issue = [
            'type' => 'dangerous_function_call',
            'severity' => $severity,
            'message' => "Dangerous function '{$functionName}' called",
            'details' => [
                'function_name' => $functionName,
                'arguments_count' => count($args),
                'metadata' => $metadata,
                'execution_context' => $executionContext,
                'backtrace_info' => $backtraceInfo,
                'timestamp' => current_time('mysql')
            ],
            'debug_info' => DebugHelper::createIssueDebugInfo()
        ];

        $issueManager->recordIssue($issue);

        // Enhanced logging
        error_log(sprintf(
            '[WP Security Monitor] Dangerous function call: %s() - Context: %s - Source: %s',
            $functionName,
            $executionContext['context_type'],
            $backtraceInfo['source_summary']
        ));

        // Optional: Block call if configured
        if ($this->config['block_calls'] && $severity === 'critical') {
            wp_die('Function call blocked for security reasons.');
        }
    }

    /**
     * Get comprehensive execution context
     */
    private function getExecutionContext(): array
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
            $context['ip_address'] = $this->getRealIPAddress();
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

            if ($context['user_id']) {
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
    private function getDetailedBacktrace(): array
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
            // Skip first few frames (override functions)
            if ($index < 3) continue;

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
        $likelySource = $this->determineLikelySource($callChain);

        $backtraceInfo['call_chain'] = array_slice($callChain, 0, 10); // Limit to 10 frames
        $backtraceInfo['files_involved'] = array_unique($filesInvolved);
        $backtraceInfo['likely_source'] = $likelySource;
        $backtraceInfo['plugin_theme_info'] = $pluginThemeInfo;
        $backtraceInfo['source_summary'] = $this->createSourceSummary($likelySource, $pluginThemeInfo);

        return $backtraceInfo;
    }

    /**
     * Determine likely source of function call
     */
    private function determineLikelySource(array $callChain): string
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
    private function createSourceSummary(string $likelySource, array $pluginThemeInfo): string
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
    private function getRealIPAddress(): string
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
     * Rate limiting cho function call alerts
     */
    private function checkRateLimit(): bool
    {
        $currentHour = date('Y-m-d-H');
        $alerts = get_option($this->alertCountKey, []);

        $hourlyCount = $alerts[$currentHour] ?? 0;

        if ($hourlyCount >= $this->config['max_alerts_per_hour']) {
            return false;
        }

        // Increment count
        $alerts[$currentHour] = $hourlyCount + 1;

        // Clean old hours
        $alerts = array_slice($alerts, -24, 24, true);

        update_option($this->alertCountKey, $alerts);

        return true;
    }

    public function getName(): string
    {
        return 'Function Override Security Monitor';
    }

    public function getPriority(): int
    {
        return $this->config['priority'];
    }

    public function isEnabled(): bool
    {
        return $this->config['enabled'] && $this->runkitAvailable;
    }

    public function configure(array $config): void
    {
        $this->config = array_merge($this->config, $config);
    }

    /**
     * Get override status
     */
    public function getOverrideStatus(): array
    {
        return [
            'runkit_available' => $this->runkitAvailable,
            'overridden_functions' => $this->overriddenFunctions,
            'total_functions' => count($this->dangerousFunctions),
            'override_percentage' => count($this->overriddenFunctions) / count($this->dangerousFunctions) * 100
        ];
    }
}
