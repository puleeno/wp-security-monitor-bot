<?php

namespace Puleeno\SecurityBot\WebMonitor\Issuers;

use Puleeno\SecurityBot\WebMonitor\Interfaces\IssuerInterface;
use Puleeno\SecurityBot\WebMonitor\DebugHelper;
use Puleeno\SecurityBot\WebMonitor\ForensicHelper;

/**
 * SQLInjectionAttemptIssuer - Detect SQL injection attack attempts
 *
 * Monitor cho SQL injection patterns trong HTTP requests và database errors
 */
class SQLInjectionAttemptIssuer implements IssuerInterface
{
    /**
     * @var array
     */
    private $config = [
        'enabled' => true,
        'priority' => 10, // Highest priority
        'log_all_attempts' => true,
        'block_suspicious_requests' => false, // Chỉ log, không block
        'max_alerts_per_hour' => 10
    ];

    /**
     * @var array SQL injection patterns
     */
    private $sqlPatterns = [
        // Union-based injection
        '/union\s+select/i',
        '/union\s+all\s+select/i',

        // Boolean-based blind
        '/\s+and\s+\d+\s*=\s*\d+/i',
        '/\s+or\s+\d+\s*=\s*\d+/i',
        '/\s+and\s+.+\s*=\s*.+/i',

        // Time-based blind
        '/sleep\s*\(/i',
        '/benchmark\s*\(/i',
        '/waitfor\s+delay/i',

        // Error-based
        '/extractvalue\s*\(/i',
        '/updatexml\s*\(/i',
        '/concat\s*\(\s*0x/i',

        // Database enumeration
        '/information_schema/i',
        '/mysql\.user/i',
        '/sysdatabases/i',
        '/msysaccessobjects/i',

        // Command execution
        '/xp_cmdshell/i',
        '/sp_oacreate/i',

        // Comment-based
        '/\/\*.*\*\//i',
        '/--\s/i',
        '/#.*$/m',

        // Common functions
        '/load_file\s*\(/i',
        '/into\s+outfile/i',
        '/into\s+dumpfile/i',

        // String manipulation
        '/char\s*\(\s*\d+/i',
        '/ascii\s*\(/i',
        '/substring\s*\(/i',

        // Conditional statements
        '/if\s*\(\s*\d+\s*=\s*\d+/i',
        '/case\s+when/i',

        // Special characters sequences
        '/\'\s*(or|and)\s*\'/i',
        '/\'\s*(union|select|insert|update|delete|drop)\s/i',
        '/0x[0-9a-f]+/i'
    ];

    /**
     * @var array Database error patterns
     */
    private $dbErrorPatterns = [
        '/mysql_fetch_array/i',
        '/mysql_num_rows/i',
        '/mysql_query/i',
        '/you have an error in your sql syntax/i',
        '/mysql server version for the right syntax/i',
        '/\[mysql\]/i',
        '/supplied argument is not a valid mysql/i',
        '/table.*doesn\'t exist/i',
        '/unknown column/i',
        '/column count doesn\'t match/i'
    ];

    /**
     * @var string
     */
    private $alertCountKey = 'wp_security_monitor_sqli_alerts_hour';

    public function __construct()
    {
        // Hook vào WordPress request processing
        add_action('init', [$this, 'monitorRequest'], 1);

        // Hook vào database errors
        add_action('wp_die_handler', [$this, 'monitorDatabaseErrors'], 10, 1);

        // Monitor AJAX requests
        add_action('wp_ajax_nopriv_*', [$this, 'monitorAjaxRequest'], 1);
        add_action('wp_ajax_*', [$this, 'monitorAjaxRequest'], 1);
    }

    public function detect(): array
    {
        // Detection được thực hiện qua hooks, không cần chạy scheduled
        return [];
    }

    /**
     * Monitor HTTP request cho SQL injection patterns
     */
    public function monitorRequest(): void
    {
        if (!$this->isEnabled()) {
            return;
        }

        // Skip admin và login pages để tránh false positives
        if (is_admin() || strpos($_SERVER['REQUEST_URI'], 'wp-login.php') !== false) {
            return;
        }

        $suspiciousParams = [];

        // Check GET parameters
        foreach ($_GET as $key => $value) {
            if ($this->containsSQLInjection($value)) {
                $suspiciousParams['GET'][$key] = $value;
            }
        }

        // Check POST parameters
        foreach ($_POST as $key => $value) {
            if (is_string($value) && $this->containsSQLInjection($value)) {
                $suspiciousParams['POST'][$key] = $value;
            }
        }

        // Check raw POST data
        $rawPost = file_get_contents('php://input');
        if ($rawPost && $this->containsSQLInjection($rawPost)) {
            $suspiciousParams['RAW_POST'] = substr($rawPost, 0, 500); // First 500 chars
        }

        // Check cookies
        foreach ($_COOKIE as $key => $value) {
            if ($this->containsSQLInjection($value)) {
                $suspiciousParams['COOKIE'][$key] = $value;
            }
        }

        // Check headers
        $headers = getallheaders();
        if ($headers) {
            foreach ($headers as $name => $value) {
                if ($this->containsSQLInjection($value)) {
                    $suspiciousParams['HEADER'][$name] = $value;
                }
            }
        }

        if (!empty($suspiciousParams)) {
            $this->logSQLInjectionAttempt($suspiciousParams);
        }
    }

    /**
     * Monitor AJAX requests
     */
    public function monitorAjaxRequest(): void
    {
        // AJAX requests cũng được monitor qua monitorRequest()
        // Có thể thêm specific logic cho AJAX nếu cần
    }

    /**
     * Monitor database errors
     */
    public function monitorDatabaseErrors($handler): callable
    {
        return function($message, $title = '', $args = []) use ($handler) {
            if ($this->isEnabled()) {
                // Check if error message contains SQL injection indicators
                if ($this->containsDatabaseError($message)) {
                    $this->logDatabaseError($message, $title, $args);
                }
            }

            // Call original handler
            return call_user_func($handler, $message, $title, $args);
        };
    }

    /**
     * Kiểm tra string có chứa SQL injection pattern không
     */
    private function containsSQLInjection(string $input): bool
    {
        $input = urldecode($input); // Decode URL encoding
        $input = html_entity_decode($input); // Decode HTML entities

        foreach ($this->sqlPatterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Kiểm tra database error message
     */
    private function containsDatabaseError(string $message): bool
    {
        foreach ($this->dbErrorPatterns as $pattern) {
            if (preg_match($pattern, $message)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Log SQL injection attempt
     */
    private function logSQLInjectionAttempt(array $suspiciousParams): void
    {
        // Rate limiting
        if (!$this->checkRateLimit()) {
            return;
        }

        $severity = $this->calculateSeverity($suspiciousParams);

                // Tạo issue với full forensic data
        $issueManager = new \Puleeno\SecurityBot\WebMonitor\IssueManager();
        
        $issue = ForensicHelper::createSecurityIssue(
            'sql_injection_attempt',
            $severity,
            'SQL Injection attempt detected',
            [
                'suspicious_parameters' => $suspiciousParams,
                'detection_patterns' => $this->getMatchedPatterns($suspiciousParams)
            ],
            1 // Skip this function frame
        );

        $issueManager->recordIssue($issue);

        // Enhanced logging với forensic context
        ForensicHelper::logSecurityEvent(
            'SQL_INJECTION_ATTEMPT',
            'SQL Injection patterns detected',
            [
                'severity' => $severity,
                'patterns_count' => count($this->getMatchedPatterns($suspiciousParams)),
                'parameters_affected' => array_keys($suspiciousParams)
            ]
        );

        // Optional: Block request if configured
        if ($this->config['block_suspicious_requests'] && $severity === 'critical') {
            $this->blockRequest();
        }
    }

    /**
     * Log database error
     */
    private function logDatabaseError(string $message, string $title, array $args): void
    {
        // Rate limiting
        if (!$this->checkRateLimit()) {
            return;
        }

                $issueManager = new \Puleeno\SecurityBot\WebMonitor\IssueManager();
        
        $issue = ForensicHelper::createSecurityIssue(
            'database_error_sqli',
            'medium',
            'Database error potentially caused by SQL injection',
            [
                'error_message' => $message,
                'error_title' => $title,
                'error_patterns' => $this->getDbErrorPatterns($message)
            ],
            1 // Skip this function frame
        );

        $issueManager->recordIssue($issue);
    }

    /**
     * Calculate severity based on patterns detected
     */
    private function calculateSeverity(array $suspiciousParams): string
    {
        $criticalPatterns = [
            '/union\s+select/i',
            '/drop\s+table/i',
            '/delete\s+from/i',
            '/insert\s+into/i',
            '/load_file/i',
            '/into\s+outfile/i'
        ];

        $allParams = '';
        foreach ($suspiciousParams as $method => $params) {
            if (is_array($params)) {
                $allParams .= implode(' ', $params);
            } else {
                $allParams .= $params;
            }
        }

        foreach ($criticalPatterns as $pattern) {
            if (preg_match($pattern, $allParams)) {
                return 'critical';
            }
        }

        return 'high'; // Default to high for any SQL injection attempt
    }

    /**
     * Rate limiting để tránh spam alerts
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

        // Clean old hours (keep only last 24 hours)
        $alerts = array_slice($alerts, -24, 24, true);

        update_option($this->alertCountKey, $alerts);

        return true;
    }

    /**
     * Get database error patterns cho forensic analysis
     */
    private function getDbErrorPatterns(string $message): array
    {
        $matches = [];
        
        foreach ($this->dbErrorPatterns as $pattern) {
            if (preg_match($pattern, $message, $match)) {
                $matches[] = [
                    'pattern' => $pattern,
                    'match' => $match[0] ?? ''
                ];
            }
        }
        
        return $matches;
    }

    /**
     * Get matched patterns cho forensic analysis
     */
    private function getMatchedPatterns(array $suspiciousParams): array
    {
        $matchedPatterns = [];
        
        foreach ($suspiciousParams as $method => $params) {
            if (is_array($params)) {
                foreach ($params as $key => $value) {
                    $matches = $this->findMatchingPatterns($value);
                    if (!empty($matches)) {
                        $matchedPatterns["{$method}[{$key}]"] = $matches;
                    }
                }
            } else {
                $matches = $this->findMatchingPatterns($params);
                if (!empty($matches)) {
                    $matchedPatterns[$method] = $matches;
                }
            }
        }
        
        return $matchedPatterns;
    }

    /**
     * Find matching SQL injection patterns
     */
    private function findMatchingPatterns(string $input): array
    {
        $matches = [];
        $input = urldecode($input);
        $input = html_entity_decode($input);
        
        foreach ($this->sqlPatterns as $pattern) {
            if (preg_match($pattern, $input, $match)) {
                $matches[] = [
                    'pattern' => $pattern,
                    'match' => $match[0] ?? '',
                    'full_match' => $match
                ];
            }
        }
        
        return $matches;
    }

    /**
     * Block suspicious request
     */
    private function blockRequest(): void
    {
        header('HTTP/1.1 403 Forbidden');
        die('Request blocked due to suspicious activity.');
    }

    public function getName(): string
    {
        return 'SQL Injection Attempt Detector';
    }

    public function getPriority(): int
    {
        return $this->config['priority'];
    }

    public function isEnabled(): bool
    {
        return $this->config['enabled'];
    }

    public function configure(array $config): void
    {
        $this->config = array_merge($this->config, $config);
    }
}
