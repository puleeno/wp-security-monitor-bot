<?php

namespace Puleeno\SecurityBot\WebMonitor\Issuers;

use Puleeno\SecurityBot\WebMonitor\Interfaces\IssuerInterface;
use Puleeno\SecurityBot\WebMonitor\DebugHelper;

/**
 * BackdoorDetectionIssuer - Detect known backdoor patterns
 *
 * PERFORMANCE-OPTIMIZED:
 * - Chỉ scan files khi có file modification events
 * - Targeted patterns cho known backdoors
 * - Skip binary files và large files
 * - Rate limiting để avoid false positives
 */
class BackdoorDetectionIssuer implements IssuerInterface
{
    /**
     * @var array
     */
    private $config = [
        'enabled' => true,
        'priority' => 8,
        'max_file_size' => 1048576, // 1MB
        'scan_depth' => 3,
        'max_files_per_scan' => 20,
        'excluded_extensions' => ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'zip', 'tar', 'gz'],
        'high_risk_extensions' => ['php', 'asp', 'aspx', 'jsp', 'py', 'pl', 'cgi'],
        'scan_directories' => [
            'wp-content/themes',
            'wp-content/plugins',
            'wp-content/uploads',
            'wp-admin',
            'wp-includes'
        ]
    ];

    /**
     * @var array Known backdoor signatures
     */
    private $backdoorPatterns = [
        // PHP backdoors
        'php_backdoors' => [
            // eval() based
            '/eval\s*\(\s*base64_decode/i',
            '/eval\s*\(\s*gzinflate/i',
            '/eval\s*\(\s*gzuncompress/i',
            '/eval\s*\(\s*str_rot13/i',
            '/eval\s*\(\s*\$_[GET|POST|REQUEST|COOKIE]/i',

            // assert() backdoors
            '/assert\s*\(\s*base64_decode/i',
            '/assert\s*\(\s*\$_[GET|POST|REQUEST]/i',

            // preg_replace() /e modifier
            '/preg_replace\s*\([^,]*\/[^\/]*e[^\/]*\//i',

            // create_function() backdoors
            '/create_function\s*\([^,]*,\s*[\'"][^\'"]*(eval|base64_decode)/i',

            // file_get_contents() + eval
            '/eval\s*\(\s*file_get_contents/i',

            // Shell execution
            '/system\s*\(\s*base64_decode/i',
            '/exec\s*\(\s*base64_decode/i',
            '/shell_exec\s*\(\s*base64_decode/i',
            '/passthru\s*\(\s*base64_decode/i',

            // Dynamic function calls
            '/\$[a-z_]+\s*\(\s*base64_decode/i',
            '/\$\{[^}]*\}\s*\(/i',

            // Obfuscated patterns
            '/chr\s*\(\s*\d+\s*\)\s*\.\s*chr/i',
            '/\\x[0-9a-f]{2}\\x[0-9a-f]{2}/i',

            // Common backdoor variables
            '/\$_[A-Z]+\[[\'"][a-z0-9_]+[\'"]\]\s*\(/i',

            // Known backdoor functions
            '/\b(c99|r57|wso|b374k|indoxploit|adminer)\b/i',

            // File operations with user input
            '/file_put_contents\s*\([^,]*\$_(GET|POST|REQUEST)/i',
            '/fwrite\s*\([^,]*\$_(GET|POST|REQUEST)/i',

            // Database operations with user input
            '/mysql_query\s*\(\s*\$_(GET|POST|REQUEST)/i',
            '/mysqli_query\s*\([^,]*\$_(GET|POST|REQUEST)/i'
        ],

        // ASP/ASPX backdoors
        'asp_backdoors' => [
            '/eval\s*\(\s*request\s*\(/i',
            '/execute\s*\(\s*request\s*\(/i',
            '/response\.write\s*\(\s*eval/i'
        ],

        // JSP backdoors
        'jsp_backdoors' => [
            '/runtime\.getruntime\(\)\.exec/i',
            '/processbuilder\s*\(/i'
        ],

        // Suspicious base64 patterns
        'base64_patterns' => [
            // Common PHP functions encoded
            '/[A-Za-z0-9+\/]{50,}={0,2}/', // Long base64 strings
        ],

        // Known malware signatures
        'malware_signatures' => [
            // C99 shell variants
            '/c99sh_getpwd|c99_buff_prepare|c99_sess_put/i',

            // WSO shell
            '/wso_version|WSOsetcookie|wso_ex/i',

            // R57 shell
            '/r57shell|r57_getCwd|r57_fsbuff/i',

            // B374k shell
            '/b374k|SAJAK|authenticate_email/i',

            // IndoXploit
            '/indoxploit|suid_exec_python/i',

            // Common webshell names in comments
            '/\/\*.*?(?:shell|backdoor|rootkit|bypass|hack).*?\*\//is'
        ]
    ];

    /**
     * @var array Ignored file hashes
     */
    private $ignoredHashes = [];

    /**
     * @var string
     */
    private $ignoredHashesKey = 'wp_security_monitor_backdoor_ignored_hashes';

    /**
     * @var string
     */
    private $lastScanKey = 'wp_security_monitor_backdoor_last_scan';

        public function __construct()
    {
        $this->ignoredHashes = get_option($this->ignoredHashesKey, []);

        // Schedule WP Cron job cho backdoor scanning
        add_action('wp_security_monitor_backdoor_scan', [$this, 'performScheduledScan']);

        // Hook vào file modifications để schedule scans (không scan trực tiếp)
        add_action('wp_update_plugins', [$this, 'scheduleScan']);
        add_action('wp_update_themes', [$this, 'scheduleScan']);
        add_action('upgrader_process_complete', [$this, 'scheduleScan'], 10, 2);

        // Schedule regular scans
        $this->scheduleRegularScan();
    }

        public function detect(): array
    {
        // BackdoorDetectionIssuer chỉ chạy trong WP Cron
        // Không scan trong detect() để tránh performance impact
        return [];
    }

    /**
     * Perform targeted backdoor scan
     */
    private function performTargetedScan(): array
    {
        $detectedFiles = [];
        $scannedCount = 0;

        foreach ($this->config['scan_directories'] as $directory) {
            $fullPath = ABSPATH . $directory;

            if (!is_dir($fullPath)) {
                continue;
            }

            $files = $this->getFilesToScan($fullPath);

            // Exclude this plugin's files from scanning
            $files = $this->excludeOwnPluginFiles($files);

            foreach ($files as $file) {
                if ($scannedCount >= $this->config['max_files_per_scan']) {
                    break 2; // Break both loops
                }

                $result = $this->scanFile($file);
                if ($result) {
                    $detectedFiles[] = $result;
                }

                $scannedCount++;
            }
        }

        return $detectedFiles;
    }

    /**
     * Exclude this plugin's files from scanning
     */
    private function excludeOwnPluginFiles(array $files): array
    {
        $pluginDir = dirname(dirname(__DIR__)); // Get plugin root directory
        $pluginPath = wp_normalize_path($pluginDir);

        return array_filter($files, function($file) use ($pluginPath) {
            $normalizedFile = wp_normalize_path($file);
            return strpos($normalizedFile, $pluginPath) === false;
        });
    }

    /**
     * Get files to scan trong directory
     */
    private function getFilesToScan(string $directory): array
    {
        $files = [];
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($directory, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::LEAVES_ONLY
        );

        $iterator->setMaxDepth($this->config['scan_depth']);

        foreach ($iterator as $file) {
            if (!$file->isFile()) {
                continue;
            }

            // Skip large files
            if ($file->getSize() > $this->config['max_file_size']) {
                continue;
            }

            $extension = strtolower($file->getExtension());

            // Skip excluded extensions
            if (in_array($extension, $this->config['excluded_extensions'])) {
                continue;
            }

            // Priority cho high-risk extensions
            if (in_array($extension, $this->config['high_risk_extensions'])) {
                array_unshift($files, $file->getPathname());
            } else {
                $files[] = $file->getPathname();
            }
        }

        return array_slice($files, 0, $this->config['max_files_per_scan']);
    }

    /**
     * Scan single file cho backdoor patterns
     */
    private function scanFile(string $filePath): ?array
    {
        // Check if file is ignored
        $fileHash = md5_file($filePath);
        if (in_array($fileHash, $this->ignoredHashes)) {
            return null;
        }

        $content = file_get_contents($filePath);
        if ($content === false) {
            return null;
        }

        $detectedPatterns = [];
        $extension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));

        // Scan based on file type
        if ($extension === 'php') {
            $detectedPatterns = array_merge(
                $detectedPatterns,
                $this->scanForPatterns($content, $this->backdoorPatterns['php_backdoors'], 'PHP Backdoor')
            );
        } elseif (in_array($extension, ['asp', 'aspx'])) {
            $detectedPatterns = array_merge(
                $detectedPatterns,
                $this->scanForPatterns($content, $this->backdoorPatterns['asp_backdoors'], 'ASP Backdoor')
            );
        } elseif ($extension === 'jsp') {
            $detectedPatterns = array_merge(
                $detectedPatterns,
                $this->scanForPatterns($content, $this->backdoorPatterns['jsp_backdoors'], 'JSP Backdoor')
            );
        }

        // Scan for common patterns regardless of extension
        $detectedPatterns = array_merge(
            $detectedPatterns,
            $this->scanForPatterns($content, $this->backdoorPatterns['malware_signatures'], 'Known Malware'),
            $this->scanForSuspiciousBase64($content)
        );

        if (!empty($detectedPatterns)) {
            return [
                'file' => $filePath,
                'file_hash' => $fileHash,
                'relative_path' => str_replace(ABSPATH, '', $filePath),
                'patterns' => $detectedPatterns,
                'file_size' => filesize($filePath),
                'last_modified' => filemtime($filePath)
            ];
        }

        return null;
    }

    /**
     * Scan for specific patterns
     */
    private function scanForPatterns(string $content, array $patterns, string $type): array
    {
        $detected = [];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $content, $matches)) {
                $detected[] = [
                    'type' => $type,
                    'pattern' => $pattern,
                    'match' => $matches[0] ?? '',
                    'context' => $this->getPatternContext($content, $matches[0] ?? '')
                ];
            }
        }

        return $detected;
    }

    /**
     * Scan for suspicious base64 encoded content
     */
    private function scanForSuspiciousBase64(string $content): array
    {
        $detected = [];

        // Find base64 patterns
        preg_match_all('/[A-Za-z0-9+\/]{50,}={0,2}/', $content, $matches);

        foreach ($matches[0] as $base64String) {
            $decoded = base64_decode($base64String, true);

            if ($decoded !== false) {
                // Check if decoded content contains suspicious patterns
                $suspiciousInDecoded = [];
                $suspiciousInDecoded = array_merge(
                    $suspiciousInDecoded,
                    $this->scanForPatterns($decoded, $this->backdoorPatterns['php_backdoors'], 'Encoded PHP Backdoor')
                );

                if (!empty($suspiciousInDecoded)) {
                    $detected[] = [
                        'type' => 'Base64 Encoded Backdoor',
                        'encoded' => substr($base64String, 0, 100) . '...',
                        'decoded_patterns' => $suspiciousInDecoded
                    ];
                }
            }
        }

        return $detected;
    }

    /**
     * Get context around pattern match
     */
    private function getPatternContext(string $content, string $match): string
    {
        $position = strpos($content, $match);
        if ($position === false) {
            return '';
        }

        $start = max(0, $position - 100);
        $length = min(200, strlen($content) - $start);

        return substr($content, $start, $length);
    }

    /**
     * Create issues from scan results
     */
    private function createBackdoorIssues(array $scanResults): array
    {
        $issues = [];

        foreach ($scanResults as $result) {
            $severity = $this->calculateSeverity($result['patterns']);

            $issues[] = [
                'type' => 'backdoor_detected',
                'severity' => $severity,
                'message' => sprintf('Backdoor patterns detected in %s', $result['relative_path']),
                'details' => [
                    'file_path' => $result['relative_path'],
                    'file_hash' => $result['file_hash'],
                    'file_size' => $result['file_size'],
                    'last_modified' => date('Y-m-d H:i:s', $result['last_modified']),
                    'detected_patterns' => $result['patterns'],
                    'pattern_count' => count($result['patterns'])
                ],
                'debug_info' => DebugHelper::createFileDebugContext($result['file'])
            ];
        }

        return $issues;
    }

    /**
     * Calculate severity based on detected patterns
     */
    private function calculateSeverity(array $patterns): string
    {
        $criticalPatterns = ['eval', 'system', 'exec', 'shell_exec', 'passthru'];
        $highPatterns = ['base64_decode', 'assert', 'create_function'];

        foreach ($patterns as $pattern) {
            $match = strtolower($pattern['match'] ?? '');

            foreach ($criticalPatterns as $critical) {
                if (strpos($match, $critical) !== false) {
                    return 'critical';
                }
            }

            foreach ($highPatterns as $high) {
                if (strpos($match, $high) !== false) {
                    return 'high';
                }
            }
        }

        return 'medium';
    }

    /**
     * Add file hash to ignored list
     */
    public function addIgnoredHash(string $fileHash): void
    {
        if (!in_array($fileHash, $this->ignoredHashes)) {
            $this->ignoredHashes[] = $fileHash;
            update_option($this->ignoredHashesKey, $this->ignoredHashes);
        }
    }

        /**
     * Schedule regular backdoor scan via WP Cron
     */
    private function scheduleRegularScan(): void
    {
        $cronHook = 'wp_security_monitor_backdoor_scan';

        if (!wp_next_scheduled($cronHook)) {
            // Schedule scan mỗi 6 hours
            wp_schedule_event(time(), 'twicedaily', $cronHook);
        }
    }

    /**
     * Schedule immediate scan (trong background via WP Cron)
     */
    public function scheduleScan(): void
    {
        $cronHook = 'wp_security_monitor_backdoor_scan';

        // Schedule scan ngay lập tức (nhưng vẫn qua cron)
        if (!wp_next_scheduled($cronHook)) {
            wp_schedule_single_event(time() + 60, $cronHook); // Delay 1 phút
        }
    }

    /**
     * Perform scheduled scan (chỉ chạy trong WP Cron)
     */
    public function performScheduledScan(): void
    {
        // Chỉ chạy trong WP Cron context
        if (!wp_doing_cron()) {
            return;
        }

        // Skip nếu scan quá gần (throttling)
        $lastScan = get_option($this->lastScanKey, 0);
        if (time() - $lastScan < 3600) { // 1 hour throttle
            return;
        }

        try {
            $scanResults = $this->performTargetedScan();

            if (!empty($scanResults)) {
                $issues = $this->createBackdoorIssues($scanResults);

                // Record issues via IssueManager
                $issueManager = new \Puleeno\SecurityBot\WebMonitor\IssueManager();
                foreach ($issues as $issue) {
                    $issueManager->recordIssue($issue);
                }

                // Log scan results
                error_log(sprintf(
                    '[WP Security Monitor] Backdoor scan completed: %d threats detected in %d files',
                    count($issues),
                    count($scanResults)
                ));
            }

            // Update last scan time
            update_option($this->lastScanKey, time());

        } catch (\Exception $e) {
            // Log errors
            error_log('[WP Security Monitor] Backdoor scan error: ' . $e->getMessage());

            // Record error as issue
            $issueManager = new \Puleeno\SecurityBot\WebMonitor\IssueManager();
            $issueManager->recordIssue([
                'type' => 'backdoor_scan_error',
                'severity' => 'low',
                'message' => 'Error during backdoor scanning',
                'details' => $e->getMessage(),
                'debug_info' => DebugHelper::createIssueDebugInfo($this->getName())
            ]);
        }
    }

    public function getName(): string
    {
        return 'Backdoor Detection Scanner';
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
