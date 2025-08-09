<?php

namespace Puleeno\SecurityBot\WebMonitor\Issuers;

use Puleeno\SecurityBot\WebMonitor\Interfaces\IssuerInterface;
use Puleeno\SecurityBot\WebMonitor\DebugHelper;

/**
 * EvalFunctionIssuer
 *
 * Scan các file PHP để tìm các hàm nguy hiểm như eval(), exec(), shell_exec(), system()
 * Tracking caller và cho phép admin ignore những file đã được kiểm tra
 *
 * @package Puleeno\SecurityBot\WebMonitor\Issuers
 */
class EvalFunctionIssuer implements IssuerInterface
{
    private array $config = [];
    private string $optionKey = 'wp_security_monitor_eval_scan_data';
    private string $ignoreOptionKey = 'wp_security_monitor_eval_ignore_hashes';

    /**
     * Các hàm nguy hiểm cần scan
     */
    private array $dangerousFunctions = [
        'eval' => [
            'pattern' => '/\beval\s*\(/i',
            'severity' => 'critical',
            'description' => 'eval() function allows arbitrary code execution'
        ],
        'exec' => [
            'pattern' => '/\bexec\s*\(/i',
            'severity' => 'high',
            'description' => 'exec() function executes system commands'
        ],
        'shell_exec' => [
            'pattern' => '/\bshell_exec\s*\(/i',
            'severity' => 'high',
            'description' => 'shell_exec() function executes shell commands'
        ],
        'system' => [
            'pattern' => '/\bsystem\s*\(/i',
            'severity' => 'high',
            'description' => 'system() function executes system commands'
        ],
        'passthru' => [
            'pattern' => '/\bpassthru\s*\(/i',
            'severity' => 'high',
            'description' => 'passthru() function executes system commands'
        ],
        'file_get_contents_remote' => [
            'pattern' => '/file_get_contents\s*\(\s*[\'"]https?:\/\//i',
            'severity' => 'medium',
            'description' => 'file_get_contents() with remote URL can be dangerous'
        ],
        'curl_exec' => [
            'pattern' => '/\bcurl_exec\s*\(/i',
            'severity' => 'medium',
            'description' => 'curl_exec() can be used for remote code execution'
        ],
        'base64_decode_eval' => [
            'pattern' => '/eval\s*\(\s*base64_decode\s*\(/i',
            'severity' => 'critical',
            'description' => 'eval(base64_decode()) pattern commonly used in malware'
        ],
        'preg_replace_eval' => [
            'pattern' => '/preg_replace\s*\([^,]*\/[^\/]*e[^\/]*\/[^,]*,/i',
            'severity' => 'critical',
            'description' => 'preg_replace() with /e modifier allows code execution'
        ],
        'create_function' => [
            'pattern' => '/\bcreate_function\s*\(/i',
            'severity' => 'high',
            'description' => 'create_function() is deprecated and can be dangerous'
        ]
    ];

    /**
     * Directories to scan
     */
    private array $scanDirectories = [
        'themes' => 'wp-content/themes',
        'plugins' => 'wp-content/plugins',
        'uploads' => 'wp-content/uploads',
        'mu-plugins' => 'wp-content/mu-plugins'
    ];

    /**
     * File extensions to scan
     */
    private array $scanExtensions = ['.php', '.php3', '.php4', '.php5', '.phtml', '.inc'];

    /**
     * Implement detection method
     */
    public function detect(): array
    {
        $issues = [];
        $scanData = $this->getScanData();
        $ignoredHashes = $this->getIgnoredHashes();

        foreach ($this->scanDirectories as $dirType => $relativePath) {
            $fullPath = ABSPATH . $relativePath;

            if (!is_dir($fullPath)) {
                continue;
            }

            $files = $this->getPhpFiles($fullPath);

            // Exclude this plugin's files from scanning
            $files = $this->excludeOwnPluginFiles($files);
            $maxFiles = $this->getConfig('max_files_per_scan', 50);

            // Limit số files scan mỗi lần để tránh timeout
            $filesToScan = array_slice($files, 0, $maxFiles);

            foreach ($filesToScan as $filePath) {
                $fileHash = $this->getFileHash($filePath);

                // Skip nếu file đã được ignore
                if (in_array($fileHash, $ignoredHashes)) {
                    continue;
                }

                // Skip nếu file chưa thay đổi từ lần scan trước
                if (isset($scanData[$filePath]) && $scanData[$filePath]['hash'] === $fileHash) {
                    continue;
                }

                $fileIssues = $this->scanFile($filePath, $dirType);
                if (!empty($fileIssues)) {
                    $issues = array_merge($issues, $fileIssues);
                }

                // Update scan data
                $scanData[$filePath] = [
                    'hash' => $fileHash,
                    'last_scanned' => current_time('mysql'),
                    'size' => filesize($filePath)
                ];
            }
        }

        // Save scan data
        $this->updateScanData($scanData);

        return $issues;
    }

    /**
     * Scan một file cụ thể
     */
    private function scanFile(string $filePath, string $dirType): array
    {
        $issues = [];

        if (!is_readable($filePath)) {
            return $issues;
        }

        $content = file_get_contents($filePath);
        if ($content === false) {
            return $issues;
        }

        // Scan cho từng dangerous function
        foreach ($this->dangerousFunctions as $functionName => $config) {
            $matches = $this->findMatches($content, $config['pattern'], $filePath);

            foreach ($matches as $match) {
                $issues[] = $this->createEvalIssue(
                    $filePath,
                    $functionName,
                    $match,
                    $config,
                    $dirType
                );
            }
        }

        return $issues;
    }

    /**
     * Tìm matches trong file content
     */
    private function findMatches(string $content, string $pattern, string $filePath): array
    {
        $matches = [];
        $lines = explode("\n", $content);

        foreach ($lines as $lineNumber => $line) {
            if (preg_match($pattern, $line, $match)) {
                $matches[] = [
                    'line_number' => $lineNumber + 1,
                    'line_content' => trim($line),
                    'match' => $match[0],
                    'context' => $this->getLineContext($lines, $lineNumber)
                ];
            }
        }

        return $matches;
    }

    /**
     * Lấy context xung quanh line được match
     */
    private function getLineContext(array $lines, int $lineNumber, int $contextLines = 3): array
    {
        $start = max(0, $lineNumber - $contextLines);
        $end = min(count($lines) - 1, $lineNumber + $contextLines);

        $context = [];
        for ($i = $start; $i <= $end; $i++) {
            $context[] = [
                'line_number' => $i + 1,
                'content' => $lines[$i],
                'is_match' => $i === $lineNumber
            ];
        }

        return $context;
    }

    /**
     * Tạo issue cho eval function detection
     */
    private function createEvalIssue(string $filePath, string $functionName, array $match, array $config, string $dirType): array
    {
        $relativeFilePath = str_replace(ABSPATH, '', $filePath);
        $fileHash = $this->getFileHash($filePath);

        $title = sprintf(
            "Dangerous function '%s' found in %s",
            $functionName,
            basename($filePath)
        );

        $description = $this->generateDescription($filePath, $functionName, $match, $config, $dirType);

        return [
            'message' => $title,
            'details' => $description,
            'type' => 'dangerous_function',
            'function_name' => $functionName,
            'file_path' => $relativeFilePath,
            'file_hash' => $fileHash,
            'line_number' => $match['line_number'],
            'matched_code' => $match['line_content'],
            'directory_type' => $dirType,
            'severity' => $config['severity'],
            'debug_info' => DebugHelper::createIssueDebugInfo($this->getName(), [
                'file_path' => $relativeFilePath,
                'function_name' => $functionName,
                'match_details' => $match,
                'scan_config' => $config
            ])
        ];
    }

    /**
     * Generate description cho issue
     */
    private function generateDescription(string $filePath, string $functionName, array $match, array $config, string $dirType): string
    {
        $relativeFilePath = str_replace(ABSPATH, '', $filePath);
        $lines = [];

        $lines[] = "**Dangerous Function Detected**";
        $lines[] = "";
        $lines[] = "**Function Information:**";
        $lines[] = "- Function: `{$functionName}()`";
        $lines[] = "- Description: {$config['description']}";
        $lines[] = "- Severity: {$config['severity']}";
        $lines[] = "";
        $lines[] = "**File Information:**";
        $lines[] = "- File: `{$relativeFilePath}`";
        $lines[] = "- Directory Type: {$dirType}";
        $lines[] = "- Line Number: {$match['line_number']}";
        $lines[] = "- File Size: " . $this->formatBytes(filesize($filePath));
        $lines[] = "- Last Modified: " . date('Y-m-d H:i:s', filemtime($filePath));
        $lines[] = "";
        $lines[] = "**Code Context:**";
        $lines[] = "```php";

        foreach ($match['context'] as $contextLine) {
            $prefix = $contextLine['is_match'] ? '>>> ' : '    ';
            $lines[] = sprintf('%s%3d: %s', $prefix, $contextLine['line_number'], $contextLine['content']);
        }

        $lines[] = "```";
        $lines[] = "";
        $lines[] = "**Matched Code:**";
        $lines[] = "```php";
        $lines[] = $match['line_content'];
        $lines[] = "```";
        $lines[] = "";
        $lines[] = "**Recommendations:**";
        $lines[] = $this->getRecommendations($functionName);

        return implode("\n", $lines);
    }

    /**
     * Get recommendations dựa trên function name
     */
    private function getRecommendations(string $functionName): string
    {
        $recommendations = [
            'eval' => "- Review code carefully to ensure it's legitimate\n- Consider using safer alternatives\n- If legitimate, you can ignore this issue",
            'exec' => "- Verify if system command execution is necessary\n- Sanitize all inputs properly\n- Consider using WordPress APIs instead",
            'shell_exec' => "- Review if shell command execution is required\n- Ensure proper input validation\n- Use WordPress built-in functions when possible",
            'system' => "- Check if system calls are legitimate\n- Validate and sanitize all inputs\n- Consider alternative approaches",
            'passthru' => "- Verify necessity of system command execution\n- Implement proper input validation\n- Use safer alternatives if possible",
            'file_get_contents_remote' => "- Verify remote URL access is intentional\n- Use wp_remote_get() for HTTP requests\n- Implement proper error handling",
            'curl_exec' => "- Review if cURL usage is legitimate\n- Use wp_remote_request() for HTTP requests\n- Ensure proper input validation",
            'base64_decode_eval' => "- This pattern is commonly used in malware\n- Remove immediately if not legitimate\n- Scan for additional malicious code",
            'preg_replace_eval' => "- Update to use preg_replace_callback()\n- The /e modifier is deprecated and dangerous\n- Review for potential security vulnerabilities",
            'create_function' => "- Replace with anonymous functions (closures)\n- create_function() is deprecated since PHP 7.2\n- Use modern PHP syntax instead"
        ];

        return $recommendations[$functionName] ?? "- Review code for legitimacy\n- Ensure proper security measures\n- Consider safer alternatives";
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
     * Lấy danh sách PHP files từ directory
     */
    private function getPhpFiles(string $directory): array
    {
        $files = [];
        $maxDepth = $this->getConfig('max_scan_depth', 3);

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($directory, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::LEAVES_ONLY
        );

        $iterator->setMaxDepth($maxDepth);

        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $extension = '.' . strtolower($file->getExtension());
                if (in_array($extension, $this->scanExtensions)) {
                    $files[] = $file->getPathname();
                }
            }
        }

        // Sort by last modified time (newest first)
        usort($files, function($a, $b) {
            return filemtime($b) - filemtime($a);
        });

        return $files;
    }

    /**
     * Get file hash for tracking changes
     */
    private function getFileHash(string $filePath): string
    {
        return md5_file($filePath) . '_' . filemtime($filePath);
    }

    /**
     * Get scan data từ options
     */
    private function getScanData(): array
    {
        return get_option($this->optionKey, []);
    }

    /**
     * Update scan data
     */
    private function updateScanData(array $data): void
    {
        // Giữ chỉ data của 30 ngày gần nhất để tránh database quá lớn
        $cutoffTime = current_time('timestamp') - (30 * DAY_IN_SECONDS);

        foreach ($data as $filePath => $fileData) {
            $lastScanned = strtotime($fileData['last_scanned']);
            if ($lastScanned < $cutoffTime) {
                unset($data[$filePath]);
            }
        }

        update_option($this->optionKey, $data);
    }

    /**
     * Get ignored file hashes
     */
    private function getIgnoredHashes(): array
    {
        return get_option($this->ignoreOptionKey, []);
    }

    /**
     * Add file hash to ignore list
     */
    public function addIgnoredHash(string $hash): void
    {
        $ignored = $this->getIgnoredHashes();
        if (!in_array($hash, $ignored)) {
            $ignored[] = $hash;
            update_option($this->ignoreOptionKey, $ignored);
        }
    }

    /**
     * Remove file hash from ignore list
     */
    public function removeIgnoredHash(string $hash): void
    {
        $ignored = $this->getIgnoredHashes();
        $ignored = array_filter($ignored, function($item) use ($hash) {
            return $item !== $hash;
        });
        update_option($this->ignoreOptionKey, array_values($ignored));
    }

    /**
     * Format bytes to human readable
     */
    private function formatBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];
        for ($i = 0; $bytes >= 1024 && $i < count($units) - 1; $i++) {
            $bytes /= 1024;
        }
        return round($bytes, 2) . ' ' . $units[$i];
    }

    /**
     * Get configuration value
     */
    private function getConfig(string $key, $default = null)
    {
        return $this->config[$key] ?? $default;
    }

    /**
     * Get issuer name
     */
    public function getName(): string
    {
        return 'Dangerous Function Scanner';
    }

    /**
     * Get priority
     */
    public function getPriority(): int
    {
        return 15; // Medium-high priority
    }

    /**
     * Check if enabled
     */
    public function isEnabled(): bool
    {
        return $this->getConfig('enabled', true);
    }

    /**
     * Configure issuer
     */
    public function configure(array $config): void
    {
        $this->config = array_merge($this->config, $config);

        // Update scan directories if provided
        if (isset($config['scan_directories'])) {
            $this->scanDirectories = array_merge($this->scanDirectories, $config['scan_directories']);
        }

        // Update dangerous functions if provided
        if (isset($config['dangerous_functions'])) {
            $this->dangerousFunctions = array_merge($this->dangerousFunctions, $config['dangerous_functions']);
        }
    }
}
