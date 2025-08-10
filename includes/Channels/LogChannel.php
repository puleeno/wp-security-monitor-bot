<?php

namespace Puleeno\SecurityBot\WebMonitor\Channels;

use Puleeno\SecurityBot\WebMonitor\Abstracts\Channel;

/**
 * LogChannel
 *
 * Ghi security alerts vào file log với rotation và management features
 *
 * @package Puleeno\SecurityBot\WebMonitor\Channels
 */
class LogChannel extends Channel
{
    /**
     * Default log directory (relative to WordPress root)
     */
    private string $defaultLogDir = 'wp-content/uploads/security-logs';

    /**
     * Log file name pattern
     */
    private string $logFilePattern = 'security-monitor-%Y-%m-%d.log';

    /**
     * Maximum log file size (in bytes)
     */
    private int $maxFileSize = 10 * 1024 * 1024; // 10MB

    /**
     * Maximum number of log files to keep
     */
    private int $maxFiles = 30; // 30 days

    /**
     * Log levels
     */
    private array $logLevels = [
        'critical' => 'CRITICAL',
        'high' => 'ERROR',
        'medium' => 'WARNING',
        'low' => 'INFO'
    ];

    /**
     * Get channel name
     */
    public function getName(): string
    {
        return 'Log File';
    }

    /**
     * Send message to log file
     */
    public function send(string $message, array $data = []): bool
    {
        if (!$this->isAvailable()) {
            $this->logError('Log channel is not properly configured');
            return false;
        }

        try {
            $logEntry = $this->formatLogEntry($message, $data);
            $logFile = $this->getLogFilePath();

            // Ensure log directory exists and is writable
            if (!$this->ensureLogDirectory()) {
                $this->logError('Failed to create or access log directory: ' . $this->getLogDirectory());
                return false;
            }

            // Check file size and rotate if needed
            $this->rotateLogIfNeeded($logFile);

            // Write log entry with better error handling
            $result = file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);

            if ($result === false) {
                $error = error_get_last();
                $this->logError('Failed to write to log file: ' . $logFile . '. Error: ' . ($error['message'] ?? 'Unknown error'));
                return false;
            }

            // Clean old log files
            $this->cleanOldLogs();

            return true;

        } catch (\Exception $e) {
            $this->logError('Log channel error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Check if log channel is available
     */
    protected function checkConnection(): bool
    {
        $logDir = $this->getLogDirectory();

        // Check if directory exists or can be created
        if (!is_dir($logDir)) {
            if (!wp_mkdir_p($logDir)) {
                return false;
            }
        }

        // Check if directory is writable
        if (!is_writable($logDir)) {
            return false;
        }

        // Test write operation
        $testFile = $logDir . '/test-' . time() . '.tmp';
        $testContent = 'Security Monitor Log Test - ' . date('Y-m-d H:i:s');

        $result = file_put_contents($testFile, $testContent);

        if ($result !== false && file_exists($testFile)) {
            unlink($testFile); // Clean up test file
            return true;
        }

        return false;
    }

    /**
     * Configure channel
     */
    public function configure(array $config): void
    {
        parent::configure($config);

        $this->defaultLogDir = $this->getConfig('log_directory', $this->defaultLogDir);
        $this->logFilePattern = $this->getConfig('file_pattern', $this->logFilePattern);
        $this->maxFileSize = $this->getConfig('max_file_size', $this->maxFileSize);
        $this->maxFiles = $this->getConfig('max_files', $this->maxFiles);
    }

    /**
     * Format log entry
     */
    private function formatLogEntry(string $message, array $data): string
    {
        $issuer = $data['issuer'] ?? 'Unknown';
        $issues = $data['issues'] ?? [];
        $timestamp = current_time('Y-m-d H:i:s');
        $siteUrl = get_site_url();
        $siteName = get_bloginfo('name');

        // Determine log level
        $logLevel = $this->determineLogLevel($issues);

        // Build log entry
        $logEntry = [];

        // Header line
        $logEntry[] = sprintf(
            '[%s] %s - %s - %s (%s)',
            $timestamp,
            $logLevel,
            $siteName,
            $issuer,
            $siteUrl
        );

        // Issues details
        if (!empty($issues)) {
            foreach ($issues as $index => $issue) {
                $logEntry[] = sprintf(
                    '  Issue #%d: %s',
                    $index + 1,
                    $issue['message'] ?? 'Security issue detected'
                );

                // Add issue details
                if (isset($issue['severity'])) {
                    $logEntry[] = sprintf('    Severity: %s', strtoupper($issue['severity']));
                }

                if (isset($issue['type'])) {
                    $logEntry[] = sprintf('    Type: %s', $issue['type']);
                }

                if (isset($issue['file_path'])) {
                    $logEntry[] = sprintf('    File: %s', $issue['file_path']);
                }

                if (isset($issue['ip_address'])) {
                    $logEntry[] = sprintf('    IP: %s', $issue['ip_address']);
                }

                if (isset($issue['domain'])) {
                    $logEntry[] = sprintf('    Domain: %s', $issue['domain']);
                }

                if (isset($issue['details']) && !empty($issue['details'])) {
                    $details = str_replace(["\r\n", "\n", "\r"], ' ', $issue['details']);
                    $details = preg_replace('/\s+/', ' ', $details);
                    if (strlen($details) > 200) {
                        $details = substr($details, 0, 200) . '...';
                    }
                    $logEntry[] = sprintf('    Details: %s', trim($details));
                }

                // Add debug info if available
                if (isset($issue['debug_info']) && $this->getConfig('include_debug_info', false)) {
                    $debugInfo = is_array($issue['debug_info']) ? json_encode($issue['debug_info']) : $issue['debug_info'];
                    $logEntry[] = sprintf('    Debug: %s', $debugInfo);
                }

                $logEntry[] = ''; // Empty line between issues
            }
        } else {
            $logEntry[] = '  No specific issue details available';
            $logEntry[] = '';
        }

        // Summary line
        $issueCount = count($issues);
        $logEntry[] = sprintf(
            '  Summary: %d issue(s) detected by %s at %s',
            $issueCount,
            $issuer,
            $timestamp
        );

        $logEntry[] = str_repeat('-', 80); // Separator
        $logEntry[] = ''; // Empty line

        return implode("\n", $logEntry);
    }

    /**
     * Determine log level based on issues
     */
    private function determineLogLevel(array $issues): string
    {
        if (empty($issues)) {
            return 'INFO';
        }

        $severities = array_column($issues, 'severity');

        if (in_array('critical', $severities)) {
            return $this->logLevels['critical'];
        } elseif (in_array('high', $severities)) {
            return $this->logLevels['high'];
        } elseif (in_array('medium', $severities)) {
            return $this->logLevels['medium'];
        } else {
            return $this->logLevels['low'];
        }
    }

    /**
     * Get log file path for current date
     */
    private function getLogFilePath(): string
    {
        $logDir = $this->getLogDirectory();

        // Use a safe, clean date format for filename
        $fileName = 'security-monitor-' . date('Y-m-d') . '.log';

        return $logDir . '/' . $fileName;
    }

    /**
     * Get log directory path
     */
    private function getLogDirectory(): string
    {
        $logDir = $this->defaultLogDir;

        // Convert relative path to absolute
        if (!path_is_absolute($logDir)) {
            $logDir = ABSPATH . $logDir;
        }

        return $logDir;
    }

    /**
     * Ensure log directory exists
     */
    private function ensureLogDirectory(): bool
    {
        $logDir = $this->getLogDirectory();

        try {
            if (!is_dir($logDir)) {
                if (!wp_mkdir_p($logDir)) {
                    $this->logError('Cannot create log directory: ' . $logDir);
                    return false;
                }

                // Verify directory was created
                if (!is_dir($logDir)) {
                    $this->logError('Directory creation failed: ' . $logDir);
                    return false;
                }
            }

            // Check if directory is writable
            if (!is_writable($logDir)) {
                $this->logError('Log directory is not writable: ' . $logDir);
                return false;
            }

            // Create .htaccess to protect log files
            $this->createHtaccessProtection($logDir);

            // Create index.php to prevent directory listing
            $this->createIndexFile($logDir);

            return true;
        } catch (\Exception $e) {
            $this->logError('Error ensuring log directory: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Create .htaccess file to protect logs
     */
    private function createHtaccessProtection(string $logDir): void
    {
        $htaccessFile = $logDir . '/.htaccess';

        if (!file_exists($htaccessFile)) {
            $htaccessContent = [
                '# Security Monitor Bot - Log Protection',
                'Order deny,allow',
                'Deny from all',
                '<Files "*.log">',
                '    Deny from all',
                '</Files>'
            ];

            file_put_contents($htaccessFile, implode("\n", $htaccessContent));
        }
    }

    /**
     * Create index.php to prevent directory listing
     */
    private function createIndexFile(string $logDir): void
    {
        $indexFile = $logDir . '/index.php';

        if (!file_exists($indexFile)) {
            $indexContent = "<?php\n// Security Monitor Bot - Access Denied\nhttp_response_code(403);\nexit('Access Denied');";
            file_put_contents($indexFile, $indexContent);
        }
    }

    /**
     * Rotate log file if it exceeds size limit
     */
    private function rotateLogIfNeeded(string $logFile): void
    {
        if (!file_exists($logFile)) {
            return;
        }

        $fileSize = filesize($logFile);

        if ($fileSize >= $this->maxFileSize) {
            $rotatedFile = $logFile . '.old.' . time();
            rename($logFile, $rotatedFile);

            // Compress old file if possible
            if (function_exists('gzopen')) {
                $this->compressLogFile($rotatedFile);
            }
        }
    }

    /**
     * Compress log file using gzip
     */
    private function compressLogFile(string $logFile): void
    {
        try {
            $gzFile = $logFile . '.gz';

            $input = fopen($logFile, 'rb');
            $output = gzopen($gzFile, 'wb9');

            if ($input && $output) {
                while (!feof($input)) {
                    gzwrite($output, fread($input, 8192));
                }

                fclose($input);
                gzclose($output);

                // Remove original file after compression
                unlink($logFile);
            }
        } catch (\Exception $e) {
            // If compression fails, keep original file
            $this->logError('Log compression failed: ' . $e->getMessage());
        }
    }

    /**
     * Clean old log files
     */
    private function cleanOldLogs(): void
    {
        $logDir = $this->getLogDirectory();

        if (!is_dir($logDir)) {
            return;
        }

        $files = glob($logDir . '/security-monitor-*.log*');

        if (empty($files)) {
            return;
        }

        // Sort files by modification time (oldest first)
        usort($files, function($a, $b) {
            return filemtime($a) - filemtime($b);
        });

        // Remove old files if we exceed the limit
        $filesToRemove = count($files) - $this->maxFiles;

        if ($filesToRemove > 0) {
            for ($i = 0; $i < $filesToRemove; $i++) {
                if (file_exists($files[$i])) {
                    unlink($files[$i]);
                }
            }
        }
    }

    /**
     * Get log file statistics
     */
    public function getLogStats(): array
    {
        $logDir = $this->getLogDirectory();
        $stats = [
            'log_directory' => $logDir,
            'directory_exists' => is_dir($logDir),
            'directory_writable' => is_dir($logDir) && is_writable($logDir),
            'total_files' => 0,
            'total_size' => 0,
            'oldest_file' => null,
            'newest_file' => null,
            'files' => []
        ];

        if (!is_dir($logDir)) {
            return $stats;
        }

        $files = glob($logDir . '/security-monitor-*.log*');

        if (empty($files)) {
            return $stats;
        }

        $stats['total_files'] = count($files);

        foreach ($files as $file) {
            $fileInfo = [
                'name' => basename($file),
                'size' => filesize($file),
                'modified' => filemtime($file),
                'readable' => is_readable($file)
            ];

            $stats['total_size'] += $fileInfo['size'];
            $stats['files'][] = $fileInfo;

            if ($stats['oldest_file'] === null || $fileInfo['modified'] < $stats['oldest_file']) {
                $stats['oldest_file'] = $fileInfo['modified'];
            }

            if ($stats['newest_file'] === null || $fileInfo['modified'] > $stats['newest_file']) {
                $stats['newest_file'] = $fileInfo['modified'];
            }
        }

        return $stats;
    }

    /**
     * Read log entries from file(s)
     */
    public function readLogs(int $maxLines = 100, string $dateFilter = null): array
    {
        $logDir = $this->getLogDirectory();
        $entries = [];

        if (!is_dir($logDir)) {
            return $entries;
        }

        // Get log files
        $pattern = $dateFilter ?
            "security-monitor-{$dateFilter}*.log*" :
            'security-monitor-*.log*';

        $files = glob($logDir . '/' . $pattern);

        if (empty($files)) {
            return $entries;
        }

        // Sort files by modification time (newest first)
        usort($files, function($a, $b) {
            return filemtime($b) - filemtime($a);
        });

        $lineCount = 0;

        foreach ($files as $file) {
            if ($lineCount >= $maxLines) {
                break;
            }

            $content = $this->readLogFile($file);
            $lines = explode("\n", $content);

            foreach (array_reverse($lines) as $line) {
                if ($lineCount >= $maxLines) {
                    break;
                }

                if (!empty(trim($line))) {
                    $entries[] = [
                        'file' => basename($file),
                        'line' => $line,
                        'timestamp' => $this->extractTimestamp($line)
                    ];
                    $lineCount++;
                }
            }
        }

        return array_reverse($entries); // Return in chronological order
    }

    /**
     * Read log file content (handle compressed files)
     */
    private function readLogFile(string $file): string
    {
        if (str_ends_with($file, '.gz')) {
            return gzfile($file) ? implode('', gzfile($file)) : '';
        } else {
            return file_get_contents($file) ?: '';
        }
    }

    /**
     * Extract timestamp from log line
     */
    private function extractTimestamp(string $line): ?string
    {
        if (preg_match('/^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]/', $line, $matches)) {
            return $matches[1];
        }

        return null;
    }

    /**
     * Test connection method
     */
    public function testConnection(): array
    {
        try {
            if (!$this->isAvailable()) {
                return [
                    'success' => false,
                    'message' => 'Log channel not available. Check directory permissions.'
                ];
            }

            // Test write operation
            $testLogFile = $this->getLogDirectory() . '/test-' . time() . '.log';
            $testContent = sprintf(
                "[%s] TEST - Security Monitor Bot Test Log Entry\n",
                current_time('Y-m-d H:i:s')
            );

            $result = file_put_contents($testLogFile, $testContent);

            if ($result !== false) {
                // Clean up test file
                if (file_exists($testLogFile)) {
                    unlink($testLogFile);
                }

                $stats = $this->getLogStats();

                return [
                    'success' => true,
                    'message' => sprintf(
                        'Log channel is working. Directory: %s (%d files, %s total)',
                        $stats['log_directory'],
                        $stats['total_files'],
                        $this->formatBytes($stats['total_size'])
                    )
                ];
            } else {
                return [
                    'success' => false,
                    'message' => 'Failed to write test log entry. Check directory permissions.'
                ];
            }

        } catch (\Exception $e) {
            return [
                'success' => false,
                'message' => 'Log test failed: ' . $e->getMessage()
            ];
        }
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
     * Check if path is absolute
     */
    private function path_is_absolute(string $path): bool
    {
        return !empty($path) && ($path[0] === '/' || (strlen($path) > 3 && $path[1] === ':'));
    }

    /**
     * Get suggested configuration
     */
    public static function getSuggestedConfig(): array
    {
        return [
            'log_directory' => [
                'type' => 'text',
                'label' => 'Log Directory',
                'description' => 'Directory để lưu log files (relative to WordPress root)',
                'required' => false,
                'default' => 'wp-content/uploads/security-logs',
                'placeholder' => 'wp-content/uploads/security-logs'
            ],
            'file_pattern' => [
                'type' => 'text',
                'label' => 'File Pattern',
                'description' => 'Pattern cho tên file log (sử dụng date format)',
                'required' => false,
                'default' => 'security-monitor-%Y-%m-%d.log',
                'placeholder' => 'security-monitor-%Y-%m-%d.log'
            ],
            'max_file_size' => [
                'type' => 'number',
                'label' => 'Max File Size (MB)',
                'description' => 'Kích thước tối đa của mỗi log file',
                'required' => false,
                'default' => 10,
                'min' => 1,
                'max' => 100
            ],
            'max_files' => [
                'type' => 'number',
                'label' => 'Max Files',
                'description' => 'Số lượng file log tối đa giữ lại',
                'required' => false,
                'default' => 30,
                'min' => 1,
                'max' => 365
            ],
            'include_debug_info' => [
                'type' => 'checkbox',
                'label' => 'Include Debug Info',
                'description' => 'Bao gồm debug information trong log entries',
                'required' => false,
                'default' => false
            ]
        ];
    }

    /**
     * Validate configuration
     */
    public function validateConfig(array $config): array
    {
        $errors = [];

        // Validate log directory
        if (!empty($config['log_directory'])) {
            $logDir = $config['log_directory'];

            // Check for invalid characters
            if (preg_match('/[<>"|*?]/', $logDir)) {
                $errors[] = 'Log directory contains invalid characters';
            }
        }

        // Validate file pattern
        if (!empty($config['file_pattern'])) {
            $pattern = $config['file_pattern'];

            if (!str_contains($pattern, '%Y') || !str_contains($pattern, '%m') || !str_contains($pattern, '%d')) {
                $errors[] = 'File pattern must include %Y, %m, and %d for date formatting';
            }

            if (!str_ends_with($pattern, '.log')) {
                $errors[] = 'File pattern should end with .log extension';
            }
        }

        // Validate max file size
        if (isset($config['max_file_size'])) {
            $maxSize = intval($config['max_file_size']);
            if ($maxSize < 1 || $maxSize > 100) {
                $errors[] = 'Max file size must be between 1 and 100 MB';
            }
        }

        // Validate max files
        if (isset($config['max_files'])) {
            $maxFiles = intval($config['max_files']);
            if ($maxFiles < 1 || $maxFiles > 365) {
                $errors[] = 'Max files must be between 1 and 365';
            }
        }

        return $errors;
    }
}
