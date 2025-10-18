<?php

namespace Puleeno\SecurityBot\WebMonitor\Issuers;

use Puleeno\SecurityBot\WebMonitor\Abstracts\RealtimeIssuerAbstract;

/**
 * Plugin/Theme Upload Security Issuer
 *
 * Scans uploaded plugins and themes for malicious code patterns
 * Blocks installation if malware is detected
 */
class PluginThemeUploadIssuer extends RealtimeIssuerAbstract
{
    protected $name = 'Malware Upload Scanner';
    protected $description = 'Scans uploaded plugins and themes for malicious code patterns';

    /**
     * Malicious code patterns to detect
     */
    private $maliciousPatterns = [
        // PHP execution functions
        'eval\s*\(' => 'eval() function detected',
        'assert\s*\(' => 'assert() function detected',
        'create_function\s*\(' => 'create_function() detected',
        'preg_replace.*e["\']' => 'preg_replace with e modifier',

        // System execution
        'system\s*\(' => 'system() function detected',
        'exec\s*\(' => 'exec() function detected',
        'shell_exec\s*\(' => 'shell_exec() function detected',
        'passthru\s*\(' => 'passthru() function detected',
        'proc_open\s*\(' => 'proc_open() function detected',
        'popen\s*\(' => 'popen() function detected',

        // File operations
        'php:\/\/input' => 'php://input access detected',
        'show_source\s*\(' => 'show_source() function detected',
        'highlight_file\s*\(' => 'highlight_file() function detected',
        'symlink\s*\(' => 'symlink() function detected',

        // Obfuscation
        'str_rot13\s*\(' => 'str_rot13() obfuscation detected',
        'base64_decode\s*\(' => 'base64_decode() obfuscation detected',
        'gzinflate\s*\(' => 'gzinflate() obfuscation detected',
        'gzuncompress\s*\(' => 'gzuncompress() obfuscation detected',
        'chr\s*\(' => 'chr() obfuscation detected',

        // Error suppression
        'set_time_limit\s*\(\s*0\s*\)' => 'set_time_limit(0) detected',
        'error_reporting\s*\(\s*0\s*\)' => 'error_reporting(0) detected',
        '@\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\(' => 'Error suppression operator @ detected',

        // Variable variables
        '\$\$\s*[a-zA-Z_][a-zA-Z0-9_]*' => 'Variable variables detected',
        '\$\{[^}]+\}' => 'Complex variable syntax detected',

        // HTTP requests
        'curl_init\s*\(' => 'curl_init() detected',
        'fsockopen\s*\(' => 'fsockopen() detected',

        // Database operations
        'mysql_query\s*\(' => 'mysql_query() detected',
        'mysqli_query\s*\(' => 'mysqli_query() detected',
        'pg_query\s*\(' => 'pg_query() detected',
    ];

    /**
     * Suspicious file extensions
     */
    private $suspiciousExtensions = ['php', 'phtml', 'php3', 'php4', 'php5', 'inc', 'tpl'];

    public function __construct()
    {
        $this->registerHooks();
    }

    /**
     * Register WordPress hooks
     */
    protected function registerHooks(): void
    {
        // Hook vào unzip_file filter - được gọi SAU KHI extract nhưng TRƯỚC KHI move files
        // Đây là hook CHÍNH để block malware trước khi install
        add_filter('unzip_file', [$this, 'scanAfterUnzip'], 10, 4);
    }

    /**
     * Scan extracted files after unzip but before moving to final destination
     *
     * @param mixed $result Result from unzip_file
     * @param string $file Original zip file path
     * @param string $to Extracted directory path
     * @param array $needed_dirs Required directories
     * @return mixed WP_Error if malware found, original result otherwise
     */
    public function scanAfterUnzip($result, $file, $to, $needed_dirs)
    {
        if (!$this->isEnabled()) {
            return $result;
        }

        // Nếu đã có error từ unzip, return luôn
        if (is_wp_error($result)) {
            return $result;
        }

        // Scan extracted directory
        $findings = $this->scanDirectory($to);

        if (!empty($findings)) {
            $fileName = basename($file);

            // Gửi alert TRƯỚC KHI return WP_Error
            $type = (strpos($file, 'plugin') !== false || strpos($to, 'plugin') !== false) ? 'plugin' : 'theme';
            $this->sendAlert($type, $fileName, $findings);

            // Return WP_Error để block installation
            $blockUpload = $this->config['block_suspicious_uploads'] ?? true;

            if ($blockUpload) {
                $this->removeDirectory($to);
                @unlink($file);

                return new \WP_Error(
                    'malware_detected',
                    sprintf(
                        '🚨 <strong>Security Alert</strong>: The uploaded file "<strong>%s</strong>" contains <strong>%d malicious file(s)</strong> with suspicious code patterns and has been blocked for your security.<br><br>Please contact your administrator if you believe this is a false positive.',
                        esc_html($fileName),
                        count($findings)
                    ),
                    ['findings' => $findings]
                );
            }
        }

        return $result;
    }

    /**
     * Scan directory for malicious files
     *
     * @param string $dir Directory to scan
     * @return array Findings grouped by file
     */
    private function scanDirectory(string $dir): array
    {
        $findings = [];

        if (!is_dir($dir)) {
            return $findings;
        }

        $filesScanned = 0;
        $maxFiles = $this->config['max_files_per_scan'] ?? 100;

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $file) {
            if ($filesScanned >= $maxFiles) {
                break;
            }

            if ($file->isFile()) {
                $fileName = $file->getFilename();

                // Chỉ scan PHP files
                if (!$this->isSuspiciousExtension($fileName)) {
                    continue;
                }

                // Scan file
                $content = @file_get_contents($file->getPathname());

                if ($content === false) {
                    continue;
                }

                $filesScanned++;

                $fileFindings = $this->scanFileContent($content, $file->getPathname());

                if (!empty($fileFindings)) {
                    // Store relative path for better readability
                    $relativePath = str_replace($dir . DIRECTORY_SEPARATOR, '', $file->getPathname());
                    $findings[$relativePath] = $fileFindings;
                }
            }
        }

        return $findings;
    }

    /**
     * Scan file content for malicious patterns
     *
     * @param string $content File content
     * @param string $fileName File name for logging
     * @return array Found patterns
     */
    private function scanFileContent(string $content, string $fileName): array
    {
        $findings = [];

        foreach ($this->maliciousPatterns as $pattern => $description) {
            if (preg_match('/' . $pattern . '/i', $content, $matches)) {
                $findings[] = [
                    'pattern' => $pattern,
                    'description' => $description,
                    'match' => $matches[0] ?? '',
                    'line' => $this->getLineNumber($content, $matches[0] ?? ''),
                ];
            }
        }

        return $findings;
    }

    /**
     * Get line number where pattern was found
     *
     * @param string $content File content
     * @param string $search Search string
     * @return int Line number
     */
    private function getLineNumber(string $content, string $search): int
    {
        $lines = explode("\n", $content);
        foreach ($lines as $lineNum => $line) {
            if (strpos($line, $search) !== false) {
                return $lineNum + 1;
            }
        }
        return 0;
    }

    /**
     * Check if file extension is suspicious
     *
     * @param string $fileName File name
     * @return bool
     */
    private function isSuspiciousExtension(string $fileName): bool
    {
        $ext = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
        return in_array($ext, $this->suspiciousExtensions);
    }

    /**
     * Remove directory recursively
     *
     * @param string $dir Directory path
     * @return bool
     */
    private function removeDirectory(string $dir): bool
    {
        if (!is_dir($dir)) {
            return false;
        }

        $files = array_diff(scandir($dir), ['.', '..']);
        foreach ($files as $file) {
            $path = $dir . DIRECTORY_SEPARATOR . $file;
            if (is_dir($path)) {
                $this->removeDirectory($path);
            } else {
                unlink($path);
            }
        }

        return rmdir($dir);
    }



    /**
     * Send security alert
     *
     * @param string $type Plugin or theme
     * @param string $name Item name
     * @param array $findings Malicious findings
     */
    private function sendAlert(string $type, string $name, array $findings): void
    {
        // Realtime issuer - gửi notification trực tiếp
        $bot = \Puleeno\SecurityBot\WebMonitor\Bot::getInstance();
        if ($bot) {
            // Tạo issue trước
            global $wpdb;
            $tableName = $wpdb->prefix . 'security_monitor_issues';

            // Thu thập thông tin người upload
            $uploaderId = get_current_user_id();
            $uploader = wp_get_current_user();
            $uploadMetadata = [
                'uploader_id' => $uploaderId,
                'uploader_login' => $uploader->user_login,
                'uploader_email' => $uploader->user_email,
                'uploader_display_name' => $uploader->display_name,
                'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
                'referer' => $_SERVER['HTTP_REFERER'] ?? 'unknown',
                'upload_time' => current_time('mysql'),
                'upload_method' => wp_doing_ajax() ? 'ajax' : (defined('WP_CLI') ? 'cli' : 'web'),
            ];

            $issueData = [
                'issue_hash' => md5($type . '_' . $name . '_' . time()),
                'issue_type' => 'malicious_' . $type,
                'severity' => 'critical',
                'title' => ucfirst($type) . ' Contains Malicious Code: ' . $name,
                'description' => sprintf(
                    '%s "%s" contains %d suspicious file(s) with malicious patterns',
                    ucfirst($type),
                    $name,
                    count($findings)
                ),
                'status' => 'new',
                'issuer_name' => 'PluginThemeUploadIssuer',
                'first_detected' => current_time('mysql'),
                'last_detected' => current_time('mysql'),
                'details' => json_encode($findings),
                'metadata' => json_encode($uploadMetadata),
                'ip_address' => $uploadMetadata['ip_address'],
                'user_agent' => $uploadMetadata['user_agent'],
            ];

            $wpdb->insert($tableName, $issueData);
            $issueId = $wpdb->insert_id;

            if ($issueId) {
                // Realtime issuer - gửi notification ngay lập tức qua Telegram
                try {
                    // Format message cho Telegram
                    $message = sprintf(
                        "🚨 *CẢNH BÁO BẢO MẬT*\n\n*%s Contains Malicious Code: %s*\n\n📝 _%s contains %d suspicious file(s) with malicious patterns_\n\n⚠️ Mức độ: 🔴 *CRITICAL*\n\n👤 *Người upload:*\n• Tên: %s (%s)\n• Email: %s\n• IP: %s\n• Phương thức: %s\n\n⏰ %s\n🌐 %s",
                        ucfirst($type),
                        $name,
                        ucfirst($type),
                        count($findings),
                        $uploadMetadata['uploader_display_name'],
                        $uploadMetadata['uploader_login'],
                        $uploadMetadata['uploader_email'],
                        $uploadMetadata['ip_address'],
                        strtoupper($uploadMetadata['upload_method']),
                        current_time('d/m/Y H:i:s'),
                        home_url()
                    );

                    $context = [
                        'issuer' => 'PluginThemeUploadIssuer',
                        'issue_data' => $issueData,
                        'findings' => $findings,
                        'timestamp' => current_time('mysql'),
                        'is_realtime' => true
                    ];

                    // Gửi trực tiếp qua Telegram channel
                    $telegramChannel = \Puleeno\SecurityBot\WebMonitor\Channels\TelegramChannel::getInstance();
                    if ($telegramChannel && $telegramChannel->isAvailable()) {
                        $telegramChannel->send($message, $context);
                    }
                } catch (\Exception $e) {
                    // Silent fail
                }
            }
        }
    }

    /**
     * Get issuer name
     *
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Detect issues (not used for realtime issuer)
     *
     * @return array
     */
    public function detect(): array
    {
        return [];
    }
}
