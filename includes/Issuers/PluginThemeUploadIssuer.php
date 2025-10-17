<?php
namespace Puleeno\SecurityBot\WebMonitor\Issuers;

use Puleeno\SecurityBot\WebMonitor\Abstracts\RealtimeIssuerAbstract;

/**
 * Plugin/Theme Upload Scanner Issuer
 *
 * Detects và scan plugins/themes khi được upload
 * Tìm malicious code patterns: error_reporting(0), set_time_limit(0), str_rot13, shell functions
 */
class PluginThemeUploadIssuer extends RealtimeIssuerAbstract
{
    /**
     * @var string
     */
    protected $name = 'Plugin/Theme Upload Scanner';

    /**
     * @var string
     */
    protected $description = 'Scans uploaded plugins and themes for malicious code';

    /**
     * @var array Malicious patterns cần detect
     */
    private $maliciousPatterns = [
        'error_reporting\s*\(\s*0\s*\)' => 'Error reporting disabled',
        'set_time_limit\s*\(\s*0\s*\)' => 'Time limit disabled',
        'str_rot13' => 'ROT13 encoding detected',
        'base64_decode' => 'Base64 decode detected',
        'eval\s*\(' => 'Eval function detected',
        'system\s*\(' => 'System command execution',
        'exec\s*\(' => 'Exec command execution',
        'shell_exec' => 'Shell execution detected',
        'passthru' => 'Passthru function detected',
        'proc_open' => 'Process open detected',
        'popen' => 'Pipe open detected',
        'curl_exec' => 'cURL execution detected',
        'curl_multi_exec' => 'cURL multi execution',
        'parse_ini_file' => 'INI file parsing',
        'show_source' => 'Source code disclosure',
        'symlink' => 'Symbolic link creation',
        'link' => 'Hard link creation',
        '@\$_(GET|POST|REQUEST|COOKIE|SERVER)\[' => 'Direct superglobal access',
        'file_get_contents\s*\(\s*[\'"]php:\/\/input' => 'PHP input stream access',
        'assert\s*\(' => 'Assert function (code execution)',
        'create_function' => 'Create function (deprecated, dangerous)',
        'preg_replace.*\/e' => 'PREG replace with eval modifier',
        '\$\{' => 'Variable variables (potential obfuscation)',
        'goto\s+' => 'Goto statement (obfuscation)',
    ];

    /**
     * @var array Suspicious file extensions
     */
    private $suspiciousExtensions = [
        'php',
        'php3',
        'php4',
        'php5',
        'phtml',
        'phar',
    ];

    public function __construct()
    {
        // Register hooks
        $this->registerHooks();
    }

    /**
     * Register WordPress hooks
     */
    protected function registerHooks(): void
    {
        // Hook khi plugin được uploaded
        add_filter('upgrader_pre_install', [$this, 'scanBeforeInstall'], 10, 2);

        // Hook khi plugin/theme được activated
        add_action('activated_plugin', [$this, 'scanActivatedPlugin'], 10, 2);
        add_action('switch_theme', [$this, 'scanActivatedTheme'], 10, 3);

        // Hook vào file upload
        add_filter('wp_handle_upload_prefilter', [$this, 'scanUploadedFile'], 10, 1);
    }

    /**
     * Scan trước khi install plugin/theme
     */
    public function scanBeforeInstall($response, $hook_extra)
    {
        if (!$this->isEnabled()) {
            return $response;
        }

        // Get type: plugin or theme
        $type = isset($hook_extra['type']) ? $hook_extra['type'] : 'unknown';

        if (!in_array($type, ['plugin', 'theme'])) {
            return $response;
        }

        // Scan sẽ được thực hiện sau khi file được extract
        // Tạo flag để scan sau
        set_transient('wp_security_monitor_pending_scan', [
            'type' => $type,
            'hook_extra' => $hook_extra,
            'timestamp' => time(),
        ], 300); // 5 minutes

        return $response;
    }

    /**
     * Scan activated plugin
     */
    public function scanActivatedPlugin($plugin, $network_wide)
    {
        if (!$this->isEnabled()) {
            return;
        }

        $pluginPath = WP_PLUGIN_DIR . '/' . $plugin;
        $pluginDir = dirname($pluginPath);

        if (!is_dir($pluginDir)) {
            $pluginDir = WP_PLUGIN_DIR;
        }

        $this->scanDirectory($pluginDir, 'plugin', $plugin);
    }

    /**
     * Scan activated theme
     */
    public function scanActivatedTheme($new_name, $new_theme, $old_theme)
    {
        if (!$this->isEnabled()) {
            return;
        }

        $themeDir = get_theme_root() . '/' . $new_name;

        if (is_dir($themeDir)) {
            $this->scanDirectory($themeDir, 'theme', $new_name);
        }
    }

    /**
     * Scan uploaded file
     */
    public function scanUploadedFile($file)
    {
        // Debug log
        if (defined('WP_DEBUG') && WP_DEBUG) {
            error_log('[WP Security Monitor] scanUploadedFile called for: ' . ($file['name'] ?? 'unknown'));
        }

        if (!$this->isEnabled()) {
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('[WP Security Monitor] PluginThemeUploadIssuer is disabled');
            }
            return $file;
        }

        // Only scan PHP files
        $extension = pathinfo($file['name'], PATHINFO_EXTENSION);

        if (in_array(strtolower($extension), $this->suspiciousExtensions)) {
            $tmpPath = $file['tmp_name'];

            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('[WP Security Monitor] Scanning PHP file: ' . $file['name']);
            }

            // Check file size
            $maxSize = $this->getConfig('max_file_size', 1048576); // 1MB
            if ($file['size'] > $maxSize) {
                if (defined('WP_DEBUG') && WP_DEBUG) {
                    error_log('[WP Security Monitor] File too large, skipping: ' . $file['name']);
                }
                return $file;
            }

            if (file_exists($tmpPath)) {
                $findings = $this->scanFile($tmpPath);

                if (defined('WP_DEBUG') && WP_DEBUG) {
                    error_log('[WP Security Monitor] Scan results: ' . count($findings) . ' findings for ' . $file['name']);
                }

                if (!empty($findings)) {
                    if (defined('WP_DEBUG') && WP_DEBUG) {
                        error_log('[WP Security Monitor] MALICIOUS FILE DETECTED: ' . $file['name'] . ' - Findings: ' . json_encode($findings));
                    }

                    $this->reportIssue([
                        'type' => 'malicious_upload',
                        'severity' => 'critical',
                        'title' => 'Malicious File Upload Detected: ' . $file['name'],
                        'description' => sprintf(
                            'File "%s" contains %d malicious patterns',
                            $file['name'],
                            count($findings)
                        ),
                        'file_name' => $file['name'],
                        'file_size' => $file['size'],
                        'file_type' => $extension,
                        'findings' => $findings,
                        'upload_dir' => dirname($tmpPath),
                        'content_preview' => substr(file_get_contents($tmpPath), 0, 500),
                    ]);

                    // Block upload if enabled
                    if ($this->getConfig('block_suspicious_uploads', true)) {
                        $file['error'] = 'File upload blocked: Malicious code detected by security monitor';
                    }
                }
            }
        } else {
            if (defined('WP_DEBUG') && WP_DEBUG) {
                error_log('[WP Security Monitor] File not scanned (not PHP): ' . $file['name']);
            }
        }

        return $file;
    }

    /**
     * Scan directory recursively
     */
    private function scanDirectory(string $dir, string $type, string $name): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $findings = [];
        $filesScanned = 0;
        $maxFiles = $this->getConfig('max_files_per_scan', 100);

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $file) {
            if ($filesScanned >= $maxFiles) {
                break;
            }

            if ($file->isFile()) {
                $extension = $file->getExtension();

                if (in_array(strtolower($extension), $this->suspiciousExtensions)) {
                    $fileFindings = $this->scanFile($file->getPathname());

                    if (!empty($fileFindings)) {
                        $findings[$file->getPathname()] = $fileFindings;
                    }

                    $filesScanned++;
                }
            }
        }

        if (!empty($findings)) {
            $this->reportIssue([
                'type' => 'malicious_' . $type,
                'severity' => 'critical',
                'title' => ucfirst($type) . ' Contains Malicious Code: ' . $name,
                'description' => sprintf(
                    '%s "%s" contains %d suspicious file(s) with malicious patterns',
                    ucfirst($type),
                    $name,
                    count($findings)
                ),
                'item_type' => $type,
                'item_name' => $name,
                'directory' => $dir,
                'files_scanned' => $filesScanned,
                'findings' => $findings,
            ]);
        }
    }

    /**
     * Scan single file
     */
    private function scanFile(string $filePath): array
    {
        if (!file_exists($filePath) || !is_readable($filePath)) {
            return [];
        }

        // Skip large files
        $maxSize = $this->getConfig('max_file_size', 1048576); // 1MB default
        if (filesize($filePath) > $maxSize) {
            return [];
        }

        $content = file_get_contents($filePath);
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
     * Get line number of match
     */
    private function getLineNumber(string $content, string $match): int
    {
        if (empty($match)) {
            return 0;
        }

        $pos = strpos($content, $match);
        if ($pos === false) {
            return 0;
        }

        return substr_count(substr($content, 0, $pos), "\n") + 1;
    }


    /**
     * Report issue
     */
    private function reportIssue(array $issueData): void
    {
        $issueData['ip_address'] = $_SERVER['REMOTE_ADDR'] ?? '';
        $issueData['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $issueData['user_id'] = get_current_user_id();
        $issueData['username'] = wp_get_current_user()->user_login ?? '';
        $issueData['timestamp'] = current_time('mysql');
        $issueData['url'] = $_SERVER['REQUEST_URI'] ?? '';

        // Trigger action để Bot xử lý
        do_action('wp_security_monitor_malicious_upload', $issueData);
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
            'max_files_per_scan' => 100,
            'max_file_size' => 1048576, // 1MB
            'block_suspicious_uploads' => true,
        ];
    }
}

