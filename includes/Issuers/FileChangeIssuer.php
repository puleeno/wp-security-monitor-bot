<?php
namespace Puleeno\SecurityBot\WebMonitor\Issuers;

use Puleeno\SecurityBot\WebMonitor\Interfaces\IssuerInterface;

class FileChangeIssuer implements IssuerInterface
{
    /**
     * @var array
     */
    private $config = [];

    /**
     * @var bool
     */
    private $enabled = true;

    /**
     * @var string
     */
    private $optionKey = 'wp_security_monitor_file_hashes';

    public function getName(): string
    {
        return 'File Change Monitor';
    }

    public function getPriority(): int
    {
        return 6; // Mức độ ưu tiên trung bình cao
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function configure(array $config): void
    {
        $this->config = array_merge($this->config, $config);

        if (isset($config['enabled'])) {
            $this->enabled = (bool) $config['enabled'];
        }
    }

    public function detect(): array
    {
        $issues = [];

        try {
            // Kiểm tra core WordPress files
            $coreIssues = $this->checkCoreFiles();
            if (!empty($coreIssues)) {
                $issues = array_merge($issues, $coreIssues);
            }

            // Kiểm tra plugin files
            $pluginIssues = $this->checkPluginFiles();
            if (!empty($pluginIssues)) {
                $issues = array_merge($issues, $pluginIssues);
            }

            // Kiểm tra theme files
            $themeIssues = $this->checkThemeFiles();
            if (!empty($themeIssues)) {
                $issues = array_merge($issues, $themeIssues);
            }

            // Kiểm tra critical files
            $criticalIssues = $this->checkCriticalFiles();
            if (!empty($criticalIssues)) {
                $issues = array_merge($issues, $criticalIssues);
            }

        } catch (\Exception $e) {
            $issues[] = [
                'message' => 'Lỗi khi kiểm tra file changes',
                'details' => $e->getMessage()
            ];
        }

        return $issues;
    }

    /**
     * Kiểm tra WordPress core files
     *
     * @return array
     */
    private function checkCoreFiles(): array
    {
        $issues = [];

        if (!$this->getConfig('check_core_files', true)) {
            return $issues;
        }

        $coreFiles = [
            ABSPATH . 'wp-config.php',
            ABSPATH . 'index.php',
            ABSPATH . 'wp-load.php',
            ABSPATH . 'wp-blog-header.php'
        ];

        foreach ($coreFiles as $file) {
            if (file_exists($file)) {
                $issues = array_merge($issues, $this->checkFileChanges($file, 'WordPress Core'));
            }
        }

        return $issues;
    }

    /**
     * Kiểm tra plugin files
     *
     * @return array
     */
    private function checkPluginFiles(): array
    {
        $issues = [];

        if (!$this->getConfig('check_plugin_files', true)) {
            return $issues;
        }

        $activePlugins = get_option('active_plugins', []);
        $maxFiles = $this->getConfig('max_plugin_files_check', 50);
        $checkedFiles = 0;

        foreach ($activePlugins as $plugin) {
            if ($checkedFiles >= $maxFiles) {
                break;
            }

            $pluginFile = WP_PLUGIN_DIR . '/' . $plugin;
            if (file_exists($pluginFile)) {
                $pluginDir = dirname($pluginFile);
                $pluginName = basename($pluginDir);

                // Kiểm tra main plugin file
                $issues = array_merge($issues, $this->checkFileChanges($pluginFile, "Plugin: {$pluginName}"));
                $checkedFiles++;

                // Kiểm tra một số file quan trọng trong plugin
                $importantFiles = [
                    $pluginDir . '/functions.php',
                    $pluginDir . '/admin.php',
                    $pluginDir . '/includes/admin.php'
                ];

                foreach ($importantFiles as $file) {
                    if ($checkedFiles >= $maxFiles) {
                        break;
                    }
                    if (file_exists($file)) {
                        $issues = array_merge($issues, $this->checkFileChanges($file, "Plugin: {$pluginName}"));
                        $checkedFiles++;
                    }
                }
            }
        }

        return $issues;
    }

    /**
     * Kiểm tra theme files
     *
     * @return array
     */
    private function checkThemeFiles(): array
    {
        $issues = [];

        if (!$this->getConfig('check_theme_files', true)) {
            return $issues;
        }

        $currentTheme = get_stylesheet_directory();
        $themeFiles = [
            $currentTheme . '/functions.php',
            $currentTheme . '/index.php',
            $currentTheme . '/header.php',
            $currentTheme . '/footer.php'
        ];

        foreach ($themeFiles as $file) {
            if (file_exists($file)) {
                $issues = array_merge($issues, $this->checkFileChanges($file, 'Active Theme'));
            }
        }

        return $issues;
    }

    /**
     * Kiểm tra critical files
     *
     * @return array
     */
    private function checkCriticalFiles(): array
    {
        $issues = [];

        $criticalFiles = [
            ABSPATH . '.htaccess' => 'htaccess',
            ABSPATH . 'wp-config.php' => 'wp-config',
            ABSPATH . 'robots.txt' => 'robots.txt'
        ];

        foreach ($criticalFiles as $file => $name) {
            if (file_exists($file)) {
                $issues = array_merge($issues, $this->checkFileChanges($file, "Critical File: {$name}"));
            }
        }

        return $issues;
    }

    /**
     * Kiểm tra changes của một file
     *
     * @param string $filePath
     * @param string $category
     * @return array
     */
    private function checkFileChanges(string $filePath, string $category): array
    {
        $issues = [];

        if (!file_exists($filePath) || !is_readable($filePath)) {
            return $issues;
        }

        $storedHashes = get_option($this->optionKey, []);
        $fileKey = md5($filePath);

        // Tính hash hiện tại
        $currentHash = md5_file($filePath);
        $currentSize = filesize($filePath);
        $currentModified = filemtime($filePath);

        if (isset($storedHashes[$fileKey])) {
            $stored = $storedHashes[$fileKey];

            // So sánh hash
            if ($stored['hash'] !== $currentHash) {
                $issues[] = [
                    'message' => 'Phát hiện file đã bị thay đổi',
                    'details' => sprintf(
                        '%s - File: %s (Size: %s bytes, Modified: %s)',
                        $category,
                        str_replace(ABSPATH, '', $filePath),
                        number_format($currentSize),
                        date('d/m/Y H:i:s', $currentModified)
                    )
                ];
            }

            // Kiểm tra thay đổi size đáng ngờ
            $sizeDiff = abs($currentSize - $stored['size']);
            $sizeThreshold = $this->getConfig('size_change_threshold', 10240); // 10KB

            if ($sizeDiff > $sizeThreshold) {
                $issues[] = [
                    'message' => 'Phát hiện thay đổi kích thước file đáng ngờ',
                    'details' => sprintf(
                        '%s - File: %s thay đổi %s bytes',
                        $category,
                        str_replace(ABSPATH, '', $filePath),
                        number_format($sizeDiff)
                    )
                ];
            }
        }

        // Cập nhật hash cho lần check tiếp theo
        $storedHashes[$fileKey] = [
            'hash' => $currentHash,
            'size' => $currentSize,
            'modified' => $currentModified,
            'path' => $filePath,
            'category' => $category,
            'last_checked' => time()
        ];

        // Cleanup old entries
        $maxAge = $this->getConfig('hash_retention_days', 30) * 86400;
        $storedHashes = array_filter($storedHashes, function($entry) use ($maxAge) {
            return isset($entry['last_checked']) && $entry['last_checked'] > (time() - $maxAge);
        });

        update_option($this->optionKey, $storedHashes);

        return $issues;
    }

    /**
     * Quét nhanh để tìm file mới đáng ngờ
     *
     * @return array
     */
    private function scanForSuspiciousFiles(): array
    {
        $issues = [];
        $maxFiles = $this->getConfig('max_suspicious_scan', 100);

        $suspiciousPatterns = [
            '*.php.suspected',
            '*backup*',
            '*tmp*',
            '*.bak',
            '*shell*',
            '*backdoor*'
        ];

        $scanDirs = [
            ABSPATH,
            WP_CONTENT_DIR,
            get_template_directory()
        ];

        $scannedFiles = 0;

        foreach ($scanDirs as $dir) {
            if ($scannedFiles >= $maxFiles) {
                break;
            }

            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::LEAVES_ONLY
            );

            foreach ($iterator as $file) {
                if ($scannedFiles >= $maxFiles) {
                    break;
                }

                $filename = $file->getFilename();
                $filepath = $file->getPathname();

                foreach ($suspiciousPatterns as $pattern) {
                    if (fnmatch($pattern, $filename)) {
                        $issues[] = [
                            'message' => 'Phát hiện file có tên đáng ngờ',
                            'details' => sprintf(
                                'File: %s (Size: %s bytes, Modified: %s)',
                                str_replace(ABSPATH, '', $filepath),
                                number_format($file->getSize()),
                                date('d/m/Y H:i:s', $file->getMTime())
                            )
                        ];
                        break;
                    }
                }

                $scannedFiles++;
            }
        }

        return $issues;
    }

    /**
     * Khởi tạo hash cho files quan trọng
     *
     * @return void
     */
    public function initializeFileHashes(): void
    {
        $this->detect(); // Chạy detect để tự động tạo hash
    }

    /**
     * Lấy giá trị config
     *
     * @param string $key
     * @param mixed $default
     * @return mixed
     */
    private function getConfig(string $key, $default = null)
    {
        return $this->config[$key] ?? $default;
    }
}
