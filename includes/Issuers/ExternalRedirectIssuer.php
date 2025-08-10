<?php
namespace Puleeno\SecurityBot\WebMonitor\Issuers;

use Puleeno\SecurityBot\WebMonitor\Interfaces\IssuerInterface;
use Puleeno\SecurityBot\WebMonitor\WhitelistManager;
use Puleeno\SecurityBot\WebMonitor\DebugHelper;
use Puleeno\SecurityBot\WebMonitor\ForensicHelper;
use Puleeno\SecurityBot\WebMonitor\Enums\IssuerType;

class ExternalRedirectIssuer implements IssuerInterface
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
     * @var WhitelistManager
     */
    private $whitelistManager;

    public function __construct()
    {
        $this->whitelistManager = WhitelistManager::getInstance();
    }

    public function getName(): string
    {
        return 'External Redirect Monitor';
    }

    public function getPriority(): int
    {
        return 5; // Mức độ ưu tiên trung bình
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
            // Kiểm tra redirect trong .htaccess
            $htaccessIssues = $this->checkHtaccessRedirects();
            if (!empty($htaccessIssues)) {
                $issues = array_merge($issues, $htaccessIssues);
            }

            // Kiểm tra redirect trong database
            $dbIssues = $this->checkDatabaseRedirects();
            if (!empty($dbIssues)) {
                $issues = array_merge($issues, $dbIssues);
            }

            // Kiểm tra redirect trong WordPress hooks
            $hookIssues = $this->checkWordPressRedirects();
            if (!empty($hookIssues)) {
                $issues = array_merge($issues, $hookIssues);
            }

            // Kiểm tra redirect trong files PHP
            $fileIssues = $this->checkPhpFileRedirects();
            if (!empty($fileIssues)) {
                $issues = array_merge($issues, $fileIssues);
            }

        } catch (\Exception $e) {
            $issues[] = [
                'message' => 'Lỗi khi kiểm tra redirect',
                'details' => $e->getMessage()
            ];
        }

        return $issues;
    }

    /**
     * Kiểm tra redirect trong file .htaccess
     *
     * @return array
     */
    private function checkHtaccessRedirects(): array
    {
        $issues = [];
        $htaccessFile = ABSPATH . '.htaccess';

        if (!file_exists($htaccessFile)) {
            return $issues;
        }

        $content = file_get_contents($htaccessFile);
        if ($content === false) {
            return $issues;
        }

        // Tìm các redirect rule đáng ngờ
        $suspiciousPatterns = [
            '/Redirect\s+30[12]\s+.*?(http|https):\/\/(?!'.preg_quote($_SERVER['HTTP_HOST'], '/').')([^\s]+)/i',
            '/RewriteRule\s+.*?\s+.*?(http|https):\/\/(?!'.preg_quote($_SERVER['HTTP_HOST'], '/').')([^\s\]]+)/i',
            '/Header\s+.*?Location.*?(http|https):\/\/(?!'.preg_quote($_SERVER['HTTP_HOST'], '/').')([^\s"\']+)/i'
        ];

        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match_all($pattern, $content, $matches, PREG_SET_ORDER)) {
                foreach ($matches as $match) {
                    $redirectUrl = $match[2] . $match[3];
                    $domain = $this->whitelistManager->extractDomain($redirectUrl);

                    if ($domain && !$this->shouldIgnoreDomain($domain)) {
                        $debugContext = DebugHelper::createFileDebugContext($htaccessFile, 'htaccess_scan');
                        $debugContext['redirect_url'] = $redirectUrl;
                        $debugContext['pattern_matched'] = $match[0];

                        $issues[] = [
                            'message' => 'Phát hiện redirect đáng ngờ trong .htaccess',
                            'details' => "Redirect tới domain ngoài: {$redirectUrl}",
                            'type' => 'external_redirect',
                            'domain' => $domain,
                            'redirect_url' => $redirectUrl,
                            'source_file' => '.htaccess',
                            'debug_info' => array_merge(
                                ForensicHelper::createForensicData(0, $this->getName()),
                                [
                                    'additional_context' => array_merge($debugContext, [
                                        'redirect_url' => $redirectUrl,
                                        'pattern_matched' => $match[0]
                                    ])
                                ]
                            )
                        ];

                        // Track domain for whitelist management
                        $this->trackDomainForWhitelist($domain, [
                            'source' => '.htaccess',
                            'redirect_url' => $redirectUrl,
                            'pattern' => $match[0]
                        ]);
                    }
                }
            }
        }

        return $issues;
    }

    /**
     * Kiểm tra redirect trong database
     *
     * @return array
     */
    private function checkDatabaseRedirects(): array
    {
        global $wpdb;
        $issues = [];

        try {
            // Kiểm tra options table
            $redirectOptions = $wpdb->get_results(
                "SELECT option_name, option_value FROM {$wpdb->options}
                WHERE option_value LIKE '%http%'
                AND option_value REGEXP 'https?://[^{$_SERVER['HTTP_HOST']}]'"
            );

            foreach ($redirectOptions as $option) {
                if ($this->isExternalRedirect($option->option_value)) {
                    $domain = $this->whitelistManager->extractDomain($option->option_value);

                    if ($domain && !$this->shouldIgnoreDomain($domain)) {
                        $debugContext = [
                            'option_name' => $option->option_name,
                            'option_value' => $option->option_value,
                            'source' => 'database_options'
                        ];

                        $issues[] = [
                            'message' => 'Phát hiện redirect đáng ngờ trong database',
                            'details' => "Option: {$option->option_name} chứa URL ngoài: {$option->option_value}",
                            'type' => 'external_redirect',
                            'domain' => $domain,
                            'redirect_url' => $option->option_value,
                            'source_file' => 'database',
                            'debug_info' => ForensicHelper::createForensicData(
                                0,
                                $this->getName()
                            )
                        ];

                        $this->trackDomainForWhitelist($domain, [
                            'source' => 'database',
                            'option_name' => $option->option_name,
                            'option_value' => $option->option_value
                        ]);
                    }
                }
            }

            // Kiểm tra trong post content
            $suspiciousPosts = $wpdb->get_results(
                "SELECT ID, post_title FROM {$wpdb->posts}
                WHERE post_content LIKE '%<script%location%'
                OR post_content LIKE '%window.location%'
                OR post_content LIKE '%document.location%'"
            );

            foreach ($suspiciousPosts as $post) {
                $debugContext = [
                    'post_id' => $post->ID,
                    'post_title' => $post->post_title,
                    'source' => 'post_content'
                ];

                $issues[] = [
                                    'message' => 'Phát hiện JavaScript redirect đáng ngờ trong post',
                'details' => "Post ID: {$post->ID} - {$post->post_title}",
                'type' => 'javascript_redirect',
                'source_file' => 'post_content',
                'post_id' => $post->ID,
                'debug_info' => ForensicHelper::createForensicData(
                    0,
                    $this->getName()
                )
                ];
            }

        } catch (\Exception $e) {
            $issues[] = [
                'message' => 'Lỗi khi kiểm tra database',
                'details' => $e->getMessage()
            ];
        }

        return $issues;
    }

    /**
     * Kiểm tra redirect trong WordPress hooks
     *
     * @return array
     */
    private function checkWordPressRedirects(): array
    {
        $issues = [];

        // Kiểm tra template_redirect hook
        global $wp_filter;

        if (isset($wp_filter['template_redirect'])) {
            foreach ($wp_filter['template_redirect']->callbacks as $priority => $callbacks) {
                foreach ($callbacks as $callback) {
                    $function = $callback['function'];

                    if (is_array($function) && is_object($function[0])) {
                        $className = get_class($function[0]);
                        if (strpos($className, 'eval') !== false || strpos($className, 'obfuscated') !== false) {
                            $debugContext = [
                                'hook' => 'template_redirect',
                                'class_name' => $className,
                                'method' => $function[1],
                                'priority' => $priority,
                                'source' => 'wordpress_hooks'
                            ];

                            $issues[] = [
                                'message' => 'Phát hiện hook đáng ngờ trong template_redirect',
                                'details' => "Class: {$className}, Method: {$function[1]}",
                                'type' => 'suspicious_hook',
                                'source_file' => 'wordpress_hooks',
                                'debug_info' => ForensicHelper::createForensicData(
                                    0,
                                    $this->getName()
                                )
                            ];
                        }
                    }
                }
            }
        }

        return $issues;
    }

    /**
     * Kiểm tra redirect trong files PHP
     *
     * @return array
     */
    private function  checkPhpFileRedirects(): array
    {
        $issues = [];
        $maxFiles = $this->getConfig('max_files_scan', 100);
        $scannedFiles = 0;

        // Quét các file PHP chính
        $criticalFiles = [
            ABSPATH . 'index.php',
            ABSPATH . 'wp-config.php',
            get_template_directory() . '/index.php',
            get_template_directory() . '/functions.php'
        ];

        foreach ($criticalFiles as $file) {
            if (file_exists($file) && $scannedFiles < $maxFiles) {
                $fileIssues = $this->scanFileForRedirects($file);
                if (!empty($fileIssues)) {
                    $issues = array_merge($issues, $fileIssues);
                }
                $scannedFiles++;
            }
        }

        return $issues;
    }

    /**
     * Quét một file để tìm redirect đáng ngờ
     *
     * @param string $filePath
     * @return array
     */
    private function scanFileForRedirects(string $filePath): array
    {
        $issues = [];
        $content = file_get_contents($filePath);

        if ($content === false) {
            return $issues;
        }

        // Các pattern đáng ngờ
        $suspiciousPatterns = [
            '/header\s*\(\s*[\'"]location\s*:\s*https?:\/\/(?!'.preg_quote($_SERVER['HTTP_HOST'], '/').')([^\'"]+)/i',
            '/wp_redirect\s*\(\s*[\'"]https?:\/\/(?!'.preg_quote($_SERVER['HTTP_HOST'], '/').')([^\'"]+)/i',
            '/window\.location\s*=\s*[\'"]https?:\/\/(?!'.preg_quote($_SERVER['HTTP_HOST'], '/').')([^\'"]+)/i',
            '/document\.location\s*=\s*[\'"]https?:\/\/(?!'.preg_quote($_SERVER['HTTP_HOST'], '/').')([^\'"]+)/i',
            '/eval\s*\(\s*base64_decode/i',
            '/eval\s*\(\s*gzinflate/i'
        ];

        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match_all($pattern, $content, $matches, PREG_SET_ORDER)) {
                foreach ($matches as $match) {
                    $redirectUrl = $match[1] ?? '';
                    $domain = $redirectUrl ? $this->whitelistManager->extractDomain($redirectUrl) : null;

                    $debugContext = DebugHelper::createFileDebugContext($filePath, 'php_file_scan');
                    $debugContext['pattern_matched'] = substr($match[0], 0, 200);
                    $debugContext['redirect_url'] = $redirectUrl;

                    // Chỉ tạo issue nếu domain không trong whitelist
                    if (!$domain || !$this->shouldIgnoreDomain($domain)) {
                        $issues[] = [
                            'message' => 'Phát hiện code đáng ngờ trong file PHP',
                            'details' => "File: " . basename($filePath) . " - Pattern: " . substr($match[0], 0, 100),
                            'type' => $redirectUrl ? 'external_redirect' : 'suspicious_code',
                            'source_file' => $filePath,
                            'domain' => $domain,
                            'redirect_url' => $redirectUrl,
                            'debug_info' => ForensicHelper::createForensicData(
                                0,
                                $this->getName()
                            )
                        ];

                        if ($domain) {
                            $this->trackDomainForWhitelist($domain, [
                                'source' => 'php_file',
                                'file_path' => $filePath,
                                'pattern' => substr($match[0], 0, 100)
                            ]);
                        }
                    }
                }
            }
        }

        return $issues;
    }

    /**
     * Kiểm tra URL có phải redirect ngoài không
     *
     * @param string $url
     * @return bool
     */
    private function isExternalRedirect(string $url): bool
    {
        $parsed = parse_url($url);
        if (!isset($parsed['host'])) {
            return false;
        }

        $currentHost = $_SERVER['HTTP_HOST'] ?? '';
        return $parsed['host'] !== $currentHost;
    }

        /**
     * Kiểm tra domain có nên bị ignore không
     *
     * @param string $domain
     * @return bool
     */
    private function shouldIgnoreDomain(string $domain): bool
    {
        // Kiểm tra whitelist
        if ($this->whitelistManager->isDomainWhitelisted($domain)) {
            $this->whitelistManager->recordDomainUsage($domain);
            return true;
        }

        // Kiểm tra rejected list - nếu đã bị reject thì vẫn tạo issue
        if ($this->whitelistManager->isDomainRejected($domain)) {
            // Domain đã bị reject, vẫn tạo issue để admin biết
            return false;
        }

        return false;
    }

    /**
     * Track domain để quản lý whitelist
     *
     * @param string $domain
     * @param array $context
     * @return void
     */
    private function trackDomainForWhitelist(string $domain, array $context): void
    {
        // Thêm vào pending domains để admin có thể review
        $this->whitelistManager->addPendingDomain($domain, $context);
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
