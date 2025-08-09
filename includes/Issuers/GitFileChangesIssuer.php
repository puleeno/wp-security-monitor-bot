<?php

namespace Puleeno\SecurityBot\WebMonitor\Issuers;

use Puleeno\SecurityBot\WebMonitor\Interfaces\IssuerInterface;
use Puleeno\SecurityBot\WebMonitor\DebugHelper;

/**
 * GitFileChangesIssuer - Monitor file changes using Git
 *
 * Sử dụng Git để track file changes chính xác hơn filesystem monitoring.
 *
 * REQUIREMENTS:
 * - Git phải được cài đặt trên hosting
 * - ABSPATH (WordPress root) phải nằm trong Git repository
 * - Hosting phải cho phép shell_exec()
 *
 * AUTO-DISABLE nếu requirements không đủ.
 */
class GitFileChangesIssuer implements IssuerInterface
{
    /**
     * @var array
     */
    private $config = [
        'enabled' => true,
        'priority' => 5,
        'check_interval' => 300, // 5 phút
        'max_files_per_alert' => 10,
        'exclude_patterns' => [
            '*.log',
            '*.tmp',
            'wp-content/cache/*',
            'wp-content/uploads/*',
            'node_modules/*',
            '.git/*'
        ],
        'critical_paths' => [
            'wp-config.php',
            'wp-admin/*',
            'wp-includes/*',
            '*.php'
        ]
    ];

    /**
     * @var string|null
     */
    private $gitPath;

    /**
     * @var string
     */
    private $lastCheckOptionKey = 'wp_security_monitor_git_last_check';

    public function __construct()
    {
        $this->gitPath = $this->findGitPath();
    }

    public function detect(): array
    {
        if (!$this->isGitAvailable()) {
            // Không tạo issue nếu Git không available
            // Chỉ log debug info nếu cần
            if (WP_DEBUG) {
                error_log('[WP Security Monitor] GitFileChangesIssuer disabled: Git not available or ABSPATH not in Git repository');
            }
            return [];
        }

        $issues = [];

        try {
            // Lấy thời điểm check lần cuối
            $lastCheck = get_option($this->lastCheckOptionKey, time() - 3600); // Default 1 hour ago

            // Lấy danh sách files đã thay đổi
            $changedFiles = $this->getChangedFiles($lastCheck);

            if (!empty($changedFiles)) {
                $issues = array_merge($issues, $this->analyzeChangedFiles($changedFiles));
            }

            // Cập nhật thời điểm check
            update_option($this->lastCheckOptionKey, time());

        } catch (\Exception $e) {
            $issues[] = [
                'type' => 'git_error',
                'severity' => 'medium',
                'message' => 'Error checking Git changes',
                'details' => $e->getMessage(),
                'debug_info' => DebugHelper::createIssueDebugInfo()
            ];
        }

        return $issues;
    }

    /**
     * Kiểm tra Git có available không và ABSPATH nằm trong Git repo
     */
    private function isGitAvailable(): bool
    {
        return !is_null($this->gitPath) &&
               $this->isGitRepository() &&
               $this->isAbspathInGitRepo();
    }

    /**
     * Tìm Git executable path
     */
    private function findGitPath(): ?string
    {
        // Try common paths
        $possiblePaths = [
            'git', // In PATH
            '/usr/bin/git',
            '/usr/local/bin/git',
            '/opt/local/bin/git',
            'C:\\Program Files\\Git\\bin\\git.exe',
            'C:\\Program Files (x86)\\Git\\bin\\git.exe'
        ];

        foreach ($possiblePaths as $path) {
            if ($this->testGitCommand($path)) {
                return $path;
            }
        }

        return null;
    }

    /**
     * Test Git command
     */
    private function testGitCommand(string $gitPath): bool
    {
        $command = escapeshellcmd($gitPath) . ' --version 2>&1';
        $output = shell_exec($command);

        return $output && strpos($output, 'git version') !== false;
    }

    /**
     * Kiểm tra có phải Git repository không
     */
    private function isGitRepository(): bool
    {
        $gitDir = ABSPATH . '.git';
        return is_dir($gitDir) || is_file($gitDir); // Support worktree
    }

    /**
     * Kiểm tra ABSPATH có thực sự nằm trong Git repository không
     * Verify bằng cách chạy git command trong thư mục đó
     */
    private function isAbspathInGitRepo(): bool
    {
        if (is_null($this->gitPath)) {
            return false;
        }

        // Test git command trong ABSPATH
        $command = sprintf(
            'cd %s && %s rev-parse --is-inside-work-tree 2>/dev/null',
            escapeshellarg(ABSPATH),
            escapeshellcmd($this->gitPath)
        );

        $output = shell_exec($command);

        // Git trả về "true" nếu trong working tree
        return trim($output ?? '') === 'true';
    }

    /**
     * Lấy danh sách files đã thay đổi từ thời điểm specified
     */
    private function getChangedFiles(int $since): array
    {
        $sinceDate = date('Y-m-d H:i:s', $since);

        // Git command để lấy files thay đổi
        $command = sprintf(
            'cd %s && %s log --since="%s" --name-status --pretty=format:"COMMIT:%%H:%%s:%%an:%%ad" --date=iso',
            escapeshellarg(ABSPATH),
            escapeshellcmd($this->gitPath),
            $sinceDate
        );

        $output = shell_exec($command . ' 2>&1');

        if (!$output) {
            return [];
        }

        return $this->parseGitLogOutput($output);
    }

    /**
     * Parse Git log output
     */
    private function parseGitLogOutput(string $output): array
    {
        $lines = explode("\n", trim($output));
        $changes = [];
        $currentCommit = null;

        foreach ($lines as $line) {
            $line = trim($line);

            if (empty($line)) {
                continue;
            }

            // Parse commit line
            if (strpos($line, 'COMMIT:') === 0) {
                $parts = explode(':', $line, 5);
                if (count($parts) >= 5) {
                    $currentCommit = [
                        'hash' => $parts[1],
                        'message' => $parts[2],
                        'author' => $parts[3],
                        'date' => $parts[4],
                        'files' => []
                    ];
                }
                continue;
            }

            // Parse file change line (M, A, D followed by filename)
            if ($currentCommit && preg_match('/^([AMD])\s+(.+)$/', $line, $matches)) {
                $status = $matches[1];
                $filename = $matches[2];

                // Skip excluded patterns
                if ($this->shouldExcludeFile($filename)) {
                    continue;
                }

                $currentCommit['files'][] = [
                    'status' => $status,
                    'file' => $filename,
                    'full_path' => ABSPATH . $filename
                ];

                // Add to changes array when commit is complete
                if (!in_array($currentCommit, $changes)) {
                    $changes[] = $currentCommit;
                }
            }
        }

        return $changes;
    }

    /**
     * Kiểm tra file có nên exclude không
     */
    private function shouldExcludeFile(string $filename): bool
    {
        foreach ($this->config['exclude_patterns'] as $pattern) {
            if (fnmatch($pattern, $filename)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Phân tích files đã thay đổi và tạo issues
     */
    private function analyzeChangedFiles(array $changes): array
    {
        $issues = [];

        foreach ($changes as $commit) {
            if (empty($commit['files'])) {
                continue;
            }

            $criticalFiles = [];
            $normalFiles = [];

            foreach ($commit['files'] as $fileInfo) {
                if ($this->isCriticalFile($fileInfo['file'])) {
                    $criticalFiles[] = $fileInfo;
                } else {
                    $normalFiles[] = $fileInfo;
                }
            }

            // Tạo issue cho critical files
            if (!empty($criticalFiles)) {
                $issues[] = $this->createCriticalFileChangeIssue($commit, $criticalFiles);
            }

            // Tạo issue cho normal files nếu số lượng lớn
            if (count($normalFiles) > $this->config['max_files_per_alert']) {
                $issues[] = $this->createBulkFileChangeIssue($commit, $normalFiles);
            }
        }

        return $issues;
    }

    /**
     * Kiểm tra file có critical không
     */
    private function isCriticalFile(string $filename): bool
    {
        foreach ($this->config['critical_paths'] as $pattern) {
            if (fnmatch($pattern, $filename)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Tạo issue cho critical file changes
     */
    private function createCriticalFileChangeIssue(array $commit, array $files): array
    {
        $fileList = array_map(function($f) {
            return sprintf('%s: %s', $this->getStatusText($f['status']), $f['file']);
        }, $files);

        return [
            'type' => 'critical_file_change',
            'severity' => 'critical',
            'message' => sprintf('Critical files modified in commit %s', substr($commit['hash'], 0, 8)),
            'details' => [
                'commit_hash' => $commit['hash'],
                'commit_message' => $commit['message'],
                'author' => $commit['author'],
                'date' => $commit['date'],
                'files_changed' => $fileList,
                'file_count' => count($files)
            ],
            'debug_info' => DebugHelper::createIssueDebugInfo()
        ];
    }

    /**
     * Tạo issue cho bulk file changes
     */
    private function createBulkFileChangeIssue(array $commit, array $files): array
    {
        return [
            'type' => 'bulk_file_change',
            'severity' => 'medium',
            'message' => sprintf('Large number of files changed in commit %s (%d files)',
                substr($commit['hash'], 0, 8), count($files)),
            'details' => [
                'commit_hash' => $commit['hash'],
                'commit_message' => $commit['message'],
                'author' => $commit['author'],
                'date' => $commit['date'],
                'file_count' => count($files),
                'first_10_files' => array_slice(array_map(function($f) {
                    return sprintf('%s: %s', $this->getStatusText($f['status']), $f['file']);
                }, $files), 0, 10)
            ],
            'debug_info' => DebugHelper::createIssueDebugInfo()
        ];
    }

    /**
     * Convert Git status code to text
     */
    private function getStatusText(string $status): string
    {
        switch ($status) {
            case 'M': return 'Modified';
            case 'A': return 'Added';
            case 'D': return 'Deleted';
            default: return 'Changed';
        }
    }

    public function getName(): string
    {
        return 'Git File Changes Monitor';
    }

    public function getPriority(): int
    {
        return $this->config['priority'];
    }

    public function isEnabled(): bool
    {
        return $this->config['enabled'] && $this->isGitAvailable();
    }

    public function configure(array $config): void
    {
        $this->config = array_merge($this->config, $config);
    }
}
