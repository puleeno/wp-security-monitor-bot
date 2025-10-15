<?php
/**
 * Debug Logs Viewer Page
 * Pure PHP log viewer for WP Security Monitor
 */

if (!defined('ABSPATH')) {
    exit;
}

// Get WordPress debug log file
$debugLogFile = WP_CONTENT_DIR . '/debug.log';
$pluginLogDir = WP_CONTENT_DIR . '/uploads/security-logs';

// Get selected log for actions
$selectedLogForAction = isset($_POST['selected_log']) ? sanitize_text_field($_POST['selected_log']) : 'WordPress Debug Log';

// Handle actions
if (isset($_POST['action']) && check_admin_referer('wp_security_monitor_logs')) {
    // Determine which file to act on
    $targetFile = $debugLogFile; // Default

    if ($selectedLogForAction !== 'WordPress Debug Log' && is_dir($pluginLogDir)) {
        $possibleFile = $pluginLogDir . '/' . $selectedLogForAction;
        if (file_exists($possibleFile)) {
            $targetFile = $possibleFile;
        }
    }

    switch ($_POST['action']) {
        case 'clear_log':
            if (file_exists($targetFile)) {
                file_put_contents($targetFile, '');
                echo '<div class="notice notice-success"><p>✅ Log file đã được xóa: ' . esc_html(basename($targetFile)) . '</p></div>';
            }
            break;

        case 'download_log':
            if (file_exists($targetFile)) {
                header('Content-Type: text/plain');
                header('Content-Disposition: attachment; filename="' . basename($targetFile, '.log') . '-' . date('Y-m-d-His') . '.log"');
                readfile($targetFile);
                exit;
            }
            break;
    }
}

// Read log files
$logFiles = [];

// WordPress debug.log
if (file_exists($debugLogFile)) {
    $logFiles['WordPress Debug Log'] = [
        'path' => $debugLogFile,
        'size' => filesize($debugLogFile),
        'modified' => filemtime($debugLogFile),
    ];
}

// Plugin logs directory
if (is_dir($pluginLogDir)) {
    $files = glob($pluginLogDir . '/*.log');
    foreach ($files as $file) {
        $logFiles[basename($file)] = [
            'path' => $file,
            'size' => filesize($file),
            'modified' => filemtime($file),
        ];
    }
}

// Get selected log file
$selectedLog = isset($_GET['log']) ? sanitize_text_field($_GET['log']) : 'WordPress Debug Log';
$currentLogFile = isset($logFiles[$selectedLog]) ? $logFiles[$selectedLog]['path'] : $debugLogFile;

// Read log content
$logContent = '';
$lines = [];
$totalLines = 0;

if (file_exists($currentLogFile)) {
    $maxLines = 500; // Show last 500 lines
    $allLines = file($currentLogFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $totalLines = count($allLines);
    $lines = array_slice($allLines, -$maxLines);
    $lines = array_reverse($lines); // Show newest first
}

// Filter logs
$filterKeyword = isset($_GET['filter']) ? sanitize_text_field($_GET['filter']) : '';
if ($filterKeyword && !empty($lines)) {
    $lines = array_filter($lines, function($line) use ($filterKeyword) {
        return stripos($line, $filterKeyword) !== false;
    });
}

?>

<div class="wrap">
    <h1>📋 Debug Logs Viewer</h1>
    <p>Xem và quản lý debug logs của WordPress và WP Security Monitor plugin.</p>

    <?php if (!is_dir($pluginLogDir)): ?>
        <div class="notice notice-info">
            <p>
                <strong>ℹ️ Plugin logs directory chưa tồn tại:</strong><br>
                <code><?php echo esc_html($pluginLogDir); ?></code><br>
                Directory sẽ được tạo tự động khi plugin ghi log lần đầu.
            </p>
        </div>
    <?php endif; ?>

    <div class="log-viewer-container">

        <!-- Log File Selector -->
        <div class="card" style="margin-bottom: 20px;">
            <h2>📁 Chọn Log File</h2>
            <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                <?php foreach ($logFiles as $name => $info): ?>
                    <a href="<?php echo admin_url('admin.php?page=wp-security-monitor-logs&log=' . urlencode($name)); ?>"
                       class="button <?php echo $selectedLog === $name ? 'button-primary' : ''; ?>">
                        <?php echo esc_html($name); ?>
                        <span style="font-size: 11px; opacity: 0.8;">
                            (<?php echo size_format($info['size']); ?>)
                        </span>
                    </a>
                <?php endforeach; ?>

                <?php if (empty($logFiles)): ?>
                    <p><em>Không tìm thấy log files nào.</em></p>
                <?php endif; ?>
            </div>
        </div>

        <!-- Actions -->
        <div class="card" style="margin-bottom: 20px;">
            <h2>⚡ Actions</h2>
            <div style="display: flex; gap: 10px; align-items: center; flex-wrap: wrap;">
                <form method="get" style="display: inline-block; margin: 0;">
                    <input type="hidden" name="page" value="wp-security-monitor-logs">
                    <input type="hidden" name="log" value="<?php echo esc_attr($selectedLog); ?>">
                    <input type="search" name="filter" value="<?php echo esc_attr($filterKeyword); ?>"
                           placeholder="🔍 Filter logs..."
                           style="width: 300px;">
                    <button type="submit" class="button">Filter</button>
                    <?php if ($filterKeyword): ?>
                        <a href="<?php echo admin_url('admin.php?page=wp-security-monitor-logs&log=' . urlencode($selectedLog)); ?>"
                           class="button">Clear Filter</a>
                    <?php endif; ?>
                </form>

                <form method="post" style="display: inline-block; margin: 0;"
                      onsubmit="return confirm('Bạn có chắc muốn xóa toàn bộ log file này?');">
                    <?php wp_nonce_field('wp_security_monitor_logs'); ?>
                    <input type="hidden" name="action" value="clear_log">
                    <input type="hidden" name="selected_log" value="<?php echo esc_attr($selectedLog); ?>">
                    <button type="submit" class="button button-secondary">
                        🗑️ Clear Log
                    </button>
                </form>

                <form method="post" style="display: inline-block; margin: 0;">
                    <?php wp_nonce_field('wp_security_monitor_logs'); ?>
                    <input type="hidden" name="action" value="download_log">
                    <input type="hidden" name="selected_log" value="<?php echo esc_attr($selectedLog); ?>">
                    <button type="submit" class="button">
                        💾 Download
                    </button>
                </form>

                <a href="<?php echo admin_url('admin.php?page=wp-security-monitor-logs&log=' . urlencode($selectedLog)); ?>"
                   class="button">
                    🔄 Refresh
                </a>
            </div>
        </div>

        <!-- Log Stats -->
        <div class="card" style="margin-bottom: 20px;">
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                <div>
                    <strong>📄 File:</strong>
                    <?php echo esc_html(basename($currentLogFile)); ?>
                </div>
                <div>
                    <strong>💾 Size:</strong>
                    <?php echo size_format(file_exists($currentLogFile) ? filesize($currentLogFile) : 0); ?>
                </div>
                <div>
                    <strong>📊 Total Lines:</strong>
                    <?php echo number_format($totalLines); ?>
                </div>
                <div>
                    <strong>👁️ Showing:</strong>
                    <?php echo number_format(count($lines)); ?> lines
                    <?php if ($filterKeyword): ?>
                        (filtered)
                    <?php endif; ?>
                </div>
                <div>
                    <strong>🕐 Modified:</strong>
                    <?php echo file_exists($currentLogFile) ? date('Y-m-d H:i:s', filemtime($currentLogFile)) : 'N/A'; ?>
                </div>
            </div>
        </div>

        <!-- Log Content -->
        <div class="card">
            <h2>📜 Log Content (Last <?php echo count($lines); ?> lines, newest first)</h2>

            <?php if (empty($lines)): ?>
                <div style="padding: 40px; text-align: center; background: #f0f0f1; border-radius: 4px;">
                    <p style="font-size: 16px; color: #666;">
                        <?php if ($filterKeyword): ?>
                            🔍 No logs matching filter: <strong><?php echo esc_html($filterKeyword); ?></strong>
                        <?php else: ?>
                            📭 Log file is empty or not found.
                        <?php endif; ?>
                    </p>
                </div>
            <?php else: ?>
                <div class="log-content">
                    <?php
                    $lineNumber = $totalLines;
                    foreach ($lines as $line):
                        // Highlight different log levels
                        $class = '';
                        if (stripos($line, 'error') !== false || stripos($line, 'fatal') !== false) {
                            $class = 'log-error';
                        } elseif (stripos($line, 'warning') !== false) {
                            $class = 'log-warning';
                        } elseif (stripos($line, 'notice') !== false) {
                            $class = 'log-notice';
                        } elseif (stripos($line, 'debug') !== false) {
                            $class = 'log-debug';
                        }

                        // Highlight filter keyword
                        $displayLine = esc_html($line);
                        if ($filterKeyword) {
                            $displayLine = preg_replace(
                                '/(' . preg_quote($filterKeyword, '/') . ')/i',
                                '<mark>$1</mark>',
                                $displayLine
                            );
                        }
                    ?>
                        <div class="log-line <?php echo $class; ?>">
                            <span class="log-line-number"><?php echo $lineNumber; ?></span>
                            <span class="log-line-content"><?php echo $displayLine; ?></span>
                        </div>
                    <?php
                        $lineNumber--;
                    endforeach;
                    ?>
                </div>
            <?php endif; ?>
        </div>

    </div>
</div>

<style>
    .log-viewer-container .card {
        background: white;
        padding: 20px;
        border: 1px solid #ccd0d4;
        box-shadow: 0 1px 1px rgba(0,0,0,.04);
        border-radius: 4px;
    }

    .log-viewer-container .card h2 {
        margin-top: 0;
        font-size: 16px;
        padding-bottom: 10px;
        border-bottom: 1px solid #e0e0e0;
    }

    .log-content {
        background: #23282d;
        color: #f0f0f1;
        padding: 15px;
        border-radius: 4px;
        max-height: 600px;
        overflow-y: auto;
        font-family: 'Courier New', monospace;
        font-size: 12px;
        line-height: 1.6;
    }

    .log-line {
        display: flex;
        padding: 2px 0;
        border-bottom: 1px solid rgba(255,255,255,0.05);
    }

    .log-line:hover {
        background: rgba(255,255,255,0.05);
    }

    .log-line-number {
        min-width: 60px;
        color: #666;
        text-align: right;
        padding-right: 15px;
        border-right: 1px solid rgba(255,255,255,0.1);
        margin-right: 15px;
        user-select: none;
    }

    .log-line-content {
        flex: 1;
        word-wrap: break-word;
        white-space: pre-wrap;
    }

    .log-error {
        background: rgba(255, 0, 0, 0.1);
        color: #ff6b6b;
    }

    .log-warning {
        background: rgba(255, 165, 0, 0.1);
        color: #ffa500;
    }

    .log-notice {
        background: rgba(100, 149, 237, 0.1);
        color: #6495ed;
    }

    .log-debug {
        color: #999;
    }

    .log-content mark {
        background: #ffeb3b;
        color: #23282d;
        padding: 2px 4px;
        border-radius: 2px;
        font-weight: bold;
    }

    .log-content::-webkit-scrollbar {
        width: 12px;
    }

    .log-content::-webkit-scrollbar-track {
        background: #1a1d23;
    }

    .log-content::-webkit-scrollbar-thumb {
        background: #555;
        border-radius: 6px;
    }

    .log-content::-webkit-scrollbar-thumb:hover {
        background: #777;
    }
</style>

