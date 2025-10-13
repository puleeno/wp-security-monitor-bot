<?php
if (!defined('ABSPATH')) {
    exit;
}

use Puleeno\SecurityBot\WebMonitor\Database\Schema;
use Puleeno\SecurityBot\WebMonitor\IssueManager;
use Puleeno\SecurityBot\WebMonitor\WhitelistManager;
use Puleeno\SecurityBot\WebMonitor\Issuers\EvalFunctionIssuer;

$issueManager = IssueManager::getInstance();
$whitelistManager = WhitelistManager::getInstance();

// Xử lý actions
if (isset($_POST['action']) && isset($_POST['issue_id']) && wp_verify_nonce($_POST['_wpnonce'], 'security_monitor_issues')) {
    $action = $_POST['action'];
    $issueId = intval($_POST['issue_id']);

    switch ($action) {
        case 'ignore':
            $reason = sanitize_textarea_field($_POST['ignore_reason'] ?? '');
            if ($issueManager->ignoreIssue($issueId, $reason)) {
                echo '<div class="notice notice-success"><p>Issue đã được ignore!</p></div>';
            }
            break;

        case 'unignore':
            if ($issueManager->unignoreIssue($issueId)) {
                echo '<div class="notice notice-success"><p>Issue đã được unignore!</p></div>';
            }
            break;

        case 'resolve':
            $notes = sanitize_textarea_field($_POST['resolution_notes'] ?? '');
            if ($issueManager->resolveIssue($issueId, $notes)) {
                echo '<div class="notice notice-success"><p>Issue đã được đánh dấu resolved!</p></div>';
            }
            break;

        case 'create_ignore_rule':
            $ruleType = sanitize_text_field($_POST['rule_type']);
            $options = [
                'description' => sanitize_textarea_field($_POST['rule_description'] ?? ''),
                'expires_days' => intval($_POST['expires_days'] ?? 0) ?: null
            ];

            if ($_POST['rule_type'] === 'pattern') {
                $options['pattern'] = sanitize_text_field($_POST['pattern_value']);
            }

            if ($issueManager->createIgnoreRuleFromIssue($issueId, $ruleType, $options)) {
                echo '<div class="notice notice-success"><p>Ignore rule đã được tạo!</p></div>';
            }
            break;

        case 'approve_domain':
            if (isset($_POST['domain'])) {
                $domain = sanitize_text_field($_POST['domain']);
                $reason = sanitize_textarea_field($_POST['approve_reason'] ?? '');
                if ($whitelistManager->approvePendingDomain($domain, $reason)) {
                    echo '<div class="notice notice-success"><p>Domain đã được approve và thêm vào whitelist!</p></div>';
                }
            }
            break;

        case 'reject_domain':
            if (isset($_POST['domain'])) {
                $domain = sanitize_text_field($_POST['domain']);
                $reason = sanitize_textarea_field($_POST['reject_reason'] ?? '');
                if ($whitelistManager->rejectPendingDomain($domain, $reason)) {
                    echo '<div class="notice notice-success"><p>Domain đã được reject!</p></div>';
                }
            }
            break;

        case 'add_whitelist_domain':
            if (isset($_POST['whitelist_domain'])) {
                $domain = sanitize_text_field($_POST['whitelist_domain']);
                $reason = sanitize_textarea_field($_POST['whitelist_reason'] ?? '');
                if ($whitelistManager->addToWhitelist($domain, $reason)) {
                    echo '<div class="notice notice-success"><p>Domain đã được approve và thêm vào whitelist!</p></div>';
                } else {
                    echo '<div class="notice notice-error"><p>Không thể thêm domain vào whitelist!</p></div>';
                }
            }
            break;

        case 'remove_whitelist_domain':
            if (isset($_POST['domain'])) {
                $domain = sanitize_text_field($_POST['domain']);
                if ($whitelistManager->removeFromWhitelist($domain)) {
                    echo '<div class="notice notice-success"><p>Domain đã được xóa khỏi whitelist!</p></div>';
                }
            }
            break;

        case 'ignore_file_hash':
            if (isset($_POST['file_hash']) && isset($_POST['issue_id'])) {
                $fileHash = sanitize_text_field($_POST['file_hash']);
                $evalIssuer = new EvalFunctionIssuer();
                $evalIssuer->addIgnoredHash($fileHash);

                // Cũng ignore issue hiện tại
                $reason = "File đã được kiểm tra và xác nhận an toàn";
                if ($issueManager->ignoreIssue($issueId, $reason)) {
                    echo '<div class="notice notice-success"><p>File hash đã được thêm vào ignore list và issue đã được ignore!</p></div>';
                }
            }
            break;

        case 'allow_rejected_domain':
            if (isset($_POST['domain'])) {
                $domain = sanitize_text_field($_POST['domain']);
                if ($whitelistManager->removeFromRejected($domain)) {
                    echo '<div class="notice notice-success"><p>Domain "' . esc_html($domain) . '" đã được xóa khỏi rejected list!</p></div>';
                } else {
                    echo '<div class="notice notice-error"><p>Không thể xóa domain khỏi rejected list!</p></div>';
                }
            }
            break;
    }
}

// Lấy parameters từ URL
$current_tab = $_GET['tab'] ?? 'issues';
$page = max(1, intval($_GET['paged'] ?? 1));
$status_filter = $_GET['status'] ?? '';
$severity_filter = $_GET['severity'] ?? '';
$issuer_filter = $_GET['issuer'] ?? '';
$search = $_GET['s'] ?? '';

// Lấy danh sách issues
$args = [
    'page' => $page,
    'per_page' => 20,
    'status' => $status_filter,
    'severity' => $severity_filter,
    'issuer' => $issuer_filter,
    'search' => $search,
    'include_ignored' => $current_tab === 'ignored'
];

if ($current_tab === 'ignored') {
    $args['include_ignored'] = true;
    unset($args['status']); // Show all statuses for ignored tab
}

$results = $issueManager->getIssues($args);
$stats = $issueManager->getStats();
$whitelistStats = $whitelistManager->getStats();
$pendingDomains = $whitelistManager->getPendingDomains();
$whitelistDetails = $whitelistManager->getWhitelistDetails();

// Lấy unique issuers cho filter
global $wpdb;
$table = $wpdb->prefix . Schema::TABLE_ISSUES;
$unique_issuers = $wpdb->get_col("SELECT DISTINCT issuer_name FROM $table ORDER BY issuer_name");
?>

<div class="wrap">
    <h1>🔍 Security Issues Management</h1>

    <!-- Tabs -->
    <nav class="nav-tab-wrapper">
        <a href="?page=wp-security-monitor-issues&tab=issues"
           class="nav-tab <?php echo $current_tab === 'issues' ? 'nav-tab-active' : ''; ?>">
            📋 Issues (<?php echo $stats['total_issues'] - $stats['ignored_issues']; ?>)
        </a>
        <a href="?page=wp-security-monitor-issues&tab=ignored"
           class="nav-tab <?php echo $current_tab === 'ignored' ? 'nav-tab-active' : ''; ?>">
            🚫 Ignored (<?php echo $stats['ignored_issues']; ?>)
        </a>
        <a href="?page=wp-security-monitor-issues&tab=rules"
           class="nav-tab <?php echo $current_tab === 'rules' ? 'nav-tab-active' : ''; ?>">
            📝 Ignore Rules (<?php echo $stats['active_ignore_rules']; ?>)
        </a>
                <a href="?page=wp-security-monitor-issues&tab=stats"
           class="nav-tab <?php echo $current_tab === 'stats' ? 'nav-tab-active' : ''; ?>">
            📊 Statistics
        </a>
        <a href="?page=wp-security-monitor-issues&tab=whitelist"
           class="nav-tab <?php echo $current_tab === 'whitelist' ? 'nav-tab-active' : ''; ?>">
            ✅ Whitelist Domains (<?php echo $whitelistStats['whitelisted_count']; ?>)
        </a>
        <a href="?page=wp-security-monitor-issues&tab=pending-domains"
           class="nav-tab <?php echo $current_tab === 'pending-domains' ? 'nav-tab-active' : ''; ?>">
            ⏳ Pending Domains (<?php echo $whitelistStats['pending_count']; ?>)
        </a>
        <a href="?page=wp-security-monitor-issues&tab=rejected-domains"
           class="nav-tab <?php echo $current_tab === 'rejected-domains' ? 'nav-tab-active' : ''; ?>">
            ❌ Rejected Domains (<?php echo $whitelistStats['rejected_count']; ?>)
        </a>
    </nav>

    <?php if ($current_tab === 'issues' || $current_tab === 'ignored'): ?>

        <!-- Filters -->
        <div class="tablenav top">
            <form method="get" class="alignleft">
                <input type="hidden" name="page" value="wp-security-monitor-issues">
                <input type="hidden" name="tab" value="<?php echo esc_attr($current_tab); ?>">

                <select name="status">
                    <option value="">All Statuses</option>
                    <option value="new" <?php selected($status_filter, 'new'); ?>>New</option>
                    <option value="investigating" <?php selected($status_filter, 'investigating'); ?>>Investigating</option>
                    <option value="resolved" <?php selected($status_filter, 'resolved'); ?>>Resolved</option>
                    <option value="false_positive" <?php selected($status_filter, 'false_positive'); ?>>False Positive</option>
                </select>

                <select name="severity">
                    <option value="">All Severities</option>
                    <option value="low" <?php selected($severity_filter, 'low'); ?>>Low</option>
                    <option value="medium" <?php selected($severity_filter, 'medium'); ?>>Medium</option>
                    <option value="high" <?php selected($severity_filter, 'high'); ?>>High</option>
                    <option value="critical" <?php selected($severity_filter, 'critical'); ?>>Critical</option>
                </select>

                <select name="issuer">
                    <option value="">All Issuers</option>
                    <?php foreach ($unique_issuers as $issuer): ?>
                        <option value="<?php echo esc_attr($issuer); ?>" <?php selected($issuer_filter, $issuer); ?>>
                            <?php echo esc_html($issuer); ?>
                        </option>
                    <?php endforeach; ?>
                </select>

                <input type="text" name="s" value="<?php echo esc_attr($search); ?>" placeholder="Search issues...">
                <input type="submit" class="button" value="Filter">

                <?php if ($status_filter || $severity_filter || $issuer_filter || $search): ?>
                    <a href="?page=wp-security-monitor-issues&tab=<?php echo esc_attr($current_tab); ?>" class="button">Clear</a>
                <?php endif; ?>
            </form>

            <div class="tablenav-pages">
                <?php if ($results['pages'] > 1): ?>
                    <?php
                    $page_links = paginate_links([
                        'base' => add_query_arg(['paged' => '%#%']),
                        'format' => '',
                        'prev_text' => '&laquo;',
                        'next_text' => '&raquo;',
                        'total' => $results['pages'],
                        'current' => $page,
                        'type' => 'array'
                    ]);

                    if ($page_links) {
                        echo '<span class="pagination-links">' . implode('', $page_links) . '</span>';
                    }
                    ?>
                <?php endif; ?>

                <span class="displaying-num">
                    <?php echo number_format($results['total']); ?> items
                </span>
            </div>
        </div>

        <!-- Issues Table -->
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th style="width: 50px;">ID</th>
                    <th style="width: 80px;">Severity</th>
                    <th>Issue</th>
                    <th style="width: 120px;">Issuer</th>
                    <th style="width: 100px;">Detection</th>
                    <th style="width: 80px;">Count</th>
                    <th style="width: 120px;">Last Detected</th>
                    <th style="width: 100px;">Status</th>
                    <th style="width: 100px;">Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($results['issues'])): ?>
                    <tr>
                        <td colspan="9" class="no-items">No issues found.</td>
                    </tr>
                <?php else: ?>
                    <?php foreach ($results['issues'] as $issue): ?>
                        <tr class="<?php echo $issue['is_ignored'] ? 'ignored-issue' : ''; ?>">
                            <td><?php echo $issue['id']; ?></td>
                            <td>
                                <span class="severity-<?php echo $issue['severity']; ?>">
                                    <?php echo strtoupper($issue['severity']); ?>
                                </span>
                            </td>
                            <td>
                                <strong><?php echo esc_html($issue['title']); ?></strong>
                                <?php if ($issue['file_path']): ?>
                                    <br><small>📁 <?php echo esc_html($issue['file_path']); ?></small>
                                <?php endif; ?>
                                <?php if ($issue['ip_address']): ?>
                                    <br><small>🌐 <?php echo esc_html($issue['ip_address']); ?></small>
                                <?php endif; ?>

                                <div class="row-actions">
                                    <span class="view">
                                        <a href="#" onclick="showIssueDetails(<?php echo $issue['id']; ?>)">View Details</a>
                                    </span>
                                </div>

                                <!-- Hidden details -->
                                <div id="details-<?php echo $issue['id']; ?>" class="issue-details" style="display: none;">
                                    <h4>📋 Description:</h4>
                                    <p><?php echo esc_html($issue['description']); ?></p>

                                    <?php if ($issue['details']): ?>
                                        <h4>🔍 Technical Details:</h4>
                                        <pre><?php echo esc_html($issue['details']); ?></pre>
                                    <?php endif; ?>

                                    <?php
                                    // Debug: Kiểm tra backtrace
                                    $hasBacktrace = !empty($issue['backtrace']) && $issue['backtrace'] !== 'null' && $issue['backtrace'] !== '[]';
                                    if ($hasBacktrace):
                                    ?>
                                        <h4>🗂️ Backtrace:</h4>
                                        <div class="backtrace-container">
                                            <?php
                                            $backtrace = is_string($issue['backtrace']) ? json_decode($issue['backtrace'], true) : $issue['backtrace'];
                                            if (is_array($backtrace) && !empty($backtrace)):
                                            ?>
                                                <table class="backtrace-table">
                                                    <thead>
                                                        <tr>
                                                            <th>#</th>
                                                            <th>File</th>
                                                            <th>Line</th>
                                                            <th>Function</th>
                                                            <th>Class</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        <?php foreach ($backtrace as $index => $frame): ?>
                                                            <tr>
                                                                <td><?php echo $index + 1; ?></td>
                                                                <td>
                                                                    <code class="file-path" title="<?php echo esc_attr($frame['file'] ?? 'Unknown'); ?>">
                                                                        <?php
                                                                        $file = $frame['file'] ?? 'Unknown';
                                                                        // Hiển thị relative path từ ABSPATH
                                                                        if (defined('ABSPATH') && strpos($file, ABSPATH) === 0) {
                                                                            echo esc_html(str_replace(ABSPATH, '', $file));
                                                                        } else {
                                                                            echo esc_html(basename($file));
                                                                        }
                                                                        ?>
                                                                    </code>
                                                                </td>
                                                                <td><code><?php echo esc_html($frame['line'] ?? '-'); ?></code></td>
                                                                <td><code><?php echo esc_html($frame['function'] ?? 'unknown'); ?></code></td>
                                                                <td><code><?php echo esc_html($frame['class'] ?? '-'); ?></code></td>
                                                            </tr>
                                                        <?php endforeach; ?>
                                                    </tbody>
                                                </table>
                                            <?php else: ?>
                                                <p><em>No backtrace available</em></p>
                                            <?php endif; ?>
                                        </div>
                                    <?php else: ?>
                                        <h4>🗂️ Backtrace:</h4>
                                        <p><em>Debug: Backtrace data: <?php echo esc_html($issue['backtrace'] ?? 'NULL'); ?></em></p>
                                        <?php if (!empty($issue['backtrace'])): ?>
                                            <details>
                                                <summary>Raw Backtrace JSON</summary>
                                                <pre><?php echo esc_html($issue['backtrace']); ?></pre>
                                            </details>
                                        <?php endif; ?>
                                    <?php endif; ?>

                                    <?php if (!empty($issue['user_agent'])): ?>
                                        <h4>🌐 User Agent:</h4>
                                        <code><?php echo esc_html($issue['user_agent']); ?></code>
                                    <?php endif; ?>

                                    <?php if (!empty($issue['metadata'])): ?>
                                        <h4>📊 Metadata:</h4>
                                        <pre><?php echo esc_html(is_string($issue['metadata']) ? $issue['metadata'] : json_encode($issue['metadata'], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)); ?></pre>
                                    <?php endif; ?>
                                </div>
                            </td>
                            <td><?php echo esc_html($issue['issuer_name']); ?></td>
                            <td>
                                <?php
                                // Handle both array and JSON string formats
                                if (is_array($issue['raw_data'])) {
                                    $debugInfo = $issue['raw_data'];
                                } else {
                                    $debugInfo = json_decode($issue['raw_data'], true) ?: [];
                                }
                                $detectionMethod = $debugInfo['detection_method'] ?? 'Unknown';
                                $issuerType = $debugInfo['issuer_type'] ?? 'Unknown';

                                $typeIcon = '';
                                $typeColor = '';
                                switch($issuerType) {
                                    case 'TRIGGER':
                                        $typeIcon = '⚡';
                                        $typeColor = '#e74c3c';
                                        break;
                                    case 'SCAN':
                                        $typeIcon = '🔍';
                                        $typeColor = '#3498db';
                                        break;
                                    case 'HYBRID':
                                        $typeIcon = '🔄';
                                        $typeColor = '#f39c12';
                                        break;
                                    default:
                                        $typeIcon = '❓';
                                        $typeColor = '#95a5a6';
                                }
                                ?>
                                <span style="color: <?php echo $typeColor; ?>; font-weight: bold;" title="<?php echo esc_attr($detectionMethod); ?>">
                                    <?php echo $typeIcon; ?> <?php echo esc_html($issuerType); ?>
                                </span>
                            </td>
                            <td><span class="count-badge"><?php echo $issue['detection_count']; ?></span></td>
                            <td><?php echo date('M j, H:i', strtotime($issue['last_detected'])); ?></td>
                            <td>
                                <span class="status-<?php echo $issue['status']; ?>">
                                    <?php echo ucfirst($issue['status']); ?>
                                </span>
                                <?php if ($issue['is_ignored']): ?>
                                    <br><small>🚫 Ignored</small>
                                <?php endif; ?>
                            </td>
                            <td>
                                <div class="button-group">
                                    <?php if (!$issue['is_ignored']): ?>
                                        <?php
                                        $isViewed = isset($issue['viewed']) && $issue['viewed'] == 1;
                                        ?>

                                        <?php if (!$isViewed): ?>
                                            <button class="button-small button button-primary" onclick="markAsViewed(<?php echo $issue['id']; ?>)" id="viewed-btn-<?php echo $issue['id']; ?>">
                                                👁️ Đánh dấu đã xem
                                            </button>
                                        <?php else: ?>
                                            <button class="button-small button" onclick="unmarkAsViewed(<?php echo $issue['id']; ?>)" id="viewed-btn-<?php echo $issue['id']; ?>" style="opacity: 0.6;">
                                                ✅ Đã xem
                                            </button>
                                        <?php endif; ?>

                                        <button class="button-small button" onclick="showIgnoreModal(<?php echo $issue['id']; ?>)">
                                            🚫 Ignore
                                        </button>

                                        <?php if ($issue['status'] !== 'resolved'): ?>
                                            <button class="button-small button" onclick="showResolveModal(<?php echo $issue['id']; ?>)">
                                                ✅ Resolve
                                            </button>
                                        <?php endif; ?>

                                        <?php if (($issue['issue_type'] ?? '') === 'dangerous_function' && !empty($issue['file_hash'])): ?>
                                            <button class="button-small button" onclick="showIgnoreFileModal(<?php echo $issue['id']; ?>, '<?php echo esc_attr($issue['file_hash']); ?>')">
                                                📁 Ignore File
                                            </button>
                                        <?php endif; ?>
                                    <?php else: ?>
                                        <form method="post" style="display: inline;">
                                            <?php wp_nonce_field('security_monitor_issues'); ?>
                                            <input type="hidden" name="action" value="unignore">
                                            <input type="hidden" name="issue_id" value="<?php echo $issue['id']; ?>">
                                            <button type="submit" class="button-small button">↩️ Unignore</button>
                                        </form>
                                    <?php endif; ?>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>

    <?php elseif ($current_tab === 'stats'): ?>

        <!-- Statistics Dashboard -->
        <div class="stats-dashboard">
            <div class="stats-cards">
                <div class="stats-card">
                    <h3>📊 Overview</h3>
                    <div class="stat-item">
                        <span class="stat-label">Total Issues:</span>
                        <span class="stat-value"><?php echo number_format($stats['total_issues']); ?></span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">New Issues:</span>
                        <span class="stat-value critical"><?php echo number_format($stats['new_issues']); ?></span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Resolved:</span>
                        <span class="stat-value success"><?php echo number_format($stats['resolved_issues']); ?></span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Ignored:</span>
                        <span class="stat-value"><?php echo number_format($stats['ignored_issues']); ?></span>
                    </div>
                </div>

                <div class="stats-card">
                    <h3>🎯 By Severity</h3>
                    <?php foreach (['critical', 'high', 'medium', 'low'] as $sev): ?>
                        <div class="stat-item">
                            <span class="stat-label severity-<?php echo $sev; ?>">
                                <?php echo ucfirst($sev); ?>:
                            </span>
                            <span class="stat-value"><?php echo $stats['by_severity'][$sev] ?? 0; ?></span>
                        </div>
                    <?php endforeach; ?>
                </div>

                <div class="stats-card">
                    <h3>🔍 By Issuer</h3>
                    <?php foreach ($stats['by_issuer'] as $issuer => $count): ?>
                        <div class="stat-item">
                            <span class="stat-label"><?php echo esc_html($issuer); ?>:</span>
                            <span class="stat-value"><?php echo number_format($count); ?></span>
                        </div>
                    <?php endforeach; ?>
                </div>

                <div class="stats-card">
                    <h3>📅 Recent Activity</h3>
                    <div class="stat-item">
                        <span class="stat-label">Last 24h:</span>
                        <span class="stat-value"><?php echo number_format($stats['issues_last_24h']); ?></span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Last 7 days:</span>
                        <span class="stat-value"><?php echo number_format($stats['issues_last_7d']); ?></span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Ignore Rules:</span>
                        <span class="stat-value"><?php echo number_format($stats['active_ignore_rules']); ?></span>
                    </div>
                </div>
            </div>
        </div>

        <?php elseif ($current_tab === 'rules'): ?>

        <!-- Ignore Rules Management -->
        <p>Coming soon: Ignore Rules management interface</p>

    <?php elseif ($current_tab === 'whitelist'): ?>

        <!-- Whitelist Domains Management -->
        <div class="card">
            <h2>✅ Whitelist Domains</h2>

            <!-- Add new domain form -->
            <form method="post" style="margin-bottom: 20px;">
                <?php wp_nonce_field('security_monitor_issues'); ?>
                <input type="hidden" name="action" value="add_whitelist_domain">
                <table class="form-table">
                    <tr>
                        <th><label for="whitelist_domain">Domain:</label></th>
                        <td>
                            <input type="text" id="whitelist_domain" name="whitelist_domain"
                                   placeholder="example.com hoặc *.example.com" required style="width: 300px;">
                        </td>
                    </tr>
                    <tr>
                        <th><label for="whitelist_reason">Reason:</label></th>
                        <td>
                            <textarea id="whitelist_reason" name="whitelist_reason"
                                      placeholder="Lý do thêm domain này vào whitelist..." rows="2" style="width: 400px;"></textarea>
                        </td>
                    </tr>
                </table>
                <p><button type="submit" class="button button-primary">➕ Add Domain</button></p>
            </form>

            <!-- Whitelist table -->
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>Reason</th>
                        <th>Added By</th>
                        <th>Added Date</th>
                        <th>Usage Count</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($whitelistDetails)): ?>
                        <tr><td colspan="6">No whitelisted domains.</td></tr>
                    <?php else: ?>
                        <?php foreach ($whitelistDetails as $domain => $data): ?>
                            <?php $user = get_userdata($data['added_by']); ?>
                            <tr>
                                <td><strong><?php echo esc_html($domain); ?></strong></td>
                                <td><?php echo esc_html($data['reason'] ?: 'No reason provided'); ?></td>
                                <td><?php echo $user ? esc_html($user->display_name) : 'Unknown'; ?></td>
                                <td><?php echo date('M j, Y', strtotime($data['added_at'])); ?></td>
                                <td><span class="count-badge"><?php echo $data['usage_count']; ?></span></td>
                                <td>
                                    <form method="post" style="display: inline;" onsubmit="return confirm('Remove this domain from whitelist?');">
                                        <?php wp_nonce_field('security_monitor_issues'); ?>
                                        <input type="hidden" name="action" value="remove_whitelist_domain">
                                        <input type="hidden" name="domain" value="<?php echo esc_attr($domain); ?>">
                                        <button type="submit" class="button button-small">🗑️ Remove</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>

    <?php elseif ($current_tab === 'pending-domains'): ?>

        <!-- Pending Domains for Review -->
        <div class="card">
            <h2>⏳ Pending Domains for Review</h2>
            <p>Các domain sau đây đã được phát hiện trong external redirects và cần được review để quyết định whitelist hay không.</p>

            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>Detection Count</th>
                        <th>First Detected</th>
                        <th>Last Detected</th>
                        <th>Context</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($pendingDomains)): ?>
                        <tr><td colspan="7">No pending domains.</td></tr>
                    <?php else: ?>
                        <?php foreach ($pendingDomains as $domain => $data): ?>
                            <tr class="<?php echo $data['status'] === 'rejected' ? 'rejected-domain' : ''; ?>">
                                <td><strong><?php echo esc_html($domain); ?></strong></td>
                                <td><?php echo $data['detection_count']; ?></td>
                                <td><?php echo date('M j, H:i', strtotime($data['first_detected'])); ?></td>
                                <td><?php echo isset($data['last_detected']) ? date('M j, H:i', strtotime($data['last_detected'])) : '-'; ?></td>
                                <td>
                                    <?php if (!empty($data['contexts'])): ?>
                                        <?php $context = end($data['contexts']); ?>
                                        <small>
                                            Source: <?php echo esc_html($context['source'] ?? 'unknown'); ?><br>
                                            <?php if (isset($context['redirect_url'])): ?>
                                                URL: <?php echo esc_html(substr($context['redirect_url'], 0, 50)) . '...'; ?>
                                            <?php endif; ?>
                                        </small>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <span class="status-<?php echo $data['status']; ?>">
                                        <?php echo ucfirst($data['status']); ?>
                                    </span>
                                    <?php if ($data['status'] === 'approved'): ?>
                                        <br><small>✅ In whitelist</small>
                                    <?php elseif ($data['status'] === 'rejected'): ?>
                                        <br><small>❌ Rejected</small>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ($data['status'] === 'pending'): ?>
                                        <button class="button button-small button-primary"
                                                onclick="showApproveModal('<?php echo esc_attr($domain); ?>')">
                                            ✅ Approve
                                        </button>
                                        <button class="button button-small"
                                                onclick="showRejectModal('<?php echo esc_attr($domain); ?>')">
                                            ❌ Reject
                                        </button>
                                    <?php else: ?>
                                        <small>No actions</small>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>

    <?php elseif ($current_tab === 'rejected-domains'): ?>

        <!-- Rejected Domains -->
        <div class="wrap">
            <h2>❌ Rejected Domains</h2>
            <p>Các domain đã bị reject bởi admin. Những domain này sẽ tiếp tục tạo issue khi có redirect.</p>

            <?php
            $rejectedDomains = $whitelistManager->getRejectedDomains(50);
            ?>

            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th style="width: 200px;">Domain</th>
                        <th style="width: 100px;">Detection Count</th>
                        <th style="width: 140px;">First Detected</th>
                        <th style="width: 140px;">Rejected At</th>
                        <th style="width: 120px;">Rejected By</th>
                        <th>Reject Reason</th>
                        <th style="width: 100px;">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($rejectedDomains)): ?>
                        <tr>
                            <td colspan="7" style="text-align: center; padding: 20px;">
                                <em>Chưa có domain nào bị reject</em>
                            </td>
                        </tr>
                    <?php else: ?>
                        <?php foreach ($rejectedDomains as $domain): ?>
                            <tr>
                                <td>
                                    <strong><?php echo esc_html($domain['domain']); ?></strong>
                                </td>
                                <td style="text-align: center;">
                                    <span class="count-badge"><?php echo $domain['detection_count']; ?></span>
                                </td>
                                <td>
                                    <?php echo esc_html($domain['first_detected']); ?>
                                </td>
                                <td>
                                    <?php echo esc_html($domain['rejected_at']); ?>
                                </td>
                                <td>
                                    <?php
                                    $user = $domain['rejected_by_user'];
                                    echo $user ? esc_html($user->display_name) : 'Unknown';
                                    ?>
                                </td>
                                <td>
                                    <?php echo esc_html($domain['reject_reason'] ?: 'No reason provided'); ?>
                                </td>
                                <td>
                                    <button class="button button-small"
                                            onclick="showAllowModal('<?php echo esc_attr($domain['domain']); ?>')">
                                        ✅ Allow Again
                                    </button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>

    <?php endif; ?>
</div>

<!-- Allow Domain Modal -->
<div id="allow-modal" class="modal" style="display: none;">
    <div class="modal-content">
        <h3>✅ Allow Domain Again</h3>
        <p>Domain sẽ được xóa khỏi rejected list và có thể được approve lần sau.</p>
        <form method="post">
            <?php wp_nonce_field('security_monitor_issues'); ?>
            <input type="hidden" name="action" value="allow_rejected_domain">
            <input type="hidden" name="domain" id="allow-domain">

            <p>
                <strong>Domain: </strong><span id="allow-domain-display"></span>
            </p>

            <p>
                <button type="submit" class="button button-primary">✅ Allow Domain</button>
                <button type="button" class="button" onclick="hideAllowModal()">Cancel</button>
            </p>
        </form>
    </div>
</div>

<!-- Ignore Modal -->
<div id="ignore-modal" class="modal" style="display: none;">
    <div class="modal-content">
        <h3>🚫 Ignore Issue</h3>
        <form method="post">
            <?php wp_nonce_field('security_monitor_issues'); ?>
            <input type="hidden" name="action" value="ignore">
            <input type="hidden" name="issue_id" id="ignore-issue-id">

            <p>
                <label for="ignore-reason">Reason for ignoring:</label><br>
                <textarea name="ignore_reason" id="ignore-reason" rows="3" cols="50" placeholder="Optional reason..."></textarea>
            </p>

            <p>
                <strong>Create Ignore Rule:</strong><br>
                <label>
                    <input type="radio" name="rule_type" value="hash" checked>
                    Ignore this specific issue only
                </label><br>
                <label>
                    <input type="radio" name="rule_type" value="file">
                    Ignore all issues from this file
                </label><br>
                <label>
                    <input type="radio" name="rule_type" value="pattern">
                    Ignore similar issues (pattern match)
                </label><br>
                <label>
                    <input type="radio" name="rule_type" value="issuer">
                    Disable this entire issuer
                </label>
            </p>

            <div id="pattern-input" style="display: none;">
                <label for="pattern-value">Pattern:</label><br>
                <input type="text" name="pattern_value" id="pattern-value" style="width: 100%;">
            </div>

            <p>
                <label for="rule-description">Rule Description:</label><br>
                <textarea name="rule_description" id="rule-description" rows="2" cols="50"></textarea>
            </p>

            <p>
                <label for="expires-days">Expires after (days, 0 = never):</label><br>
                <input type="number" name="expires_days" id="expires-days" value="0" min="0" max="365">
            </p>

            <p>
                <button type="submit" class="button button-primary">Ignore Issue</button>
                <button type="button" class="button" onclick="closeModal('ignore-modal')">Cancel</button>
            </p>
        </form>
    </div>
</div>

<!-- Resolve Modal -->
<div id="resolve-modal" class="modal" style="display: none;">
    <div class="modal-content">
        <h3>✅ Resolve Issue</h3>
        <form method="post">
            <?php wp_nonce_field('security_monitor_issues'); ?>
            <input type="hidden" name="action" value="resolve">
            <input type="hidden" name="issue_id" id="resolve-issue-id">

            <p>
                <label for="resolution-notes">Resolution Notes:</label><br>
                <textarea name="resolution_notes" id="resolution-notes" rows="4" cols="50" placeholder="Describe how this issue was resolved..."></textarea>
            </p>

            <p>
                <button type="submit" class="button button-primary">Mark as Resolved</button>
                <button type="button" class="button" onclick="closeModal('resolve-modal')">Cancel</button>
            </p>
        </form>
    </div>
</div>

<!-- Approve Domain Modal -->
<div id="approve-domain-modal" class="modal" style="display: none;">
    <div class="modal-content">
        <h3>✅ Approve Domain</h3>
        <form method="post">
            <?php wp_nonce_field('security_monitor_issues'); ?>
            <input type="hidden" name="action" value="approve_domain">
            <input type="hidden" name="domain" id="approve-domain-name">

            <p>Approve domain: <strong id="approve-domain-display"></strong></p>

            <p>
                <label for="approve-reason">Reason for approval:</label><br>
                <textarea name="approve_reason" id="approve-reason" rows="3" cols="50"
                          placeholder="Why is this domain legitimate?"></textarea>
            </p>

            <p>
                <button type="submit" class="button button-primary">Approve & Add to Whitelist</button>
                <button type="button" class="button" onclick="closeModal('approve-domain-modal')">Cancel</button>
            </p>
        </form>
    </div>
</div>

<!-- Reject Domain Modal -->
<div id="reject-domain-modal" class="modal" style="display: none;">
    <div class="modal-content">
        <h3>❌ Reject Domain</h3>
        <form method="post">
            <?php wp_nonce_field('security_monitor_issues'); ?>
            <input type="hidden" name="action" value="reject_domain">
            <input type="hidden" name="domain" id="reject-domain-name">

            <p>Reject domain: <strong id="reject-domain-display"></strong></p>

            <p>
                <label for="reject-reason">Reason for rejection:</label><br>
                <textarea name="reject_reason" id="reject-reason" rows="3" cols="50"
                          placeholder="Why is this domain suspicious/unwanted?"></textarea>
            </p>

            <p>
                <button type="submit" class="button button-primary">Reject Domain</button>
                <button type="button" class="button" onclick="closeModal('reject-domain-modal')">Cancel</button>
            </p>
        </form>
    </div>
</div>

<!-- Ignore File Modal -->
<div id="ignore-file-modal" class="modal" style="display: none;">
    <div class="modal-content">
        <h3>📁 Ignore File</h3>
        <p>Bạn có muốn thêm file này vào ignore list không? File này sẽ được bỏ qua trong các lần scan tương lai.</p>
        <p><strong>Lưu ý:</strong> Chỉ ignore nếu bạn đã kiểm tra và xác nhận file này an toàn.</p>

        <form method="post">
            <?php wp_nonce_field('security_monitor_issues'); ?>
            <input type="hidden" name="action" value="ignore_file_hash">
            <input type="hidden" name="issue_id" id="ignore-file-issue-id">
            <input type="hidden" name="file_hash" id="ignore-file-hash">

            <div class="file-info" id="ignore-file-info">
                <!-- File info will be populated by JavaScript -->
            </div>

            <div class="modal-buttons">
                <button type="submit" class="button button-primary">📁 Ignore File & Issue</button>
                <button type="button" class="button" onclick="hideIgnoreFileModal()">Cancel</button>
            </div>
        </form>
    </div>
</div>

<style>
/* Styles cho issue management */
.severity-critical { color: #dc3232; font-weight: bold; }
.severity-high { color: #f56e28; font-weight: bold; }
.severity-medium { color: #ffb900; font-weight: bold; }
.severity-low { color: #00a32a; font-weight: bold; }

.status-new { color: #dc3232; }
.status-investigating { color: #f56e28; }
.status-resolved { color: #00a32a; }
.status-ignored { color: #646970; }
.status-false_positive { color: #646970; }

.ignored-issue { opacity: 0.6; }

.count-badge {
    background: #2271b1;
    color: white;
    padding: 2px 6px;
    border-radius: 3px;
    font-size: 11px;
    font-weight: bold;
}

.button-group {
    display: flex;
    flex-direction: column;
    gap: 2px;
}

.button-small {
    font-size: 11px;
    padding: 2px 6px;
    height: auto;
    line-height: 1.2;
}

.issue-details {
    background: #f9f9f9;
    border: 1px solid #ddd;
    padding: 10px;
    margin-top: 10px;
    border-radius: 4px;
}

.issue-details pre {
    background: #fff;
    border: 1px solid #ddd;
    padding: 8px;
    overflow-x: auto;
    font-size: 12px;
}

/* Modal styles */
.modal {
    position: fixed;
    z-index: 100000;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0,0,0,0.5);
}

.modal-content {
    background-color: #fefefe;
    margin: 5% auto;
    padding: 20px;
    border: 1px solid #888;
    width: 500px;
    max-width: 90%;
    border-radius: 4px;
}

/* Stats dashboard */
.stats-dashboard {
    margin-top: 20px;
}

.stats-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
    margin-bottom: 20px;
}

.stats-card {
    background: #fff;
    border: 1px solid #ccd0d4;
    border-radius: 4px;
    padding: 20px;
}

.stats-card h3 {
    margin-top: 0;
    border-bottom: 1px solid #eee;
    padding-bottom: 10px;
}

.stat-item {
    display: flex;
    justify-content: space-between;
    padding: 8px 0;
    border-bottom: 1px solid #f0f0f0;
}

.stat-item:last-child {
    border-bottom: none;
}

.stat-value {
    font-weight: bold;
}

.stat-value.critical { color: #dc3232; }
.stat-value.success { color: #00a32a; }

.rejected-domain { opacity: 0.6; background: #ffebee; }
.status-pending { color: #f56e28; font-weight: bold; }
.status-approved { color: #00a32a; font-weight: bold; }
.status-rejected { color: #dc3232; font-weight: bold; }

/* Backtrace styles */
.backtrace-container {
    max-height: 400px;
    overflow-y: auto;
    margin-top: 10px;
}

.backtrace-table {
    width: 100%;
    border-collapse: collapse;
    background: #fff;
    font-size: 12px;
}

.backtrace-table thead {
    background: #f0f0f0;
    position: sticky;
    top: 0;
    z-index: 1;
}

.backtrace-table th {
    padding: 8px;
    text-align: left;
    border: 1px solid #ddd;
    font-weight: bold;
}

.backtrace-table td {
    padding: 6px 8px;
    border: 1px solid #ddd;
    vertical-align: top;
}

.backtrace-table tr:nth-child(even) {
    background: #f9f9f9;
}

.backtrace-table tr:hover {
    background: #e8f4f8;
}

.backtrace-table code {
    background: transparent;
    padding: 0;
    font-family: 'Courier New', monospace;
    font-size: 11px;
}

.backtrace-table .file-path {
    color: #0073aa;
    display: block;
    max-width: 300px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}

.backtrace-table .file-path:hover {
    max-width: none;
    white-space: normal;
    word-break: break-all;
}

.issue-details h4 {
    margin-top: 15px;
    margin-bottom: 8px;
    border-bottom: 1px solid #e0e0e0;
    padding-bottom: 5px;
}

.issue-details > h4:first-child {
    margin-top: 0;
}
</style>

<script>
function showIssueDetails(issueId) {
    const details = document.getElementById('details-' + issueId);
    if (details.style.display === 'none') {
        details.style.display = 'block';
    } else {
        details.style.display = 'none';
    }
}

function showIgnoreModal(issueId) {
    document.getElementById('ignore-issue-id').value = issueId;
    document.getElementById('ignore-modal').style.display = 'block';
}

function showResolveModal(issueId) {
    document.getElementById('resolve-issue-id').value = issueId;
    document.getElementById('resolve-modal').style.display = 'block';
}

function closeModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
}

function markAsViewed(issueId) {
    if (!confirm('Đánh dấu issue này là đã xem? Nếu issue xuất hiện lại sẽ được báo cáo tiếp.')) {
        return;
    }

    const btn = document.getElementById('viewed-btn-' + issueId);
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '⏳ Đang xử lý...';

    jQuery.ajax({
        url: ajaxurl,
        type: 'POST',
        data: {
            action: 'security_monitor_mark_viewed',
            issue_id: issueId,
            nonce: '<?php echo wp_create_nonce('security_monitor_nonce'); ?>'
        },
        success: function(response) {
            if (response.success) {
                btn.innerHTML = '✅ Đã xem';
                btn.className = 'button-small button';
                btn.style.opacity = '0.6';
                btn.onclick = function() { unmarkAsViewed(issueId); };
                btn.disabled = false;

                // Show success message
                const notice = document.createElement('div');
                notice.className = 'notice notice-success is-dismissible';
                notice.innerHTML = '<p>' + response.data.message + '</p>';
                document.querySelector('.wrap').insertBefore(notice, document.querySelector('.wrap').firstChild);
                setTimeout(() => notice.remove(), 3000);
            } else {
                alert('Lỗi: ' + response.data.message);
                btn.innerHTML = originalText;
                btn.disabled = false;
            }
        },
        error: function() {
            alert('Có lỗi xảy ra. Vui lòng thử lại.');
            btn.innerHTML = originalText;
            btn.disabled = false;
        }
    });
}

function unmarkAsViewed(issueId) {
    if (!confirm('Bỏ đánh dấu đã xem? Issue này sẽ được báo cáo lại nếu phát hiện tiếp.')) {
        return;
    }

    const btn = document.getElementById('viewed-btn-' + issueId);
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '⏳ Đang xử lý...';

    jQuery.ajax({
        url: ajaxurl,
        type: 'POST',
        data: {
            action: 'security_monitor_unmark_viewed',
            issue_id: issueId,
            nonce: '<?php echo wp_create_nonce('security_monitor_nonce'); ?>'
        },
        success: function(response) {
            if (response.success) {
                btn.innerHTML = '👁️ Đánh dấu đã xem';
                btn.className = 'button-small button button-primary';
                btn.style.opacity = '1';
                btn.onclick = function() { markAsViewed(issueId); };
                btn.disabled = false;

                // Show success message
                const notice = document.createElement('div');
                notice.className = 'notice notice-success is-dismissible';
                notice.innerHTML = '<p>' + response.data.message + '</p>';
                document.querySelector('.wrap').insertBefore(notice, document.querySelector('.wrap').firstChild);
                setTimeout(() => notice.remove(), 3000);
            } else {
                alert('Lỗi: ' + response.data.message);
                btn.innerHTML = originalText;
                btn.disabled = false;
            }
        },
        error: function() {
            alert('Có lỗi xảy ra. Vui lòng thử lại.');
            btn.innerHTML = originalText;
            btn.disabled = false;
        }
    });
}

function showApproveModal(domain) {
    document.getElementById('approve-domain-name').value = domain;
    document.getElementById('approve-domain-display').textContent = domain;
    document.getElementById('approve-domain-modal').style.display = 'block';
}

function showRejectModal(domain) {
    document.getElementById('reject-domain-name').value = domain;
    document.getElementById('reject-domain-display').textContent = domain;
    document.getElementById('reject-domain-modal').style.display = 'block';
}

function showIgnoreFileModal(issueId, fileHash) {
    // Populate hidden inputs
    document.getElementById('ignore-file-issue-id').value = issueId;
    document.getElementById('ignore-file-hash').value = fileHash;

    // Find the issue row để get file info
    const issueRow = document.querySelector('tr').closest('tr');
    const filePathElement = issueRow ? issueRow.querySelector('small') : null;
    const filePath = filePathElement ? filePathElement.textContent.replace('📁 ', '') : 'Unknown file';

    // Populate file info
    const fileInfoDiv = document.getElementById('ignore-file-info');
    fileInfoDiv.innerHTML = `
        <p><strong>File:</strong> ${filePath}</p>
        <p><strong>File Hash:</strong> <code>${fileHash}</code></p>
        <p><small>Issue ID: ${issueId}</small></p>
    `;

    // Show modal
    document.getElementById('ignore-file-modal').style.display = 'block';
}

function hideIgnoreFileModal() {
    document.getElementById('ignore-file-modal').style.display = 'none';
}

function showAllowModal(domain) {
    document.getElementById('allow-domain').value = domain;
    document.getElementById('allow-domain-display').innerText = domain;
    document.getElementById('allow-modal').style.display = 'block';
}

function hideAllowModal() {
    document.getElementById('allow-modal').style.display = 'none';
}

// Show/hide pattern input based on rule type
document.addEventListener('DOMContentLoaded', function() {
    const ruleTypeInputs = document.querySelectorAll('input[name="rule_type"]');
    const patternInput = document.getElementById('pattern-input');

    ruleTypeInputs.forEach(input => {
        input.addEventListener('change', function() {
            if (this.value === 'pattern') {
                patternInput.style.display = 'block';
            } else {
                patternInput.style.display = 'none';
            }
        });
    });
});

// Close modal when clicking outside
window.onclick = function(event) {
    if (event.target.classList.contains('modal')) {
        event.target.style.display = 'none';
    }
}
</script>
