<?php
namespace Puleeno\SecurityBot\WebMonitor\Database;

class Schema
{
    /**
     * Tên table chính để lưu issues
     */
    const TABLE_ISSUES = 'security_monitor_issues';

    /**
     * Tên table cho ignore rules
     */
    const TABLE_IGNORE_RULES = 'security_monitor_ignore_rules';

    /**
     * Tên table cho whitelist domains
     */
    const TABLE_WHITELIST_DOMAINS = 'security_monitor_whitelist_domains';

    /**
     * Tên table cho pending domains
     */
    const TABLE_PENDING_DOMAINS = 'security_monitor_pending_domains';

    /**
     * Tên table cho rejected domains
     */
    const TABLE_REJECTED_DOMAINS = 'security_monitor_rejected_domains';

    /**
     * Tên table cho audit logs
     */
    const TABLE_AUDIT_LOG = 'security_monitor_audit_log';

    /**
     * Tên table cho notifications queue
     */
    const TABLE_NOTIFICATIONS = 'security_monitor_notifications';

    /**
     * Tạo tables khi plugin được activate
     *
     * @return void
     */
    public static function createTables(): void
    {
        global $wpdb;

        $charset_collate = $wpdb->get_charset_collate();

        // Table cho issues
        $issuesTable = $wpdb->prefix . self::TABLE_ISSUES;
        $issuesSQL = "CREATE TABLE IF NOT EXISTS $issuesTable (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            issue_hash varchar(32) NOT NULL,
            line_code_hash varchar(32) DEFAULT NULL,
            issuer_name varchar(100) NOT NULL,
            issue_type varchar(50) NOT NULL,
            severity enum('low','medium','high','critical') DEFAULT 'medium',
            status enum('new','investigating','resolved','ignored','false_positive') DEFAULT 'new',
            title varchar(255) NOT NULL,
            description text,
            details longtext,
            raw_data longtext,
            backtrace longtext DEFAULT NULL,
            file_path varchar(500) DEFAULT NULL,
            ip_address varchar(45) DEFAULT NULL,
            user_agent text DEFAULT NULL,
            first_detected datetime NOT NULL,
            last_detected datetime NOT NULL,
            detection_count int(11) DEFAULT 1,
            is_ignored tinyint(1) DEFAULT 0,
            viewed tinyint(1) DEFAULT 0,
            viewed_by bigint(20) unsigned DEFAULT NULL,
            viewed_at datetime DEFAULT NULL,
            ignored_by bigint(20) unsigned DEFAULT NULL,
            ignored_at datetime DEFAULT NULL,
            ignore_reason text DEFAULT NULL,
            resolved_by bigint(20) unsigned DEFAULT NULL,
            resolved_at datetime DEFAULT NULL,
            resolution_notes text DEFAULT NULL,
            metadata longtext DEFAULT NULL,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY unique_issue_hash (issue_hash),
            KEY idx_issuer_name (issuer_name),
            KEY idx_issue_type (issue_type),
            KEY idx_severity (severity),
            KEY idx_status (status),
            KEY idx_first_detected (first_detected),
            KEY idx_last_detected (last_detected),
            KEY idx_is_ignored (is_ignored),
            KEY idx_viewed (viewed),
            KEY idx_file_path (file_path(255)),
            KEY idx_line_code_hash (line_code_hash),
            KEY idx_ip_address (ip_address)
        ) $charset_collate;";

        // Table cho ignore rules
        $ignoreTable = $wpdb->prefix . self::TABLE_IGNORE_RULES;
        $ignoreSQL = "CREATE TABLE IF NOT EXISTS $ignoreTable (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            rule_name varchar(100) NOT NULL,
            rule_type enum('hash','pattern','issuer','file','ip','regex') NOT NULL,
            rule_value text NOT NULL,
            issuer_name varchar(100) DEFAULT NULL,
            issue_type varchar(50) DEFAULT NULL,
            description text DEFAULT NULL,
            is_active tinyint(1) DEFAULT 1,
            created_by bigint(20) unsigned NOT NULL,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            expires_at datetime DEFAULT NULL,
            usage_count int(11) DEFAULT 0,
            last_used_at datetime DEFAULT NULL,
            PRIMARY KEY (id),
            KEY idx_rule_type (rule_type),
            KEY idx_issuer_name (issuer_name),
            KEY idx_issue_type (issue_type),
            KEY idx_is_active (is_active),
            KEY idx_created_by (created_by),
            KEY idx_expires_at (expires_at)
        ) $charset_collate;";

        // Table cho whitelist domains
        $whitelistTable = $wpdb->prefix . self::TABLE_WHITELIST_DOMAINS;
        $whitelistSQL = "CREATE TABLE IF NOT EXISTS $whitelistTable (
            domain varchar(255) NOT NULL,
            reason text DEFAULT NULL,
            added_by bigint(20) unsigned DEFAULT NULL,
            added_at datetime NOT NULL,
            usage_count int(11) DEFAULT 0,
            last_used datetime DEFAULT NULL,
            PRIMARY KEY (domain),
            KEY idx_added_by (added_by),
            KEY idx_added_at (added_at),
            KEY idx_usage_count (usage_count)
        ) $charset_collate;";

        // Table cho pending domains
        $pendingTable = $wpdb->prefix . self::TABLE_PENDING_DOMAINS;
        $pendingSQL = "CREATE TABLE IF NOT EXISTS $pendingTable (
            domain varchar(255) NOT NULL,
            first_detected datetime NOT NULL,
            detection_count int(11) DEFAULT 1,
            status enum('pending','approved','rejected') DEFAULT 'pending',
            contexts longtext DEFAULT NULL,
            approved_by bigint(20) unsigned DEFAULT NULL,
            approved_at datetime DEFAULT NULL,
            rejected_by bigint(20) unsigned DEFAULT NULL,
            rejected_at datetime DEFAULT NULL,
            reject_reason text DEFAULT NULL,
            PRIMARY KEY (domain),
            KEY idx_status (status),
            KEY idx_first_detected (first_detected),
            KEY idx_approved_by (approved_by),
            KEY idx_rejected_by (rejected_by)
        ) $charset_collate;";

        // Table để lưu các domains đã bị reject
        $rejectedSQL = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}" . self::TABLE_REJECTED_DOMAINS . " (
            id mediumint(9) NOT NULL AUTO_INCREMENT,
            domain varchar(255) NOT NULL,
            first_detected datetime DEFAULT CURRENT_TIMESTAMP,
            detection_count int(11) DEFAULT 1,
            last_detected datetime DEFAULT CURRENT_TIMESTAMP,
            rejected_at datetime DEFAULT CURRENT_TIMESTAMP,
            rejected_by bigint(20) UNSIGNED,
            reject_reason text,
            contexts longtext COMMENT 'JSON array of detection contexts',
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY domain (domain),
            KEY idx_domain (domain),
            KEY idx_rejected_at (rejected_at),
            KEY idx_rejected_by (rejected_by)
        ) $charset_collate;";

        // Audit log table
        $auditSQL = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}" . self::TABLE_AUDIT_LOG . " (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            event_type varchar(100) NOT NULL,
            user_id bigint(20) unsigned NOT NULL DEFAULT 0,
            ip_address varchar(45) NOT NULL,
            user_agent text,
            event_data longtext,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_event_type (event_type),
            KEY idx_user_id (user_id),
            KEY idx_ip_address (ip_address),
            KEY idx_created_at (created_at)
        ) $charset_collate;";

        // Notifications queue table
        $notificationsTable = $wpdb->prefix . self::TABLE_NOTIFICATIONS;
        $issuesTable = $wpdb->prefix . self::TABLE_ISSUES;

        $notificationsSQL = "CREATE TABLE IF NOT EXISTS " . $notificationsTable . " (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            channel_name varchar(100) NOT NULL,
            issue_id bigint(20) unsigned NOT NULL,
            message text NOT NULL,
            context longtext DEFAULT NULL,
            status enum('pending','sent','failed','retry') DEFAULT 'pending',
            retry_count int(11) DEFAULT 0,
            max_retries int(11) DEFAULT 3,
            last_attempt datetime DEFAULT NULL,
            sent_at datetime DEFAULT NULL,
            error_message text DEFAULT NULL,
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            updated_at datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_channel_name (channel_name),
            KEY idx_issue_id (issue_id),
            KEY idx_status (status),
            KEY idx_created_at (created_at),
            KEY idx_pending (status, created_at)
    ) " . $charset_collate . ";";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');

        dbDelta($issuesSQL);
        dbDelta($ignoreSQL);
        dbDelta($whitelistSQL);
        dbDelta($pendingSQL);
        dbDelta($rejectedSQL);
        dbDelta($auditSQL);
        dbDelta($notificationsSQL);

        // Ensure the foreign key exists for notifications.issue_id -> issues.id
        // dbDelta can sometimes create ALTER statements that are invalid for FKs,
        // so add the constraint explicitly if it's missing.
        try {
            $constraintExists = $wpdb->get_var($wpdb->prepare(
                "SELECT CONSTRAINT_NAME FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE
                 WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND COLUMN_NAME = %s AND REFERENCED_TABLE_NAME = %s",
                DB_NAME,
                /* TABLE_NAME */ $notificationsTable,
                /* COLUMN_NAME */ 'issue_id',
                /* REFERENCED_TABLE_NAME */ $issuesTable
            ));

            if (empty($constraintExists)) {
                $constraintName = 'fk_security_monitor_notifications_issue_id';
                $wpdb->query("ALTER TABLE `{$notificationsTable}` ADD CONSTRAINT `{$constraintName}` FOREIGN KEY (`issue_id`) REFERENCES `{$issuesTable}` (`id`) ON DELETE CASCADE");
                if (WP_DEBUG) {
                    error_log("WP Security Monitor: Added foreign key {$constraintName} on {$notificationsTable}(issue_id)");
                }
            }
        } catch (\Exception $e) {
            if (WP_DEBUG) {
                error_log('WP Security Monitor: Failed to ensure notifications foreign key: ' . $e->getMessage());
            }
        }

        // Lưu phiên bản database
        update_option('wp_security_monitor_db_version', '1.2');
    }

    /**
     * Migration: add line_code_hash column if missing
     *
     * @return void
     */
    public static function addLineCodeHashColumn(): void
    {
        global $wpdb;

        $issuesTable = self::getTableName(self::TABLE_ISSUES);

        $columnExists = $wpdb->get_var($wpdb->prepare(
            "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
             WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND COLUMN_NAME = 'line_code_hash'",
            DB_NAME,
            $issuesTable
        ));

        if (empty($columnExists)) {
            $wpdb->query("ALTER TABLE `{$issuesTable}` ADD COLUMN `line_code_hash` varchar(32) DEFAULT NULL AFTER `issue_hash`");
            $wpdb->query("ALTER TABLE `{$issuesTable}` ADD INDEX `idx_line_code_hash` (`line_code_hash`)");
            if (WP_DEBUG) {
                error_log("WP Security Monitor: Added column line_code_hash to {$issuesTable}");
            }
        }
    }

    /**
     * Migration: add viewed columns
     *
     * @return void
     */
    public static function addViewedColumns(): void
    {
        global $wpdb;

        $issuesTable = self::getTableName(self::TABLE_ISSUES);

        // Check if viewed column exists
        $viewedExists = $wpdb->get_var($wpdb->prepare(
            "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
             WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND COLUMN_NAME = 'viewed'",
            DB_NAME,
            $issuesTable
        ));

        if (empty($viewedExists)) {
            $wpdb->query("ALTER TABLE `{$issuesTable}` ADD COLUMN `viewed` tinyint(1) DEFAULT 0 AFTER `is_ignored`");
            $wpdb->query("ALTER TABLE `{$issuesTable}` ADD COLUMN `viewed_by` bigint(20) unsigned DEFAULT NULL AFTER `viewed`");
            $wpdb->query("ALTER TABLE `{$issuesTable}` ADD COLUMN `viewed_at` datetime DEFAULT NULL AFTER `viewed_by`");
            $wpdb->query("ALTER TABLE `{$issuesTable}` ADD INDEX `idx_viewed` (`viewed`)");

            if (WP_DEBUG) {
                error_log("WP Security Monitor: Added viewed columns to {$issuesTable}");
            }
        }
    }

    /**
     * Xóa tables khi plugin được uninstall
     *
     * @return void
     */
    public static function dropTables(): void
    {
        global $wpdb;

        $issuesTable = $wpdb->prefix . self::TABLE_ISSUES;
        $ignoreTable = $wpdb->prefix . self::TABLE_IGNORE_RULES;
        $whitelistTable = $wpdb->prefix . self::TABLE_WHITELIST_DOMAINS;
        $pendingTable = $wpdb->prefix . self::TABLE_PENDING_DOMAINS;
        $rejectedTable = $wpdb->prefix . self::TABLE_REJECTED_DOMAINS;

        $wpdb->query("DROP TABLE IF EXISTS $issuesTable");
        $wpdb->query("DROP TABLE IF EXISTS $ignoreTable");
        $wpdb->query("DROP TABLE IF EXISTS $whitelistTable");
        $wpdb->query("DROP TABLE IF EXISTS $pendingTable");
        $wpdb->query("DROP TABLE IF EXISTS $rejectedTable");

        $auditTable = $wpdb->prefix . self::TABLE_AUDIT_LOG;
        $wpdb->query("DROP TABLE IF EXISTS $auditTable");

        delete_option('wp_security_monitor_db_version');
    }

    /**
     * Cập nhật database schema nếu cần
     *
     * @return void
     */
    public static function updateSchema(): void
    {
        $currentVersion = get_option('wp_security_monitor_db_version', '0');
        $latestVersion = '1.2';

        if (version_compare($currentVersion, $latestVersion, '<')) {
            if (version_compare($currentVersion, '1.0', '<')) {
                self::createTables();
            }

            // Migration từ version 1.0 lên 1.1: thêm column backtrace
            if (version_compare($currentVersion, '1.1', '<')) {
                self::addBacktraceColumn();
                // Ensure line_code_hash exists as part of 1.1 migration
                if (method_exists(__CLASS__, 'addLineCodeHashColumn')) {
                    self::addLineCodeHashColumn();
                }
            }

            // Migration từ version 1.1 lên 1.2: thêm viewed columns
            if (version_compare($currentVersion, '1.2', '<')) {
                self::addViewedColumns();
            }

            update_option('wp_security_monitor_db_version', $latestVersion);
            update_option('wp_security_monitor_db_updated_at', time());

            if (WP_DEBUG) {
                error_log('[WP Security Monitor] Database migrated to version ' . $latestVersion);
            }
        }
    }

    /**
     * Thêm column backtrace vào table issues
     *
     * @return void
     */
    private static function addBacktraceColumn(): void
    {
        global $wpdb;

        $issuesTable = self::getTableName(self::TABLE_ISSUES);

        // Kiểm tra xem column backtrace đã tồn tại chưa
        $columnExists = $wpdb->get_results($wpdb->prepare(
            "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
             WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND COLUMN_NAME = 'backtrace'",
            DB_NAME,
            $issuesTable
        ));

        if (empty($columnExists)) {
            $wpdb->query("ALTER TABLE $issuesTable ADD COLUMN backtrace longtext DEFAULT NULL AFTER raw_data");

            if (WP_DEBUG) {
                error_log("WP Security Monitor: Added backtrace column to issues table");
            }
        }
    }

    /**
     * Lấy tên table đầy đủ
     *
     * @param string $tableName
     * @return string
     */
    public static function getTableName(string $tableName): string
    {
        global $wpdb;
        return $wpdb->prefix . $tableName;
    }

    /**
     * Kiểm tra table có tồn tại không
     *
     * @param string $tableName
     * @return bool
     */
    public static function tableExists(string $tableName): bool
    {
        global $wpdb;
        $table = self::getTableName($tableName);
        return $wpdb->get_var("SHOW TABLES LIKE '$table'") === $table;
    }

    /**
     * Làm sạch dữ liệu cũ
     *
     * @param int $daysToKeep Số ngày giữ lại dữ liệu
     * @return array Thống kê cleanup
     */
    public static function cleanupOldData(int $daysToKeep = 90): array
    {
        global $wpdb;

        $issuesTable = self::getTableName(self::TABLE_ISSUES);
        $ignoreTable = self::getTableName(self::TABLE_IGNORE_RULES);

        $cutoffDate = date('Y-m-d H:i:s', strtotime("-{$daysToKeep} days"));

        // Xóa issues cũ đã resolved
        $deletedIssues = $wpdb->query($wpdb->prepare(
            "DELETE FROM $issuesTable
             WHERE status IN ('resolved', 'false_positive')
             AND updated_at < %s",
            $cutoffDate
        ));

        // Xóa ignore rules đã hết hạn
        $deletedRules = $wpdb->query($wpdb->prepare(
            "DELETE FROM $ignoreTable
             WHERE expires_at IS NOT NULL
             AND expires_at < %s",
            date('Y-m-d H:i:s')
        ));

        // Cập nhật usage count cho ignore rules không sử dụng
        $wpdb->query($wpdb->prepare(
            "UPDATE $ignoreTable
             SET is_active = 0
             WHERE last_used_at < %s
             AND usage_count < 5",
            $cutoffDate
        ));

        return [
            'deleted_issues' => $deletedIssues ?: 0,
            'deleted_rules' => $deletedRules ?: 0,
            'cutoff_date' => $cutoffDate
        ];
    }

    /**
     * Lấy thống kê database
     *
     * @return array
     */
    public static function getStats(): array
    {
        global $wpdb;

        $issuesTable = self::getTableName(self::TABLE_ISSUES);
        $ignoreTable = self::getTableName(self::TABLE_IGNORE_RULES);

        $stats = [];

        // Issues stats
        $stats['total_issues'] = $wpdb->get_var("SELECT COUNT(*) FROM $issuesTable");
        $stats['new_issues'] = $wpdb->get_var("SELECT COUNT(*) FROM $issuesTable WHERE status = 'new'");
        $stats['ignored_issues'] = $wpdb->get_var("SELECT COUNT(*) FROM $issuesTable WHERE is_ignored = 1");
        $stats['resolved_issues'] = $wpdb->get_var("SELECT COUNT(*) FROM $issuesTable WHERE status = 'resolved'");

        // Severity breakdown
        $severityStats = $wpdb->get_results(
            "SELECT severity, COUNT(*) as count FROM $issuesTable GROUP BY severity",
            ARRAY_A
        );
        $stats['by_severity'] = array_column($severityStats, 'count', 'severity');

        // Issuer breakdown
        $issuerStats = $wpdb->get_results(
            "SELECT issuer_name, COUNT(*) as count FROM $issuesTable GROUP BY issuer_name ORDER BY count DESC LIMIT 10",
            ARRAY_A
        );
        $stats['by_issuer'] = array_column($issuerStats, 'count', 'issuer_name');

        // Ignore rules stats
        $stats['total_ignore_rules'] = $wpdb->get_var("SELECT COUNT(*) FROM $ignoreTable");
        $stats['active_ignore_rules'] = $wpdb->get_var("SELECT COUNT(*) FROM $ignoreTable WHERE is_active = 1");

        // Recent activity
        $stats['issues_last_24h'] = $wpdb->get_var(
            "SELECT COUNT(*) FROM $issuesTable WHERE first_detected >= DATE_SUB(NOW(), INTERVAL 1 DAY)"
        );
        $stats['issues_last_7d'] = $wpdb->get_var(
            "SELECT COUNT(*) FROM $issuesTable WHERE first_detected >= DATE_SUB(NOW(), INTERVAL 7 DAY)"
        );

        return $stats;
    }
}
