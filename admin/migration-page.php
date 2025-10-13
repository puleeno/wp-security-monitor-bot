<?php
if (!defined('ABSPATH')) {
    exit;
}

use Puleeno\SecurityBot\WebMonitor\Database\Schema;

$currentVersion = get_option('wp_security_monitor_db_version', '0');
$latestVersion = '1.2';
$needsMigration = version_compare($currentVersion, $latestVersion, '<');

// Handle migration action
if (isset($_POST['run_migration']) && wp_verify_nonce($_POST['_wpnonce'], 'security_monitor_migration')) {
    $oldVersion = get_option('wp_security_monitor_db_version', '0');

    try {
        Schema::updateSchema();
        $newVersion = get_option('wp_security_monitor_db_version');

        echo '<div class="notice notice-success is-dismissible">';
        echo '<p><strong>✅ Migration thành công!</strong> Database đã được cập nhật từ version <code>' . esc_html($oldVersion) . '</code> lên <code>' . esc_html($newVersion) . '</code></p>';
        echo '</div>';

        $needsMigration = false;
        $currentVersion = $newVersion;
    } catch (Exception $e) {
        echo '<div class="notice notice-error">';
        echo '<p><strong>❌ Migration thất bại:</strong> ' . esc_html($e->getMessage()) . '</p>';
        echo '</div>';
    }
}

?>

<div class="wrap">
    <h1>🔄 Database Migration</h1>

    <?php if ($needsMigration): ?>
        <!-- Migration Required -->
        <div class="notice notice-warning" style="padding: 20px; margin-top: 20px;">
            <h2 style="margin-top: 0;">⚠️ Cần cập nhật Database</h2>
            <p style="font-size: 14px;">
                Plugin <strong>WP Security Monitor</strong> đã được cập nhật với các tính năng mới.
                Database cần được migrate để hỗ trợ các tính năng này.
            </p>
        </div>

        <div class="card" style="max-width: 800px; margin-top: 20px;">
            <h2>📋 Thông tin Migration</h2>

            <table class="widefat" style="margin-bottom: 20px;">
                <tr>
                    <th style="width: 200px;">Database Version hiện tại:</th>
                    <td><code><?php echo esc_html($currentVersion); ?></code></td>
                </tr>
                <tr>
                    <th>Version mới nhất:</th>
                    <td><code><?php echo esc_html($latestVersion); ?></code></td>
                </tr>
                <tr>
                    <th>Trạng thái:</th>
                    <td><span style="color: orange;">⚠️ Cần migration</span></td>
                </tr>
            </table>

            <h3>🆕 Tính năng mới trong v1.2:</h3>
            <ul style="line-height: 1.8;">
                <li>✅ <strong>Viewed Flag</strong> - Đánh dấu issues đã xem, tự động notify lại nếu issue xuất hiện lại</li>
                <li>✅ <strong>Backtrace Support</strong> - Thu thập call stack để debug nguồn gốc security issues</li>
                <li>✅ <strong>Reported Flag</strong> - Đánh dấu login records đã tạo issue, tránh spam notifications</li>
                <li>✅ <strong>Notification Behavior</strong> - Abstract classes để control realtime vs scheduled notifications</li>
            </ul>

            <h3>📝 Các thay đổi Database:</h3>
            <ul style="line-height: 1.8;">
                <li>➕ Thêm column <code>viewed</code> (tinyint) - Flag đã xem issue</li>
                <li>➕ Thêm column <code>viewed_by</code> (bigint) - User ID đánh dấu</li>
                <li>➕ Thêm column <code>viewed_at</code> (datetime) - Timestamp đánh dấu</li>
                <li>➕ Thêm index <code>idx_viewed</code> - Optimize query</li>
            </ul>

            <div style="background: #f0f0f1; padding: 15px; border-left: 4px solid #2271b1; margin: 20px 0;">
                <p style="margin: 0;">
                    <strong>ℹ️ Lưu ý:</strong> Migration process an toàn và không ảnh hưởng đến dữ liệu hiện tại.
                    Nên backup database trước khi chạy migration.
                </p>
            </div>

            <form method="post" style="margin-top: 30px;">
                <?php wp_nonce_field('security_monitor_migration'); ?>
                <input type="hidden" name="run_migration" value="1">
                <button type="submit" class="button button-primary button-hero" style="padding: 12px 36px; font-size: 16px;">
                    🚀 Chạy Migration Ngay
                </button>
                <a href="<?php echo admin_url('admin.php?page=wp-security-monitor-bot'); ?>" class="button button-secondary" style="margin-left: 10px;">
                    ← Quay lại Settings
                </a>
            </form>
        </div>

    <?php else: ?>
        <!-- Migration Complete -->
        <div class="notice notice-success" style="padding: 20px; margin-top: 20px;">
            <h2 style="margin-top: 0;">✅ Database đã được cập nhật</h2>
            <p style="font-size: 14px;">
                Database của bạn đang chạy version mới nhất (<code><?php echo esc_html($currentVersion); ?></code>).
                Không cần migration!
            </p>
        </div>

        <div class="card" style="max-width: 800px; margin-top: 20px;">
            <h2>📊 Thông tin Database</h2>

            <table class="widefat">
                <tr>
                    <th style="width: 200px;">Database Version:</th>
                    <td><code><?php echo esc_html($currentVersion); ?></code> <span style="color: green;">✅ Latest</span></td>
                </tr>
                <tr>
                    <th>Last Updated:</th>
                    <td><?php echo date('d/m/Y H:i:s', get_option('wp_security_monitor_db_updated_at', time())); ?></td>
                </tr>
            </table>

            <p style="margin-top: 30px;">
                <a href="<?php echo admin_url('admin.php?page=wp-security-monitor-bot'); ?>" class="button button-primary">
                    ← Quay lại Settings
                </a>
            </p>
        </div>
    <?php endif; ?>
</div>

<style>
.card {
    background: #fff;
    border: 1px solid #ccd0d4;
    box-shadow: 0 1px 1px rgba(0,0,0,.04);
    padding: 20px;
}

.card h2 {
    margin-top: 0;
    padding-bottom: 10px;
    border-bottom: 1px solid #e0e0e0;
}

.widefat th {
    background: #f9f9f9;
}
</style>

