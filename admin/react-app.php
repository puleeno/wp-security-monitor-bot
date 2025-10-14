<?php
/**
 * React Admin App Loader
 *
 * File này load React TypeScript admin interface
 */

if (!defined('ABSPATH')) {
    exit;
}

// Force development mode (sẽ dùng Vite dev server)
$isDevelopment = defined('WP_DEBUG') && WP_DEBUG && file_exists(dirname(__FILE__) . '/../admin-app/package.json');

if ($isDevelopment) {
    ?>
    <div class="wrap">
        <div class="notice notice-info" style="margin: 20px 0;">
            <p>
                <strong>🚀 Development Mode</strong><br>
                React UI đang chạy từ Vite dev server. Đảm bảo đã chạy: <code>npm run dev</code> trong folder <code>admin-app/</code>
            </p>
        </div>
    </div>
    <?php

    // Enqueue Vite dev server scripts
    ?>
    <script type="module">
        import RefreshRuntime from 'http://localhost:3000/@react-refresh'
        RefreshRuntime.injectIntoGlobalHook(window)
        window.$RefreshReg$ = () => {}
        window.$RefreshSig$ = () => (type) => type
        window.__vite_plugin_react_preamble_installed__ = true
    </script>
    <script type="module" src="http://localhost:3000/@vite/client"></script>
    <script type="module" src="http://localhost:3000/src/main.tsx"></script>
    <?php

    // Pass WordPress data vào window
    ?>
    <script>
        window.wpApiSettings = {
            root: '<?php echo esc_url_raw(rest_url()); ?>',
            nonce: '<?php echo wp_create_nonce('wp_rest'); ?>'
        };
    </script>
    <?php
} else {
    // Production mode - load built files
    $buildDir = plugin_dir_path(dirname(__FILE__)) . 'assets/admin-app/';
    $assetsUrl = plugin_dir_url(dirname(__FILE__)) . 'assets/admin-app/';

    if (!file_exists($buildDir)) {
        ?>
        <div class="wrap">
            <div class="notice notice-error" style="margin: 20px 0;">
                <p>
                    <strong>⚠️ React Admin UI chưa được build!</strong><br>
                    Vui lòng chạy: <code>cd admin-app && npm install && npm run build</code>
                </p>
            </div>
            <p>Hoặc quay lại <a href="<?php echo admin_url('admin.php?page=wp-security-monitor-bot'); ?>">Settings cũ (PHP)</a></p>
        </div>
        <?php
        return;
    }

    // Find and enqueue built files
    $jsFiles = glob($buildDir . 'js/*.js');
    $cssFiles = glob($buildDir . 'css/*.css');

    // Enqueue CSS
    foreach ($cssFiles as $index => $cssFile) {
        $cssFilename = basename($cssFile);
        wp_enqueue_style(
            'wp-security-monitor-css-' . $index,
            $assetsUrl . 'css/' . $cssFilename,
            [],
            filemtime($cssFile)
        );
    }

    // Enqueue JS
    foreach ($jsFiles as $index => $jsFile) {
        $jsFilename = basename($jsFile);
        wp_enqueue_script(
            'wp-security-monitor-js-' . $index,
            $assetsUrl . 'js/' . $jsFilename,
            [],
            filemtime($jsFile),
            true
        );
    }

    // Pass WordPress data
    wp_localize_script('wp-security-monitor-js-0', 'wpApiSettings', [
        'root' => esc_url_raw(rest_url()),
        'nonce' => wp_create_nonce('wp_rest'),
    ]);
}

?>
<!-- React App Root -->
<div id="wp-security-monitor-root"></div>

<!-- Placeholder UI nếu React chưa load -->
<style>
    .security-monitor-placeholder {
        padding: 40px 20px;
        max-width: 1200px;
        margin: 0 auto;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen-Sans, Ubuntu, Cantarell, sans-serif;
    }
    .security-monitor-placeholder h1 {
        font-size: 32px;
        margin-bottom: 20px;
        color: #1d2327;
    }
    .security-monitor-placeholder .feature-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
        gap: 20px;
        margin: 30px 0;
    }
    .security-monitor-placeholder .feature-card {
        background: white;
        padding: 24px;
        border-radius: 8px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        border-left: 4px solid #2271b1;
    }
    .security-monitor-placeholder .feature-card h3 {
        margin: 0 0 12px 0;
        font-size: 18px;
        color: #2271b1;
    }
    .security-monitor-placeholder .feature-card ul {
        margin: 0;
        padding-left: 20px;
    }
    .security-monitor-placeholder .setup-box {
        background: #f0f6fc;
        border: 1px solid #2271b1;
        border-radius: 8px;
        padding: 24px;
        margin: 30px 0;
    }
    .security-monitor-placeholder .setup-box h2 {
        margin-top: 0;
        color: #2271b1;
    }
    .security-monitor-placeholder code {
        background: #23282d;
        color: #f0f0f1;
        padding: 2px 8px;
        border-radius: 4px;
        font-family: 'Courier New', monospace;
        font-size: 14px;
    }
    .security-monitor-placeholder .code-block {
        background: #23282d;
        color: #f0f0f1;
        padding: 16px;
        border-radius: 4px;
        margin: 12px 0;
        overflow-x: auto;
    }
    .security-monitor-placeholder .button-primary {
        display: inline-block;
        padding: 10px 20px;
        background: #2271b1;
        color: white;
        text-decoration: none;
        border-radius: 4px;
        margin-right: 10px;
    }
    .security-monitor-placeholder .button-primary:hover {
        background: #135e96;
        color: white;
    }
    .security-monitor-placeholder .status-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 12px;
        font-weight: bold;
        margin-left: 8px;
    }
    .security-monitor-placeholder .status-ready {
        background: #d4edda;
        color: #155724;
    }
    .security-monitor-placeholder .status-pending {
        background: #fff3cd;
        color: #856404;
    }
</style>

<div class="security-monitor-placeholder">
    <h1>🛡️ WP Security Monitor - React Admin UI <span class="status-badge status-ready">✅ Đã tích hợp</span></h1>

    <div class="feature-grid">
        <div class="feature-card">
            <h3>⚡ Tech Stack</h3>
            <ul>
                <li>React 18 + TypeScript (Strict Mode)</li>
                <li>Ant Design 5.0 - UI đẹp & nhẹ</li>
                <li>Redux + Redux Observable</li>
                <li>Vite - Build tool siêu nhanh</li>
                <li>REST API integration</li>
            </ul>
        </div>

        <div class="feature-card">
            <h3>📊 Features Đã Có</h3>
            <ul>
                <li>Dashboard với real-time stats</li>
                <li>Issues management (CRUD)</li>
                <li>Mark as viewed</li>
                <li>Ignore/Resolve issues</li>
                <li>Backtrace viewer</li>
                <li>Responsive design</li>
            </ul>
        </div>

        <div class="feature-card">
            <h3>🚧 Coming Soon</h3>
            <ul>
                <li>Settings page</li>
                <li>Security status</li>
                <li>Access control</li>
                <li>Charts & visualizations</li>
                <li>Real-time updates</li>
                <li>Export/Import</li>
            </ul>
        </div>
    </div>

    <div class="setup-box" style="background: #d4edda; border-color: #28a745;">
        <h2 style="color: #155724;">✅ Dev Server đang chạy!</h2>

        <p style="font-size: 16px;"><strong>🎉 Reload trang này để xem React UI!</strong></p>

        <p>Nếu chưa start dev server, chạy:</p>
        <div class="code-block">
cd <?php echo plugin_dir_path(dirname(__FILE__)); ?>admin-app<br>
npm run dev
        </div>

        <p><strong>Lưu ý:</strong> <code>WP_DEBUG</code> = <code>true</code> ✅ (đã bật)</p>

        <p style="margin-top: 24px;">
            <a href="<?php echo plugin_dir_url(dirname(__FILE__)); ?>admin-app/README.md" class="button-primary" target="_blank">
                📖 Documentation
            </a>
            <a href="<?php echo admin_url('admin.php?page=wp-security-monitor-bot'); ?>" class="button-primary">
                ⬅️ Quay về PHP Admin (cũ)
            </a>
        </p>
    </div>

    <div class="setup-box" style="background: #fff3cd; border-color: #856404;">
        <h2>💡 Production Mode</h2>
        <p>Để build cho production (không cần dev server):</p>
        <div class="code-block">
cd <?php echo plugin_dir_path(dirname(__FILE__)); ?>admin-app<br>
npm run build
        </div>
        <p>Build output sẽ được tạo trong <code>assets/admin-app/</code></p>
        <p>Sau đó tắt <code>WP_DEBUG</code> để dùng production build.</p>
    </div>

    <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666;">
        <p><strong>🗂️ Project Structure:</strong></p>
        <ul style="font-family: monospace; font-size: 13px;">
            <li>📁 admin-app/src/pages/ - 6 pages (Dashboard, Issues, Settings, Security, Access Control, Migration)</li>
            <li>📁 admin-app/src/store/ - Redux store với strict TypeScript</li>
            <li>📁 admin-app/src/components/ - React components</li>
            <li>📁 admin-app/src/services/ - API services</li>
            <li>📄 includes/RestApi.php - Backend REST API endpoints</li>
        </ul>
    </div>

    <div style="margin-top: 20px; padding: 16px; background: #d4edda; border-left: 4px solid #28a745; border-radius: 4px;">
        <strong style="color: #155724;">✅ Menu đã được thêm vào WordPress:</strong><br>
        <span style="color: #155724;">Xác nhận bằng cách check sidebar bên trái: <strong>Puleeno Security → 🚀 New UI</strong></span>
    </div>
</div>

<?php if (!$isDevelopment): ?>
<style>
    /* Hide WordPress admin notices trong React app */
    #wp-security-monitor-root ~ .notice,
    #wp-security-monitor-root ~ .update-nag {
        display: none !important;
    }
</style>
<?php endif; ?>

