<?php
/**
 * React Admin App Loader
 */

if (!defined('ABSPATH')) {
    exit;
}

// Determine if we're in development mode
// Ưu tiên production mode nếu built files tồn tại
$buildDir = plugin_dir_path(dirname(__FILE__)) . 'assets/admin-app/';
$hasBuiltFiles = file_exists($buildDir) && !empty(glob($buildDir . 'js/*.js'));

// Chỉ dùng dev mode khi:
// 1. Có constant WP_SECURITY_MONITOR_DEV_MODE = true HOẶC
// 2. WP_DEBUG = true VÀ không có built files VÀ có package.json
$isDevelopment = (defined('WP_SECURITY_MONITOR_DEV_MODE') && WP_SECURITY_MONITOR_DEV_MODE)
    || (!$hasBuiltFiles && defined('WP_DEBUG') && WP_DEBUG && file_exists(dirname(__FILE__) . '/../admin-app/package.json'));

if ($isDevelopment) {
    // Development mode - use Vite dev server
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
    <script>
        window.wpApiSettings = {
            root: '<?php echo esc_url_raw(rest_url()); ?>',
            nonce: '<?php echo wp_create_nonce('wp_rest'); ?>'
        };
        window.wpSecurityMonitorLocale = '<?php echo get_locale(); ?>';
    </script>
    <?php
} else {
    // Production mode - load built files
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

    // Pass locale for i18n
    wp_add_inline_script('wp-security-monitor-js-0',
        'window.wpSecurityMonitorLocale = "' . get_locale() . '";',
        'before'
    );
}

?>
<!-- React App Root -->
<div id="wp-security-monitor-root"></div>

<style>
    /* Hide WordPress admin notices trong React app */
    #wp-security-monitor-root ~ .notice,
    #wp-security-monitor-root ~ .update-nag {
        display: none !important;
    }
</style>
