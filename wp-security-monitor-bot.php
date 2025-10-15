<?php

/**
 * Plugin Name: WP Security Monitor Bot
 * Author: Puleeno Nguyen
 * Description: Advanced WordPress security monitoring system with real-time notifications via Telegram, Email, and Slack. Tracks external redirects, login attempts, file changes, admin user creation, and dangerous PHP functions automatically.
 * Author URI: https://puleeno.com
 * Version: 1.3.0
 * Text Domain: wp-security-monitor
 * Domain Path: /languages
 */

// Load Composer autoloader ngay lập tức
$autoloader = sprintf('%s/vendor/autoload.php', dirname(__FILE__));
if (file_exists($autoloader)) {
    require_once $autoloader;
}

if (!class_exists('WP_Security_Monitor_Bot')) {
    class WP_Security_Monitor_Bot
    {
        protected static $instance;

        protected function __construct()
        {
            // Composer autoloader đã được load ở trên

            // Load text domain for translations
            add_action('plugins_loaded', [$this, 'loadTextDomain']);
        }

        /**
         * Load plugin text domain for translations
         */
        public function loadTextDomain()
        {
            load_plugin_textdomain(
                'wp-security-monitor',
                false,
                dirname(plugin_basename(__FILE__)) . '/languages'
            );
        }

        public static function getInstance()
        {
            if (is_null(static::$instance)) {
                static::$instance = new static();
            }
            return static::$instance;
        }
    }

    $wpSecurityBot = WP_Security_Monitor_Bot::getInstance();

    // Plugin activation hook
    register_activation_hook(__FILE__, function() {
        if (class_exists('Puleeno\SecurityBot\WebMonitor\Bot')) {
            \Puleeno\SecurityBot\WebMonitor\Bot::onActivation();
        }
    });

    // Plugin deactivation hook
    register_deactivation_hook(__FILE__, function() {
        if (class_exists('Puleeno\SecurityBot\WebMonitor\Bot')) {
            \Puleeno\SecurityBot\WebMonitor\Bot::onDeactivation();
        }
    });

    // Khởi tạo Bot instance
    add_action('plugins_loaded', function() {
        if (class_exists('Puleeno\SecurityBot\WebMonitor\Bot')) {
            \Puleeno\SecurityBot\WebMonitor\Bot::getInstance();
        }
    });

    // Add settings link in plugins list
    add_filter('plugin_action_links_' . plugin_basename(__FILE__), function($links) {
        $settings_link = '<a href="' . admin_url('admin.php?page=wp-security-monitor-bot') . '">' . __('Settings') . '</a>';
        array_unshift($links, $settings_link);
        return $links;
    });

    // Check for database migration after plugin update
    add_action('admin_init', function() {
        $currentVersion = get_option('wp_security_monitor_db_version', '0');
        $latestVersion = '1.3';
        $pluginVersion = get_option('wp_security_monitor_plugin_version', '0');
        $currentPluginVersion = '1.0.0';

        // Nếu plugin được update (version thay đổi)
        if (version_compare($pluginVersion, $currentPluginVersion, '<')) {
            update_option('wp_security_monitor_plugin_version', $currentPluginVersion);

            // Check nếu cần database migration
            if (version_compare($currentVersion, $latestVersion, '<')) {
                add_action('admin_notices', function() use ($currentVersion, $latestVersion) {
                    // Không hiển thị notice nếu đang ở migration page
                    $screen = get_current_screen();
                    if ($screen && $screen->id === 'puleeno-security_page_wp-security-monitor-migration') {
                        return;
                    }

                    echo '<div class="notice notice-warning" style="padding: 15px; border-left-color: #d63638;">';
                    echo '<h3 style="margin-top: 0;">⚠️ WP Security Monitor - Cần Migration</h3>';
                    echo '<p><strong>Plugin đã được cập nhật!</strong> Database cần được migrate từ version <code>' . esc_html($currentVersion) . '</code> lên <code>' . esc_html($latestVersion) . '</code> để sử dụng các tính năng mới.</p>';
                    echo '<p>';
                    echo '<a href="' . admin_url('admin.php?page=wp-security-monitor-migration') . '" class="button button-primary">🚀 Chạy Migration Ngay</a> ';
                    echo '<a href="' . admin_url('admin.php?page=wp-security-monitor-bot') . '" class="button button-secondary">Xem Settings</a>';
                    echo '</p>';
                    echo '</div>';
                });
            }
        }
    });
}
