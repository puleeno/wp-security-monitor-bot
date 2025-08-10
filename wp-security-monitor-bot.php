<?php

/**
 * Plugin Name: WP Security Monitor Bot
 * Author: Puleeno Nguyen
 * Description: Advanced WordPress security monitoring system with real-time notifications via Telegram, Email, and Slack. Tracks external redirects, login attempts, file changes, admin user creation, and dangerous PHP functions automatically.
 * Author URI: https://puleeno.com
 * Version: 1.0.0
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
}
