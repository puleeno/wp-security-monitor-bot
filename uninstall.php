<?php
/**
 * Plugin uninstall script
 *
 * Runs when the plugin is deleted via WordPress admin
 */

// If uninstall not called from WordPress, then exit
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Load the plugin's autoloader
$autoloader = __DIR__ . '/vendor/autoload.php';
if (file_exists($autoloader)) {
    require_once $autoloader;
}

use Puleeno\SecurityBot\WebMonitor\Database\Schema;
use Puleeno\SecurityBot\WebMonitor\Security\AccessControl;

// Remove database tables
Schema::dropTables();

// Cleanup access control
AccessControl::cleanup();

// Remove all plugin options
$options_to_delete = [
    'wp_security_monitor_bot_config',
    'wp_security_monitor_bot_running',
    'wp_security_monitor_last_check',
    'wp_security_monitor_last_issues',
    'wp_security_monitor_telegram_config',
    'wp_security_monitor_email_config',
    'wp_security_monitor_issuers_config',
    'wp_security_monitor_failed_logins',
    'wp_security_monitor_admin_logins',
    'wp_security_monitor_file_hashes',
    'wp_security_monitor_db_version',
    'wp_security_monitor_roles_setup',
    'wp_security_monitor_ip_whitelist',
    'wp_security_monitor_plugin_salt',
    'wp_security_monitor_crypto_salt',
    'wp_security_monitor_credentials_migrated'
];

foreach ($options_to_delete as $option) {
    delete_option($option);
    delete_site_option($option); // For multisite
}

// Remove scheduled cron events
wp_clear_scheduled_hook('wp_security_monitor_bot_check');

// Clean up any remaining cron events
$cron_jobs = _get_cron_array();
foreach ($cron_jobs as $timestamp => $jobs) {
    foreach ($jobs as $hook => $events) {
        if (strpos($hook, 'wp_security_monitor') !== false) {
            wp_unschedule_event($timestamp, $hook);
        }
    }
}

// Remove any custom capabilities if added
// (None in current implementation, but good practice)

// Log the uninstall action
error_log('WP Security Monitor Bot: Plugin uninstalled and all data removed');
