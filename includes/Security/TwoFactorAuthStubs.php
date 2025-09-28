<?php

namespace Puleeno\SecurityBot\WebMonitor\Security;

// Lightweight stubs to handle AJAX calls that previously belonged to the
// TwoFactorAuth class. These return safe responses indicating the feature
// has been removed so frontend code can handle the result gracefully.

add_action('wp_ajax_security_monitor_setup_2fa', function() {
    wp_send_json_error('Two-Factor Authentication has been removed from this plugin.');
});

add_action('wp_ajax_security_monitor_verify_2fa', function() {
    wp_send_json_error('Two-Factor Authentication has been removed from this plugin.');
});

add_action('wp_ajax_security_monitor_disable_2fa', function() {
    wp_send_json_error('Two-Factor Authentication has been removed from this plugin.');
});

add_action('wp_ajax_security_monitor_generate_backup_codes', function() {
    wp_send_json_error('Two-Factor Authentication has been removed from this plugin.');
});

// Ensure file can be included safely
return true;
