<?php
/**
 * Admin Menu Manager
 * Handles WordPress admin menu registration and rendering
 */

namespace Puleeno\SecurityBot\WebMonitor\Admin;

if (!defined('ABSPATH')) {
    exit;
}

class AdminMenuManager
{
    /**
     * Register WordPress admin menus
     */
    public function register(): void
    {
        add_action('admin_menu', [$this, 'addMenus']);
    }

    /**
     * Add admin menus
     */
    public function addMenus(): void
    {
        // Main menu - Load React UI directly
        add_menu_page(
            'Puleeno Security',
            'Puleeno Security',
            'read',
            'puleeno-security',
            [$this, 'renderDashboard'],
            'dashicons-shield-alt',
            30
        );

        // Dashboard submenu (same as parent - WordPress convention)
        add_submenu_page(
            'puleeno-security',
            'Dashboard',
            'Dashboard',
            'read',
            'puleeno-security',
            [$this, 'renderDashboard']
        );

        // Logs submenu - PHP viewer for debug logs
        add_submenu_page(
            'puleeno-security',
            'Security Logs',
            'Security Logs',
            'manage_options',
            'wp-security-monitor-logs',
            [$this, 'renderLogsPage']
        );
    }

    /**
     * Render React dashboard page
     */
    public function renderDashboard(): void
    {
        include dirname(__FILE__, 2) . '/../admin/react-app.php';
    }

    /**
     * Render logs viewer page (PHP)
     */
    public function renderLogsPage(): void
    {
        include dirname(__FILE__, 2) . '/../admin/logs-page.php';
    }
}

