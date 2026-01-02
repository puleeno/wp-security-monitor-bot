<?php
namespace Puleeno\SecurityBot\WebMonitor\Issuers;

use Puleeno\SecurityBot\WebMonitor\Interfaces\RealtimeIssuerInterface;
use Puleeno\SecurityBot\WebMonitor\DebugHelper;

class AdminActivityIssuer implements RealtimeIssuerInterface
{
    /**
     * @var array
     */
    private $config = [];

    /**
     * @var bool
     */
    private $enabled = true;

    public function __construct()
    {
        // 1. Admin Login
        add_action('wp_login', [$this, 'logAdminLogin'], 10, 2);

        // 2. Plugin Activities
        add_action('activated_plugin', [$this, 'logPluginActivation'], 10, 2);
        add_action('deactivated_plugin', [$this, 'logPluginDeactivation'], 10, 2);
        add_action('deleted_plugin', [$this, 'logPluginDeletion'], 10, 2);

        // 3. Theme Activities
        add_action('switch_theme', [$this, 'logThemeActivation'], 10, 3);
        add_action('deleted_theme', [$this, 'logThemeDeletion'], 10, 2);

        // Install/Update (Plugins & Themes)
        add_action('upgrader_process_complete', [$this, 'logInstallOrUpdate'], 10, 2);

        // 4. File Editing (Theme/Plugin Editor)
        add_action('wp_edit_theme_plugin_file', [$this, 'logFileEdit'], 10, 2);

        // 5. Widget Monitors
        // Monitor widget changes via options
        add_action('updated_option', [$this, 'logWidgetChanges'], 10, 3);
        add_action('added_option', [$this, 'logWidgetDeepChanges'], 10, 2);
        add_action('deleted_option', [$this, 'logWidgetDeepChanges'], 10, 2);
    }

    public function getName(): string
    {
        return 'Admin Activity Monitor';
    }

    public function getPriority(): int
    {
        return 10; // Low priority
    }

    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    public function configure(array $config): void
    {
        $this->config = array_merge($this->config, $config);

        if (isset($config['enabled'])) {
            $this->enabled = (bool) $config['enabled'];
        }
    }

    public function detect(): array
    {
        // Realtime issuer, no periodic detection needed
        return [];
    }

    /**
     * Log Admin Login
     */
    public function logAdminLogin($user_login, $user)
    {
        if (!in_array('administrator', $user->roles)) {
            return;
        }

        $this->triggerIssue('admin_login', [
            'title' => 'Admin Login Detected',
            'description' => sprintf('Administrator "%s" logged in successfully.', $user_login),
            'severity' => 'info',
            'username' => $user_login,
            'user_id' => $user->ID,
            'ip_address' => $this->getUserIP()
        ]);
    }

    /**
     * Log Plugin Activation
     */
    public function logPluginActivation($plugin, $network_wide)
    {
        $pluginName = $this->getPluginName($plugin);
        $this->triggerIssue('plugin_activity', [
            'title' => 'Plugin Activated',
            'description' => sprintf('Plugin "%s" was activated.', $pluginName),
            'severity' => 'info',
            'details' => [
                'plugin_file' => $plugin,
                'network_wide' => $network_wide
            ]
        ]);
    }

    /**
     * Log Plugin Deactivation
     */
    public function logPluginDeactivation($plugin, $network_wide)
    {
        $pluginName = $this->getPluginName($plugin);
        $this->triggerIssue('plugin_activity', [
            'title' => 'Plugin Deactivated',
            'description' => sprintf('Plugin "%s" was deactivated.', $pluginName),
            'severity' => 'info',
            'details' => [
                'plugin_file' => $plugin,
                'network_wide' => $network_wide
            ]
        ]);
    }

    /**
     * Log Plugin Deletion
     */
    public function logPluginDeletion($plugin_file, $deleted)
    {
        if ($deleted) {
            $this->triggerIssue('plugin_activity', [
                'title' => 'Plugin Deleted',
                'description' => sprintf('Plugin "%s" was deleted.', $plugin_file),
                'severity' => 'notice'
            ]);
        }
    }

    /**
     * Log Theme Activation (Switch)
     */
    public function logThemeActivation($new_name, $new_theme, $old_theme)
    {
        $this->triggerIssue('theme_activity', [
            'title' => 'Theme Changed',
            'description' => sprintf('Theme changed from "%s" to "%s".', $old_theme ? $old_theme->get('Name') : 'Unknown', $new_theme->get('Name')),
            'severity' => 'info'
        ]);
    }

    /**
     * Log Theme Deletion
     */
    public function logThemeDeletion($stylesheet, $deleted)
    {
        if ($deleted) {
            $this->triggerIssue('theme_activity', [
                'title' => 'Theme Deleted',
                'description' => sprintf('Theme "%s" was deleted.', $stylesheet),
                'severity' => 'notice'
            ]);
        }
    }

    /**
     * Log Install/Update via Upgrader
     */
    public function logInstallOrUpdate($upgrader_object, $options)
    {
        $action = $options['action'] ?? '';
        $type = $options['type'] ?? '';

        if ($action === 'install') {
            if ($type === 'plugin') {
                $this->triggerIssue('plugin_activity', [
                    'title' => 'Plugin Installed',
                    'description' => 'A new plugin was installed.',
                    'severity' => 'info',
                    'details' => $options
                ]);
            } elseif ($type === 'theme') {
                $this->triggerIssue('theme_activity', [
                    'title' => 'Theme Installed',
                    'description' => 'A new theme was installed.',
                    'severity' => 'info',
                    'details' => $options
                ]);
            }
        }
    }

    /**
     * Log File Edit via WP Editor
     */
    public function logFileEdit($return, $args)
    {
        // args: [ file, content, nonce ] (varies by WP version, mostly checking if it saved)
        // Actually wp_edit_theme_plugin_file hook fires AFTER check, but args passed might depend on context.
        // It passes $return (null usually) and $args which contains file path relative to plugin/theme.

        // WP 4.9+ uses wp_ajax_edit_theme_plugin_file
        // The action `wp_edit_theme_plugin_file` fires on successful edit.

        // $args typically contains:
        // array('file' => ..., 'theme' => ..., 'plugin' => ..., 'nonce' => ...)

        $file = $args['file'] ?? 'unknown file';
        $type = isset($args['plugin']) ? 'plugin' : (isset($args['theme']) ? 'theme' : 'file');

        $this->triggerIssue('file_edit', [
            'title' => 'File Edited via Admin',
            'description' => sprintf('A %s file was edited via WordPress Editor: %s', $type, $file),
            'severity' => 'notice',
            'details' => $args
        ]);
    }

    /**
     * Log Widget Changes (Option updates)
     */
    public function logWidgetChanges($option, $old_value, $value)
    {
        // Check for sidebar widgets changes
        if ($option === 'sidebars_widgets') {
            $this->triggerIssue('widget_activity', [
                'title' => 'Widget Area Updated',
                'description' => 'Widgets were reordered or modified in sidebars.',
                'severity' => 'info'
            ]);
            return;
        }

        // Check for specific widget updates (options starting with 'widget_')
        if (strpos($option, 'widget_') === 0 && $option !== 'widget_recently_viewed') { // Skip some noise
            $this->triggerIssue('widget_activity', [
                'title' => 'Widget Updated',
                'description' => sprintf('Widget configuration updated: %s', $option),
                'severity' => 'info'
            ]);
        }
    }

    public function logWidgetDeepChanges($option, $value)
    {
        if (strpos($option, 'widget_') === 0) {
            $action = current_action() === 'added_option' ? 'Added' : 'Deleted';
            $this->triggerIssue('widget_activity', [
                'title' => "Widget {$action}",
                'description' => sprintf('Widget configuration %s: %s', strtolower($action), $option),
                'severity' => 'info'
            ]);
        }
    }

    private function triggerIssue(string $type, array $data): void
    {
        $currentUser = wp_get_current_user();
        $username = $currentUser->exists() ? $currentUser->user_login : 'unknown';
        $userId = $currentUser->exists() ? $currentUser->ID : 0;
        $roles = $currentUser->exists() ? $currentUser->roles : [];

        $context = $this->getContext();
        $backtrace = $this->getBacktrace();

        $issueData = array_merge([
            'message' => $data['title'],
            'type' => $type,
            'severity' => 'info',
            'ip_address' => $this->getUserIP(),
            'username' => $username,
            'user_id' => $userId,
            'user_roles' => $roles,
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
            'request_method' => $context['method'],
            'request_source' => $context['source'],
            'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
            'backtrace' => $backtrace,
            'details' => []
        ], $data);

        do_action('wp_security_monitor_admin_activity', $issueData);
    }

    private function getUserIP(): string
    {
        $ipKeys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_FORWARDED', 'REMOTE_ADDR'];
        foreach ($ipKeys as $key) {
            if (!empty($_SERVER[$key])) {
                $ips = explode(',', $_SERVER[$key]);
                return trim($ips[0]);
            }
        }
        return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    }

    private function getPluginName($pluginFile)
    {
        if (!function_exists('get_plugin_data')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        $pluginPath = WP_PLUGIN_DIR . '/' . $pluginFile;
        if (file_exists($pluginPath)) {
            $data = get_plugin_data($pluginPath);
            return $data['Name'] ?? $pluginFile;
        }
        return $pluginFile;
    }

    /**
     * Determine the request context/method
     */
    private function getContext(): array
    {
        $method = $_SERVER['REQUEST_METHOD'] ?? 'UNKNOWN';
        $source = 'HTTP';

        if (defined('WP_CLI') && WP_CLI) {
            $method = 'CLI';
            $source = 'WP-CLI';
        } elseif (wp_doing_ajax()) {
            $source = 'AJAX';
        } elseif (defined('REST_REQUEST') && REST_REQUEST) {
            $source = 'REST API';
        } elseif (is_admin()) {
            $source = 'WP Admin';
        }

        return [
            'method' => $method,
            'source' => $source
        ];
    }

    /**
     * Capture debug backtrace
     */
    private function getBacktrace(): array
    {
        if (!function_exists('debug_backtrace')) {
            return [];
        }

        // Limit to 20 frames
        $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 20);
        $filtered = [];

        foreach ($trace as $frame) {
            // Skip internal issuer frames and common WP hooks
            if (isset($frame['class']) && strpos($frame['class'], 'AdminActivityIssuer') !== false) {
                continue;
            }
            if (isset($frame['function']) && in_array($frame['function'], ['triggerIssue', 'getBacktrace', 'apply_filters', 'do_action'])) {
                continue;
            }

            $file = $frame['file'] ?? '';
            // Simplify file path
            if (defined('ABSPATH')) {
                $file = str_replace(ABSPATH, '', $file);
            }

            $filtered[] = [
                'file' => $file,
                'line' => $frame['line'] ?? 0,
                'function' => $frame['function'] ?? 'unknown',
                'class' => $frame['class'] ?? '',
                // 'type' => $frame['type'] ?? ''
            ];
        }

        return $filtered;
    }
}
