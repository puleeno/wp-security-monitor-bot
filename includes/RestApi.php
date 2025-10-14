<?php
namespace Puleeno\SecurityBot\WebMonitor;

use WP_REST_Controller;
use WP_REST_Server;
use WP_REST_Request;
use WP_REST_Response;
use WP_Error;

class RestApi extends WP_REST_Controller
{
    /**
     * @var string
     */
    protected $namespace = 'wp-security-monitor/v1';

    /**
     * @var IssueManager
     */
    private $issueManager;

    public function __construct()
    {
        $this->issueManager = IssueManager::getInstance();
    }

    /**
     * Register REST API routes
     *
     * @return void
     */
    public function registerRoutes(): void
    {
        // Issues endpoints
        register_rest_route($this->namespace, '/issues', [
            [
                'methods' => WP_REST_Server::READABLE,
                'callback' => [$this, 'getIssues'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
        ]);

        register_rest_route($this->namespace, '/issues/(?P<id>\d+)/viewed', [
            [
                'methods' => WP_REST_Server::CREATABLE,
                'callback' => [$this, 'markAsViewed'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
            [
                'methods' => WP_REST_Server::DELETABLE,
                'callback' => [$this, 'unmarkAsViewed'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
        ]);

        register_rest_route($this->namespace, '/issues/(?P<id>\d+)/ignore', [
            [
                'methods' => WP_REST_Server::CREATABLE,
                'callback' => [$this, 'ignoreIssue'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
        ]);

        register_rest_route($this->namespace, '/issues/(?P<id>\d+)/resolve', [
            [
                'methods' => WP_REST_Server::CREATABLE,
                'callback' => [$this, 'resolveIssue'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
        ]);

        // Stats endpoints
        register_rest_route($this->namespace, '/stats/security', [
            [
                'methods' => WP_REST_Server::READABLE,
                'callback' => [$this, 'getSecurityStats'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
        ]);

        register_rest_route($this->namespace, '/stats/bot', [
            [
                'methods' => WP_REST_Server::READABLE,
                'callback' => [$this, 'getBotStats'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
        ]);

        // Settings endpoints
        register_rest_route($this->namespace, '/settings', [
            [
                'methods' => WP_REST_Server::READABLE,
                'callback' => [$this, 'getSettings'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
            [
                'methods' => WP_REST_Server::CREATABLE,
                'callback' => [$this, 'updateSettings'],
                'permission_callback' => [$this, 'checkPermissions'],
            ],
        ]);
    }

    /**
     * Check permissions
     *
     * @return bool
     */
    public function checkPermissions(): bool
    {
        return current_user_can('manage_options');
    }

    /**
     * Get issues
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response|WP_Error
     */
    public function getIssues(WP_REST_Request $request)
    {
        $page = $request->get_param('page') ?? 1;
        $per_page = $request->get_param('per_page') ?? 20;
        $status = $request->get_param('status') ?? '';
        $severity = $request->get_param('severity') ?? '';
        $issuer = $request->get_param('issuer') ?? '';
        $search = $request->get_param('search') ?? '';

        $args = [
            'page' => (int) $page,
            'per_page' => (int) $per_page,
            'status' => $status,
            'severity' => $severity,
            'issuer' => $issuer,
            'search' => $search,
        ];

        $result = $this->issueManager->getIssues($args);

        return new WP_REST_Response($result, 200);
    }

    /**
     * Mark issue as viewed
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response|WP_Error
     */
    public function markAsViewed(WP_REST_Request $request)
    {
        $issueId = (int) $request->get_param('id');

        if (!$issueId) {
            return new WP_Error('invalid_id', 'Invalid issue ID', ['status' => 400]);
        }

        $success = $this->issueManager->markAsViewed($issueId);

        if ($success) {
            return new WP_REST_Response([
                'success' => true,
                'message' => 'Issue marked as viewed',
            ], 200);
        }

        return new WP_Error('update_failed', 'Failed to mark as viewed', ['status' => 500]);
    }

    /**
     * Unmark issue as viewed
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response|WP_Error
     */
    public function unmarkAsViewed(WP_REST_Request $request)
    {
        $issueId = (int) $request->get_param('id');

        if (!$issueId) {
            return new WP_Error('invalid_id', 'Invalid issue ID', ['status' => 400]);
        }

        $success = $this->issueManager->unmarkAsViewed($issueId);

        if ($success) {
            return new WP_REST_Response([
                'success' => true,
                'message' => 'Unmarked as viewed',
            ], 200);
        }

        return new WP_Error('update_failed', 'Failed to unmark', ['status' => 500]);
    }

    /**
     * Ignore issue
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response|WP_Error
     */
    public function ignoreIssue(WP_REST_Request $request)
    {
        $issueId = (int) $request->get_param('id');
        $reason = sanitize_textarea_field($request->get_param('reason') ?? '');

        if (!$issueId) {
            return new WP_Error('invalid_id', 'Invalid issue ID', ['status' => 400]);
        }

        $success = $this->issueManager->ignoreIssue($issueId, $reason);

        if ($success) {
            return new WP_REST_Response([
                'success' => true,
                'message' => 'Issue ignored',
            ], 200);
        }

        return new WP_Error('update_failed', 'Failed to ignore issue', ['status' => 500]);
    }

    /**
     * Resolve issue
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response|WP_Error
     */
    public function resolveIssue(WP_REST_Request $request)
    {
        $issueId = (int) $request->get_param('id');
        $notes = sanitize_textarea_field($request->get_param('notes') ?? '');

        if (!$issueId) {
            return new WP_Error('invalid_id', 'Invalid issue ID', ['status' => 400]);
        }

        $success = $this->issueManager->resolveIssue($issueId, $notes);

        if ($success) {
            return new WP_REST_Response([
                'success' => true,
                'message' => 'Issue resolved',
            ], 200);
        }

        return new WP_Error('update_failed', 'Failed to resolve issue', ['status' => 500]);
    }

    /**
     * Get security stats
     *
     * @return WP_REST_Response
     */
    public function getSecurityStats()
    {
        $stats = $this->issueManager->getStats();
        return new WP_REST_Response($stats, 200);
    }

    /**
     * Get bot stats
     *
     * @return WP_REST_Response
     */
    public function getBotStats()
    {
        $bot = Bot::getInstance();
        $stats = $bot->getStats();
        return new WP_REST_Response($stats, 200);
    }

    /**
     * Get settings
     *
     * @return WP_REST_Response
     */
    public function getSettings()
    {
        $settings = [
            'telegram' => [
                'enabled' => get_option('wp_security_monitor_telegram_enabled', false),
            ],
            'email' => [
                'enabled' => get_option('wp_security_monitor_email_enabled', false),
            ],
            'slack' => [
                'enabled' => get_option('wp_security_monitor_slack_enabled', false),
            ],
            'log' => [
                'enabled' => true,
            ],
        ];

        return new WP_REST_Response($settings, 200);
    }

    /**
     * Update settings
     *
     * @param WP_REST_Request $request
     * @return WP_REST_Response
     */
    public function updateSettings(WP_REST_Request $request)
    {
        $settings = $request->get_json_params();

        // Update settings here
        // ... implementation

        return new WP_REST_Response([
            'success' => true,
            'message' => 'Settings updated',
        ], 200);
    }
}

