<?php
namespace Puleeno\SecurityBot\WebMonitor\Issuers;

use Puleeno\SecurityBot\WebMonitor\Abstracts\IssuerAbstract;

/**
 * Fatal Error Issuer
 *
 * Detects và report WordPress fatal errors, warnings, notices
 * Hook vào WordPress error handler và shutdown function
 */
class FatalErrorIssuer extends IssuerAbstract
{
    /**
     * @var array Lưu các errors đã detect trong request hiện tại
     */
    private static $detectedErrors = [];

    /**
     * @var array Error levels cần monitor
     */
    private $monitorLevels = ['error', 'warning', 'notice'];

    public function __construct()
    {
        parent::__construct();
        $this->name = 'Fatal Error Monitor';
        $this->description = 'Monitors WordPress fatal errors, warnings, and notices';

        // Register error handlers
        $this->registerErrorHandlers();
    }

    /**
     * Register các error handlers
     */
    private function registerErrorHandlers(): void
    {
        // Hook vào shutdown để bắt fatal errors
        add_action('shutdown', [$this, 'handleShutdown'], 1);

        // Hook vào error handler
        set_error_handler([$this, 'handleError']);

        // Hook vào wp_die để bắt critical errors
        add_filter('wp_die_handler', [$this, 'handleWpDie'], 10, 1);
    }

    /**
     * Handle PHP errors
     */
    public function handleError($errno, $errstr, $errfile, $errline): bool
    {
        if (!$this->isEnabled()) {
            return false;
        }

        $level = $this->getErrorLevel($errno);

        // Check xem level này có được monitor không
        if (!in_array($level, $this->monitorLevels)) {
            return false;
        }

        $errorData = [
            'type' => 'php_error',
            'level' => $level,
            'severity' => $this->getSeverityFromLevel($level),
            'title' => "PHP {$level}: {$errstr}",
            'description' => $errstr,
            'file_path' => $errfile,
            'line_number' => $errline,
            'error_code' => $errno,
            'url' => $_SERVER['REQUEST_URI'] ?? '',
            'ip_address' => $_SERVER['REMOTE_ADDR'] ?? '',
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'timestamp' => current_time('mysql'),
        ];

        self::$detectedErrors[] = $errorData;

        // Return false để PHP tiếp tục xử lý error bình thường
        return false;
    }

    /**
     * Handle shutdown - bắt fatal errors
     */
    public function handleShutdown(): void
    {
        if (!$this->isEnabled()) {
            return;
        }

        $error = error_get_last();

        if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
            $level = 'error';

            if (!in_array($level, $this->monitorLevels)) {
                return;
            }

            $errorData = [
                'type' => 'fatal_error',
                'level' => $level,
                'severity' => 'critical',
                'title' => "Fatal Error: {$error['message']}",
                'description' => $error['message'],
                'file_path' => $error['file'],
                'line_number' => $error['line'],
                'error_code' => $error['type'],
                'url' => $_SERVER['REQUEST_URI'] ?? '',
                'ip_address' => $_SERVER['REMOTE_ADDR'] ?? '',
                'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                'timestamp' => current_time('mysql'),
                'backtrace' => $this->getBacktrace(),
            ];

            // Trigger action để Bot xử lý
            do_action('wp_security_monitor_fatal_error', $errorData);
        }
    }

    /**
     * Handle wp_die
     */
    public function handleWpDie($handler)
    {
        if (!$this->isEnabled()) {
            return $handler;
        }

        return function($message, $title = '', $args = []) use ($handler) {
            $level = 'error';

            if (in_array($level, $this->monitorLevels)) {
                $errorData = [
                    'type' => 'wp_die',
                    'level' => $level,
                    'severity' => 'high',
                    'title' => "WordPress Critical Error: {$title}",
                    'description' => is_string($message) ? $message : print_r($message, true),
                    'url' => $_SERVER['REQUEST_URI'] ?? '',
                    'ip_address' => $_SERVER['REMOTE_ADDR'] ?? '',
                    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                    'timestamp' => current_time('mysql'),
                    'backtrace' => $this->getBacktrace(),
                ];

                do_action('wp_security_monitor_fatal_error', $errorData);
            }

            // Call original handler
            return call_user_func($handler, $message, $title, $args);
        };
    }

    /**
     * Detect issues
     */
    public function detect(): array
    {
        // Return các errors đã detect
        $errors = self::$detectedErrors;
        self::$detectedErrors = []; // Clear

        return $errors;
    }

    /**
     * Get error level từ error number
     */
    private function getErrorLevel(int $errno): string
    {
        switch ($errno) {
            case E_ERROR:
            case E_PARSE:
            case E_CORE_ERROR:
            case E_COMPILE_ERROR:
            case E_USER_ERROR:
                return 'error';

            case E_WARNING:
            case E_CORE_WARNING:
            case E_COMPILE_WARNING:
            case E_USER_WARNING:
                return 'warning';

            case E_NOTICE:
            case E_USER_NOTICE:
            case E_STRICT:
            case E_DEPRECATED:
            case E_USER_DEPRECATED:
                return 'notice';

            default:
                return 'unknown';
        }
    }

    /**
     * Get severity từ error level
     */
    private function getSeverityFromLevel(string $level): string
    {
        switch ($level) {
            case 'error':
                return 'critical';
            case 'warning':
                return 'high';
            case 'notice':
                return 'medium';
            default:
                return 'low';
        }
    }

    /**
     * Get backtrace
     */
    private function getBacktrace(): array
    {
        $backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 10);
        $formatted = [];

        foreach ($backtrace as $trace) {
            $formatted[] = sprintf(
                '%s%s%s() in %s:%d',
                $trace['class'] ?? '',
                $trace['type'] ?? '',
                $trace['function'] ?? '',
                $trace['file'] ?? 'unknown',
                $trace['line'] ?? 0
            );
        }

        return $formatted;
    }

    /**
     * Configure issuer
     */
    public function configure(array $config): void
    {
        parent::configure($config);

        if (isset($config['monitor_levels'])) {
            $this->monitorLevels = $config['monitor_levels'];
        }
    }

    /**
     * Get default config
     */
    public function getDefaultConfig(): array
    {
        return [
            'enabled' => true,
            'monitor_levels' => ['error', 'warning'], // Mặc định chỉ monitor error và warning
        ];
    }
}

