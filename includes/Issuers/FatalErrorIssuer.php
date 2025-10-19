<?php
namespace Puleeno\SecurityBot\WebMonitor\Issuers;

use Puleeno\SecurityBot\WebMonitor\Abstracts\RealtimeIssuerAbstract;

/**
 * Fatal Error Issuer
 *
 * Detects và report WordPress fatal errors, warnings, notices
 * Hook vào WordPress error handler và shutdown function
 */
class FatalErrorIssuer extends RealtimeIssuerAbstract
{
	/**
	 * @var string
	 */
	protected $name = 'Fatal Error Monitor';

	/**
	 * @var string
	 */
	protected $description = 'Monitors WordPress fatal errors, warnings, and notices';

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

		$backtrace = $this->getBacktrace(12);
		$source = $this->detectSourceFromBacktrace($backtrace, [
			'file' => $errfile,
			'line' => $errline,
		]);

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
			'backtrace' => $backtrace,
			'context' => $this->getRequestContext(),
			'php_last_error' => $this->getPhpLastError(),
			'source_type' => $source['type'],
			'source_slug' => $source['slug'],
			'source_file' => $source['file'],
			'source_line' => $source['line'],
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

		// Bỏ qua các request không nên alert (static assets, HEAD/OPTIONS, 404)
		if ($this->shouldIgnoreRequest()) {
			return;
		}

		$error = error_get_last();

		if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
			$level = 'error';

			if (!in_array($level, $this->monitorLevels)) {
				return;
			}

			$backtrace = $this->getBacktrace(15);
			$source = $this->detectSourceFromBacktrace($backtrace, $error);

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
				'backtrace' => $backtrace,
				'context' => $this->getRequestContext(),
				'php_last_error' => $this->getPhpLastError(),
				'source_type' => $source['type'],
				'source_slug' => $source['slug'],
				'source_file' => $source['file'],
				'source_line' => $source['line'],
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
				// Bỏ qua các request không nên alert
				if (!$this->shouldIgnoreRequest()) {
					$desc = '';
					// Chuẩn hoá nội dung message để tránh dump object dài
					if (is_object($message) && class_exists('WP_Error') && $message instanceof \WP_Error) {
						$desc = $message->get_error_message();
					} elseif (is_array($message)) {
						$desc = 'A critical error occurred while rendering this request.';
					} else {
						$desc = (string) $message;
					}

					// Loại bỏ HTML tags nếu có
					if (function_exists('wp_strip_all_tags')) {
						$desc = wp_strip_all_tags($desc);
					} else {
						$desc = strip_tags($desc);
					}

					// Truncate để tránh quá dài
					if (strlen($desc) > 500) {
						$desc = substr($desc, 0, 500) . '...';
					}

					$backtrace = $this->getBacktrace(15);
					$source = $this->detectSourceFromBacktrace($backtrace, null);

					$errorData = [
						'type' => 'wp_die',
						'level' => $level,
						'severity' => 'high',
						'title' => "WordPress Critical Error: {$title}",
						'description' => $desc,
						'url' => $_SERVER['REQUEST_URI'] ?? '',
						'ip_address' => $_SERVER['REMOTE_ADDR'] ?? '',
						'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
						'timestamp' => current_time('mysql'),
						'backtrace' => $backtrace,
						'context' => $this->getRequestContext(),
						'php_last_error' => $this->getPhpLastError(),
						'source_type' => $source['type'],
						'source_slug' => $source['slug'],
						'source_file' => $source['file'],
						'source_line' => $source['line'],
					];

					do_action('wp_security_monitor_fatal_error', $errorData);
				}
			}

			// Call original handler
			return call_user_func($handler, $message, $title, $args);
		};
	}

	/**
	 * Get issuer name
	 */
	public function getName(): string
	{
		return $this->name;
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
	 * Get backtrace (đưa ra danh sách gọn, không bao gồm args)
	 */
	private function getBacktrace(int $limit = 10): array
	{
		$backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, $limit);
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
	 * Tìm nguồn lỗi (plugin/theme) dựa vào backtrace, fallback vào error file/line nếu cần
	 */
	private function detectSourceFromBacktrace(array $backtrace, ?array $fallbackError): array
	{
		$pluginsMarker = '/wp-content/plugins/';
		$muPluginsMarker = '/wp-content/mu-plugins/';
		$themesMarker = '/wp-content/themes/';

		$choose = function(string $file, int $line) use ($pluginsMarker, $muPluginsMarker, $themesMarker) {
			$path = $this->normalizePath($file);
			if (strpos($path, $pluginsMarker) !== false) {
				$slug = explode('/', substr($path, strpos($path, $pluginsMarker) + strlen($pluginsMarker)))[0] ?? '';
				return ['type' => 'plugin', 'slug' => $slug, 'file' => $file, 'line' => $line];
			}
			if (strpos($path, $muPluginsMarker) !== false) {
				$slug = explode('/', substr($path, strpos($path, $muPluginsMarker) + strlen($muPluginsMarker)))[0] ?? '';
				return ['type' => 'mu-plugin', 'slug' => $slug, 'file' => $file, 'line' => $line];
			}
			if (strpos($path, $themesMarker) !== false) {
				$slug = explode('/', substr($path, strpos($path, $themesMarker) + strlen($themesMarker)))[0] ?? '';
				return ['type' => 'theme', 'slug' => $slug, 'file' => $file, 'line' => $line];
			}
			return ['type' => 'core', 'slug' => '', 'file' => $file, 'line' => $line];
		};

		foreach ($backtrace as $frame) {
			// Parse chuỗi "Class::method() in /path/file.php:123"
			$pos = strrpos($frame, ' in ');
			if ($pos === false) continue;
			$rest = substr($frame, $pos + 4);
			$parts = explode(':', $rest);
			if (count($parts) >= 2) {
				$file = $parts[0];
				$line = (int) $parts[1];
				$src = $choose($file, $line);
				if (in_array($src['type'], ['plugin', 'mu-plugin', 'theme'], true)) {
					return $src;
				}
			}
		}

		if (is_array($fallbackError) && isset($fallbackError['file'])) {
			return $choose($fallbackError['file'], (int)($fallbackError['line'] ?? 0));
		}

		return ['type' => 'unknown', 'slug' => '', 'file' => '', 'line' => 0];
	}

	private function normalizePath(string $path): string
	{
		return str_replace('\\', '/', $path);
	}

	private function getPhpLastError(): ?array
	{
		$e = error_get_last();
		if (!$e) return null;
		return [
			'type' => $e['type'] ?? null,
			'message' => $e['message'] ?? null,
			'file' => $e['file'] ?? null,
			'line' => $e['line'] ?? null,
		];
	}

	private function getRequestContext(): array
	{
		$uri = $_SERVER['REQUEST_URI'] ?? '';
		return [
			'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
			'referer' => $_SERVER['HTTP_REFERER'] ?? '',
			'is_ajax' => defined('DOING_AJAX') && DOING_AJAX,
			'is_rest' => (strpos($uri, '/wp-json/') !== false),
			'hook' => function_exists('current_filter') ? current_filter() : '',
		];
	}

	/**
	 * Xác định request có nên ignore không (static asset/404/head/options)
	 */
	private function shouldIgnoreRequest(): bool
	{
		$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
		if (in_array($method, ['HEAD', 'OPTIONS'], true)) {
			return true;
		}

		$uri = $_SERVER['REQUEST_URI'] ?? '';
		if ($this->isStaticAssetRequest($uri)) {
			return true;
		}

		if (function_exists('http_response_code')) {
			$code = http_response_code();
			if ($code === 404) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Kiểm tra URL có phải static asset (ảnh, css, js, font, media)
	 */
	private function isStaticAssetRequest(string $uri): bool
	{
		$path = parse_url($uri, PHP_URL_PATH) ?: $uri;
		$ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
		if (!$ext) return false;

		$staticExts = [
			'jpg','jpeg','png','gif','svg','webp','ico',
			'css','js','map',
			'woff','woff2','ttf','eot','otf',
			'mp4','webm','ogg','mp3','wav'
		];

		return in_array($ext, $staticExts, true);
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

