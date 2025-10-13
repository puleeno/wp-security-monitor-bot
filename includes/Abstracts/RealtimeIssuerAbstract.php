<?php
namespace Puleeno\SecurityBot\WebMonitor\Abstracts;

use Puleeno\SecurityBot\WebMonitor\Interfaces\RealtimeIssuerInterface;

/**
 * Abstract class cho Realtime Issuers
 *
 * Default behavior: LUÔN báo cáo lại mỗi lần phát hiện
 * Phù hợp cho: Login attempts, Brute force, Redirects, User registration, etc.
 */
abstract class RealtimeIssuerAbstract implements RealtimeIssuerInterface
{
    /**
     * @var array
     */
    protected $config = [];

    /**
     * @var bool
     */
    protected $enabled = true;

    /**
     * Có nên báo cáo lại khi phát hiện issue cũ hay không
     *
     * @return bool
     */
    public function shouldNotifyOnRedetection(): bool
    {
        // Realtime issues: LUÔN báo lại
        return true;
    }

    /**
     * Check xem issuer có phải realtime không
     *
     * @return bool
     */
    public function isRealtime(): bool
    {
        return true;
    }

    /**
     * Configure issuer
     *
     * @param array $config
     * @return void
     */
    public function configure(array $config): void
    {
        $this->config = $config;
    }

    /**
     * Get config value
     *
     * @param string $key
     * @param mixed $default
     * @return mixed
     */
    protected function getConfig(string $key, $default = null)
    {
        return $this->config[$key] ?? $default;
    }

    /**
     * Kiểm tra issuer có được kích hoạt không
     *
     * @return bool
     */
    public function isEnabled(): bool
    {
        return $this->enabled;
    }

    /**
     * Lấy mức độ ưu tiên của issuer
     *
     * @return int
     */
    public function getPriority(): int
    {
        return 10;
    }

    // Abstract methods - must be implemented by child classes
    abstract public function detect(): array;
    abstract public function getName(): string;
}

