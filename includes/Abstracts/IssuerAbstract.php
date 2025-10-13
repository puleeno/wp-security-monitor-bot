<?php
namespace Puleeno\SecurityBot\WebMonitor\Abstracts;

use Puleeno\SecurityBot\WebMonitor\Interfaces\IssuerInterface;

/**
 * Abstract class cho Scheduled Issuers
 *
 * Default behavior: KHÔNG báo cáo lại (chỉ báo lần đầu phát hiện)
 * Phù hợp cho: File changes, Dangerous functions, etc.
 */
abstract class IssuerAbstract implements IssuerInterface
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
        // Scheduled issues: KHÔNG báo lại (trừ khi đã viewed)
        return false;
    }

    /**
     * Check xem issuer có phải realtime không
     *
     * @return bool
     */
    public function isRealtime(): bool
    {
        return false;
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

