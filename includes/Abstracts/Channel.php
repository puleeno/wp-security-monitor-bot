<?php
namespace Puleeno\SecurityBot\WebMonitor\Abstracts;

use Puleeno\SecurityBot\WebMonitor\Interfaces\ChannelInterface;

abstract class Channel implements ChannelInterface
{
    /**
     * @var array
     */
    protected $config = [];

    /**
     * @var bool
     */
    protected $enabled = true;

    public function configure(array $config): void
    {
        $this->config = array_merge($this->config, $config);

        if (isset($config['enabled'])) {
            $this->enabled = (bool) $config['enabled'];
        }
    }

    public function isAvailable(): bool
    {
        return $this->enabled && $this->checkConnection();
    }

    /**
     * Kiểm tra kết nối với service
     *
     * @return bool
     */
    abstract protected function checkConnection(): bool;

    /**
     * Lấy giá trị config
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
     * Log lỗi
     *
     * @param string $message
     * @return void
     */
    protected function logError(string $message): void
    {
        error_log(sprintf('[%s] %s', $this->getName(), $message));
    }
}
