<?php
namespace Puleeno\SecurityBot\WebMonitor\Interfaces;

interface ChannelInterface
{
    /**
     * Gửi thông báo qua channel
     *
     * @param string $message Nội dung thông báo
     * @param array $data Dữ liệu bổ sung
     * @return bool
     */
    public function send(string $message, array $data = []): bool;

    /**
     * Kiểm tra channel có khả dụng không
     *
     * @return bool
     */
    public function isAvailable(): bool;

    /**
     * Lấy tên channel
     *
     * @return string
     */
    public function getName(): string;

    /**
     * Cấu hình channel
     *
     * @param array $config
     * @return void
     */
    public function configure(array $config): void;
}
