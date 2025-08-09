<?php
namespace Puleeno\SecurityBot\WebMonitor\Interfaces;

interface IssuerInterface
{
    /**
     * Kiểm tra và phát hiện vấn đề bảo mật
     *
     * @return array Danh sách vấn đề được phát hiện
     */
    public function detect(): array;

    /**
     * Lấy tên của issuer
     *
     * @return string
     */
    public function getName(): string;

    /**
     * Lấy mức độ ưu tiên của issuer
     *
     * @return int
     */
    public function getPriority(): int;

    /**
     * Kiểm tra issuer có được kích hoạt không
     *
     * @return bool
     */
    public function isEnabled(): bool;

    /**
     * Cấu hình issuer
     *
     * @param array $config
     * @return void
     */
    public function configure(array $config): void;
}
