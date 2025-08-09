<?php
namespace Puleeno\SecurityBot\WebMonitor\Interfaces;

interface MonitorInterface
{
    /**
     * Bắt đầu giám sát
     *
     * @return void
     */
    public function start(): void;

    /**
     * Dừng giám sát
     *
     * @return void
     */
    public function stop(): void;

    /**
     * Kiểm tra trạng thái giám sát
     *
     * @return bool
     */
    public function isRunning(): bool;

    /**
     * Thêm issuer vào danh sách giám sát
     *
     * @param IssuerInterface $issuer
     * @return void
     */
    public function addIssuer(IssuerInterface $issuer): void;

    /**
     * Thêm channel để nhận thông báo
     *
     * @param ChannelInterface $channel
     * @return void
     */
    public function addChannel(ChannelInterface $channel): void;

    /**
     * Chạy một lần kiểm tra
     *
     * @return array
     */
    public function runCheck(): array;
}
