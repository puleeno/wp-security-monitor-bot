<?php
namespace Puleeno\SecurityBot\WebMonitor\Channels;

use Puleeno\SecurityBot\WebMonitor\Abstracts\Channel;
use Telegram\Bot\Api;
use Telegram\Bot\Exceptions\TelegramException;

class TelegramChannel extends Channel
{
    /**
     * @var Api
     */
    private $telegram;

    public function getName(): string
    {
        return 'Telegram';
    }

    public function send(string $message, array $data = []): bool
    {
        try {
            $this->initializeTelegram();

            $chatId = $this->getConfig('chat_id');
            if (empty($chatId)) {
                $this->logError('Chat ID không được cấu hình');
                return false;
            }

            $response = $this->telegram->sendMessage([
                'chat_id' => $chatId,
                'text' => $message,
                'parse_mode' => 'Markdown',
                'disable_web_page_preview' => true
            ]);

            return $response->getMessageId() > 0;

        } catch (TelegramException $e) {
            $this->logError('Telegram API Error: ' . $e->getMessage());
            return false;
        } catch (\Exception $e) {
            $this->logError('Unexpected error: ' . $e->getMessage());
            return false;
        }
    }

    protected function checkConnection(): bool
    {
        try {
            $this->initializeTelegram();

            $botInfo = $this->telegram->getMe();
            return !empty($botInfo->getUsername());

        } catch (TelegramException $e) {
            $this->logError('Connection check failed: ' . $e->getMessage());
            return false;
        } catch (\Exception $e) {
            $this->logError('Connection check error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Khởi tạo Telegram API
     *
     * @return void
     * @throws \Exception
     */
    private function initializeTelegram(): void
    {
        if ($this->telegram instanceof Api) {
            return;
        }

        $botToken = $this->getConfig('bot_token');
        if (empty($botToken)) {
            throw new \Exception('Bot token không được cấu hình');
        }

        $this->telegram = new Api($botToken);
    }

    /**
     * Lấy thông tin bot
     *
     * @return array|null
     */
    public function getBotInfo(): ?array
    {
        try {
            $this->initializeTelegram();
            $botInfo = $this->telegram->getMe();

            return [
                'id' => $botInfo->getId(),
                'username' => $botInfo->getUsername(),
                'first_name' => $botInfo->getFirstName(),
                'can_join_groups' => $botInfo->getCanJoinGroups(),
                'can_read_all_group_messages' => $botInfo->getCanReadAllGroupMessages(),
                'supports_inline_queries' => $botInfo->getSupportsInlineQueries()
            ];

        } catch (\Exception $e) {
            $this->logError('Cannot get bot info: ' . $e->getMessage());
            return null;
        }
    }

    /**
     * Test gửi tin nhắn
     *
     * @return array
     */
    public function testConnection(): array
    {
        try {
            // Check if properly configured
            if (!$this->isAvailable()) {
                return [
                    'success' => false,
                    'message' => 'Telegram channel not available. Check bot token and chat ID configuration.'
                ];
            }

            $testMessage = "🤖 *Test kết nối thành công!*\n\n";
            $testMessage .= "Bot Security Monitor đã được cấu hình và hoạt động bình thường.\n";
            $testMessage .= "⏰ Thời gian test: " . date('d/m/Y H:i:s');

            $result = $this->send($testMessage);

            if ($result) {
                return [
                    'success' => true,
                    'message' => 'Test message sent successfully to Telegram!'
                ];
            } else {
                return [
                    'success' => false,
                    'message' => 'Failed to send test message. Check bot token, chat ID, and network connectivity.'
                ];
            }

        } catch (\Exception $e) {
            return [
                'success' => false,
                'message' => 'Telegram test failed: ' . $e->getMessage()
            ];
        }
    }
}
