<?php
namespace Puleeno\SecurityBot\WebMonitor\Channels;

use Puleeno\SecurityBot\WebMonitor\Abstracts\Channel;

class TelegramChannel extends Channel
{
    protected static $instance;

    public static function setInstance(TelegramChannel $instance) {
        static::$instance = $instance;
    }

    public static function getInstance() : ? TelegramChannel {
        return static::$instance;
    }

    public function getName(): string
    {
        return 'Telegram';
    }

    /**
     * Escape các ký tự đặc biệt trong Markdown để tránh lỗi parsing
     *
     * @param string $text
     * @return string
     */
    private function escapeMarkdown(string $text): string
    {
        // Escape các ký tự đặc biệt trong Markdown
        $specialChars = [
            '_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!'
        ];

        foreach ($specialChars as $char) {
            $text = str_replace($char, '\\' . $char, $text);
        }

        return $text;
    }

    /**
     * Gửi tin nhắn qua Telegram
     *
     * @param string $message
     * @param array $context
     * @return bool
     */
    public function send(string $message, array $context = []): bool
    {
        try {
            // Debug: Log send attempt
            if (WP_DEBUG) {
                error_log("[Telegram Debug] Attempting to send message");
                error_log("[Telegram Debug] Message length: " . strlen($message));
                error_log("[Telegram Debug] Data: " . print_r($context, true));
            }

            $botToken = $this->getConfig('bot_token');
            if (empty($botToken)) {
                $this->logError('Bot token không được cấu hình');
                if (WP_DEBUG) {
                    error_log("[Telegram Debug] Bot token is empty");
                }
                return false;
            }

            $chatId = $this->getConfig('chat_id');
            if (empty($chatId)) {
                $this->logError('Chat ID không được cấu hình');
                if (WP_DEBUG) {
                    error_log("[Telegram Debug] Chat ID is empty");
                }
                return false;
            }

            if (WP_DEBUG) {
                error_log("[Telegram Debug] Bot Token: " . substr($botToken, 0, 10) . "...");
                error_log("[Telegram Debug] Chat ID: {$chatId}");
            }

            // Escape message để tránh lỗi Markdown parsing
            $escapedMessage = $this->escapeMarkdown($message);

            if (WP_DEBUG) {
                error_log("[Telegram Debug] Original message: " . substr($message, 0, 100) . "...");
                error_log("[Telegram Debug] Escaped message: " . substr($escapedMessage, 0, 100) . "...");
            }

            // Luôn sử dụng HTTPS vì Telegram API không hỗ trợ HTTP
            $sslVerify = get_option('wp_security_monitor_telegram_ssl_verify', true);

            // Debug log chi tiết
            error_log("[Telegram Debug] Sending message - SSL Verify: " . var_export($sslVerify, true));
            error_log("[Telegram Debug] Protocol: https (Telegram API chỉ hỗ trợ HTTPS)");

            $args = [
                'timeout' => 30,
                'sslverify' => $sslVerify,
                'user-agent' => 'Puleeno Security Bot/1.0',
                'body' => [
                    'chat_id' => $chatId,
                    'text' => $escapedMessage,
                    'parse_mode' => 'Markdown',
                    'disable_web_page_preview' => 'true'
                ]
            ];

            // Nếu SSL verification bị tắt, thêm các tùy chọn để bỏ qua SSL certificate check
            if (!$sslVerify) {
                $args['sslverify'] = false;
                $args['httpversion'] = '1.1';
                // Thêm các tùy chọn cURL để bỏ qua SSL certificate
                $args['ssl'] = false;
                $args['curl_ssl_verifypeer'] = false;
                $args['curl_ssl_verifyhost'] = false;

                error_log("[Telegram Debug] SSL verification disabled - using cURL options to bypass SSL");
            } else {
                error_log("[Telegram Debug] SSL verification enabled - using default SSL settings");
            }

            error_log("[Telegram Debug] Final args: " . print_r($args, true));
            error_log("[Telegram Debug] Making request to: https://api.telegram.org/bot{$botToken}/sendMessage");

            $response = wp_remote_post(
                "https://api.telegram.org/bot{$botToken}/sendMessage",
                $args
            );

            if (is_wp_error($response)) {
                $errorMessage = $response->get_error_message();
                $errorCode = $response->get_error_code();
                error_log("[Telegram Debug] HTTP request failed - Error: {$errorMessage}, Code: {$errorCode}");
                $this->logError('HTTP request failed: ' . $errorMessage);
                return false;
            }

            $responseCode = wp_remote_retrieve_response_code($response);
            $responseHeaders = wp_remote_retrieve_headers($response);
            $body = wp_remote_retrieve_body($response);

            error_log("[Telegram Debug] Response Code: {$responseCode}");
            error_log("[Telegram Debug] Response Headers: " . print_r($responseHeaders, true));
            error_log("[Telegram Debug] Response Body: " . $body);

            if ($responseCode !== 200) {
                error_log("[Telegram Debug] Non-200 response code: {$responseCode}");
                $this->logError("HTTP response code: {$responseCode}, Body: {$body}");
                return false;
            }

            $data = json_decode($body, true);

            if (!$data || !isset($data['ok']) || !$data['ok']) {
                error_log("[Telegram Debug] Invalid JSON response or API error");
                $this->logError('Telegram API response error: ' . $body);
                return false;
            }

            $messageId = $data['result']['message_id'] ?? null;
            error_log("[Telegram Debug] Message sent successfully - Message ID: " . ($messageId ?? 'N/A'));

            if (WP_DEBUG) {
                error_log("[Telegram Debug] Message sent successfully to Telegram");
                error_log("[Telegram Debug] Telegram API response: " . print_r($data, true));
            }

            return isset($messageId) && $messageId > 0;

        } catch (\Exception $e) {
            error_log("[Telegram Debug] Exception caught: " . $e->getMessage());
            error_log("[Telegram Debug] Exception trace: " . $e->getTraceAsString());
            $this->logError('Unexpected error: ' . $e->getMessage());
            return false;
        }
    }

    public static function sendHelper($message, $context = []) {
        if (is_null(static::getInstance())) {
            error_log('Web Monitor: Telegram bot is not ready');
            return;
        }
        static::getInstance()->send($message, $context);
    }

    public static function sendFile(string $filePath, string $caption = '', string $fileType = 'document') {
        if (is_null(static::getInstance())) {
            error_log('Web Monitor: Telegram bot is not ready');
            return;
        }
        static::getInstance()->sendFileWithPath($filePath, $caption, $fileType);
    }

    /**
     * Gửi file qua Telegram
     *
     * @param string $filePath Đường dẫn đến file cần gửi
     * @param string $caption Caption cho file (tùy chọn)
     * @param string $fileType Loại file: document, photo, video, audio, voice, video_note, animation, sticker (mặc định: document)
     * @return bool
     */
    public function sendFileWithPath(string $filePath, string $caption = '', string $fileType = 'document'): bool
    {
        try {
            // Debug: Log send file attempt
            if (WP_DEBUG) {
                error_log("[Telegram Debug] Attempting to send file: {$filePath}");
                error_log("[Telegram Debug] File type: {$fileType}");
                error_log("[Telegram Debug] Caption: " . substr($caption, 0, 100));
            }

            // Kiểm tra file có tồn tại không
            if (!file_exists($filePath)) {
                $this->logError("File không tồn tại: {$filePath}");
                if (WP_DEBUG) {
                    error_log("[Telegram Debug] File does not exist: {$filePath}");
                }
                return false;
            }

            // Kiểm tra file có thể đọc được không
            if (!is_readable($filePath)) {
                $this->logError("Không thể đọc file: {$filePath}");
                if (WP_DEBUG) {
                    error_log("[Telegram Debug] File is not readable: {$filePath}");
                }
                return false;
            }

            // Kiểm tra kích thước file (Telegram giới hạn 50MB)
            $fileSize = filesize($filePath);
            $maxSize = 50 * 1024 * 1024; // 50MB
            if ($fileSize > $maxSize) {
                $this->logError("File quá lớn: {$fileSize} bytes (giới hạn: {$maxSize} bytes)");
                if (WP_DEBUG) {
                    error_log("[Telegram Debug] File too large: {$fileSize} bytes");
                }
                return false;
            }

            $botToken = $this->getConfig('bot_token');
            if (empty($botToken)) {
                $this->logError('Bot token không được cấu hình');
                if (WP_DEBUG) {
                    error_log("[Telegram Debug] Bot token is empty");
                }
                return false;
            }

            $chatId = $this->getConfig('chat_id');
            if (empty($chatId)) {
                $this->logError('Chat ID không được cấu hình');
                if (WP_DEBUG) {
                    error_log("[Telegram Debug] Chat ID is empty");
                }
                return false;
            }

            if (WP_DEBUG) {
                error_log("[Telegram Debug] Bot Token: " . substr($botToken, 0, 10) . "...");
                error_log("[Telegram Debug] Chat ID: {$chatId}");
                error_log("[Telegram Debug] File size: {$fileSize} bytes");
            }

            // Escape caption để tránh lỗi Markdown parsing
            $escapedCaption = $this->escapeMarkdown($caption);

            // Chuẩn bị multipart form data
            $boundary = wp_generate_password(16, false);
            $fileContent = file_get_contents($filePath);
            $fileName = basename($filePath);
            $mimeType = wp_check_filetype($filePath)['type'] ?? 'application/octet-stream';

            // Xác định endpoint dựa trên loại file
            $endpoint = "https://api.telegram.org/bot{$botToken}/sendDocument";
            switch ($fileType) {
                case 'photo':
                    $endpoint = "https://api.telegram.org/bot{$botToken}/sendPhoto";
                    break;
                case 'video':
                    $endpoint = "https://api.telegram.org/bot{$botToken}/sendVideo";
                    break;
                case 'audio':
                    $endpoint = "https://api.telegram.org/bot{$botToken}/sendAudio";
                    break;
                case 'voice':
                    $endpoint = "https://api.telegram.org/bot{$botToken}/sendVoice";
                    break;
                case 'video_note':
                    $endpoint = "https://api.telegram.org/bot{$botToken}/sendVideoNote";
                    break;
                case 'animation':
                    $endpoint = "https://api.telegram.org/bot{$botToken}/sendAnimation";
                    break;
                case 'sticker':
                    $endpoint = "https://api.telegram.org/bot{$botToken}/sendSticker";
                    break;
                default:
                    $endpoint = "https://api.telegram.org/bot{$botToken}/sendDocument";
                    break;
            }

            // Chuẩn bị multipart body
            $body = '';
            $body .= "--{$boundary}\r\n";
            $body .= "Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n";
            $body .= $chatId . "\r\n";

            if (!empty($escapedCaption)) {
                $body .= "--{$boundary}\r\n";
                $body .= "Content-Disposition: form-data; name=\"caption\"\r\n\r\n";
                $body .= $escapedCaption . "\r\n";
            }

            $body .= "--{$boundary}\r\n";
            $body .= "Content-Disposition: form-data; name=\"parse_mode\"\r\n\r\n";
            $body .= "Markdown\r\n";

            $body .= "--{$boundary}\r\n";
            $body .= "Content-Disposition: form-data; name=\"{$fileType}\"; filename=\"{$fileName}\"\r\n";
            $body .= "Content-Type: {$mimeType}\r\n\r\n";
            $body .= $fileContent . "\r\n";
            $body .= "--{$boundary}--\r\n";

            // SSL settings
            $sslVerify = get_option('wp_security_monitor_telegram_ssl_verify', true);

            $args = [
                'timeout' => 60, // Tăng timeout cho file upload
                'sslverify' => $sslVerify,
                'user-agent' => 'Puleeno Security Bot/1.0',
                'headers' => [
                    'Content-Type' => "multipart/form-data; boundary={$boundary}",
                ],
                'body' => $body
            ];

            // Nếu SSL verification bị tắt
            if (!$sslVerify) {
                $args['sslverify'] = false;
                $args['httpversion'] = '1.1';
                $args['ssl'] = false;
                $args['curl_ssl_verifypeer'] = false;
                $args['curl_ssl_verifyhost'] = false;
            }

            if (WP_DEBUG) {
                error_log("[Telegram Debug] Making request to: {$endpoint}");
                error_log("[Telegram Debug] File name: {$fileName}");
                error_log("[Telegram Debug] MIME type: {$mimeType}");
            }

            $response = wp_remote_post($endpoint, $args);

            if (is_wp_error($response)) {
                $errorMessage = $response->get_error_message();
                $errorCode = $response->get_error_code();
                error_log("[Telegram Debug] HTTP request failed - Error: {$errorMessage}, Code: {$errorCode}");
                $this->logError('HTTP request failed: ' . $errorMessage);
                return false;
            }

            $responseCode = wp_remote_retrieve_response_code($response);
            $body = wp_remote_retrieve_body($response);

            if (WP_DEBUG) {
                error_log("[Telegram Debug] Response Code: {$responseCode}");
                error_log("[Telegram Debug] Response Body: " . $body);
            }

            if ($responseCode !== 200) {
                error_log("[Telegram Debug] Non-200 response code: {$responseCode}");
                $this->logError("HTTP response code: {$responseCode}, Body: {$body}");
                return false;
            }

            $data = json_decode($body, true);

            if (!$data || !isset($data['ok']) || !$data['ok']) {
                error_log("[Telegram Debug] Invalid JSON response or API error");
                $this->logError('Telegram API response error: ' . $body);
                return false;
            }

            $messageId = $data['result']['message_id'] ?? null;
            error_log("[Telegram Debug] File sent successfully - Message ID: " . ($messageId ?? 'N/A'));

            if (WP_DEBUG) {
                error_log("[Telegram Debug] File sent successfully to Telegram");
                error_log("[Telegram Debug] Telegram API response: " . print_r($data, true));
            }

            return isset($messageId) && $messageId > 0;

        } catch (\Exception $e) {
            error_log("[Telegram Debug] Exception caught: " . $e->getMessage());
            error_log("[Telegram Debug] Exception trace: " . $e->getTraceAsString());
            $this->logError('Unexpected error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Static helper để gửi file
     *
     * @param string $filePath Đường dẫn đến file
     * @param string $caption Caption cho file
     * @param string $fileType Loại file
     * @return bool
     */
    public static function sendFileHelper(string $filePath, string $caption = '', string $fileType = 'document'): bool
    {
        if (is_null(static::getInstance())) {
            error_log('Web Monitor: Telegram bot is not ready');
            return false;
        }
        return static::getInstance()->sendFileWithPath($filePath, $caption, $fileType);
    }

    protected function checkConnection(): bool
    {
        try {
            $botToken = $this->getConfig('bot_token');
            if (empty($botToken)) {
                $this->logError('Bot token không được cấu hình');
                return false;
            }

            // Luôn sử dụng HTTPS vì Telegram API không hỗ trợ HTTP
            $sslVerify = get_option('wp_security_monitor_telegram_ssl_verify', true);

            // Debug log chi tiết
            error_log("[Telegram Debug] SSL Verify setting: " . var_export($sslVerify, true));
            error_log("[Telegram Debug] Protocol: https (Telegram API chỉ hỗ trợ HTTPS)");

            $args = [
                'timeout' => 30,
                'sslverify' => $sslVerify,
                'user-agent' => 'Puleeno Security Bot/1.0'
            ];

            // Nếu SSL verification bị tắt, thêm các tùy chọn để bỏ qua SSL certificate check
            if (!$sslVerify) {
                $args['sslverify'] = false;
                $args['httpversion'] = '1.1';
                // Thêm các tùy chọn cURL để bỏ qua SSL certificate
                $args['ssl'] = false;
                $args['curl_ssl_verifypeer'] = false;
                $args['curl_ssl_verifyhost'] = false;

                error_log("[Telegram Debug] SSL verification disabled - using cURL options to bypass SSL");
            } else {
                error_log("[Telegram Debug] SSL verification enabled - using default SSL settings");
            }

            error_log("[Telegram Debug] Final args: " . print_r($args, true));
            error_log("[Telegram Debug] Making request to: https://api.telegram.org/bot{$botToken}/getMe");

            $response = wp_remote_get(
                "https://api.telegram.org/bot{$botToken}/getMe",
                $args
            );

            if (is_wp_error($response)) {
                $errorMessage = $response->get_error_message();
                $errorCode = $response->get_error_code();
                error_log("[Telegram Debug] HTTP request failed - Error: {$errorMessage}, Code: {$errorCode}");
                $this->logError('HTTP request failed: ' . $errorMessage);
                return false;
            }

            $responseCode = wp_remote_retrieve_response_code($response);
            $responseHeaders = wp_remote_retrieve_headers($response);
            $body = wp_remote_retrieve_body($response);

            error_log("[Telegram Debug] Response Code: {$responseCode}");
            error_log("[Telegram Debug] Response Headers: " . print_r($responseHeaders, true));
            error_log("[Telegram Debug] Response Body: " . $body);

            if ($responseCode !== 200) {
                error_log("[Telegram Debug] Non-200 response code: {$responseCode}");
                $this->logError("HTTP response code: {$responseCode}, Body: {$body}");
                return false;
            }

            $data = json_decode($body, true);

            if (!$data || !isset($data['ok']) || !$data['ok']) {
                error_log("[Telegram Debug] Invalid JSON response or API error");
                $this->logError('Telegram API response error: ' . $body);
                return false;
            }

            error_log("[Telegram Debug] Connection successful - Bot username: " . ($data['result']['username'] ?? 'N/A'));
            return !empty($data['result']['username']);

        } catch (\Exception $e) {
            error_log("[Telegram Debug] Exception caught: " . $e->getMessage());
            error_log("[Telegram Debug] Exception trace: " . $e->getTraceAsString());
            $this->logError('Connection check error: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Lấy thông tin bot
     *
     * @return array|null
     */
    public function getBotInfo(): ?array
    {
        try {
            $botToken = $this->getConfig('bot_token');
            if (empty($botToken)) {
                $this->logError('Bot token không được cấu hình');
                return null;
            }

            // Luôn sử dụng HTTPS vì Telegram API không hỗ trợ HTTP
            $sslVerify = get_option('wp_security_monitor_telegram_ssl_verify', true);

            // Debug log chi tiết
            error_log("[Telegram Debug] Getting bot info - SSL Verify: " . var_export($sslVerify, true));
            error_log("[Telegram Debug] Protocol: https (Telegram API chỉ hỗ trợ HTTPS)");

            $args = [
                'timeout' => 30,
                'sslverify' => $sslVerify,
                'user-agent' => 'Puleeno Security Bot/1.0'
            ];

            // Nếu SSL verification bị tắt, thêm các tùy chọn để bỏ qua SSL certificate check
            if (!$sslVerify) {
                $args['sslverify'] = false;
                $args['httpversion'] = '1.1';
                // Thêm các tùy chọn cURL để bỏ qua SSL certificate
                $args['ssl'] = false;
                $args['curl_ssl_verifypeer'] = false;
                $args['curl_ssl_verifyhost'] = false;

                error_log("[Telegram Debug] SSL verification disabled - using cURL options to bypass SSL");
            } else {
                error_log("[Telegram Debug] SSL verification enabled - using default SSL settings");
            }

            error_log("[Telegram Debug] Final args: " . print_r($args, true));
            error_log("[Telegram Debug] Making request to: https://api.telegram.org/bot{$botToken}/getMe");

            $response = wp_remote_get(
                "https://api.telegram.org/bot{$botToken}/getMe",
                $args
            );

            if (is_wp_error($response)) {
                $errorMessage = $response->get_error_message();
                $errorCode = $response->get_error_code();
                error_log("[Telegram Debug] HTTP request failed - Error: {$errorMessage}, Code: {$errorCode}");
                $this->logError('HTTP request failed: ' . $errorMessage);
                return null;
            }

            $responseCode = wp_remote_retrieve_response_code($response);
            $responseHeaders = wp_remote_retrieve_headers($response);
            $body = wp_remote_retrieve_body($response);

            error_log("[Telegram Debug] Response Code: {$responseCode}");
            error_log("[Telegram Debug] Response Headers: " . print_r($responseHeaders, true));
            error_log("[Telegram Debug] Response Body: " . $body);

            if ($responseCode !== 200) {
                error_log("[Telegram Debug] Non-200 response code: {$responseCode}");
                $this->logError("HTTP response code: {$responseCode}, Body: {$body}");
                return null;
            }

            $data = json_decode($body, true);

            if (!$data || !isset($data['ok']) || !$data['ok']) {
                error_log("[Telegram Debug] Invalid JSON response or API error");
                $this->logError('Telegram API response error: ' . $body);
                return null;
            }

            $botInfo = $data['result'];
            error_log("[Telegram Debug] Bot info retrieved successfully - Username: " . ($botInfo['username'] ?? 'N/A'));
            return [
                'id' => $botInfo['id'] ?? null,
                'username' => $botInfo['username'] ?? null,
                'first_name' => $botInfo['first_name'] ?? null,
                'can_join_groups' => $botInfo['can_join_groups'] ?? false,
                'can_read_all_group_messages' => $botInfo['can_read_all_group_messages'] ?? false,
                'supports_inline_queries' => $botInfo['supports_inline_queries'] ?? false
            ];

        } catch (\Exception $e) {
            error_log("[Telegram Debug] Exception caught: " . $e->getMessage());
            error_log("[Telegram Debug] Exception trace: " . $e->getTraceAsString());
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

            // Lấy thông tin debug về SSL setting
            $sslVerify = get_option('wp_security_monitor_telegram_ssl_verify', true);

            // Luôn sử dụng HTTPS vì Telegram API không hỗ trợ HTTP
            $protocol = 'https';

            // Test connection bằng cách kiểm tra bot info
            $connectionResult = $this->checkConnection();

            if ($connectionResult) {
                return [
                    'success' => true,
                    'message' => "Test kết nối thành công! Bot đã sẵn sàng nhận và gửi tin nhắn. (Protocol: {$protocol}, SSL Verification: " . ($sslVerify ? 'enabled' : 'disabled') . ")"
                ];
            } else {
                $debugInfo = "Protocol: {$protocol}, SSL Verification: " . ($sslVerify ? 'enabled' : 'disabled');

                return [
                    'success' => false,
                    'message' => "Test kết nối thất bại. Kiểm tra bot token và kết nối mạng. {$debugInfo}"
                ];
            }

        } catch (\Exception $e) {
            return [
                'success' => false,
                'message' => 'Telegram test failed: ' . $e->getMessage()
            ];
        }
    }

    public function isAvailable(): bool
    {
        // Debug: Log availability check
        if (WP_DEBUG) {
            error_log("[Telegram Debug] Checking if channel is available");
            error_log("[Telegram Debug] Channel enabled: " . var_export($this->enabled, true));
        }

        if (!$this->enabled) {
            if (WP_DEBUG) {
                error_log("[Telegram Debug] Channel is disabled - returning false");
            }
            return false;
        }

        // Check if we have required credentials
        $botToken = $this->getConfig('bot_token');
        $chatId = $this->getConfig('chat_id');

        if (empty($botToken) || empty($chatId)) {
            if (WP_DEBUG) {
                error_log("[Telegram Debug] Missing credentials - Bot Token: " . (!empty($botToken) ? 'SET' : 'MISSING') . ", Chat ID: " . (!empty($chatId) ? 'SET' : 'MISSING'));
            }
            return false;
        }

        if (WP_DEBUG) {
            error_log("[Telegram Debug] Credentials check passed - proceeding with connection check");
        }

        // Only check connection if we haven't checked recently (avoid API spam)
        $lastCheckKey = 'telegram_connection_last_check';
        $lastCheck = get_transient($lastCheckKey);
        $checkInterval = 300; // 5 minutes

        if ($lastCheck && (time() - $lastCheck) < $checkInterval) {
            if (WP_DEBUG) {
                error_log("[Telegram Debug] Using cached connection status (checked " . (time() - $lastCheck) . " seconds ago)");
            }
            return get_transient('telegram_connection_status') === 'success';
        }

        if (WP_DEBUG) {
            error_log("[Telegram Debug] Performing fresh connection check");
        }

        // Perform connection check
        $connectionResult = $this->checkConnection();

        // Cache the result
        set_transient($lastCheckKey, time(), $checkInterval);
        set_transient('telegram_connection_status', $connectionResult ? 'success' : 'failed', $checkInterval);

        if (WP_DEBUG) {
            error_log("[Telegram Debug] Connection check result: " . ($connectionResult ? 'SUCCESS' : 'FAILED'));
        }

        return $connectionResult;
    }
}
