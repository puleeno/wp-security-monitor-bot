<?php

namespace Puleeno\SecurityBot\WebMonitor\Security;

/**
 * Credential Manager
 *
 * Specialized manager for handling API credentials và sensitive URLs
 * Provides high-level interface for credential operations
 */
class CredentialManager
{
    /**
     * Credential types
     */
    const TYPE_TELEGRAM_TOKEN = 'telegram_token';
    const TYPE_TELEGRAM_CHAT_ID = 'telegram_chat_id';
    const TYPE_SLACK_WEBHOOK = 'slack_webhook_url';
    const TYPE_EMAIL_SMTP = 'email_smtp_config';
    const TYPE_DATABASE_CREDS = 'database_credentials';
    const TYPE_API_KEYS = 'api_keys';

    /**
     * Set credential securely
     *
     * @param string $type Credential type
     * @param mixed $value Credential value
     * @param array $metadata Additional metadata
     * @return bool Success status
     */
    public static function setCredential(string $type, $value, array $metadata = []): bool
    {
        $credentialData = [
            'value' => $value,
            'created_at' => current_time('mysql'),
            'created_by' => get_current_user_id(),
            'metadata' => $metadata,
            'last_used' => null,
            'use_count' => 0
        ];

        return SecureConfigManager::setSecureConfig('credential_' . $type, $credentialData);
    }

    /**
     * Get credential securely
     *
     * @param string $type Credential type
     * @param bool $trackUsage Track usage statistics
     * @return mixed Credential value or null
     */
    public static function getCredential(string $type, bool $trackUsage = true)
    {
        $credentialData = SecureConfigManager::getSecureConfig('credential_' . $type);

        if (!$credentialData || !isset($credentialData['value'])) {
            return null;
        }

        // Track usage if requested
        if ($trackUsage) {
            self::trackCredentialUsage($type);
        }

        return $credentialData['value'];
    }

    /**
     * Track credential usage
     *
     * @param string $type Credential type
     */
    private static function trackCredentialUsage(string $type): void
    {
        $credentialData = SecureConfigManager::getSecureConfig('credential_' . $type);

        if ($credentialData) {
            $credentialData['last_used'] = current_time('mysql');
            $credentialData['use_count'] = ($credentialData['use_count'] ?? 0) + 1;

            SecureConfigManager::setSecureConfig('credential_' . $type, $credentialData);
        }
    }

    /**
     * Delete credential
     *
     * @param string $type Credential type
     * @return bool Success status
     */
    public static function deleteCredential(string $type): bool
    {
        return SecureConfigManager::deleteSecureConfig('credential_' . $type);
    }

    /**
     * Check if credential exists
     *
     * @param string $type Credential type
     * @return bool
     */
    public static function hasCredential(string $type): bool
    {
        return SecureConfigManager::hasSecureConfig('credential_' . $type);
    }

    /**
     * Get credential metadata
     *
     * @param string $type Credential type
     * @return array|null Metadata or null
     */
    public static function getCredentialMetadata(string $type): ?array
    {
        $credentialData = SecureConfigManager::getSecureConfig('credential_' . $type);

        if (!$credentialData) {
            return null;
        }

        return [
            'created_at' => $credentialData['created_at'] ?? null,
            'created_by' => $credentialData['created_by'] ?? null,
            'last_used' => $credentialData['last_used'] ?? null,
            'use_count' => $credentialData['use_count'] ?? 0,
            'metadata' => $credentialData['metadata'] ?? []
        ];
    }

    /**
     * List all credential types that are stored
     *
     * @return array List of credential types
     */
    public static function listCredentials(): array
    {
        global $wpdb;

        $results = $wpdb->get_results($wpdb->prepare(
            "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
            'wp_security_monitor_secure_credential_%'
        ));

        $credentials = [];
        foreach ($results as $result) {
            $key = str_replace('wp_security_monitor_secure_credential_', '', $result->option_name);
            $metadata = self::getCredentialMetadata($key);

            if ($metadata) {
                $credentials[$key] = $metadata;
            }
        }

        return $credentials;
    }

    /**
     * Validate credential format
     *
     * @param string $type Credential type
     * @param mixed $value Credential value
     * @return array Validation result
     */
    public static function validateCredential(string $type, $value): array
    {
        $result = [
            'valid' => false,
            'errors' => [],
            'warnings' => [],
            'suggestions' => []
        ];

        switch ($type) {
            case self::TYPE_TELEGRAM_TOKEN:
                $result = self::validateTelegramToken($value);
                break;

            case self::TYPE_TELEGRAM_CHAT_ID:
                $result = self::validateTelegramChatId($value);
                break;

            case self::TYPE_SLACK_WEBHOOK:
                $result = self::validateSlackWebhook($value);
                break;

            case self::TYPE_EMAIL_SMTP:
                $result = self::validateEmailSmtp($value);
                break;

            default:
                $result['valid'] = true; // Unknown types pass through
                $result['warnings'][] = 'Unknown credential type - no validation performed';
        }

        return $result;
    }

    /**
     * Validate Telegram bot token
     *
     * @param string $token Token to validate
     * @return array Validation result
     */
    private static function validateTelegramToken($token): array
    {
        $result = ['valid' => false, 'errors' => [], 'warnings' => [], 'suggestions' => []];

        if (!is_string($token)) {
            $result['errors'][] = 'Token must be a string';
            return $result;
        }

        // Basic format check: BOT_ID:BOT_TOKEN
        if (!preg_match('/^\d+:[A-Za-z0-9_-]{35}$/', $token)) {
            $result['errors'][] = 'Invalid Telegram token format. Expected format: 123456789:ABCdefGHIjklMNOpqrsTUVwxyz';
            return $result;
        }

        // Extract bot ID
        $parts = explode(':', $token);
        $botId = $parts[0];

        if (strlen($botId) < 8) {
            $result['warnings'][] = 'Bot ID seems unusually short';
        }

        $result['valid'] = true;
        $result['suggestions'][] = 'Token format is valid. Test connection to verify functionality.';

        return $result;
    }

    /**
     * Validate Telegram chat ID
     *
     * @param mixed $chatId Chat ID to validate
     * @return array Validation result
     */
    private static function validateTelegramChatId($chatId): array
    {
        $result = ['valid' => false, 'errors' => [], 'warnings' => [], 'suggestions' => []];

        if (!is_string($chatId) && !is_numeric($chatId)) {
            $result['errors'][] = 'Chat ID must be a string or number';
            return $result;
        }

        $chatId = (string) $chatId;

        // Can be positive (user/bot) or negative (group/channel)
        if (!preg_match('/^-?\d+$/', $chatId)) {
            $result['errors'][] = 'Chat ID must be numeric';
            return $result;
        }

        if (strlen($chatId) < 3) {
            $result['warnings'][] = 'Chat ID seems unusually short';
        }

        if (strpos($chatId, '-100') === 0) {
            $result['suggestions'][] = 'This appears to be a supergroup or channel ID';
        } elseif (strpos($chatId, '-') === 0) {
            $result['suggestions'][] = 'This appears to be a group chat ID';
        } else {
            $result['suggestions'][] = 'This appears to be a private chat or bot ID';
        }

        $result['valid'] = true;

        return $result;
    }

    /**
     * Validate Slack webhook URL
     *
     * @param string $url Webhook URL to validate
     * @return array Validation result
     */
    private static function validateSlackWebhook($url): array
    {
        $result = ['valid' => false, 'errors' => [], 'warnings' => [], 'suggestions' => []];

        if (!is_string($url)) {
            $result['errors'][] = 'Webhook URL must be a string';
            return $result;
        }

        // Basic URL validation
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            $result['errors'][] = 'Invalid URL format';
            return $result;
        }

        // Must be HTTPS
        if (strpos($url, 'https://') !== 0) {
            $result['errors'][] = 'Slack webhook URL must use HTTPS';
            return $result;
        }

        // Must be hooks.slack.com
        if (strpos($url, 'hooks.slack.com') === false) {
            $result['warnings'][] = 'URL does not appear to be from hooks.slack.com';
        }

        // Check for webhook path pattern
        if (!preg_match('/\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[A-Za-z0-9]+/', $url)) {
            $result['warnings'][] = 'URL does not match typical Slack webhook pattern';
        }

        $result['valid'] = true;
        $result['suggestions'][] = 'URL format appears valid. Test webhook to verify functionality.';

        return $result;
    }

    /**
     * Validate email SMTP configuration
     *
     * @param array $config SMTP configuration
     * @return array Validation result
     */
    private static function validateEmailSmtp($config): array
    {
        $result = ['valid' => false, 'errors' => [], 'warnings' => [], 'suggestions' => []];

        if (!is_array($config)) {
            $result['errors'][] = 'SMTP config must be an array';
            return $result;
        }

        $required = ['host', 'port', 'username', 'password'];
        foreach ($required as $field) {
            if (empty($config[$field])) {
                $result['errors'][] = "Missing required field: {$field}";
            }
        }

        if (!empty($result['errors'])) {
            return $result;
        }

        // Validate port
        $port = (int) $config['port'];
        if ($port < 1 || $port > 65535) {
            $result['errors'][] = 'Invalid port number';
            return $result;
        }

        // Common SMTP ports
        $commonPorts = [25, 587, 465, 2525];
        if (!in_array($port, $commonPorts)) {
            $result['warnings'][] = 'Unusual SMTP port. Common ports are: ' . implode(', ', $commonPorts);
        }

        // Validate email format
        if (!filter_var($config['username'], FILTER_VALIDATE_EMAIL)) {
            $result['warnings'][] = 'Username is not a valid email address';
        }

        $result['valid'] = true;
        $result['suggestions'][] = 'SMTP configuration appears valid. Test connection to verify.';

        return $result;
    }

    /**
     * Migrate existing credentials to secure storage
     *
     * @return array Migration results
     */
    public static function migrateExistingCredentials(): array
    {
        $migrations = [
            'telegram_token' => 'wp_security_monitor_telegram_token',
            'telegram_chat_id' => 'wp_security_monitor_telegram_chat_id',
            'slack_webhook_url' => 'wp_security_monitor_slack_webhook_url',
            'email_config' => 'wp_security_monitor_email_config'
        ];

        $results = [];

        foreach ($migrations as $newKey => $oldKey) {
            $oldValue = get_option($oldKey);

            if ($oldValue !== false && !empty($oldValue)) {
                if (self::setCredential($newKey, $oldValue, ['migrated_from' => $oldKey])) {
                    delete_option($oldKey);
                    $results[$newKey] = 'migrated';
                } else {
                    $results[$newKey] = 'failed';
                }
            } else {
                $results[$newKey] = 'not_found';
            }
        }

        return $results;
    }

    /**
     * Test credential functionality
     *
     * @param string $type Credential type
     * @return array Test results
     */
    public static function testCredential(string $type): array
    {
        $result = ['success' => false, 'message' => '', 'details' => []];

        switch ($type) {
            case self::TYPE_TELEGRAM_TOKEN:
                $result = self::testTelegramCredentials();
                break;

            case self::TYPE_SLACK_WEBHOOK:
                $result = self::testSlackCredentials();
                break;

            default:
                $result['message'] = 'Testing not implemented for this credential type';
        }

        return $result;
    }

    /**
     * Test Telegram credentials
     *
     * @return array Test results
     */
    private static function testTelegramCredentials(): array
    {
        $token = self::getCredential(self::TYPE_TELEGRAM_TOKEN, false);

        if (!$token) {
            return ['success' => false, 'message' => 'No Telegram token configured'];
        }

        try {
            $url = "https://api.telegram.org/bot{$token}/getMe";
            $response = wp_remote_get($url, ['timeout' => 10]);

            if (is_wp_error($response)) {
                return ['success' => false, 'message' => 'Connection error: ' . $response->get_error_message()];
            }

            $body = json_decode(wp_remote_retrieve_body($response), true);

            if (!$body['ok']) {
                return ['success' => false, 'message' => 'API error: ' . ($body['description'] ?? 'Unknown error')];
            }

            return [
                'success' => true,
                'message' => 'Telegram bot connection successful',
                'details' => [
                    'bot_name' => $body['result']['first_name'] ?? 'Unknown',
                    'bot_username' => $body['result']['username'] ?? 'Unknown'
                ]
            ];

        } catch (\Exception $e) {
            return ['success' => false, 'message' => 'Test failed: ' . $e->getMessage()];
        }
    }

    /**
     * Test Slack credentials
     *
     * @return array Test results
     */
    private static function testSlackCredentials(): array
    {
        $webhook = self::getCredential(self::TYPE_SLACK_WEBHOOK, false);

        if (!$webhook) {
            return ['success' => false, 'message' => 'No Slack webhook configured'];
        }

        try {
            $testMessage = [
                'text' => '🔒 WP Security Monitor - Credential Test',
                'attachments' => [
                    [
                        'color' => 'good',
                        'text' => 'Slack integration is working correctly!',
                        'footer' => 'WP Security Monitor',
                        'ts' => time()
                    ]
                ]
            ];

            $response = wp_remote_post($webhook, [
                'body' => json_encode($testMessage),
                'headers' => ['Content-Type' => 'application/json'],
                'timeout' => 10
            ]);

            if (is_wp_error($response)) {
                return ['success' => false, 'message' => 'Connection error: ' . $response->get_error_message()];
            }

            $statusCode = wp_remote_retrieve_response_code($response);

            if ($statusCode === 200) {
                return ['success' => true, 'message' => 'Slack webhook test successful'];
            } else {
                return ['success' => false, 'message' => "Slack responded with status code: {$statusCode}"];
            }

        } catch (\Exception $e) {
            return ['success' => false, 'message' => 'Test failed: ' . $e->getMessage()];
        }
    }
}
