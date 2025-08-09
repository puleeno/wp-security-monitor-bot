<?php

namespace Puleeno\SecurityBot\WebMonitor\Security;

/**
 * Secure Configuration Manager
 *
 * Quản lý việc mã hóa và bảo mật các thông tin nhạy cảm trong plugin
 * - API tokens (Telegram, Slack)
 * - Webhook URLs
 * - Database credentials
 * - Sensitive configuration data
 *
 * Sử dụng WordPress salts và custom encryption để bảo vệ data
 */
class SecureConfigManager
{
    /**
     * Encryption method
     */
    private const ENCRYPTION_METHOD = 'AES-256-CBC';

    /**
     * Configuration option key prefix
     */
    private const CONFIG_PREFIX = 'wp_security_monitor_secure_';

    /**
     * Encryption key cache
     */
    private static $encryptionKey = null;

    /**
     * Salt cache
     */
    private static $cryptoSalt = null;

    /**
     * Get encryption key derived from WordPress salts
     *
     * @return string
     */
    private static function getEncryptionKey(): string
    {
        if (self::$encryptionKey === null) {
            // Combine multiple WordPress salts for stronger entropy
            $saltBase = AUTH_KEY . SECURE_AUTH_KEY . LOGGED_IN_KEY . NONCE_KEY;
            $saltExtra = AUTH_SALT . SECURE_AUTH_SALT . LOGGED_IN_SALT . NONCE_SALT;

            // Add plugin-specific entropy
            $pluginSalt = get_option('wp_security_monitor_plugin_salt', '');
            if (empty($pluginSalt)) {
                $pluginSalt = wp_generate_password(64, true, true);
                add_option('wp_security_monitor_plugin_salt', $pluginSalt, '', false);
            }

            // Create final encryption key
            self::$encryptionKey = hash('sha256', $saltBase . $saltExtra . $pluginSalt);
        }

        return self::$encryptionKey;
    }

    /**
     * Get crypto salt for additional security
     *
     * @return string
     */
    private static function getCryptoSalt(): string
    {
        if (self::$cryptoSalt === null) {
            $salt = get_option('wp_security_monitor_crypto_salt', '');
            if (empty($salt)) {
                $salt = wp_generate_password(32, true, true);
                add_option('wp_security_monitor_crypto_salt', $salt, '', false);
            }
            self::$cryptoSalt = $salt;
        }

        return self::$cryptoSalt;
    }

    /**
     * Encrypt sensitive data
     *
     * @param string $data Data to encrypt
     * @return string Encrypted data (base64 encoded)
     */
    public static function encrypt(string $data): string
    {
        if (empty($data)) {
            return '';
        }

        $key = self::getEncryptionKey();
        $salt = self::getCryptoSalt();

        // Generate random IV
        $ivLength = openssl_cipher_iv_length(self::ENCRYPTION_METHOD);
        $iv = openssl_random_pseudo_bytes($ivLength);

        // Add salt to data for additional security
        $saltedData = $salt . '::' . $data;

        // Encrypt
        $encrypted = openssl_encrypt($saltedData, self::ENCRYPTION_METHOD, $key, 0, $iv);

        if ($encrypted === false) {
            throw new \Exception('Encryption failed');
        }

        // Combine IV and encrypted data - both need separate base64 encoding
        $result = base64_encode($iv) . '::' . base64_encode($encrypted);

        return $result;
    }

    /**
     * Decrypt sensitive data
     *
     * @param string $encryptedData Encrypted data (base64 encoded)
     * @return string Decrypted data
     */
    public static function decrypt(string $encryptedData): string
    {
        if (empty($encryptedData)) {
            return '';
        }

        try {
            $key = self::getEncryptionKey();
            $salt = self::getCryptoSalt();

            // Split IV and encrypted data (both are base64 encoded)
            $parts = explode('::', $encryptedData, 2);
            if (count($parts) !== 2) {
                throw new \Exception('Invalid encrypted data format');
            }

            // Decode IV and encrypted data separately
            $iv = base64_decode($parts[0]);
            $encrypted = base64_decode($parts[1]);

            if ($iv === false || $encrypted === false) {
                throw new \Exception('Invalid base64 data');
            }

            // Decrypt
            $decrypted = openssl_decrypt($encrypted, self::ENCRYPTION_METHOD, $key, 0, $iv);

            if ($decrypted === false) {
                throw new \Exception('Decryption failed');
            }

            // Remove salt
            $saltedParts = explode('::', $decrypted, 2);
            if (count($saltedParts) !== 2 || $saltedParts[0] !== $salt) {
                throw new \Exception('Invalid salt verification');
            }

            return $saltedParts[1];

        } catch (\Exception $e) {
            error_log('[WP Security Monitor] Decryption error: ' . $e->getMessage());

            // If decryption fails due to format change, clear the corrupted data
            if (strpos($e->getMessage(), 'IV passed is only') !== false) {
                self::clearCorruptedData();
            }

            return '';
        }
    }

    /**
     * Clear all corrupted encrypted data (format migration)
     *
     * @return void
     */
    public static function clearCorruptedData(): void
    {
        $encryptedOptions = [
            'wp_security_monitor_secure_credential_telegram_token',
            'wp_security_monitor_secure_credential_telegram_chat_id',
            'wp_security_monitor_secure_credential_slack_webhook'
        ];

        foreach ($encryptedOptions as $optionName) {
            delete_option($optionName);
        }

        if (WP_DEBUG) {
            error_log('[WP Security Monitor] Cleared corrupted encrypted data due to format change');
        }
    }

    /**
     * Store encrypted configuration
     *
     * @param string $key Configuration key
     * @param mixed $value Value to store
     * @return bool Success status
     */
    public static function setSecureConfig(string $key, $value): bool
    {
        $serialized = serialize($value);
        $encrypted = self::encrypt($serialized);

        return update_option(self::CONFIG_PREFIX . $key, $encrypted);
    }

    /**
     * Retrieve and decrypt configuration
     *
     * @param string $key Configuration key
     * @param mixed $default Default value if not found
     * @return mixed Decrypted value
     */
    public static function getSecureConfig(string $key, $default = null)
    {
        $encrypted = get_option(self::CONFIG_PREFIX . $key, '');

        if (empty($encrypted)) {
            return $default;
        }

        $decrypted = self::decrypt($encrypted);

        if (empty($decrypted)) {
            return $default;
        }

        $value = unserialize($decrypted);

        return $value !== false ? $value : $default;
    }

    /**
     * Delete secure configuration
     *
     * @param string $key Configuration key
     * @return bool Success status
     */
    public static function deleteSecureConfig(string $key): bool
    {
        return delete_option(self::CONFIG_PREFIX . $key);
    }

    /**
     * Check if secure config exists
     *
     * @param string $key Configuration key
     * @return bool
     */
    public static function hasSecureConfig(string $key): bool
    {
        $encrypted = get_option(self::CONFIG_PREFIX . $key, false);
        return $encrypted !== false && !empty($encrypted);
    }

    /**
     * Migrate existing plain config to secure config
     *
     * @param string $oldKey Old option key
     * @param string $newKey New secure key
     * @return bool Success status
     */
    public static function migrateToSecure(string $oldKey, string $newKey): bool
    {
        $oldValue = get_option($oldKey);

        if ($oldValue === false) {
            return false;
        }

        // Store securely
        $success = self::setSecureConfig($newKey, $oldValue);

        if ($success) {
            // Remove old plain option
            delete_option($oldKey);
        }

        return $success;
    }

    /**
     * Validate encryption capability
     *
     * @return array Validation results
     */
    public static function validateEncryption(): array
    {
        $results = [
            'openssl_available' => function_exists('openssl_encrypt'),
            'cipher_available' => in_array(self::ENCRYPTION_METHOD, openssl_get_cipher_methods()),
            'wp_salts_defined' => defined('AUTH_KEY') && !empty(AUTH_KEY),
            'encryption_test' => false,
            'performance_test' => null
        ];

        // Test encryption/decryption
        if ($results['openssl_available'] && $results['cipher_available']) {
            try {
                $testData = 'test_encryption_' . wp_generate_password(32, true, true);
                $encrypted = self::encrypt($testData);
                $decrypted = self::decrypt($encrypted);

                $results['encryption_test'] = ($testData === $decrypted);

                // Performance test
                $start = microtime(true);
                for ($i = 0; $i < 100; $i++) {
                    $testEncrypt = self::encrypt('performance_test_data_' . $i);
                    self::decrypt($testEncrypt);
                }
                $end = microtime(true);

                $results['performance_test'] = round(($end - $start) * 1000, 2); // ms

            } catch (\Exception $e) {
                $results['encryption_test'] = false;
                $results['error'] = $e->getMessage();
            }
        }

        return $results;
    }

    /**
     * Get security status
     *
     * @return array Security status information
     */
    public static function getSecurityStatus(): array
    {
        $validation = self::validateEncryption();

        return [
            'encryption_ready' => $validation['encryption_test'],
            'security_level' => self::getSecurityLevel(),
            'protected_configs' => self::getProtectedConfigsList(),
            'last_key_rotation' => get_option('wp_security_monitor_last_key_rotation', 'Never'),
            'encryption_performance' => $validation['performance_test'] ?? 'N/A'
        ];
    }

    /**
     * Determine security level based on configuration
     *
     * @return string Security level
     */
    private static function getSecurityLevel(): string
    {
        $validation = self::validateEncryption();

        if (!$validation['encryption_test']) {
            return 'LOW - Encryption not available';
        }

        $hasCustomSalts = (AUTH_KEY !== 'put your unique phrase here');
        $hasAllSalts = defined('AUTH_KEY') && defined('SECURE_AUTH_KEY') &&
                      defined('LOGGED_IN_KEY') && defined('NONCE_KEY') &&
                      defined('AUTH_SALT') && defined('SECURE_AUTH_SALT') &&
                      defined('LOGGED_IN_SALT') && defined('NONCE_SALT');

        if ($hasAllSalts && $hasCustomSalts) {
            return 'HIGH - All salts configured';
        } elseif ($hasAllSalts) {
            return 'MEDIUM - Default salts detected';
        } else {
            return 'LOW - Missing WordPress salts';
        }
    }

    /**
     * Get list of protected configurations
     *
     * @return array List of protected config keys
     */
    private static function getProtectedConfigsList(): array
    {
        global $wpdb;

        $results = $wpdb->get_results($wpdb->prepare(
            "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
            self::CONFIG_PREFIX . '%'
        ));

        $configs = [];
        foreach ($results as $result) {
            $key = str_replace(self::CONFIG_PREFIX, '', $result->option_name);
            $configs[] = $key;
        }

        return $configs;
    }

    /**
     * Rotate encryption keys (emergency function)
     *
     * @return bool Success status
     */
    public static function rotateKeys(): bool
    {
        try {
            // Get all current secure configs
            $protectedConfigs = self::getProtectedConfigsList();
            $backupData = [];

            // Backup all data với current key
            foreach ($protectedConfigs as $key) {
                $backupData[$key] = self::getSecureConfig($key);
            }

            // Generate new salts
            update_option('wp_security_monitor_plugin_salt', wp_generate_password(64, true, true));
            update_option('wp_security_monitor_crypto_salt', wp_generate_password(32, true, true));

            // Clear key cache
            self::$encryptionKey = null;
            self::$cryptoSalt = null;

            // Re-encrypt all data với new keys
            foreach ($backupData as $key => $value) {
                self::setSecureConfig($key, $value);
            }

            // Record rotation time
            update_option('wp_security_monitor_last_key_rotation', current_time('mysql'));

            return true;

        } catch (\Exception $e) {
            error_log('[WP Security Monitor] Key rotation failed: ' . $e->getMessage());
            return false;
        }
    }
}
