<?php

/**
 * Plugin Name: Web Monitor Bot
 * Author: Puleeno Nguyen
 * Description: Create BOT to monitor the WordPress websites of my clients
 * Author URI: https://puleeno.com
 * Version: 1.0.0
 */

if (!class_exists('WP_Security_Monitor_Bot')) {
    class WP_Security_Monitor_Bot
    {
        protected static $instance;

        protected function __construct()
        {
            $this->loadComposer();
        }

        public static function getInstance()
        {
            if (is_null(static::$instance)) {
                static::$instance = new static();
            }
            return static::$instance;
        }

        public function loadComposer()
        {
            $autloader = sprintf('%s/vendor/autoload.php', dirname(__FILE__));
            if (file_exists($autloader)) {
                require_once $autloader;
            }
        }
    }

    WP_Security_Monitor_Bot::getInstance();
}
