<?php

/**
 * Plugin Name: Web Monitor Bot
 * Author: Puleeno Nguyen
 * Author URI: https://puleeno.com
 * Version: 1.0.0
 */

class Puleeno_Web_Monitor_Bot {
    protected static $loaded = false;

    protected function __construct()
    {
    }

    public static function getInstance() {
        if (static::$loaded) {
            return;
        }

        // Bootstrap here
    }
}

Puleeno_Web_Monitor_Bot::getInstance();
