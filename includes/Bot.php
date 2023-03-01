<?php
namespace Puleeno\Bot\WebMonitor;

class Bot
{
    protected static $instance;

    /**
     * @var \Puleeno\Bot\WebMonitor\Interfaces\ChannelInterface[]
     */
    protected $channels = [];

    protected function __construct()
    {
    }

    public static function getInstance()
    {
        if (is_null(static::$instance)) {
            static::$instance = new static();
        }
        return static::$instance;
    }
}
