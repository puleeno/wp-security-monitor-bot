<?php
/**
 * Issuer Registry
 * Manages security issue detection monitors
 */

namespace Puleeno\SecurityBot\WebMonitor\Issuers;

if (!defined('ABSPATH')) {
    exit;
}

class IssuerRegistry
{
    /**
     * @var IssuerInterface[] Registered issuers
     */
    private array $issuers = [];

    /**
     * Register an issuer
     */
    public function register(IssuerInterface $issuer): void
    {
        $this->issuers[$issuer->getName()] = $issuer;
    }

    /**
     * Get all registered issuers
     *
     * @return IssuerInterface[]
     */
    public function getAll(): array
    {
        return $this->issuers;
    }

    /**
     * Get issuer by name
     */
    public function get(string $name): ?IssuerInterface
    {
        return $this->issuers[$name] ?? null;
    }

    /**
     * Run checks on all SCAN type issuers
     *
     * @return array Found issues
     */
    public function runChecks(): array
    {
        $issues = [];

        foreach ($this->issuers as $issuer) {
            if ($issuer->getType() === \Puleeno\SecurityBot\WebMonitor\Enums\IssuerType::SCAN) {
                $issuer->check();
            }
        }

        return $issues;
    }

    /**
     * Check if issuer is registered
     */
    public function has(string $name): bool
    {
        return isset($this->issuers[$name]);
    }
}

