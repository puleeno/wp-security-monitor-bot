<?php

namespace Puleeno\SecurityBot\WebMonitor\Enums;

/**
 * IssuerType - Classification của security issuers
 */
class IssuerType
{
    /**
     * TRIGGER Issuers - React to events in real-time
     *
     * Characteristics:
     * - Hooked vào WordPress events/actions
     * - Detect khi có người "bóp cò" (trigger action)
     * - Real-time detection
     * - Full backtrace cần thiết để trace tác nhân
     */
    const TRIGGER = 'trigger';

    /**
     * SCAN Issuers - Proactively scan for threats
     *
     * Characteristics:
     * - Scheduled scanning (cron-based)
     * - Tìm kiếm threats đã tồn tại
     * - Background processing
     * - Backtrace ít relevant (scan context)
     */
    const SCAN = 'scan';

    /**
     * HYBRID Issuers - Both trigger detection + validation scanning
     *
     * Characteristics:
     * - Trigger on events THEN validate through scanning
     * - Context-dependent backtrace needs
     */
    const HYBRID = 'hybrid';

    /**
     * Get issuer type classifications
     */
    public static function getClassifications(): array
    {
        return [
            // TRIGGER Issuers - Real-time event detection
            'SQLInjectionAttemptIssuer' => [
                'type' => self::TRIGGER,
                'description' => 'Detects SQL injection attempts in real-time HTTP requests',
                'backtrace_importance' => 'critical',
                'context_needs' => ['user_agent', 'ip_address', 'request_params', 'call_stack']
            ],

            'FunctionOverrideIssuer' => [
                'type' => self::TRIGGER,
                'description' => 'Intercepts dangerous function calls as they happen',
                'backtrace_importance' => 'critical',
                'context_needs' => ['call_stack', 'function_args', 'plugin_source']
            ],

            'LoginAttemptIssuer' => [
                'type' => self::TRIGGER,
                'description' => 'Monitors login attempts as they occur',
                'backtrace_importance' => 'medium',
                'context_needs' => ['ip_address', 'user_agent', 'timing_patterns']
            ],

            'AdminUserCreatedIssuer' => [
                'type' => self::TRIGGER,
                'description' => 'Detects admin user creation/role changes in real-time',
                'backtrace_importance' => 'high',
                'context_needs' => ['current_user', 'admin_context', 'call_stack']
            ],

            'AdminActivityIssuer' => [
                'type' => self::TRIGGER,
                'description' => 'Logs administrative activities (login, plugins, themes, widgets, files)',
                'backtrace_importance' => 'low',
                'context_needs' => ['user', 'ip', 'action_details']
            ],

            // SCAN Issuers - Background threat hunting
            'BackdoorDetectionIssuer' => [
                'type' => self::SCAN,
                'description' => 'Scans files for known backdoor patterns',
                'backtrace_importance' => 'low',
                'context_needs' => ['scan_context', 'file_metadata', 'detection_patterns']
            ],

            'EvalFunctionIssuer' => [
                'type' => self::SCAN,
                'description' => 'Scans code for dangerous eval() usage',
                'backtrace_importance' => 'low',
                'context_needs' => ['file_location', 'code_patterns', 'scan_scope']
            ],

            'FileChangeIssuer' => [
                'type' => self::SCAN,
                'description' => 'Scans for file system modifications',
                'backtrace_importance' => 'low',
                'context_needs' => ['file_metadata', 'change_detection', 'scan_timing']
            ],


            // HYBRID Issuers - Event-triggered + validation scanning
            'ExternalRedirectIssuer' => [
                'type' => self::HYBRID,
                'description' => 'Detects redirects in real-time + validates through scanning',
                'backtrace_importance' => 'high',
                'context_needs' => ['trigger_context', 'validation_results', 'domain_info']
            ]
        ];
    }

    /**
     * Get issuer type by class name
     */
    public static function getIssuerType(string $className): string
    {
        $classifications = self::getClassifications();
        $shortClassName = basename(str_replace('\\', '/', $className));

        return $classifications[$shortClassName]['type'] ?? self::SCAN;
    }

    /**
     * Check if issuer needs full backtrace
     */
    public static function needsFullBacktrace(string $className): bool
    {
        $classifications = self::getClassifications();
        $shortClassName = basename(str_replace('\\', '/', $className));

        $importance = $classifications[$shortClassName]['backtrace_importance'] ?? 'low';

        return in_array($importance, ['critical', 'high']);
    }

    /**
     * Get context needs for issuer
     */
    public static function getContextNeeds(string $className): array
    {
        $classifications = self::getClassifications();
        $shortClassName = basename(str_replace('\\', '/', $className));

        return $classifications[$shortClassName]['context_needs'] ?? ['basic_context'];
    }

    /**
     * Get all trigger issuers
     */
    public static function getTriggerIssuers(): array
    {
        $classifications = self::getClassifications();
        $triggerIssuers = [];

        foreach ($classifications as $className => $info) {
            if ($info['type'] === self::TRIGGER) {
                $triggerIssuers[] = $className;
            }
        }

        return $triggerIssuers;
    }

    /**
     * Get all scan issuers
     */
    public static function getScanIssuers(): array
    {
        $classifications = self::getClassifications();
        $scanIssuers = [];

        foreach ($classifications as $className => $info) {
            if ($info['type'] === self::SCAN) {
                $scanIssuers[] = $className;
            }
        }

        return $scanIssuers;
    }
}
