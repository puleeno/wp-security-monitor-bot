# WP Security Monitor Bot - Features Documentation

## 📋 **Table of Contents**

1. [Issue Management System](#issue-management-system)
2. [Smart Whitelist Management](#smart-whitelist-management)
3. [Security Issuers](#security-issuers)
4. [Notification Channels](#notification-channels)
5. [Advanced Debug System](#advanced-debug-system)
6. [Admin Dashboard](#admin-dashboard)
7. [Configuration Management](#configuration-management)

---

## 🎯 **Issue Management System**

### **Core Features**

#### **Database-Driven Tracking**
- **Persistent Storage**: Tất cả issues được lưu vào database với metadata đầy đủ
- **Hash-based Deduplication**: Tránh duplicate issues với unique hash generation
- **Status Workflow**: `new` → `investigating` → `resolved`/`ignored`/`false_positive`
- **Severity Classification**: Auto-detect từ `low` → `critical`

#### **Advanced Filtering & Search**
```php
$args = [
    'status' => 'new',
    'severity' => 'high', 
    'issuer' => 'External Redirect Monitor',
    'search' => 'malware',
    'per_page' => 20,
    'page' => 1
];
$results = $issueManager->getIssues($args);
```

#### **Issue Resolution Workflow**
1. **Detection**: Issue được phát hiện và save vào DB
2. **Review**: Admin xem chi tiết trong dashboard
3. **Action**: Ignore, Resolve, hoặc Create ignore rule
4. **Audit**: Track who did what và khi nào

### **Database Schema**

#### **Issues Table**
```sql
CREATE TABLE wp_security_monitor_issues (
    id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    issue_hash varchar(32) NOT NULL UNIQUE,
    issuer_name varchar(100) NOT NULL,
    issue_type varchar(50) NOT NULL,
    severity enum('low','medium','high','critical') DEFAULT 'medium',
    status enum('new','investigating','resolved','ignored','false_positive') DEFAULT 'new',
    title varchar(255) NOT NULL,
    description text,
    details longtext,
    debug_info longtext,
    first_detected datetime NOT NULL,
    last_detected datetime NOT NULL,
    detection_count int(11) DEFAULT 1,
    -- Additional metadata fields
    PRIMARY KEY (id),
    KEY idx_issuer_name (issuer_name),
    KEY idx_severity (severity),
    KEY idx_status (status)
);
```

### **Usage Examples**

#### **Record New Issue**
```php
$issueManager = IssueManager::getInstance();

$issueData = [
    'message' => 'Suspicious redirect detected',
    'details' => 'Redirect to external domain: example.com',
    'type' => 'external_redirect',
    'domain' => 'example.com',
    'source_file' => '.htaccess'
];

$issueId = $issueManager->recordIssue('External Redirect Monitor', $issueData);
```

#### **Ignore Issue với Reason**
```php
$issueManager->ignoreIssue(123, 'False positive - legitimate CDN redirect');
```

#### **Resolve Issue với Notes**
```php
$issueManager->resolveIssue(123, 'Fixed by removing malicious redirect from .htaccess');
```

---

## 🎯 **Smart Whitelist Management**

### **Core Concept**

Smart Whitelist System tự động học từ admin feedback để giảm false positives cho external redirects.

### **Learning Workflow**

#### **Phase 1: Discovery**
```
Redirect to example.com detected
↓
Create issue + Add to pending domains
↓
Send notification to admin
```

#### **Phase 2: Confirmation** 
```
Same redirect detected again
↓
Increase detection count
↓
Still create issue (admin chưa decide)
```

#### **Phase 3: Learning**
```
Admin review pending domain
↓
Approve → Add to whitelist
Reject → Mark as rejected
```

#### **Phase 4: Automation**
```
Future redirects to approved domain
↓
Auto-skip issue creation
↓
Only record usage statistics
```

### **WhitelistManager API**

#### **Check Domain Status**
```php
$whitelistManager = WhitelistManager::getInstance();

// Check if domain is whitelisted
if ($whitelistManager->isDomainWhitelisted('example.com')) {
    // Skip issue creation
    $whitelistManager->recordDomainUsage('example.com');
    return;
}
```

#### **Add Domain to Whitelist**
```php
$whitelistManager->addToWhitelist(
    'example.com', 
    'Legitimate CDN for our services',
    $userId
);
```

#### **Manage Pending Domains**
```php
// Add domain for review
$whitelistManager->addPendingDomain('suspicious.com', [
    'source' => '.htaccess',
    'redirect_url' => 'https://suspicious.com/malware',
    'pattern' => 'RewriteRule .* https://suspicious.com/malware [R=301,L]'
]);

// Approve pending domain
$whitelistManager->approvePendingDomain('suspicious.com', 'Actually legitimate after investigation');

// Reject pending domain
$whitelistManager->rejectPendingDomain('suspicious.com', 'Confirmed malicious redirect');
```

### **Advanced Features**

#### **Wildcard Support**
```php
// Support wildcard domains
$whitelistManager->addToWhitelist('*.cdn.example.com', 'All CDN subdomains');
```

#### **Bulk Operations**
```php
$domains = ['example.com', 'cdn.example.com', 'api.example.com'];
$results = $whitelistManager->bulkImportDomains($domains, 'Company domains');
```

#### **Export/Import**
```php
// Export to CSV
$csv = $whitelistManager->exportDomains('csv');

// Export to JSON
$json = $whitelistManager->exportDomains('json');
```

---

## 🔍 **Security Issuers**

### **1. External Redirect Issuer**

#### **Detection Capabilities**
- **.htaccess Analysis**: Parse redirect rules và rewrite conditions
- **Database Scanning**: Check WordPress options cho external URLs
- **JavaScript Detection**: Tìm client-side redirects trong post content
- **PHP Code Analysis**: Scan files cho suspicious redirect patterns
- **Hook Monitoring**: Check WordPress hooks cho malicious callbacks

#### **Smart Whitelist Integration**
```php
// Example detection with whitelist check
private function checkHtaccessRedirects(): array
{
    // ... scan .htaccess for redirects
    foreach ($matches as $match) {
        $domain = $this->whitelistManager->extractDomain($redirectUrl);
        
        if ($domain && !$this->shouldIgnoreDomain($domain)) {
            // Create issue + track domain
            $this->trackDomainForWhitelist($domain, $context);
            return $this->createIssue($redirectUrl);
        }
    }
}
```

#### **Configuration Options**
```php
$config = [
    'check_htaccess' => true,
    'check_database' => true,
    'check_php_files' => true,
    'max_files_scan' => 100,
    'scan_depth' => 3
];
```

### **2. Login Attempt Issuer**

#### **Detection Features**
- **Failed Login Tracking**: Monitor failed login attempts per IP/username
- **Brute Force Detection**: Identify coordinated attacks
- **Multiple IP Analysis**: Detect admin logins từ suspicious locations
- **Off-hours Monitoring**: Alert cho logins ngoài business hours

#### **Implementation Example**
```php
public function recordFailedLogin(string $username): void
{
    $ip = $this->getUserIP();
    $attempts = get_option($this->optionKey, []);
    
    $key = md5($ip . $username);
    $attempts[$key] = [
        'username' => $username,
        'ip' => $ip,
        'attempts' => array_merge($attempts[$key]['attempts'] ?? [], [time()]),
        'total_attempts' => ($attempts[$key]['total_attempts'] ?? 0) + 1
    ];
    
    update_option($this->optionKey, $attempts);
}
```

#### **Detection Thresholds**
```php
$config = [
    'failed_login_threshold' => 5,      // 5 attempts
    'failed_login_time_window' => 900,  // in 15 minutes
    'brute_force_threshold' => 20,      // 20 total attempts
    'office_hours' => [9, 18]           // 9 AM to 6 PM
];
```

### **3. File Change Issuer**

#### **Monitoring Capabilities**
- **WordPress Core Files**: Monitor changes to critical WP files
- **Plugin Files**: Track active plugin modifications  
- **Theme Files**: Watch current theme files
- **Critical Files**: Special monitoring for wp-config.php, .htaccess

#### **Hash-based Detection**
```php
private function checkFileChanges(string $filePath, string $category): array
{
    $currentHash = md5_file($filePath);
    $storedHashes = get_option($this->optionKey, []);
    $fileKey = md5($filePath);
    
    if (isset($storedHashes[$fileKey])) {
        if ($storedHashes[$fileKey]['hash'] !== $currentHash) {
            return $this->createFileChangeIssue($filePath, $category);
        }
    }
    
    // Store hash for next check
    $storedHashes[$fileKey] = [
        'hash' => $currentHash,
        'size' => filesize($filePath),
        'modified' => filemtime($filePath)
    ];
    
    update_option($this->optionKey, $storedHashes);
    return [];
}
```

---

## 📨 **Notification Channels**

### **1. Telegram Channel**

#### **Features**
- **Markdown Support**: Rich formatting cho messages
- **Real-time Delivery**: Instant notifications
- **Bot Integration**: Sử dụng Telegram Bot API
- **Group Support**: Send to channels/groups

#### **Configuration**
```php
$telegramConfig = [
    'enabled' => true,
    'bot_token' => '123456789:ABCdefGHIjklMNOpqrsTUVwxyz',
    'chat_id' => '-1001234567890'  // Group chat ID
];
```

#### **Message Format**
```
🚨 *Cảnh báo bảo mật - Site Name*

📍 *Website:* https://example.com
🔍 *Phát hiện bởi:* External Redirect Monitor  
⏰ *Thời gian:* 15/01/2025 14:30:25

📋 *Chi tiết vấn đề:*
• Phát hiện redirect đáng ngờ trong .htaccess
  └ Redirect tới domain ngoài: suspicious.com
```

### **2. Email Channel**

#### **Features**
- **HTML Templates**: Professional email formatting
- **WordPress Integration**: Sử dụng wp_mail()
- **Responsive Design**: Mobile-friendly emails
- **Rich Metadata**: Detailed issue information

#### **Email Template Structure**
```html
<!DOCTYPE html>
<html>
<head>
    <style>
        .header { background: #d32f2f; color: white; }
        .content { background: #f9f9f9; padding: 20px; }
        .issue-item { background: #fff3cd; border-left: 3px solid #856404; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 Cảnh báo bảo mật</h1>
        </div>
        <div class="content">
            <!-- Issue details -->
        </div>
    </div>
</body>
</html>
```

### **3. Extensible Channel System**

#### **Custom Channel Development**
```php
use Puleeno\SecurityBot\WebMonitor\Abstracts\Channel;

class SlackChannel extends Channel 
{
    public function getName(): string {
        return 'Slack';
    }
    
    public function send(string $message, array $data = []): bool {
        $webhook = $this->getConfig('webhook_url');
        $payload = [
            'text' => $message,
            'channel' => $this->getConfig('channel', '#security'),
            'username' => 'Security Monitor Bot'
        ];
        
        return $this->sendToSlack($webhook, $payload);
    }
    
    protected function checkConnection(): bool {
        // Test webhook availability
        return true;
    }
}
```

---

## 🔬 **Advanced Debug System**

### **Debug Information Collection**

#### **DebugHelper Features**
```php
$debugInfo = DebugHelper::createIssueDebugInfo('External Redirect Monitor', [
    'redirect_url' => 'https://suspicious.com',
    'source_file' => '.htaccess'
]);
```

#### **Generated Debug Data**
```json
{
    "issuer": "External Redirect Monitor",
    "timestamp": "2025-01-15 14:30:25",
    "memory_usage": "45.2 MB",
    "peak_memory": "52.8 MB",
    "request_uri": "/wp-admin/admin.php?page=security-monitor",
    "ip_address": "192.168.1.100",
    "current_user": {
        "id": 1,
        "login": "admin",
        "roles": ["administrator"]
    },
    "backtrace": [
        {
            "index": 0,
            "file": "wp-content/plugins/security-monitor/includes/Issuers/ExternalRedirectIssuer.php",
            "line": 125,
            "function": "ExternalRedirectIssuer::checkHtaccessRedirects",
            "readable": "#0 ExternalRedirectIssuer::checkHtaccessRedirects() called at ExternalRedirectIssuer.php:125"
        }
    ],
    "active_plugins": [
        {
            "file": "security-monitor/security-monitor.php",
            "name": "WP Security Monitor Bot",
            "version": "1.0.0"
        }
    ]
}
```

### **Performance Monitoring**

#### **Memory Usage Tracking**
```php
private static function formatBytes(int $bytes): string
{
    $units = ['B', 'KB', 'MB', 'GB'];
    for ($i = 0; $bytes >= 1024 && $i < count($units) - 1; $i++) {
        $bytes /= 1024;
    }
    return round($bytes, 2) . ' ' . $units[$i];
}
```

#### **Call Stack Analysis**
```php
public static function getDebugTrace(int $skipFrames = 1, int $limit = 10): array
{
    $trace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, $limit + $skipFrames);
    $trace = array_slice($trace, $skipFrames);
    
    foreach ($trace as $index => $frame) {
        $debugInfo[] = [
            'index' => $index,
            'file' => str_replace(ABSPATH, '', $frame['file']),
            'line' => $frame['line'],
            'function' => $frame['function'],
            'readable' => "#{$index} {$frame['function']}() called at {$file}:{$line}"
        ];
    }
    
    return $debugInfo;
}
```

---

## 🎛️ **Admin Dashboard**

### **Issues Management Interface**

#### **Multi-tab Layout**
- **Issues Tab**: Active security issues với filtering
- **Ignored Tab**: Issues đã được ignore
- **Rules Tab**: Ignore rules management  
- **Statistics Tab**: Analytics và metrics
- **Whitelist Tab**: Domain whitelist management
- **Pending Domains Tab**: Review queue cho domains

#### **Advanced Filtering**
```php
// Filter form
<select name="status">
    <option value="new">New Issues</option>
    <option value="investigating">Under Investigation</option>
    <option value="resolved">Resolved</option>
</select>

<select name="severity">
    <option value="critical">Critical</option>
    <option value="high">High</option>
    <option value="medium">Medium</option>
</select>

<input type="text" name="s" placeholder="Search issues...">
```

#### **Bulk Actions**
- **Mass Ignore**: Select multiple issues và ignore cùng lúc
- **Batch Resolve**: Resolve nhiều issues với shared notes
- **Export**: Download issues data as CSV/JSON

### **Statistics Dashboard**

#### **Key Metrics**
```php
$stats = [
    'total_issues' => 1250,
    'new_issues' => 45,
    'resolved_issues' => 890,
    'ignored_issues' => 315,
    'by_severity' => [
        'critical' => 12,
        'high' => 88,
        'medium' => 156,
        'low' => 994
    ],
    'by_issuer' => [
        'External Redirect Monitor' => 450,
        'Login Attempt Monitor' => 380,
        'File Change Monitor' => 420
    ],
    'issues_last_24h' => 8,
    'issues_last_7d' => 45
];
```

#### **Visual Elements**
- **Status Cards**: Overview metrics với color coding
- **Charts**: Severity distribution, issuer breakdown
- **Trends**: Time-based issue patterns
- **Performance**: Response times, memory usage

---

## ⚙️ **Configuration Management**

### **Bot Configuration**
```php
$botConfig = [
    'auto_start' => true,
    'check_interval' => 'hourly',  // hourly, twicedaily, daily
    'max_issues_per_notification' => 10,
    'notification_throttle' => 300  // 5 minutes
];
```

### **Channel Configuration**
```php
// Telegram
$telegramConfig = [
    'enabled' => true,
    'bot_token' => 'BOT_TOKEN',
    'chat_id' => 'CHAT_ID'
];

// Email  
$emailConfig = [
    'enabled' => true,
    'to' => 'admin@example.com',
    'from' => 'security@example.com',
    'from_name' => 'Security Monitor Bot'
];
```

### **Issuer Configuration**
```php
$issuersConfig = [
    'external_redirect' => [
        'enabled' => true,
        'check_htaccess' => true,
        'check_database' => true,
        'max_files_scan' => 100
    ],
    'login_attempt' => [
        'enabled' => true,
        'failed_login_threshold' => 5,
        'brute_force_threshold' => 20,
        'office_hours' => [9, 18]
    ],
    'file_change' => [
        'enabled' => true,
        'check_core_files' => true,
        'check_plugin_files' => true,
        'check_theme_files' => true
    ]
];
```

### **WordPress Integration**

#### **Hooks & Filters**
```php
// Add custom issuer
add_action('wp_security_monitor_bot_setup_complete', function($bot) {
    $customIssuer = new MyCustomIssuer();
    $bot->addIssuer($customIssuer);
});

// Add custom channel  
add_action('wp_security_monitor_bot_setup_complete', function($bot) {
    $slackChannel = new SlackChannel();
    $slackChannel->configure($slackConfig);
    $bot->addChannel($slackChannel);
});

// Custom message formatting
add_filter('wp_security_monitor_format_message', function($message, $issuer, $issues) {
    return "🚨 CUSTOM: " . $message;
}, 10, 3);
```

#### **Cron Integration**
```php
// Custom interval
add_filter('cron_schedules', function($schedules) {
    $schedules['every_30_minutes'] = [
        'interval' => 1800,
        'display' => 'Every 30 Minutes'
    ];
    return $schedules;
});
```

---

**Tài liệu này cung cấp guide chi tiết về các features và cách sử dụng WP Security Monitor Bot. Để biết thêm về API và customization, tham khảo code documentation.**
