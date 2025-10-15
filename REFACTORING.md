# 🔧 Refactoring Plan: God Classes

## Vấn đề hiện tại

### God Classes đã được xác định:

1. **`Bot.php`** - 2,090 lines
   - Core plugin class
   - Quá nhiều responsibilities

2. **`RestApi.php`** - 837 lines
   - REST API endpoints
   - Mixing nhiều concerns khác nhau

---

## 📊 Phân tích Bot.php (2,090 lines)

### Responsibilities hiện tại:

1. **Plugin Lifecycle**
   - `getInstance()` - Singleton pattern
   - `init()` - Plugin initialization
   - `activate()` / `deactivate()` - Lifecycle hooks

2. **Admin Menu Management**
   - `addAdminMenu()` - Register WordPress menus
   - `renderMainSecurityPage()` - Render React UI
   - `renderLogsPage()` - Render logs viewer

3. **Issuers Management**
   - `registerIssuers()` - Register security monitors
   - `getIssuers()` - Get active issuers
   - `runCheck()` - Run security checks

4. **Issue Management**
   - `handleSuspiciousActivity()` - Process security events
   - `createIssue()` - Create new issues
   - `updateIssue()` - Update existing issues

5. **Notification System**
   - `notifyChannels()` - Send notifications
   - Channel-specific methods (Telegram, Email, Slack, Log)

6. **REST API Registration**
   - `registerRestRoutes()` - Register API endpoints

7. **Database Management**
   - Schema updates
   - Migrations

8. **Statistics & Reporting**
   - `getStats()` - Get plugin stats

---

## 📊 Phân tích RestApi.php (837 lines)

### Endpoints hiện tại:

1. **Issues Management** (~200 lines)
   - GET `/issues` - List issues
   - POST `/issues/{id}/view` - Mark as viewed
   - POST `/issues/{id}/ignore` - Ignore issue
   - POST `/issues/{id}/resolve` - Resolve issue

2. **Settings Management** (~150 lines)
   - GET `/settings` - Get settings
   - POST `/settings` - Update settings
   - POST `/test-channel/{channel}` - Test notification channels

3. **Migration Management** (~100 lines)
   - GET `/migration/status` - Get migration status
   - POST `/migration/run` - Run migration
   - GET `/migration/changelog` - Get changelog

4. **Domains/Redirects Management** (~200 lines)
   - GET `/redirects` - List domains
   - POST `/redirects/{id}/approve` - Approve domain
   - POST `/redirects/{id}/reject` - Reject domain

5. **Statistics** (~100 lines)
   - GET `/stats` - Get dashboard stats

---

## 🎯 Kế hoạch Refactoring

### Phase 1: Tách Bot.php thành nhiều classes

#### 1.1 Tạo `AdminMenuManager.php`
```php
namespace Puleeno\SecurityBot\WebMonitor\Admin;

class AdminMenuManager {
    public function register(): void;
    public function renderDashboard(): void;
    public function renderLogsPage(): void;
}
```
**Extracted from:** `Bot.php` lines ~569-613

---

#### 1.2 Tạo `IssuerRegistry.php`
```php
namespace Puleeno\SecurityBot\WebMonitor\Issuers;

class IssuerRegistry {
    private array $issuers = [];

    public function register(IssuerInterface $issuer): void;
    public function getAll(): array;
    public function runChecks(): array;
}
```
**Extracted from:** `Bot.php` issuer management methods

---

#### 1.3 Tạo `NotificationDispatcher.php`
```php
namespace Puleeno\SecurityBot\WebMonitor\Notifications;

class NotificationDispatcher {
    private array $channels = [];

    public function addChannel(ChannelInterface $channel): void;
    public function notify(Issue $issue): void;
    private function sendToTelegram(Issue $issue): void;
    private function sendToEmail(Issue $issue): void;
    private function sendToSlack(Issue $issue): void;
    private function writeToLog(Issue $issue): void;
}
```
**Extracted from:** `Bot.php` notification methods

---

#### 1.4 Giữ `Bot.php` làm Facade/Orchestrator
```php
class Bot {
    private static ?Bot $instance = null;
    private AdminMenuManager $menuManager;
    private IssuerRegistry $issuerRegistry;
    private NotificationDispatcher $notifier;
    private IssueManager $issueManager;

    public static function getInstance(): Bot;
    public function init(): void;

    // Delegate to managers
    public function getIssuers(): array {
        return $this->issuerRegistry->getAll();
    }

    public function runCheck(): array {
        return $this->issuerRegistry->runChecks();
    }
}
```
**Kết quả:** `Bot.php` từ 2,090 lines → ~300 lines

---

### Phase 2: Tách RestApi.php thành Controllers

#### 2.1 Tạo `IssuesController.php`
```php
namespace Puleeno\SecurityBot\WebMonitor\Controllers;

class IssuesController {
    public function index(WP_REST_Request $request): WP_REST_Response;
    public function view(WP_REST_Request $request): WP_REST_Response;
    public function ignore(WP_REST_Request $request): WP_REST_Response;
    public function resolve(WP_REST_Request $request): WP_REST_Response;
}
```
**Lines:** ~200

---

#### 2.2 Tạo `SettingsController.php`
```php
namespace Puleeno\SecurityBot\WebMonitor\Controllers;

class SettingsController {
    public function index(): WP_REST_Response;
    public function update(WP_REST_Request $request): WP_REST_Response;
    public function testChannel(WP_REST_Request $request): WP_REST_Response;
}
```
**Lines:** ~150

---

#### 2.3 Tạo `MigrationController.php`
```php
namespace Puleeno\SecurityBot\WebMonitor\Controllers;

class MigrationController {
    public function status(): WP_REST_Response;
    public function run(): WP_REST_Response;
    public function changelog(): WP_REST_Response;
}
```
**Lines:** ~100

---

#### 2.4 Tạo `DomainsController.php`
```php
namespace Puleeno\SecurityBot\WebMonitor\Controllers;

class DomainsController {
    public function index(WP_REST_Request $request): WP_REST_Response;
    public function approve(WP_REST_Request $request): WP_REST_Response;
    public function reject(WP_REST_Request $request): WP_REST_Response;
}
```
**Lines:** ~200

---

#### 2.5 Giữ `RestApi.php` làm Router
```php
class RestApi {
    private IssuesController $issuesController;
    private SettingsController $settingsController;
    private MigrationController $migrationController;
    private DomainsController $domainsController;

    public function registerRoutes(): void {
        // Route registration only
        register_rest_route('wp-security-monitor/v1', '/issues', [
            'methods' => 'GET',
            'callback' => [$this->issuesController, 'index'],
        ]);

        // ... more routes
    }
}
```
**Kết quả:** `RestApi.php` từ 837 lines → ~150 lines

---

## 📁 Cấu trúc thư mục mới

```
includes/
├── Bot.php (300 lines) - Main orchestrator
├── RestApi.php (150 lines) - API router
│
├── Admin/
│   └── AdminMenuManager.php (100 lines)
│
├── Controllers/
│   ├── IssuesController.php (200 lines)
│   ├── SettingsController.php (150 lines)
│   ├── MigrationController.php (100 lines)
│   └── DomainsController.php (200 lines)
│
├── Issuers/
│   ├── IssuerRegistry.php (150 lines)
│   └── ... (existing issuers)
│
└── Notifications/
    ├── NotificationDispatcher.php (200 lines)
    └── Channels/
        ├── TelegramChannel.php
        ├── EmailChannel.php
        ├── SlackChannel.php
        └── LogChannel.php
```

---

## 📈 Metrics

### Before Refactoring:
- `Bot.php`: 2,090 lines
- `RestApi.php`: 837 lines
- **Total**: 2,927 lines in 2 files

### After Refactoring:
- `Bot.php`: ~300 lines (↓ 86%)
- `RestApi.php`: ~150 lines (↓ 82%)
- **Total**: ~2,000 lines across 12 files
- **Average per file**: ~167 lines

### Benefits:
✅ **Single Responsibility Principle** - Mỗi class có 1 mục đích rõ ràng
✅ **Maintainability** - Dễ tìm và sửa code
✅ **Testability** - Dễ viết unit tests
✅ **Readability** - File nhỏ, dễ đọc hiểu
✅ **Reusability** - Controllers và Managers có thể tái sử dụng

---

## 🚀 Implementation Timeline

### Week 1: Preparation
- [ ] Review toàn bộ Bot.php và RestApi.php
- [ ] Tạo interfaces và contracts
- [ ] Setup namespace structure

### Week 2: Refactor Bot.php
- [ ] Tạo AdminMenuManager
- [ ] Tạo IssuerRegistry
- [ ] Tạo NotificationDispatcher
- [ ] Update Bot.php to use managers

### Week 3: Refactor RestApi.php
- [ ] Tạo IssuesController
- [ ] Tạo SettingsController
- [ ] Tạo MigrationController
- [ ] Tạo DomainsController
- [ ] Update RestApi.php routing

### Week 4: Testing & Cleanup
- [ ] Unit tests cho từng component
- [ ] Integration tests
- [ ] Update documentation
- [ ] Code review

---

## ⚠️ Risks & Mitigation

### Risk 1: Breaking existing functionality
**Mitigation:**
- Refactor từng phần nhỏ
- Keep existing code working trong quá trình refactor
- Comprehensive testing sau mỗi change

### Risk 2: Performance impact
**Mitigation:**
- Sử dụng lazy loading cho managers
- Cache instances khi cần
- Profile performance trước và sau refactor

### Risk 3: Merge conflicts
**Mitigation:**
- Refactor trong branch riêng
- Communicate với team về changes
- Merge thường xuyên từ main

---

## 📝 Notes

- Refactoring này là **incremental**, không phải big-bang rewrite
- Mỗi step phải đảm bảo code vẫn hoạt động
- Backward compatibility phải được maintain
- Documentation phải được update đồng bộ

---

**Created:** 2024-10-15
**Status:** Planning Phase
**Priority:** Medium-High

