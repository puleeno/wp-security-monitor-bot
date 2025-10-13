# Issuer Notification Behavior

## Tổng quan

Plugin sử dụng 2 abstract classes để định nghĩa behavior mặc định cho việc báo cáo lại (re-notification) khi phát hiện issue cũ:

## 1. `IssuerAbstract` - Scheduled Issues

**Default behavior**: KHÔNG báo cáo lại (chỉ báo lần đầu phát hiện)

**Phù hợp cho**: File changes, Dangerous functions, Code patterns, etc.

**Lý do**: Những vấn đề này thường tồn tại liên tục trong code/files. Nếu báo mỗi lần check (mỗi 5 phút) sẽ spam notifications.

```php
use Puleeno\SecurityBot\WebMonitor\Abstracts\IssuerAbstract;

class FileChangeIssuer extends IssuerAbstract
{
    public function getName(): string
    {
        return 'File Change Monitor';
    }

    public function detect(): array
    {
        // Detect logic...
    }

    // shouldNotifyOnRedetection() mặc định = false
}
```

## 2. `RealtimeIssuerAbstract` - Realtime Issues

**Default behavior**: LUÔN báo cáo lại mỗi lần phát hiện

**Phù hợp cho**: Login attempts, Brute force, Redirects, User registration, etc.

**Lý do**: Những vấn đề này là các **sự kiện đang diễn ra** (attacks in progress). Mỗi lần phát hiện là một sự kiện mới cần được báo cáo.

```php
use Puleeno\SecurityBot\WebMonitor\Abstracts\RealtimeIssuerAbstract;

class LoginAttemptIssuer extends RealtimeIssuerAbstract
{
    public function getName(): string
    {
        return 'Login Attempt Monitor';
    }

    public function detect(): array
    {
        // Detect logic...
    }

    // shouldNotifyOnRedetection() mặc định = true
}
```

## 3. Custom Behavior

Bất kỳ issuer nào cũng có thể **override** method `shouldNotifyOnRedetection()` để custom behavior:

### Ví dụ 1: Chỉ báo lại sau X giờ

```php
class SpecialIssuer extends RealtimeIssuerAbstract
{
    private $lastNotified = [];

    public function shouldNotifyOnRedetection(): bool
    {
        // Chỉ báo lại nếu đã quá 1 giờ kể từ lần báo trước
        $issueHash = $this->getCurrentIssueHash();
        $lastTime = $this->lastNotified[$issueHash] ?? 0;

        if (time() - $lastTime > 3600) { // 1 hour
            $this->lastNotified[$issueHash] = time();
            return true;
        }

        return false;
    }
}
```

### Ví dụ 2: Chỉ báo nếu severity cao

```php
class ConditionalIssuer extends IssuerAbstract
{
    public function shouldNotifyOnRedetection(): bool
    {
        // Chỉ báo lại nếu severity là high hoặc critical
        $currentIssue = $this->getCurrentIssue();
        $severity = $currentIssue['severity'] ?? 'low';

        return in_array($severity, ['high', 'critical']);
    }
}
```

## 4. Cách hoạt động

Khi `IssueManager::recordIssue()` được gọi:

1. **Kiểm tra issue đã tồn tại** (theo `line_code_hash`)

2. **Nếu issue đã tồn tại**:
   - Update `detection_count++`, `last_detected`, reset `viewed`
   - **Check notification behavior**:
     - Nếu issuer có method `shouldNotifyOnRedetection()` → Dùng nó
     - Fallback 1: Nếu issue đã `viewed` → Báo lại
     - Fallback 2: Nếu `issuer_name` bắt đầu với `realtime_` → Báo lại
     - Default: Không báo

3. **Return value**:
   - **Negative ID** (`-123`): Issue cũ, CẦN gửi notification
   - **Positive ID** (`123`): Issue cũ, KHÔNG gửi notification
   - **Positive ID** (new): Issue mới, LUÔN gửi notification

## 5. Flow chart

```
Issue phát hiện
    ↓
Tồn tại trong DB?
    ├── NO → Tạo mới → LUÔN notify ✅
    │
    └── YES → Update detection_count
                ↓
            Check issuer có method shouldNotifyOnRedetection()?
                ├── YES → Gọi method → Return true/false
                │           ├── true → Notify ✅
                │           └── false → Không notify ❌
                │
                └── NO → Fallback checks:
                          ├── Đã viewed? → YES → Notify ✅
                          ├── issuer_name = "realtime_*"? → YES → Notify ✅
                          └── Default → Không notify ❌
```

## 6. Best Practices

### ✅ DO:
- Extend `RealtimeIssuerAbstract` cho các issues là **events** (login, attacks, etc.)
- Extend `IssuerAbstract` cho các issues là **states** (file changes, code patterns, etc.)
- Override `shouldNotifyOnRedetection()` cho custom logic phức tạp
- Sử dụng `viewed` flag để cho phép user đánh dấu đã check

### ❌ DON'T:
- Không spam notifications cho issues tồn tại liên tục
- Không bỏ sót các attacks đang diễn ra
- Không hardcode notification behavior trong detect logic
- Không quên implement abstract methods

## 7. Migration

Các issuers hiện tại đang sử dụng naming convention `realtime_*` sẽ **tự động** hoạt động đúng nhờ fallback logic.

Để migrate sang abstract classes:

```php
// Before
class LoginAttemptIssuer implements RealtimeIssuerInterface
{
    // ...
}

// After
class LoginAttemptIssuer extends RealtimeIssuerAbstract
{
    // Tự động có shouldNotifyOnRedetection() = true
    // Không cần code thêm gì!
}
```

