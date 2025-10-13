# Changelog

All notable changes to WP Security Monitor Bot will be documented in this file.

## [1.2.0] - 2025-10-13

### 🆕 Added

#### Viewed Flag System
- **Viewed tracking** - Đánh dấu issues đã xem/check
- **Auto re-notify** - Tự động thông báo lại nếu issue đã viewed xuất hiện lại
- AJAX handlers cho mark/unmark viewed
- UI buttons trong Issues page

#### Backtrace Support
- **Call stack capture** - Thu thập backtrace khi security events xảy ra
- **Smart filtering** - Loại bỏ internal frames để dễ đọc
- **Admin display** - Hiển thị backtrace table trong issue details
- **Debug info** - Giúp xác định plugin/theme nào gây ra issue

#### Notification Behavior System
- **IssuerAbstract** - Base class cho scheduled issuers (không báo lại)
- **RealtimeIssuerAbstract** - Base class cho realtime issuers (luôn báo lại)
- **Flexible override** - Mỗi issuer có thể custom `shouldNotifyOnRedetection()`
- **Backward compatibility** - Auto-detect realtime issuers qua prefix `realtime_`

#### Reported Flag for Login Records
- **Reported tracking** - Đánh dấu login records đã tạo issue
- **No duplicate issues** - Không tạo issue lại cho cùng records
- **Attack continuation detection** - Vẫn phát hiện attempts mới

#### Migration System
- **Dedicated migration page** - UI đẹp giống Elementor/WooCommerce
- **Auto-detection** - Tự động phát hiện khi cần migrate
- **Admin notices** - Cảnh báo rõ ràng khi plugin update
- **Manual migration** - Nút "Migrate Now" trong settings
- **Version tracking** - Track database version và plugin version

### 🔧 Fixed

#### Bug Fixes
- **ArgumentCountError** - Sửa `interceptWpDie()` để accept 1 hoặc 2 arguments
- **Dashboard count** - Dashboard hiển thị số issuers thực tế (9) thay vì hardcode (5)
- **Backtrace filtering** - Loại bỏ internal frames (LoginAttemptIssuer, Bot, IssueManager)
- **Telegram formatting** - Loại bỏ dòng phân cách `━━━━━` gây lỗi format

#### Performance
- **Malware flag creation** - Tạo file `.malware` ngay lập tức khi phát hiện issue
- **Record cleanup** - Không tính lại records đã reported

### 📝 Changed

#### Database Schema (v1.2)
```sql
ALTER TABLE security_monitor_issues ADD COLUMN viewed tinyint(1) DEFAULT 0;
ALTER TABLE security_monitor_issues ADD COLUMN viewed_by bigint(20) unsigned DEFAULT NULL;
ALTER TABLE security_monitor_issues ADD COLUMN viewed_at datetime DEFAULT NULL;
ALTER TABLE security_monitor_issues ADD INDEX idx_viewed (viewed);
```

#### Notification Logic
- Realtime issues (login, brute force, redirect, user registration) → **LUÔN notify**
- Scheduled issues (file changes, dangerous functions) → **Chỉ notify lần đầu**
- Viewed issues → **Notify lại nếu phát hiện tiếp**

### 📚 Documentation

- **ISSUER_NOTIFICATION_BEHAVIOR.md** - Hướng dẫn chi tiết về notification behavior
- **README.md** - Thêm section về Backtrace và Malware Flag File
- **Inline comments** - Comment rõ ràng về backtrace và notification logic

---

## [1.1.0] - 2025-10-10

### Added
- Backtrace column trong issues table
- Line code hash tracking
- Notification queue system

### Changed
- Improved issue deduplication
- Better error handling

---

## [1.0.0] - 2025-10-01

### Initial Release
- Telegram, Email, Slack, Log channels
- 11 security monitors (issuers)
- Real-time detection
- Scheduled checks
- Whitelist management
- Ignore rules
- Access control

