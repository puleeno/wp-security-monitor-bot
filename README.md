# WP Security Monitor Bot

**Tác giả**: Puleeno Nguyen
**Phiên bản**: 1.0.0
**License**: GPL-3.0

Plugin WordPress để giám sát bảo mật website và gửi cảnh báo tự động qua Telegram và Email.

## 🚀 Tính năng chính

### 📱 Kênh thông báo
- **Telegram Bot**: Gửi cảnh báo realtime qua Telegram
- **Email**: Gửi báo cáo chi tiết qua email với HTML template đẹp
- **🆕 Slack**: Rich notifications qua Slack webhooks với attachments và formatting
- **🆕 Log File**: Ghi detailed logs với rotation, compression và audit trail
- **🆕 Test Gửi Tin Nhắn**: Nút test riêng biệt cho từng kênh để kiểm tra khả năng gửi tin nhắn thực tế
- **Extensible**: Dễ dàng thêm các kênh khác (SMS, Discord, Microsoft Teams...)

### 🔍 Giám sát bảo mật

#### 1. **External Redirect Monitor**
- Phát hiện redirect đáng ngờ trong `.htaccess`
- Kiểm tra redirect trong database WordPress
- Phát hiện JavaScript redirect trong posts
- Quét code PHP để tìm redirect ra domain ngoài
- **🆕 Smart Whitelist System**: Quản lý domain hợp lệ, tự động học từ admin feedback

#### 2. **Login Attempt Monitor**
- Theo dõi failed login attempts
- Phát hiện brute force attacks
- Cảnh báo đăng nhập admin từ IP lạ
- Giám sát đăng nhập ngoài giờ làm việc

#### 3. **File Change Monitor**
- Kiểm tra thay đổi WordPress core files
- Giám sát plugin và theme files
- Theo dõi file quan trọng (wp-config.php, .htaccess)
- Phát hiện file mới có tên đáng ngờ

#### 4. **🆕 Admin User Monitor**
- Phát hiện khi có user mới được tạo với role admin
- Theo dõi user existing được promote lên admin
- Cảnh báo thay đổi capabilities admin ngoài giờ
- Track thông tin người tạo và context

#### 5. **🆕 Dangerous Function Scanner**
- Scan file PHP tìm các hàm nguy hiểm: `eval()`, `exec()`, `shell_exec()`, `system()`
- Phát hiện pattern malware phổ biến: `eval(base64_decode())`
- Smart file hash tracking để ignore files đã kiểm tra
- Context aware scanning với line numbers và code context

### 📋 Quản lý Issues

#### **Database Tracking**
- Lưu trữ tất cả issues phát hiện vào database
- Phân loại theo severity: Low, Medium, High, Critical
- Tracking theo issuer và loại vấn đề
- Hash-based deduplication để tránh spam

#### **Issue Management**
- **Dashboard quản lý**: Xem tất cả issues với filters và pagination
- **Ignore Issues**: Bỏ qua issues không quan trọng hoặc false positive
- **Resolve Issues**: Đánh dấu đã xử lý với resolution notes
- **Auto Ignore Rules**: Tạo rules để tự động ignore các issues tương tự
- **🆕 File Hash Ignore**: Ignore toàn bộ file đã được kiểm tra để tránh re-scan

#### **Smart Filtering**
- Filter theo status, severity, issuer, file path
- Search trong title và description
- Separate tabs cho active issues và ignored issues
- Statistics dashboard với charts và metrics

### 🎯 **Domain Whitelist Management**

#### **Automatic Learning System**
- **Lần 1**: Phát hiện redirect → Tạo issue + Add vào pending domains
- **Lần 2**: Vẫn chưa whitelist → Tiếp tục tạo issue
- **Admin approve** → **Lần 3+**: Tự động skip, không tạo issue

#### **Intelligent Domain Tracking**
- **Pending Domains**: Review queue cho admin
- **Detection Count**: Track số lần domain được phát hiện
- **Context Information**: Source, file path, redirect patterns
- **Approval Workflow**: Approve/Reject với reasons và audit trail

#### **Advanced Debug Information**
- **Full Call Stack**: Trace chính xác callback code gây ra issue
- **Memory Usage**: Monitor performance impact
- **Request Context**: IP, User Agent, URI, User info
- **WordPress Environment**: Active plugins, hooks, filters
- **File Operations**: Permissions, ownership, modifications

## 📦 Cài đặt

### Yêu cầu
- WordPress 5.0+
- PHP 7.4+
- Composer (để cài dependencies)

### Bước 1: Cài đặt dependencies
```bash
cd wp-content/plugins/wp-security-monitor-bot/
composer install
```

### Bước 2: Kích hoạt plugin
1. Đăng nhập WordPress Admin
2. Vào **Plugins > Installed Plugins**
3. Tìm "WP Security Monitor Bot" và click **Activate**

## ⚙️ Cấu hình

### Telegram Bot Setup

1. **Tạo Telegram Bot**:
   - Nhắn tin cho [@BotFather](https://t.me/BotFather)
   - Gửi `/newbot` và làm theo hướng dẫn
   - Lưu lại **Bot Token** (dạng: `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`)

2. **Lấy Chat ID**:
   - Nhắn tin cho [@userinfobot](https://t.me/userinfobot)
   - Bot sẽ trả về Chat ID của bạn
   - Hoặc tạo group và add bot vào, lấy Group Chat ID

3. **Cấu hình trong WordPress**:
   - Vào **Settings > Security Monitor**
   - Điền Bot Token và Chat ID
   - Click **Test Connection** để kiểm tra

### Email Setup

1. **Cấu hình Email**:
   - Vào **Settings > Security Monitor**
   - Điền email nhận thông báo
   - Tùy chỉnh email gửi và tên hiển thị
   - Click **Test Email** để kiểm tra

### 🚩 Malware Flag File

Plugin có thể tạo file `.malware` rỗng trong thư mục gốc WordPress (ABSPATH) để đánh dấu khi phát hiện vấn đề bảo mật. File này có thể được sử dụng bởi các hệ thống monitoring bên ngoài để phát hiện nhanh.

**Bật tính năng này:**

Thêm vào file `wp-config.php`:
```php
define('WP_SECURITY_MONITOR_MALWARE_FLAG', true);
```

**Cách hoạt động:**
- Khi phát hiện **bất kỳ issue nào** (không bị ignore), file `.malware` sẽ được tạo ngay lập tức
- File được tạo tại: `/path/to/wordpress/.malware`
- File chỉ tạo một lần duy nhất
- Có thể dùng cho monitoring scripts, cron jobs, hoặc hệ thống cảnh báo bên ngoài

**Tắt tính năng:**
```php
define('WP_SECURITY_MONITOR_MALWARE_FLAG', false);
```
Hoặc xóa constant này khỏi `wp-config.php`

## 🎛️ Sử dụng

### Auto Monitoring
- Plugin tự động bắt đầu giám sát sau khi cài đặt
- Chạy kiểm tra theo lịch (mặc định: mỗi giờ)
- Gửi cảnh báo tự động khi phát hiện vấn đề

### Manual Check
- Vào **Settings > Security Monitor**
- Click **🔍 Chạy kiểm tra ngay** để check thủ công
- Xem kết quả trong admin panel

### Quản lý Bot
- **▶️ Khởi động Bot**: Bắt đầu giám sát
- **⏹️ Dừng Bot**: Tạm dừng giám sát
- Xem thống kê và lịch sử cảnh báo

### Quản lý Issues
- Vào **Tools > Security Issues** để xem tất cả issues
- **Filter và Search**: Tìm issues theo nhiều tiêu chí
- **Ignore Issues**: Tạo ignore rules cho false positives
- **Resolve Issues**: Đánh dấu đã xử lý với notes
- **Statistics**: Xem báo cáo và thống kê chi tiết

### Whitelist Domain Management
- **Pending Domains Tab**: Review và approve/reject domains được phát hiện
- **Whitelist Tab**: Quản lý domains đã approved
- **Smart Detection**: Tự động skip issues cho domains trong whitelist
- **Audit Trail**: Track who approved/rejected domains và lý do

## ⚙️ Channel Configuration

### 🤖 Telegram Setup
1. Tạo bot mới với [@BotFather](https://t.me/BotFather)
2. Lấy **Bot Token**
3. Add bot vào group/channel và lấy **Chat ID**
4. Cấu hình trong **WordPress Admin > Tools > Security Monitor**

### 📧 Email Setup
- **Recipient Email**: Email nhận cảnh báo
- **Sender Email**: Email gửi (mặc định dùng admin email)
- **Sender Name**: Tên hiển thị người gửi
- **HTML Templates**: Tự động format đẹp

### 💬 Slack Setup
1. Tạo Slack App tại [https://api.slack.com/apps](https://api.slack.com/apps)
2. Kích hoạt **Incoming Webhooks**
3. Tạo webhook cho channel/user cần nhận thông báo
4. Copy **Webhook URL** và paste vào config

**Slack Configuration Options:**
- **Webhook URL**: URL từ Slack app (required)
- **Channel**: Override default channel (e.g., #security, @username)
- **Bot Username**: Tên hiển thị trong Slack
- **Icon Emoji**: Bot icon (e.g., :warning:, :shield:)

**Features:**
- Rich message formatting với attachments
- Color-coded severity levels
- Expandable issue details
- Direct links to admin dashboard

### 📄 Log File Setup
- **Auto-enabled**: Log channel được bật mặc định
- **Secure Storage**: Logs được lưu trong protected directory với .htaccess
- **Log Directory**: Configurable location (default: wp-content/uploads/security-logs)
- **File Rotation**: Tự động rotate khi file đạt size limit
- **Compression**: Gzip compression cho old files để tiết kiệm space
- **Cleanup**: Tự động xóa old files theo retention policy

**Log Configuration Options:**
- **Directory**: Custom log location
- **File Pattern**: Date-based naming (e.g., security-monitor-2025-01-15.log)
- **Max File Size**: Rotation threshold (default: 10MB)
- **Max Files**: Retention count (default: 30 files)
- **Debug Info**: Include detailed debug information

**Log Format:**
```
[2025-01-15 14:30:25] CRITICAL - Site Name - External Redirect Monitor (https://example.com)
  Issue #1: Suspicious redirect detected in .htaccess
    Severity: CRITICAL
    Type: external_redirect
    File: wp-content/.htaccess
    IP: 192.168.1.100
    Details: Redirect to external domain: malicious.com

  Summary: 1 issue(s) detected by External Redirect Monitor at 2025-01-15 14:30:25
--------------------------------------------------------------------------------
```

## 🔧 Cấu hình nâng cao

### Hooks và Filters

```php
// Thêm custom issuer
add_action('wp_security_monitor_bot_setup_complete', function($bot) {
    $customIssuer = new MyCustomIssuer();
    $bot->addIssuer($customIssuer);
});

// Thêm custom channel
add_action('wp_security_monitor_bot_setup_complete', function($bot) {
    $slackChannel = new SlackChannel();
    $slackChannel->configure([
        'webhook_url' => 'https://hooks.slack.com/...',
        'channel' => '#security-alerts'
    ]);
    $bot->addChannel($slackChannel);
});

// Custom message formatting
add_filter('wp_security_monitor_format_message', function($message, $issuer, $issues) {
    return "🚨 CUSTOM ALERT: " . $message;
}, 10, 3);
```

### Tùy chỉnh thời gian check
```php
// Thay đổi interval check (trong wp-config.php)
define('WP_SECURITY_MONITOR_INTERVAL', 'twicedaily'); // every 12 hours
```

## 📊 API và Extensibility

### Tạo Custom Issuer
```php
use Puleeno\SecurityBot\WebMonitor\Interfaces\IssuerInterface;

class MyCustomIssuer implements IssuerInterface
{
    public function getName(): string {
        return 'My Custom Security Check';
    }

    public function detect(): array {
        $issues = [];

        // Your detection logic here
        if ($this->detectProblem()) {
            $issues[] = [
                'message' => 'Problem detected!',
                'details' => 'Detailed information...'
            ];
        }

        return $issues;
    }

    // Implement other required methods...
}
```

### Tạo Custom Channel
```php
use Puleeno\SecurityBot\WebMonitor\Abstracts\Channel;

class SlackChannel extends Channel
{
    public function getName(): string {
        return 'Slack';
    }

    public function send(string $message, array $data = []): bool {
        // Implement Slack webhook logic
        return $this->sendToSlack($message, $data);
    }

    protected function checkConnection(): bool {
        // Check Slack webhook availability
        return true;
    }
}
```

## 🧪 Test Gửi Tin Nhắn

### Tính năng mới
Plugin hiện tại có **2 loại test riêng biệt** cho mỗi kênh thông báo:

1. **🔗 Test Kết Nối**: Kiểm tra khả năng kết nối với service (Telegram API, Email server, Slack webhook, Log directory)
2. **📤 Test Gửi Tin Nhắn**: Gửi tin nhắn test thực tế để kiểm tra khả năng gửi tin nhắn

### Cách sử dụng
1. Vào **WordPress Admin** → **Puleeno Security** → **Cài đặt**
2. Trong mỗi kênh (Telegram, Email, Slack, Log), bạn sẽ thấy 2 nút:
   - **🔗 Test kết nối**: Kiểm tra cấu hình và kết nối
   - **📤 Gửi tin nhắn test**: Gửi tin nhắn test thực tế

### Lợi ích
- **Phân biệt rõ ràng** giữa vấn đề kết nối và vấn đề gửi tin nhắn
- **Test thực tế** khả năng gửi tin nhắn của bot
- **Debug dễ dàng** khi có vấn đề với một kênh cụ thể
- **Xác nhận** bot hoạt động đúng trước khi deploy production

### Ví dụ sử dụng
- **Telegram**: Test kết nối → OK, Test gửi tin nhắn → Nhận được tin nhắn test
- **Email**: Test kết nối → OK, Test gửi tin nhắn → Nhận được email test
- **Slack**: Test kết nối → OK, Test gửi tin nhắn → Nhận được message trong Slack
- **Log**: Test kết nối → OK, Test gửi tin nhắn → File log được tạo với nội dung test

## 🐛 Troubleshooting

### Telegram không nhận được tin nhắn
1. Kiểm tra Bot Token và Chat ID
2. Đảm bảo bot đã được add vào group (nếu dùng group)
3. Check WordPress error logs

### Email không được gửi
1. Kiểm tra WordPress có thể gửi email: `wp_mail()`
2. Cài SMTP plugin nếu cần
3. Check spam folder

### Bot không chạy tự động
1. Kiểm tra WordPress Cron: `wp cron event list`
2. Cài WP Crontrol plugin để debug
3. Check server cron jobs

## 📝 Changelog

### Version 1.0.0
- ✅ Initial release
- ✅ Telegram và Email channels
- ✅ External Redirect Monitor
- ✅ Login Attempt Monitor
- ✅ File Change Monitor
- ✅ Admin panel với dashboard
- ✅ Auto scheduling với WordPress Cron
- ✅ **Database issue tracking với full management**
- ✅ **Smart ignore system với multiple rule types**
- ✅ **Advanced filtering và search capabilities**
- ✅ **Issue resolution workflow với notes**
- ✅ **Statistics dashboard với detailed metrics**
- ✅ **Hash-based deduplication system**
- ✅ **🆕 Smart Domain Whitelist System với automatic learning**
- ✅ **🆕 Advanced Debug Tracing với full call stack**
- ✅ **🆕 Intelligent False Positive Reduction**

## 🤝 Contributing

1. Fork repo này
2. Tạo feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push branch: `git push origin feature/amazing-feature`
5. Tạo Pull Request

## 📊 Changelog

### Version 1.1.0 (Latest)
- **🆕 Admin User Monitor**: Tracking tạo user admin mới và role changes
- **🆕 Dangerous Function Scanner**: Scan PHP files cho eval(), exec(), system()...
- **🆕 File Hash Ignore System**: Ignore files đã được admin kiểm tra
- **🆕 Slack Channel**: Rich notifications với attachments và formatting
- **🆕 Log File Channel**: Structured logging với rotation và compression
- **🆕 Test Gửi Tin Nhắn**: Nút test riêng biệt cho từng kênh để kiểm tra khả năng gửi tin nhắn thực tế
- **🔧 Enhanced Debug Info**: Detailed tracing cho tất cả issues
- **🎯 Better Issue Management**: More granular control và filtering

### Version 1.0.0
- **🔍 External Redirect Detection**: .htaccess, database, JS redirects
- **🔐 Login Attempt Monitoring**: Brute force và suspicious login detection
- **📁 File Change Detection**: WordPress core, themes, plugins monitoring
- **🤖 Smart Whitelist System**: Domain learning với admin feedback
- **📊 Database Issue Tracking**: Comprehensive issue management
- **📱 Multi-channel Notifications**: Telegram Bot và Email alerts
- **⚙️ Admin Dashboard**: Full-featured management interface

## 📄 License

GPL-3.0 License. Xem file [LICENSE](license.txt) để biết thêm chi tiết.

## 💬 Support

- **Email**: puleeno@gmail.com
- **Website**: [https://puleeno.com](https://puleeno.com)
- **Issues**: Tạo issue trên GitHub repository

---

**⚠️ Lưu ý bảo mật**
- Giữ Bot Token bí mật
- Không commit credentials vào version control
- Thường xuyên cập nhật plugin và dependencies
- Monitor logs để phát hiện false positives
