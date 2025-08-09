# WP Security Monitor Bot - Concept & Architecture

## 🎯 **Overview**

WP Security Monitor Bot là một hệ thống giám sát bảo mật WordPress tự động với khả năng học hỏi thông minh (Smart Learning). Plugin được thiết kế để phát hiện, theo dõi và quản lý các vấn đề bảo mật một cách proactive, giảm thiểu false positives thông qua AI-like learning system.

## 🏗️ **System Architecture**

### **Core Components Flow**

```mermaid
graph TB
    A[WordPress Website] --> B[WP Security Monitor Bot]
    B --> C{Bot Running?}

    C -->|Yes| D[Scheduled Check<br/>WordPress Cron]
    C -->|No| E[Manual Check<br/>Admin Action]

    D --> F[Issue Detection]
    E --> F

    F --> G[External Redirect<br/>Issuer]
    F --> H[Login Attempt<br/>Issuer]
    F --> I[File Change<br/>Issuer]

    G --> J{Check Whitelist}
    J -->|Whitelisted| K[Skip Issue<br/>Record Usage]
    J -->|Not Whitelisted| L[Create Issue]

    H --> L
    I --> L

    L --> M{Check Ignore Rules}
    M -->|Matches Rule| N[Auto Ignore]
    M -->|No Match| O[Save to Database]

    O --> P[Issue Manager]
    P --> Q[Notification Channels]

    Q --> R[Telegram Bot]
    Q --> S[Email Channel]
    Q --> T[Additional Channels]

    P --> U[Admin Dashboard]
    U --> V[Issues Management]
    U --> W[Whitelist Management]
    U --> X[Statistics]

    V --> Y[Ignore/Resolve]
    W --> Z[Approve/Reject<br/>Pending Domains]

    style B fill:#2196F3,color:#fff
    style P fill:#4CAF50,color:#fff
    style G fill:#FF9800,color:#fff
    style H fill:#FF9800,color:#fff
    style I fill:#FF9800,color:#fff
    style Q fill:#9C27B0,color:#fff
```

## 🧠 **Smart Learning System**

### **Whitelist Learning Workflow**

Plugin implement một hệ thống học thông minh để giảm false positives:

```mermaid
sequenceDiagram
    participant A as External Request
    participant W as WordPress
    participant E as ExternalRedirectIssuer
    participant WM as WhitelistManager
    participant IM as IssueManager
    participant D as Database
    participant C as Channels
    participant Admin as Admin

    Note over A,Admin: Smart Whitelist Learning Workflow

    A->>W: Redirect detected (domain.com)
    W->>E: Trigger detection
    E->>WM: Check if domain whitelisted
    WM-->>E: Not in whitelist

    E->>IM: Create issue with debug info
    IM->>D: Save issue to database
    IM->>WM: Track pending domain
    WM->>D: Add to pending domains

    IM->>C: Send notifications
    C->>Admin: Alert about redirect

    Note over Admin: First Detection - Issue Created

    rect rgb(255, 240, 240)
        A->>W: Same redirect detected again
        W->>E: Trigger detection
        E->>WM: Check whitelist (still empty)
        WM-->>E: Not whitelisted
        E->>IM: Create issue again
        WM->>D: Update detection count
        IM->>C: Send notification
    end

    Note over Admin: Second Detection - Issue Created Again

    Admin->>WM: Review pending domains
    Admin->>WM: Approve domain.com
    WM->>D: Add to whitelist

    rect rgb(240, 255, 240)
        A->>W: Same redirect detected third time
        W->>E: Trigger detection
        E->>WM: Check whitelist
        WM-->>E: Domain approved!
        WM->>D: Record usage
        E-->>IM: Skip issue creation
    end

    Note over Admin: Third+ Detection - Auto Skipped
```

### **Learning Phases**

1. **Discovery Phase**: Lần đầu phát hiện → Tạo issue + Pending domain
2. **Confirmation Phase**: Lần thứ 2 → Tăng detection count, vẫn tạo issue
3. **Learning Phase**: Admin review → Approve/Reject decision
4. **Automation Phase**: Lần 3+ → Tự động skip hoặc continue dựa vào decision

## 🔍 **Advanced Debug System**

### **Debug Information Flow**

```mermaid
flowchart TD
    A[Issue Detected] --> B[Generate Debug Info]
    B --> C[DebugHelper.createIssueDebugInfo]

    C --> D[Backtrace Analysis]
    C --> E[Memory Profiling]
    C --> F[Request Context]
    C --> G[WordPress Environment]

    D --> H[Call Stack<br/>- Function names<br/>- File paths<br/>- Line numbers]

    E --> I[Memory Usage<br/>- Current usage<br/>- Peak memory<br/>- Formatted output]

    F --> J[Request Data<br/>- IP Address<br/>- User Agent<br/>- Request URI<br/>- Current User]

    G --> K[WP Environment<br/>- Active plugins<br/>- Current hooks<br/>- WordPress version<br/>- PHP version]

    H --> L[Debug Info Object]
    I --> L
    J --> L
    K --> L

    L --> M[Store in Issue]
    M --> N[Admin Dashboard]
    N --> O[Debug Details View]

    style C fill:#2196F3,color:#fff
    style L fill:#4CAF50,color:#fff
    style O fill:#FF9800,color:#fff
```

## 🗄️ **Database Schema**

### **Entity Relationship Diagram**

```mermaid
erDiagram
    ISSUES {
        bigint id PK
        varchar issue_hash UK
        varchar issuer_name
        varchar issue_type
        enum severity
        enum status
        varchar title
        text description
        longtext details
        longtext raw_data
        varchar file_path
        varchar ip_address
        datetime first_detected
        datetime last_detected
        int detection_count
        boolean is_ignored
        bigint ignored_by FK
        datetime ignored_at
        longtext debug_info
        datetime created_at
        datetime updated_at
    }

    IGNORE_RULES {
        bigint id PK
        varchar rule_name
        enum rule_type
        text rule_value
        varchar issuer_name
        varchar issue_type
        text description
        boolean is_active
        bigint created_by FK
        datetime created_at
        datetime expires_at
        int usage_count
        datetime last_used_at
    }

    WHITELIST_DOMAINS {
        varchar domain PK
        text reason
        bigint added_by FK
        datetime added_at
        int usage_count
        datetime last_used
    }

    PENDING_DOMAINS {
        varchar domain PK
        datetime first_detected
        int detection_count
        enum status
        longtext contexts
        bigint approved_by FK
        datetime approved_at
        bigint rejected_by FK
        datetime rejected_at
        text reject_reason
    }

    WP_USERS {
        bigint ID PK
        varchar user_login
        varchar display_name
    }

    ISSUES ||--o{ IGNORE_RULES : "can be ignored by"
    ISSUES }o--|| WP_USERS : "ignored_by"
    IGNORE_RULES }o--|| WP_USERS : "created_by"
    WHITELIST_DOMAINS }o--|| WP_USERS : "added_by"
    PENDING_DOMAINS }o--|| WP_USERS : "approved_by"
    PENDING_DOMAINS }o--|| WP_USERS : "rejected_by"
```

## 🔧 **Design Patterns**

### **1. Singleton Pattern**
- `Bot::getInstance()`
- `IssueManager::getInstance()`
- `WhitelistManager::getInstance()`

**Lý do**: Đảm bảo single instance và global access point.

### **2. Strategy Pattern**
- `ChannelInterface` implementations
- `IssuerInterface` implementations

**Lý do**: Dễ dàng thêm channels và issuers mới.

### **3. Observer Pattern**
- WordPress hooks system
- Issue detection events

**Lý do**: Loose coupling và event-driven architecture.

### **4. Factory Pattern** (Implicit)
- Dynamic issuer loading
- Channel configuration

**Lý do**: Flexible object creation.

## 📊 **Performance Considerations**

### **Database Optimization**
- **Indexed fields**: `issue_hash`, `issuer_name`, `severity`, `status`
- **Partitioning**: By date for large installations
- **Cleanup**: Automated old data removal

### **Memory Management**
- **Debug info tracking**: Monitor memory usage per check
- **Lazy loading**: Load issues on-demand
- **Pagination**: Large result sets

### **Scalability Features**
- **Configurable limits**: Max files to scan, check intervals
- **Throttling**: Prevent notification spam
- **Background processing**: WordPress Cron integration

## 🛡️ **Security Features**

### **Input Validation**
- All user inputs sanitized
- SQL injection prevention
- XSS protection

### **Access Control**
- `manage_options` capability required
- Nonce verification for all forms
- User tracking for audit

### **Data Protection**
- Sensitive data encryption options
- Debug info sanitization
- Personal data anonymization

## 🔮 **Future Enhancements**

### **Planned Features**
1. **Machine Learning**: Pattern recognition for new threat types
2. **API Integration**: External threat intelligence feeds
3. **Multi-site Support**: Centralized monitoring
4. **Real-time Alerts**: WebSocket notifications
5. **Custom Issuers**: Plugin-based extension system

### **Extensibility Points**
- Custom channel development
- Additional issuer types
- Webhook integrations
- Third-party tool integration

---

**Tài liệu này cung cấp overview về architecture và concept chính của WP Security Monitor Bot. Để hiểu chi tiết implementation, tham khảo các tài liệu chức năng cụ thể.**
