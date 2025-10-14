# Setup & Installation Guide

## 📋 Hướng dẫn cài đặt React Admin UI

### Bước 1: Cài đặt Dependencies

```bash
cd wp-content/plugins/wp-security-monitor-bot/admin-app
npm install
```

### Bước 2: Development

Chạy development server với Vite:

```bash
npm run dev
```

Server sẽ chạy tại: `http://localhost:3000`

### Bước 3: Build cho Production

```bash
npm run build
```

Build output sẽ được tạo trong folder:
```
../assets/admin-app/
```

### Bước 4: Kích hoạt React UI trong WordPress

Sau khi build, React UI sẽ tự động được load khi vào:
- Dashboard: `wp-admin/admin.php?page=puleeno-security`
- Issues: `wp-admin/admin.php?page=wp-security-monitor-issues`

## 🔧 Configuration

### TypeScript Strict Mode

Project sử dụng TypeScript strict mode với các rules:
- ✅ `noImplicitAny: true`
- ✅ `strictNullChecks: true`
- ✅ `strictFunctionTypes: true`
- ✅ `strictBindCallApply: true`
- ✅ `strictPropertyInitialization: true`

### Ant Design Theme

Custom theme colors khớp với WordPress admin:
- Primary: `#2271b1` (WordPress blue)
- Success: `#00a32a`
- Warning: `#dba617`
- Error: `#d63638`

### Redux Store Structure

```
store/
├── issues/       # Issues management
├── stats/        # Statistics data
├── settings/     # Plugin settings
└── ui/           # UI state (sidebar, theme, notifications)
```

## 🌐 REST API Endpoints

Backend PHP cung cấp các endpoints:

### Issues
- `GET /wp-json/wp-security-monitor/v1/issues`
- `POST /wp-json/wp-security-monitor/v1/issues/{id}/viewed`
- `DELETE /wp-json/wp-security-monitor/v1/issues/{id}/viewed`
- `POST /wp-json/wp-security-monitor/v1/issues/{id}/ignore`
- `POST /wp-json/wp-security-monitor/v1/issues/{id}/resolve`

### Stats
- `GET /wp-json/wp-security-monitor/v1/stats/security`
- `GET /wp-json/wp-security-monitor/v1/stats/bot`

### Settings
- `GET /wp-json/wp-security-monitor/v1/settings`
- `POST /wp-json/wp-security-monitor/v1/settings`

## 🎯 Features

### ✅ Đã Implement

- **Dashboard Page**
  - Real-time statistics với Ant Design Statistic
  - Recent issues table
  - Severity breakdown chart
  - Top issuers list
  - Bot status alert

- **Issues Page**
  - Full CRUD operations
  - Mark as viewed functionality
  - Ignore/Resolve với modals
  - Issue details drawer với backtrace
  - Pagination
  - Filters (status, severity, issuer, search)
  - Real-time updates

- **Layout**
  - Collapsible sidebar
  - Responsive design
  - Dark theme menu
  - Breadcrumbs navigation

- **State Management**
  - Redux Toolkit với TypeScript
  - Redux Observable cho async operations
  - Centralized error handling
  - Notification system

### 🚧 Coming Next

- Settings page với form validation
- Security status page với charts
- Access control page
- Migration wizard UI
- Real-time WebSocket updates
- Export/Import functionality

## 🐛 Troubleshooting

### Build errors

```bash
# Clear cache and rebuild
rm -rf node_modules
npm install
npm run build
```

### CORS errors in development

Vite proxy đã được config trong `vite.config.ts`:
```ts
proxy: {
  '/wp-json': {
    target: 'https://oliversuites.com',
    changeOrigin: true,
    secure: false,
  },
}
```

### TypeScript errors

```bash
# Check types without building
npm run type-check
```

## 📚 Resources

- [React Documentation](https://react.dev/)
- [Ant Design 5.0](https://ant.design/)
- [Redux Toolkit](https://redux-toolkit.js.org/)
- [Redux Observable](https://redux-observable.js.org/)
- [RxJS](https://rxjs.dev/)

