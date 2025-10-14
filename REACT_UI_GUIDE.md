# 🚀 React Admin UI - Quick Start Guide

## Giới thiệu

Plugin đã được nâng cấp với **React TypeScript Admin UI** sử dụng:
- ✅ **React 18** + **TypeScript Strict Mode**
- ✅ **Ant Design 5.0** - UI components đẹp và nhẹ
- ✅ **Redux + Redux Observable** - State management mạnh mẽ
- ✅ **Vite** - Build tool cực nhanh

## 📦 Cài đặt

### Bước 1: Cài đặt Node.js

Yêu cầu: **Node.js 18+** và **npm 9+**

Download tại: https://nodejs.org/

### Bước 2: Cài đặt dependencies

```bash
cd wp-content/plugins/wp-security-monitor-bot/admin-app
npm install
```

### Bước 3: Chọn mode

#### A. Development Mode (Recommended cho dev)

```bash
npm run dev
```

- Hot reload tức thì
- Source maps đầy đủ
- Fast refresh
- Dev server tại `http://localhost:3000`

Sau đó vào WordPress admin:
```
wp-admin/admin.php?page=wp-security-monitor-react-app
```

#### B. Production Mode

```bash
npm run build
```

Build output → `../assets/admin-app/`

Vào WordPress admin:
```
wp-admin/admin.php?page=wp-security-monitor-react-app
```

## 🎨 Features

### Dashboard
- 📊 Stats cards: Tổng issues, Issues mới, Resolved, Monitors
- 🚨 Bot status alert
- 📋 Recent issues table
- 📈 Severity breakdown
- 🔍 Top issuers

### Issues Page
- 📝 Full table với pagination
- 👁️ Mark as viewed
- 🚫 Ignore issue
- ✅ Resolve issue
- 📂 Issue details drawer với backtrace
- 🔍 Filters: status, severity, issuer, search

## 🛠️ Development

### File Structure

```
admin-app/
├── src/
│   ├── App.tsx                    # Main app component
│   ├── main.tsx                   # Entry point
│   ├── components/
│   │   └── Layout/MainLayout.tsx  # Layout với sidebar
│   ├── pages/
│   │   ├── Dashboard.tsx          # ✅ Hoàn chỉnh
│   │   ├── Issues.tsx             # ✅ Hoàn chỉnh
│   │   ├── Settings.tsx           # Placeholder
│   │   ├── Security.tsx           # Placeholder
│   │   ├── AccessControl.tsx      # Placeholder
│   │   └── Migration.tsx          # Placeholder
│   ├── store/                     # Redux store
│   ├── reducers/                  # Redux slices
│   ├── epics/                     # Redux Observable
│   ├── services/                  # API services
│   ├── types/                     # TypeScript types
│   └── utils/                     # Utilities
├── package.json
├── tsconfig.json                  # Strict mode
├── vite.config.ts
└── index.html
```

### Available Scripts

```bash
npm run dev          # Start dev server
npm run build        # Build for production
npm run preview      # Preview production build
npm run type-check   # TypeScript type checking
```

### Ant Design Theme

Custom colors khớp với WordPress:

```ts
{
  colorPrimary: '#2271b1',    // WordPress blue
  colorSuccess: '#00a32a',     // Green
  colorWarning: '#dba617',     // Yellow
  colorError: '#d63638',       // Red
}
```

## 🔌 WordPress Integration

### REST API Endpoints

Backend PHP tự động register các endpoints:

- `/wp-json/wp-security-monitor/v1/issues`
- `/wp-json/wp-security-monitor/v1/stats/security`
- `/wp-json/wp-security-monitor/v1/stats/bot`
- `/wp-json/wp-security-monitor/v1/settings`

### Access trong WordPress

Menu item: **Puleeno Security → 🚀 New UI**

## 🎯 Roadmap

### Phase 1: Core Features (✅ Hoàn thành)
- ✅ Project setup
- ✅ Redux + Redux Observable
- ✅ Dashboard page
- ✅ Issues page với full CRUD
- ✅ REST API integration

### Phase 2: Full Migration (🚧 Đang làm)
- ⏳ Settings page
- ⏳ Security status page
- ⏳ Access control page
- ⏳ Migration wizard
- ⏳ Charts & visualizations

### Phase 3: Advanced Features (📋 Todo)
- ⏳ Real-time updates với WebSocket
- ⏳ Export/Import
- ⏳ Advanced filters
- ⏳ Bulk actions
- ⏳ Dark mode

## 🆘 Troubleshooting

### Error: Cannot find module

```bash
rm -rf node_modules package-lock.json
npm install
```

### Vite dev server không chạy

```bash
npm run dev -- --host 0.0.0.0 --port 3000
```

### Build bị lỗi TypeScript

```bash
npm run type-check
# Fix các type errors trước khi build
```

### WordPress không load React app

1. Check `WP_DEBUG` = `true` trong `wp-config.php`
2. Check dev server đang chạy: `http://localhost:3000`
3. Check REST API hoạt động: `/wp-json/wp-security-monitor/v1/issues`
4. Check browser console có errors không

## 💡 Tips

- **Dev mode**: Nhanh, hot reload, dễ debug
- **Prod mode**: Optimized, minified, no source maps
- **Type safety**: TypeScript strict mode bắt lỗi sớm
- **Code splitting**: Vite tự động split chunks
- **Tree shaking**: Chỉ bundle code được dùng

## 📝 Notes

- React UI **TÙY CHỌN** - PHP admin vẫn hoạt động bình thường
- Có thể chuyển đổi giữa PHP UI và React UI
- Dữ liệu được sync qua cùng database
- REST API được bảo vệ với WordPress nonce

Enjoy the new UI! 🎉

