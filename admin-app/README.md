# WP Security Monitor - React Admin UI

Modern React TypeScript admin interface với Ant Design 5.0, Redux, và Redux Observable.

## 🚀 Tech Stack

- **React 18** - UI library
- **TypeScript (Strict Mode)** - Type safety
- **Ant Design 5.0** - UI components
- **Redux Toolkit** - State management
- **Redux Observable** - Side effects với RxJS
- **React Router 6** - Navigation
- **Vite** - Build tool
- **Axios** - HTTP client

## 📁 Project Structure

```
admin-app/
├── src/
│   ├── components/     # React components
│   ├── pages/          # Page components
│   ├── store/          # Redux store
│   ├── reducers/       # Redux slices
│   ├── epics/          # Redux Observable epics
│   ├── services/       # API services
│   ├── types/          # TypeScript types
│   ├── utils/          # Utilities
│   └── styles/         # Global styles
├── package.json
├── tsconfig.json
├── vite.config.ts
└── index.html
```

## 🛠️ Development

### Install dependencies
```bash
npm install
```

### Run development server
```bash
npm run dev
```

### Build for production
```bash
npm run build
```

### Type check
```bash
npm run type-check
```

## 🎨 Features

- ✅ TypeScript strict mode
- ✅ Redux + Redux Observable cho state management
- ✅ Ant Design 5.0 với custom theme
- ✅ React Router cho navigation
- ✅ REST API integration với WordPress
- ✅ Loading states và error handling
- ✅ Responsive design
- ✅ Vietnamese localization

## 📦 Build Output

Build output sẽ được tạo trong:
```
../assets/admin-app/
```

WordPress plugin sẽ load files từ folder này.

