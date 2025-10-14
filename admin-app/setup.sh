#!/bin/bash

echo "🚀 WP Security Monitor - React UI Setup"
echo "========================================"
echo ""

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js chưa được cài đặt!"
    echo "📥 Download tại: https://nodejs.org/"
    exit 1
fi

echo "✅ Node.js version: $(node -v)"
echo "✅ npm version: $(npm -v)"
echo ""

# Install dependencies
echo "📦 Đang cài đặt dependencies..."
npm install

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Setup thành công!"
    echo ""
    echo "🎯 Bước tiếp theo:"
    echo "   1. Chạy: npm run dev"
    echo "   2. Vào: wp-admin/admin.php?page=wp-security-monitor-react-app"
    echo "   3. Reload trang → React UI sẽ xuất hiện!"
    echo ""

    # Ask to start dev server
    read -p "🚀 Chạy dev server ngay bây giờ? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        npm run dev
    fi
else
    echo ""
    echo "❌ Setup thất bại!"
    echo "Vui lòng check lỗi ở trên."
    exit 1
fi

