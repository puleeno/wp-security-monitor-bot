@echo off
echo ========================================
echo 🚀 WP Security Monitor - React UI Setup
echo ========================================
echo.

REM Check if Node.js is installed
where node >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo ❌ Node.js chưa được cài đặt!
    echo 📥 Download tại: https://nodejs.org/
    pause
    exit /b 1
)

echo ✅ Node.js installed
node -v
npm -v
echo.

REM Install dependencies
echo 📦 Đang cài đặt dependencies...
call npm install

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✅ Setup thành công!
    echo.
    echo 🎯 Bước tiếp theo:
    echo    1. Chạy: npm run dev
    echo    2. Vào: wp-admin/admin.php?page=wp-security-monitor-react-app
    echo    3. Reload trang → React UI sẽ xuất hiện!
    echo.

    set /p answer="🚀 Chạy dev server ngay bây giờ? (y/n): "
    if /i "%answer%"=="y" (
        call npm run dev
    )
) else (
    echo.
    echo ❌ Setup thất bại!
    echo Vui lòng check lỗi ở trên.
    pause
    exit /b 1
)

