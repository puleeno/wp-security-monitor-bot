<?php
// Cấu hình Telegram API
const BOT_TOKEN = 'YOUR_TELEGRAM_BOT_TOKEN'; // Thay bằng Token của Bot bạn
const CHAT_ID   = 'YOUR_TELEGRAM_CHAT_ID';   // Thay bằng Chat ID của bạn (có thể là số âm cho Group)
const REPO_PATH = '/path/to/your/git/repository'; // Thay bằng đường dẫn tuyệt đối tới thư mục dự án Git

// Đường dẫn TỚI THƯ MỤC CẦN XÓA khi Git status SẠCH
const PATH_TO_DELETE = '/path/to/your/directory/need-delete-files';
// --- Hàm hỗ trợ ---

// Hàm dọn dẹp nội dung thư mục (giữ lại thư mục gốc)
function cleanDirectoryContent($dir) {
    if (!is_dir($dir)) {
        return false;
    }

    $deleted_count = 0;
    // Lặp qua tất cả nội dung ngoại trừ '.' và '..'
    $files = array_diff(scandir($dir), ['.', '..']);

    foreach ($files as $file) {
        $path = "$dir/$file";

        if (is_dir($path)) {
            // Nếu là thư mục con, xóa đệ quy thư mục con đó
            if (deleteDirectoryRecursive($path)) {
                $deleted_count++;
            }
        } else {
            // Nếu là file, xóa file
            if (unlink($path)) {
                $deleted_count++;
            }
        }
    }
    return $deleted_count;
}

// Hàm xóa thư mục đệ quy (chỉ dùng cho thư mục con)
function deleteDirectoryRecursive($dir) {
    $files = array_diff(scandir($dir), ['.', '..']);
    foreach ($files as $file) {
        (is_dir("$dir/$file")) ? deleteDirectoryRecursive("$dir/$file") : unlink("$dir/$file");
    }
    return rmdir($dir);
}

// Hàm gửi tin nhắn tới Telegram
function sendTelegramMessage($message) {
    $url = 'https://api.telegram.org/bot' . BOT_TOKEN . '/sendMessage';
    $params = [
        'chat_id'    => CHAT_ID,
        'text'       => $message,
        'parse_mode' => 'Markdown'
    ];
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_exec($ch);
    curl_close($ch);
}

// --- Logic chính ---

// 1. Kiểm tra trạng thái Git
chdir(REPO_PATH);
$git_status_output = shell_exec('git status --porcelain');

// 2. Phân tích kết quả và thực hiện hành động
if (empty(trim($git_status_output))) {
    // TRẠNG THÁI SẠCH: KHÔNG CÓ THAY ĐỔI NÀO

    if (is_dir(PATH_TO_DELETE)) {
        // Tiến hành dọn dẹp nội dung thư mục
        $deleted_count = cleanDirectoryContent(PATH_TO_DELETE);

        if ($deleted_count > 0) {
            $message = "✅ *[Task Success]* Trạng thái Git sạch. Đã dọn dẹp thành công *$deleted_count* mục (files/thư mục) bên trong thư mục `" . basename(PATH_TO_DELETE) . "`.";
        } elseif ($deleted_count === 0) {
            $message = "ℹ️ *[Notice]* Trạng thái Git sạch. Thư mục `" . basename(PATH_TO_DELETE) . "` đã trống, không cần dọn dẹp.";
        } else {
            $message = "❌ *[Task Failed]* Trạng thái Git sạch, NHƯNG xảy ra lỗi khi dọn dẹp thư mục: `" . basename(PATH_TO_DELETE) . "` (Lỗi phân quyền?).";
        }
    } else {
        // Thư mục gốc không tồn tại
        $message = "ℹ️ *[Notice]* Trạng thái Git sạch. Thư mục mục tiêu `" . basename(PATH_TO_DELETE) . "` không tồn tại.";
    }

} else {
    // CÓ THAY ĐỔI: KHÔNG DỌN DẸP & GỬI CẢNH BÁO
    $changes_count = count(explode("\n", trim($git_status_output)));
    $header = "⚠️ *[Server Alert]* Phát hiện *{$changes_count}* thay đổi file đang chờ xử lý. Lệnh dọn dẹp `" . basename(PATH_TO_DELETE) . "` đã bị bỏ qua.\n\n";
    $formatted_changes = "```\n" . trim($git_status_output) . "\n```";
    $message = $header . $formatted_changes;
}

sendTelegramMessage($message);
echo "Hoàn thành kiểm tra và gửi thông báo.\n";

?>