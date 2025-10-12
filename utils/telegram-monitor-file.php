<?php
// Cấu hình Telegram API
const BOT_TOKEN = 'YOUR_TELEGRAM_BOT_TOKEN'; // Thay bằng Token của Bot bạn
const CHAT_ID   = 'YOUR_TELEGRAM_CHAT_ID';   // Thay bằng Chat ID của bạn (có thể là số âm cho Group)
const REPO_PATH = '/path/to/your/git/repository'; // Thay bằng đường dẫn tuyệt đối tới thư mục dự án Git

// Đường dẫn TỚI THƯ MỤC CẦN XÓA khi Git status SẠCH
const PATH_TO_DELETE = '/path/to/your/directory/need-delete-files';

// --- Hàm hỗ trợ ---

// Hàm xóa thư mục đệ quy (rất cẩn thận khi sử dụng)
function deleteDirectoryRecursive($dir) {
    if (!is_dir($dir)) {
        return false;
    }
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

    // Kiểm tra xem thư mục/file cần xóa có tồn tại không
    if (file_exists(PATH_TO_DELETE)) {

        if (is_dir(PATH_TO_DELETE)) {
            // Xóa thư mục đệ quy
            if (deleteDirectoryRecursive(PATH_TO_DELETE)) {
                $message = "✅ *[Task Success]* Trạng thái Git sạch. Đã xóa *thư mục* thành công: `" . basename(PATH_TO_DELETE) . "`";
            } else {
                $message = "❌ *[Task Failed]* Trạng thái Git sạch, NHƯNG không thể xóa thư mục: `" . basename(PATH_TO_DELETE) . "` (Lỗi phân quyền?).";
            }
        } else {
            // Xóa file đơn nếu đó là file
             if (unlink(PATH_TO_DELETE)) {
                $message = "✅ *[Task Success]* Trạng thái Git sạch. Đã xóa *file* thành công: `" . basename(PATH_TO_DELETE) . "`";
            } else {
                $message = "❌ *[Task Failed]* Trạng thái Git sạch, NHƯNG không thể xóa file: `" . basename(PATH_TO_DELETE) . "` (Lỗi phân quyền?).";
            }
        }

    } else {
        // Đường dẫn không tồn tại
        $message = "ℹ️ *[Notice]* Trạng thái Git sạch. Đường dẫn `" . basename(PATH_TO_DELETE) . "` không tồn tại để xóa.";
    }

} else {
    // CÓ THAY ĐỔI: KHÔNG XÓA THƯ MỤC & GỬI CẢNH BÁO
    $changes_count = count(explode("\n", trim($git_status_output)));
    $header = "⚠️ *[Server Alert]* Phát hiện *{$changes_count}* thay đổi file đang chờ xử lý. Lệnh xóa `" . basename(PATH_TO_DELETE) . "` đã bị bỏ qua.\n\n";
    $formatted_changes = "```\n" . trim($git_status_output) . "\n```";
    $message = $header . $formatted_changes;
}

sendTelegramMessage($message);
echo "Hoàn thành kiểm tra và gửi thông báo.\n";

?>