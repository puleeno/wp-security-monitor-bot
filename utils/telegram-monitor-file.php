<?php
// Cấu hình Telegram API
const BOT_TOKEN = 'YOUR_TELEGRAM_BOT_TOKEN'; // Thay bằng Token của Bot bạn
const CHAT_ID   = 'YOUR_TELEGRAM_CHAT_ID';   // Thay bằng Chat ID của bạn (có thể là số âm cho Group)
const REPO_PATH = '/path/to/your/git/repository'; // Thay bằng đường dẫn tuyệt đối tới thư mục dự án Git

// Hàm gửi tin nhắn tới Telegram
function sendTelegramMessage($message) {
    $url = 'https://api.telegram.org/bot' . BOT_TOKEN . '/sendMessage';

    // Sử dụng chế độ Markdown để định dạng
    $params = [
        'chat_id'    => CHAT_ID,
        'text'       => $message,
        'parse_mode' => 'Markdown'
    ];

    // Khởi tạo cURL
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

    $response = curl_exec($ch);
    curl_close($ch);

    // (Tùy chọn) Ghi log hoặc kiểm tra lỗi phản hồi
    // return $response;
}

// 1. Kiểm tra trạng thái Git
chdir(REPO_PATH);
$git_status_output = shell_exec('git status --porcelain'); // Sử dụng --porcelain để lấy output dễ xử lý hơn

// 2. Phân tích kết quả
if (empty(trim($git_status_output))) {
    // Không có thay đổi nào
    $message = "✅ *[Server Notice]* Không có thay đổi file nào đang chờ xử lý trong kho lưu trữ Git.";
    // Tùy chọn: Bỏ qua việc gửi tin nhắn nếu không có thay đổi
    // sendTelegramMessage($message);
} else {
    // Có thay đổi, chuẩn bị nội dung thông báo
    $changes_count = count(explode("\n", trim($git_status_output)));

    $header = "⚠️ *[Server Alert]* Phát hiện *{$changes_count}* thay đổi file đang chờ xử lý trên server:\n\n";

    // Định dạng nội dung thay đổi cho dễ đọc trong Telegram (Markdown)
    // Thay thế các ký tự đặc biệt của Markdown V2 nếu cần thiết, nhưng dùng Markdown thường là đủ
    $formatted_changes = "```\n" . trim($git_status_output) . "\n```";

    $full_message = $header . $formatted_changes;

    // 3. Gửi thông báo
    sendTelegramMessage($full_message);
}

echo "Hoàn thành kiểm tra và gửi thông báo.\n";

?>
