<?php
namespace Puleeno\SecurityBot\WebMonitor\Channels;

use Puleeno\SecurityBot\WebMonitor\Abstracts\Channel;

class EmailChannel extends Channel
{
    public function getName(): string
    {
        return 'Email';
    }

    public function send(string $message, array $data = []): bool
    {
        try {
            $to = $this->getConfig('to');
            if (empty($to)) {
                $this->logError('Email recipient không được cấu hình');
                return false;
            }

            $subject = $this->buildSubject($data);
            $body = $this->buildEmailBody($message, $data);
            $headers = $this->buildHeaders();

            $result = wp_mail($to, $subject, $body, $headers);

            if (!$result) {
                $this->logError('Không thể gửi email');
                return false;
            }

            return true;

        } catch (\Exception $e) {
            $this->logError('Email sending error: ' . $e->getMessage());
            return false;
        }
    }

    protected function checkConnection(): bool
    {
        // Kiểm tra cấu hình WordPress mail
        $to = $this->getConfig('to');
        if (empty($to) || !is_email($to)) {
            return false;
        }

        // Kiểm tra WordPress có thể gửi mail không
        return function_exists('wp_mail');
    }

    /**
     * Tạo subject cho email
     *
     * @param array $data
     * @return string
     */
    private function buildSubject(array $data): string
    {
        $siteName = get_bloginfo('name');
        $issuer = $data['issuer'] ?? 'Security Monitor';

        return sprintf(
            '[%s] 🚨 Cảnh báo bảo mật - %s',
            $siteName,
            $issuer
        );
    }

    /**
     * Tạo nội dung email HTML
     *
     * @param string $message
     * @param array $data
     * @return string
     */
    private function buildEmailBody(string $message, array $data): string
    {
        $siteUrl = home_url();
        $siteName = get_bloginfo('name');
        $timestamp = isset($data['timestamp']) ? date('d/m/Y H:i:s', $data['timestamp']) : date('d/m/Y H:i:s');

        $html = '<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Alert</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #d32f2f; color: white; padding: 20px; text-align: center; }
        .content { background: #f9f9f9; padding: 20px; border: 1px solid #ddd; }
        .footer { background: #666; color: white; padding: 15px; text-align: center; font-size: 12px; }
        .alert-icon { font-size: 48px; }
        .site-info { background: white; padding: 15px; margin: 15px 0; border-left: 4px solid #d32f2f; }
        .issue-list { background: white; padding: 15px; margin: 15px 0; }
        .issue-item { padding: 8px; margin: 5px 0; background: #fff3cd; border-left: 3px solid #856404; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="alert-icon">🚨</div>
            <h1>Cảnh báo bảo mật</h1>
            <p>' . esc_html($siteName) . '</p>
        </div>

        <div class="content">
            <div class="site-info">
                <h3>📍 Thông tin Website</h3>
                <p><strong>Tên site:</strong> ' . esc_html($siteName) . '</p>
                <p><strong>URL:</strong> <a href="' . esc_url($siteUrl) . '">' . esc_url($siteUrl) . '</a></p>
                <p><strong>Thời gian phát hiện:</strong> ' . esc_html($timestamp) . '</p>
                <p><strong>Phát hiện bởi:</strong> ' . esc_html($data['issuer'] ?? 'Unknown') . '</p>
            </div>

            <div class="issue-list">
                <h3>📋 Chi tiết vấn đề</h3>';

        if (isset($data['issues']) && is_array($data['issues'])) {
            foreach ($data['issues'] as $issue) {
                if (is_array($issue)) {
                    $html .= '<div class="issue-item">';
                    $html .= '<strong>' . esc_html($issue['message'] ?? 'Unknown issue') . '</strong>';
                    if (isset($issue['details'])) {
                        $html .= '<br><small>' . esc_html($issue['details']) . '</small>';
                    }
                    $html .= '</div>';
                } else {
                    $html .= '<div class="issue-item">' . esc_html($issue) . '</div>';
                }
            }
        } else {
            $html .= '<div class="issue-item">Xem chi tiết trong tin nhắn gốc</div>';
        }

        $html .= '
            </div>

            <div style="background: white; padding: 15px; margin: 15px 0;">
                <h3>🔍 Hành động được đề xuất</h3>
                <ul>
                    <li>Kiểm tra ngay lập tức các vấn đề được báo cáo</li>
                    <li>Thay đổi mật khẩu admin nếu cần thiết</li>
                    <li>Cập nhật WordPress và plugins lên phiên bản mới nhất</li>
                    <li>Quét malware toàn bộ website</li>
                    <li>Kiểm tra log truy cập để phát hiện hoạt động bất thường</li>
                </ul>
            </div>
        </div>

        <div class="footer">
            <p>Tin nhắn này được gửi tự động bởi WP Security Monitor Bot</p>
            <p>Thời gian: ' . esc_html($timestamp) . '</p>
        </div>
    </div>
</body>
</html>';

        return $html;
    }

    /**
     * Tạo headers cho email
     *
     * @return array
     */
    private function buildHeaders(): array
    {
        $from = $this->getConfig('from', get_option('admin_email'));
        $fromName = $this->getConfig('from_name', get_bloginfo('name') . ' Security Monitor');

        return [
            'Content-Type: text/html; charset=UTF-8',
            'From: ' . $fromName . ' <' . $from . '>',
            'Reply-To: ' . $from,
            'X-Mailer: WP Security Monitor Bot'
        ];
    }

    /**
     * Test gửi email
     *
     * @return bool
     */
    public function testConnection(): bool
    {
        $testData = [
            'issuer' => 'Email Test',
            'timestamp' => time(),
            'issues' => [
                [
                    'message' => 'Đây là email test từ Security Monitor Bot',
                    'details' => 'Email được gửi để kiểm tra cấu hình hoạt động'
                ]
            ]
        ];

        $testMessage = "🤖 *Test email thành công!*\n\n";
        $testMessage .= "Bot Security Monitor đã được cấu hình và có thể gửi email.\n";
        $testMessage .= "⏰ Thời gian test: " . date('d/m/Y H:i:s');

        return $this->send($testMessage, $testData);
    }
}
