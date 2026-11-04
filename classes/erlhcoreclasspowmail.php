<?php

/**
 * HTML e-mail layout + automatic wrapping of every mail sent by Live Helper Chat.
 *
 * Core mails (password reminder, chat transcript, notifications, ...) call
 * erLhcoreClassChatMail::setupSMTP($mail) which dispatches 'chatmail.setup_smtp'.
 * In most core mail functions Body is already filled at that point, so we can
 * re-write it into a clean HTML layout (plain text kept as AltBody).
 */
#[\AllowDynamicProperties]
class erLhcoreClassPowMail
{
    public const MARKER = '<!--lhcpow-mail-->';

    public static function onSetupSmtp($params)
    {
        try {
            $mail = (is_array($params) && isset($params['phpmailer'])) ? $params['phpmailer'] : null;
            if (!is_object($mail)) {
                return null;
            }
            $settings = erLhcoreClassPowCaptcha::getRecaptchaSettings();
            if ((int)$settings['pow_html_mail'] === 1) {
                self::wrap($mail);
            }
        } catch (\Throwable $e) {
            error_log('lhc_powcaptcha html_mail_failed: ' . $e->getMessage());
        }
        // Never stop the core SMTP setup
        return null;
    }

    public static function wrap($mail): void
    {
        $body = (string)$mail->Body;

        if (trim($body) === '' || strpos($body, self::MARKER) !== false || preg_match('/<html[\s>]/i', $body)) {
            return;
        }

        $looksHtml = ($mail->ContentType === 'text/html') || preg_match('/<(br|p|div|table|ul|ol|h[1-6])[\s>\/]/i', $body);

        if ($looksHtml) {
            $inner = self::sanitizeHtml($body);
            if (stripos($inner, '<br') === false && stripos($inner, '<p') === false) {
                $inner = nl2br($inner);
            }
            $plain = (string)$mail->AltBody !== '' ? (string)$mail->AltBody : self::htmlToText($body);
        } else {
            $inner = self::textToHtml($body);
            $plain = (string)$mail->AltBody !== '' ? (string)$mail->AltBody : $body;
        }

        $mail->isHTML(true);
        $mail->Body = self::layout((string)$mail->Subject, $inner);
        $mail->AltBody = $plain;
    }

    public static function textToHtml(string $text): string
    {
        $html = htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $html = preg_replace('~(https?://[^\s<&]+(?:&amp;[^\s<&]+)*)~i', '<a href="$1" style="color:#2b6cb0;">$1</a>', $html);
        return nl2br($html);
    }

    public static function sanitizeHtml(string $html): string
    {
        $html = preg_replace('~<(script|style|iframe|object|embed|form)\b.*?</\1>~is', '', $html);
        $allowed = '<a><b><strong><i><em><u><br><p><div><span><ul><ol><li><table><thead><tbody><tr><td><th><h1><h2><h3><h4><hr><blockquote><pre><code><img>';
        $html = strip_tags($html, $allowed);
        $html = preg_replace('~\son\w+\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]+)~i', '', $html);
        $html = preg_replace('~(href|src)\s*=\s*(["\'])\s*(?:javascript|vbscript|data):[^"\']*\2~i', '$1=$2#$2', $html);
        return $html;
    }

    public static function htmlToText(string $html): string
    {
        $t = preg_replace('~<br\s*/?>|</p>|</div>|</tr>|</li>~i', "\n", $html);
        $t = preg_replace_callback('~<a\b[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>~is', function ($m) {
            return trim(strip_tags($m[2])) . ' (' . $m[1] . ')';
        }, $t);
        return trim(html_entity_decode(strip_tags($t), ENT_QUOTES, 'UTF-8'));
    }

    /** Small helpers to build content blocks */
    public static function esc(string $s): string
    {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    public static function codeBox(string $code): string
    {
        return '<div style="margin:24px 0;text-align:center;"><span style="display:inline-block;padding:14px 28px;background:#edf2f7;border:1px dashed #a0aec0;border-radius:8px;font:700 32px/1.2 Consolas,Menlo,monospace;letter-spacing:8px;color:#1a202c;">' . self::esc($code) . '</span></div>';
    }

    public static function infoTable(array $rows): string
    {
        $out = '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:16px 0;border-collapse:collapse;">';
        foreach ($rows as $label => $value) {
            $out .= '<tr><td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;color:#718096;font-size:13px;width:34%;vertical-align:top;">' . self::esc((string)$label) . '</td>'
                . '<td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;color:#2d3748;font-size:14px;word-break:break-word;">' . self::esc((string)$value) . '</td></tr>';
        }
        return $out . '</table>';
    }

    public static function layout(string $heading, string $innerHtml, string $preheader = ''): string
    {
        $site = 'Live Helper Chat';
        if (class_exists('erConfigClassLhConfig')) {
            $site = (string)\erConfigClassLhConfig::getInstance()->getSetting('site', 'title') ?: $site;
        }
        $host = isset($_SERVER['HTTP_HOST']) ? (string)$_SERVER['HTTP_HOST'] : '';
        $year = date('Y');

        return self::MARKER . '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            . '<title>' . self::esc($heading) . '</title></head>'
            . '<body style="margin:0;padding:0;background:#f4f6f8;">'
            . '<div style="display:none;max-height:0;overflow:hidden;opacity:0;">' . self::esc($preheader !== '' ? $preheader : $heading) . '</div>'
            . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f8;padding:24px 12px;"><tr><td align="center">'
            . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:600px;background:#ffffff;border-radius:10px;overflow:hidden;border:1px solid #e2e8f0;">'
            . '<tr><td style="background:#2b6cb0;padding:18px 28px;font:600 18px/1.3 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#ffffff;">' . self::esc($site) . '</td></tr>'
            . '<tr><td style="padding:28px;font:15px/1.6 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#2d3748;">'
            . '<h1 style="margin:0 0 16px;font-size:20px;line-height:1.3;color:#1a202c;">' . self::esc($heading) . '</h1>'
            . $innerHtml
            . '</td></tr>'
            . '<tr><td style="padding:16px 28px;background:#f7fafc;border-top:1px solid #e2e8f0;font:12px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#a0aec0;">'
            . self::esc($site) . ($host !== '' ? ' &middot; ' . self::esc($host) : '') . ' &middot; &copy; ' . $year
            . '</td></tr></table></td></tr></table></body></html>';
    }
}
