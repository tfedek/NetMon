<?php
/**
 * Mailer – koristi PHPMailer (phpmailer/phpmailer via Composer)
 *
 * Instalacija: composer install
 * Greske slanja se loguju u bazu
 */

// Ucitaj Composer autoload ako postoji, inace manuelno
if (file_exists(__DIR__ . '/../vendor/autoload.php')) {
    require_once __DIR__ . '/../vendor/autoload.php';
} else {
    // Manuelni fallback ako Composer nije pokrenut
    $phpmailerSrc = __DIR__ . '/PHPMailer/src';
    if (file_exists($phpmailerSrc . '/PHPMailer.php')) {
        require_once $phpmailerSrc . '/Exception.php';
        require_once $phpmailerSrc . '/PHPMailer.php';
        require_once $phpmailerSrc . '/SMTP.php';
    }
}

/**
 * Salje email za resetovanje lozinke.
 *
 * @param string $toEmail  Email primaoca
 * @param string $toName   Ime primaoca
 * @param string $token    Reset token
 * @return bool            true ako je poslato uspesno
 */
function send_reset_email(string $toEmail, string $toName, string $token): bool {
    $resetLink = APP_URL . '/reset-password.php?token=' . urlencode($token);
    $subject   = '[' . APP_NAME . '] Resetovanje lozinke';
    $htmlBody  = <<<HTML
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:30px;background:#0d1117;color:#e6edf3;border-radius:8px;">
      <h2 style="color:#58a6ff;margin-top:0;">Resetovanje lozinke</h2>
      <p>Zdravo <strong>{$toName}</strong>,</p>
      <p>Zatražili ste resetovanje lozinke za <strong>NetMon</strong> nalog.</p>
      <p>Kliknite dugme ispod za postavljanje nove lozinke. Link ističe za <strong>1 sat</strong>.</p>
      <p style="text-align:center;margin:30px 0;">
        <a href="{$resetLink}" style="background:#238636;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:bold;">
          Resetuj lozinku
        </a>
      </p>
      <p style="font-size:12px;color:#8b949e;">
        Ako dugme ne radi, kopirajte ovaj link u browser:<br>
        <a href="{$resetLink}" style="color:#58a6ff;">{$resetLink}</a>
      </p>
      <hr style="border-color:#30363d;margin:24px 0;">
      <p style="font-size:12px;color:#8b949e;">
        Ako niste tražili resetovanje, ignorišite ovaj email.
      </p>
    </div>
    HTML;

    if (!class_exists('PHPMailer\PHPMailer\PHPMailer')) {
        // Fallback: PHP mail()
        $headers  = "MIME-Version: 1.0\r\n";
        $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
        $headers .= "From: " . MAIL_FROM_NAME . " <" . MAIL_FROM . ">\r\n";
        return mail($toEmail, $subject, $htmlBody, $headers);
    }

    try {
        $mail = new PHPMailer\PHPMailer\PHPMailer(true);
        $mail->isSMTP();
        $mail->Host       = MAIL_HOST;
        $mail->SMTPAuth   = true;
        $mail->Username   = MAIL_USER;
        $mail->Password   = MAIL_PASS;
        $mail->SMTPSecure = MAIL_ENCRYPTION === 'tls'
            ? PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS
            : PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS;
        $mail->Port       = (int) MAIL_PORT;
        $mail->CharSet    = 'UTF-8';
        $mail->setFrom(MAIL_FROM, MAIL_FROM_NAME);
        $mail->addAddress($toEmail, $toName);
        $mail->isHTML(true);
        $mail->Subject = $subject;
        $mail->Body    = $htmlBody;
        $mail->AltBody = strip_tags(str_replace(['<br>', '<br/>'], "\n", $htmlBody));
        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log('Mailer error: ' . $e->getMessage());
        return false;
    }
}
