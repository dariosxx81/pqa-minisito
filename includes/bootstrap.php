<?php
declare(strict_types=1);

if (basename($_SERVER['SCRIPT_FILENAME'] ?? '') === basename(__FILE__)) {
    http_response_code(403);
    exit;
}

define('PQA_ROOT_DIR', dirname(__DIR__));
define('PQA_STORAGE_DIR', PQA_ROOT_DIR . '/storage');
define('PQA_DOCS_DIR', PQA_STORAGE_DIR . '/docs');
define('PQA_BRAND_DIR', PQA_ROOT_DIR . '/uploads/brand');

date_default_timezone_set('Europe/Rome');

// Creazione automatica cartelle essenziali e guard index.php
foreach ([PQA_STORAGE_DIR, PQA_DOCS_DIR, dirname(PQA_BRAND_DIR), PQA_BRAND_DIR] as $dir) {
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }
    $guardIndex = $dir . '/index.php';
    if (is_dir($dir) && !is_file($guardIndex)) {
        @file_put_contents($guardIndex, "<?php\nhttp_response_code(403);\nexit('Accesso negato.');\n");
    }
}

require_once __DIR__ . '/storage.php';

/**
 * Avvia la sessione PHP con parametri di sicurezza rigorosi (HttpOnly, SameSite, Strict Mode).
 */
function pqa_start_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https')
        || ((int) ($_SERVER['SERVER_PORT'] ?? 80) === 443);

    @ini_set('session.use_strict_mode', '1');
    @ini_set('session.use_only_cookies', '1');

    session_name('pqa_sess');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);

    session_start();
}

/**
 * Invia security headers standard per pagine HTML.
 */
function pqa_send_security_headers(bool $allowSameOriginFrame = false): void
{
    if (headers_sent()) {
        return;
    }
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: ' . ($allowSameOriginFrame ? 'SAMEORIGIN' : 'DENY'));
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
}

/**
 * Genera o recupera il token CSRF legato alla sessione corrente.
 */
function pqa_csrf_token(): string
{
    pqa_start_session();
    if (empty($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Verifica il token CSRF inviato via POST o header X-CSRF-Token.
 */
function pqa_verify_csrf(?string $submitted): bool
{
    pqa_start_session();
    if (empty($_SESSION['csrf_token']) || !is_string($submitted) || $submitted === '') {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $submitted);
}

/**
 * Escape HTML sicuro in UTF-8.
 */
function pqa_e(?string $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Restituisce l'indirizzo IP del client (senza fidarsi ciecamente di X-Forwarded-For spoofing).
 */
function pqa_client_ip(): string
{
    return (string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
}

/**
 * Controlla se la sessione appartiene a un amministratore autenticato e non scaduto.
 */
function pqa_is_admin_logged_in(): bool
{
    pqa_start_session();
    if (empty($_SESSION['pqa_admin_auth'])) {
        return false;
    }
    $lastActive = (int) ($_SESSION['pqa_admin_last_active'] ?? 0);
    if ($lastActive > 0 && (time() - $lastActive) > 7200) {
        // Timeout inattività 2 ore
        $_SESSION = [];
        session_destroy();
        return false;
    }
    $_SESSION['pqa_admin_last_active'] = time();
    return true;
}
