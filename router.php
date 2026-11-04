<?php
declare(strict_types=1);

/**
 * Router per il server integrato PHP (php -S 127.0.0.1:8080 router.php).
 * Replica le regole di sicurezza di .htaccess bloccando cartelle interne, dotfile,
 * documentazione operativa (.md/.txt), file temporanei/lock ed esecuzione script in /uploads.
 */
$uri = rawurldecode((string) parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH));
if ($uri === '' || $uri[0] !== '/') {
    $uri = '/' . $uri;
}

$blockedPath = preg_match('#^/(storage|includes|Materiale)(/|$)#i', $uri)
    || preg_match('#(^|/)\.[^/]+#', $uri)
    || preg_match('#^/router\.php$#i', $uri)
    || preg_match('#\.(md|txt|lock|tmp|bak|log|ini|sh|sql)$#i', $uri)
    || preg_match('#^/uploads/.*\.(php|phtml|php[0-9]|phar)$#i', $uri);

if ($blockedPath) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    echo '403 Accesso negato.';
    return true;
}

if ($uri === '/' || $uri === '/index.php') {
    require __DIR__ . '/index.php';
    return true;
}

$fullPath = __DIR__ . $uri;
$realRoot = realpath(__DIR__);
$realTarget = realpath($fullPath);

if ($realRoot !== false && $realTarget !== false && !str_starts_with($realTarget, $realRoot)) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    echo '403 Accesso negato.';
    return true;
}

if ($realTarget !== false && is_dir($realTarget)) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    echo '403 Accesso negato.';
    return true;
}

if ($realTarget !== false && is_file($realTarget)) {
    return false;
}

http_response_code(404);
header('Content-Type: text/plain; charset=UTF-8');
echo '404 Risorsa non trovata.';
return true;
