<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/includes/bootstrap.php';

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET' && ($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'HEAD') {
    http_response_code(405);
    header('Allow: GET, HEAD');
    exit;
}

$docId = trim((string) ($_GET['id'] ?? ''));
$mode = strtolower(trim((string) ($_GET['mode'] ?? 'inline')));
if (!in_array($mode, ['inline', 'download'], true)) {
    $mode = 'inline';
}

$docs = pqa_get_documents();
if ($docId === '' || !isset($docs[$docId])) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=UTF-8');
    exit('Documento non trovato.');
}

$doc = $docs[$docId];

if (empty($doc['visible'])) {
    $isAdmin = pqa_is_admin_logged_in();
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_write_close();
    }
    if (!$isAdmin) {
        http_response_code(404);
        header('Content-Type: text/plain; charset=UTF-8');
        exit('Documento non disponibile.');
    }
}

if (empty($doc['is_available']) || empty($doc['file']['stored_name'])) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=UTF-8');
    exit('Il documento è attualmente in fase di aggiornamento.');
}

$storedName = basename((string) $doc['file']['stored_name']);
$filePath = PQA_DOCS_DIR . '/' . $storedName;

if (!is_file($filePath) || !is_readable($filePath)) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=UTF-8');
    exit('File PDF non reperibile.');
}

$fileSize = filesize($filePath);
if ($fileSize === false || $fileSize <= 0) {
    http_response_code(404);
    exit;
}

$downloadName = preg_replace('/[^A-Za-z0-9._-]/', '-', (string) ($doc['download_name'] ?? ($docId . '.pdf'))) ?: ($docId . '.pdf');
if (!str_ends_with(strtolower($downloadName), '.pdf')) {
    $downloadName .= '.pdf';
}

while (ob_get_level() > 0) {
    ob_end_clean();
}

$disposition = ($mode === 'download') ? 'attachment' : 'inline';

header('Content-Type: application/pdf');
header('Content-Disposition: ' . $disposition . '; filename="' . $downloadName . '"');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: SAMEORIGIN');
header("Content-Security-Policy: frame-ancestors 'self'");
header('Accept-Ranges: bytes');
header('Cache-Control: private, max-age=300');

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'HEAD') {
    header('Content-Length: ' . $fileSize);
    exit;
}

// Supporto HTTP Range conforme a RFC 9110 per caricamento fluido nei visualizzatori PDF integrati
$start = 0;
$end = $fileSize - 1;
$length = $fileSize;

$rangeHeader = trim((string) ($_SERVER['HTTP_RANGE'] ?? ''));
if ($rangeHeader !== '' && stripos($rangeHeader, 'bytes=') === 0) {
    if (!preg_match('/^bytes=(\d+-\d*|\d*-\d+)$/i', $rangeHeader, $specMatch)) {
        http_response_code(416);
        header("Content-Range: bytes */{$fileSize}");
        exit;
    }

    [$rawStart, $rawEnd] = explode('-', $specMatch[1], 2);
    $rangeStart = $rawStart !== '' ? (int) $rawStart : null;
    $rangeEnd = $rawEnd !== '' ? (int) $rawEnd : null;

    if ($rangeStart === null && $rangeEnd !== null) {
        if ($rangeEnd <= 0) {
            http_response_code(416);
            header("Content-Range: bytes */{$fileSize}");
            exit;
        }
        $start = max(0, $fileSize - $rangeEnd);
    } elseif ($rangeStart !== null) {
        $start = $rangeStart;
        if ($rangeEnd !== null && $rangeEnd < $fileSize) {
            $end = $rangeEnd;
        }
    }

    if ($start > $end || $start >= $fileSize) {
        http_response_code(416);
        header("Content-Range: bytes */{$fileSize}");
        exit;
    }

    $length = ($end - $start) + 1;
    http_response_code(206);
    header("Content-Range: bytes {$start}-{$end}/{$fileSize}");
}

header('Content-Length: ' . $length);

$fp = fopen($filePath, 'rb');
if ($fp === false) {
    http_response_code(500);
    exit;
}

if ($start > 0) {
    fseek($fp, $start);
}

$remaining = $length;
$chunkSize = 65536;
while ($remaining > 0 && !feof($fp)) {
    $readBytes = min($chunkSize, $remaining);
    $buffer = fread($fp, $readBytes);
    if ($buffer === false || $buffer === '') {
        break;
    }
    echo $buffer;
    $remaining -= strlen($buffer);
    flush();
}

fclose($fp);
exit;
