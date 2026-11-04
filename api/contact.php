<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/includes/bootstrap.php';

header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    echo json_encode([
        'ok' => false,
        'message' => 'Metodo non consentito.',
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

$rawBody = file_get_contents('php://input') ?: '';
$contentType = strtolower((string) ($_SERVER['CONTENT_TYPE'] ?? ''));

$input = $_POST;
if (str_contains($contentType, 'application/json')) {
    $decoded = json_decode($rawBody, true);
    if (!is_array($decoded)) {
        http_response_code(400);
        echo json_encode([
            'ok' => false,
            'message' => 'Formato della richiesta non valido.',
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }
    $input = $decoded;
}

$csrfToken = (string) ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($input['csrf_token'] ?? ''));
if (!pqa_verify_csrf($csrfToken)) {
    http_response_code(403);
    echo json_encode([
        'ok' => false,
        'message' => 'Sessione scaduta o token di sicurezza non valido. Ricarica la pagina e riprova.',
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// Protezione anti-spam Honeypot: se compilato da bot automatici, risponde 200 senza inviare nulla
$honeypot = trim((string) ($input['company_website'] ?? ''));
if ($honeypot !== '') {
    echo json_encode([
        'ok' => true,
        'message' => 'Grazie. La tua richiesta è stata presa in carico dal nostro laboratorio.',
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

$clientIp = pqa_client_ip();
if (!pqa_rate_limit_check('contact_burst', $clientIp, 30, 900, true)) {
    http_response_code(429);
    echo json_encode([
        'ok' => false,
        'message' => 'Troppe richieste ravvicinate. Attendi qualche minuto o contattaci telefonicamente.',
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

$name = trim(preg_replace('/\s+/u', ' ', (string) ($input['name'] ?? '')) ?? '');
$email = trim((string) ($input['email'] ?? ''));
$phone = trim((string) ($input['phone'] ?? ''));
$subject = trim(preg_replace('/\s+/u', ' ', (string) ($input['subject'] ?? '')) ?? '');
$message = trim((string) ($input['message'] ?? ''));
$privacy = filter_var($input['privacy_consent'] ?? false, FILTER_VALIDATE_BOOLEAN);

$errors = [];

$nameLen = mb_strlen($name, 'UTF-8');
if ($nameLen < 2 || $nameLen > 120) {
    $errors['name'] = 'Inserisci nome e cognome o ragione sociale (da 2 a 120 caratteri).';
}

if ($email === '' || mb_strlen($email, 'UTF-8') > 150 || !filter_var($email, FILTER_VALIDATE_EMAIL) || preg_match('/[\r\n]/', $email)) {
    $errors['email'] = 'Inserisci un indirizzo email valido.';
}

if ($phone !== '' && (!preg_match('/^[0-9+\s().\-]{6,28}$/', $phone))) {
    $errors['phone'] = 'Inserisci un recapito telefonico valido (solo cifre e prefisso).';
}

$subjectLen = mb_strlen($subject, 'UTF-8');
if ($subjectLen < 2 || $subjectLen > 120) {
    $subject = 'Richiesta informazioni dal sito web';
}

$msgLen = mb_strlen($message, 'UTF-8');
if ($msgLen < 10 || $msgLen > 3000) {
    $errors['message'] = 'Descrivi la tua richiesta (minimo 10 caratteri, massimo 3000).';
}

if (!$privacy) {
    $errors['privacy_consent'] = 'È necessario confermare la presa visione dell’Informativa Privacy per procedere.';
}

if (!empty($errors)) {
    http_response_code(422);
    echo json_encode([
        'ok' => false,
        'message' => 'Alcuni campi richiedono attenzione prima dell’invio.',
        'errors' => $errors,
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// Rate limit invii effettivi validati (max 5 richieste ogni 15 minuti per IP)
if (!pqa_rate_limit_check('contact_send', $clientIp, 5, 900, true)) {
    http_response_code(429);
    echo json_encode([
        'ok' => false,
        'message' => 'Hai raggiunto il limite temporaneo di richieste inviate. Per urgenze chiamaci al +39 0931 483018.',
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

$config = pqa_get_config();
$recipient = filter_var($config['email_info'] ?? '', FILTER_VALIDATE_EMAIL) ?: 'info@centroanalisipqa.it';

// Prevenzione rigorosa Email Header Injection
$cleanEmailHeader = str_replace(["\r", "\n", "%0a", "%0d"], '', $email);
$cleanNameHeader = str_replace(["\r", "\n", '"', '<', '>'], '', $name);
$cleanSubject = str_replace(["\r", "\n"], ' ', $subject);

$mailSubject = '=?UTF-8?B?' . base64_encode('[Sito P.Q.A.] ' . $cleanSubject . ' — ' . $cleanNameHeader) . '?=';
$mailBody = implode("\r\n", [
    'Nuova richiesta ricevuta dal minisito Centro Analisi P.Q.A. S.r.l.',
    '====================================================================',
    'Data e ora:      ' . date('d/m/Y H:i:s'),
    'Mittente:        ' . $name,
    'Email:           ' . $email,
    'Telefono:        ' . ($phone !== '' ? $phone : 'Non specificato'),
    'Ambito analisi:  ' . $cleanSubject,
    'Consenso GDPR:   Confermato (Art. 13 Reg. UE 2016/679)',
    '--------------------------------------------------------------------',
    'Messaggio:',
    $message,
    '====================================================================',
]);

$headers = [
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: 8bit',
    'From: Centro Analisi PQA Web <' . $recipient . '>',
    'Reply-To: ' . $cleanEmailHeader,
    'X-Mailer: PQA-Web/1.0',
];

$mailSent = @mail($recipient, $mailSubject, $mailBody, implode("\r\n", $headers));

// Salvataggio sicuro di backup nel registro richieste dell'Area Riservata
$logFile = PQA_STORAGE_DIR . '/contacts_log.json.php';
$logs = pqa_read_json($logFile, []);
array_unshift($logs, [
    'id' => bin2hex(random_bytes(8)),
    'created_at' => date('c'),
    'created_human' => date('d/m/Y H:i'),
    'name' => $name,
    'email' => $email,
    'phone' => $phone,
    'subject' => $cleanSubject,
    'message' => $message,
    'recipient' => $recipient,
    'mail_sent' => (bool) $mailSent,
]);
if (count($logs) > 200) {
    $logs = array_slice($logs, 0, 200);
}
$saved = pqa_write_json($logFile, $logs);

if (!$mailSent && !$saved) {
    http_response_code(500);
    echo json_encode([
        'ok' => false,
        'message' => 'Impossibile registrare la richiesta in questo momento. Contattaci direttamente al +39 0931 483018 o via email.',
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

echo json_encode([
    'ok' => true,
    'message' => 'Richiesta inviata con successo. La segreteria tecnica del Centro Analisi P.Q.A. ti ricontatterà al più presto.',
], JSON_UNESCAPED_UNICODE);
