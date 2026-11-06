<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/bootstrap.php';

pqa_send_security_headers(false);
header('X-Robots-Tag: noindex, nofollow');

pqa_start_session();
$csrfToken = pqa_csrf_token();
$config = pqa_get_config();
$documents = pqa_get_documents();
$isLogged = pqa_is_admin_logged_in();

$allowedTabs = ['documents', 'whistleblowing', 'settings', 'branding', 'messages', 'security'];
$activeTab = in_array($_GET['tab'] ?? '', $allowedTabs, true) ? (string) $_GET['tab'] : 'documents';

$flashSuccess = '';
$flashError = '';
if (!empty($_SESSION['pqa_flash']) && is_array($_SESSION['pqa_flash'])) {
    $flashSuccess = (string) ($_SESSION['pqa_flash']['success'] ?? '');
    $flashError = (string) ($_SESSION['pqa_flash']['error'] ?? '');
    unset($_SESSION['pqa_flash']);
}

/**
 * Helper per impostare messaggio flash e fare redirect PRG (303 See Other).
 */
function pqa_admin_redirect(string $tab, string $success = '', string $error = ''): never
{
    $_SESSION['pqa_flash'] = [
        'success' => $success,
        'error' => $error,
    ];
    header('Location: admin.php?tab=' . rawurlencode($tab), true, 303);
    exit;
}

/**
 * Traduce gli errori nativi di upload PHP in messaggi chiari in italiano.
 */
function pqa_upload_error_message(int $code): string
{
    return match ($code) {
        UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => 'Il file supera la dimensione massima consentita.',
        UPLOAD_ERR_PARTIAL => 'Il caricamento del file si è interrotto prima del completamento. Riprova.',
        UPLOAD_ERR_NO_FILE => 'Nessun file selezionato.',
        UPLOAD_ERR_NO_TMP_DIR, UPLOAD_ERR_CANT_WRITE => 'Errore temporaneo di scrittura sul server.',
        default => 'Errore durante il caricamento del file.',
    };
}

/**
 * Valida in modo rigoroso un file SVG tramite parser XML DOM (LIBXML_NONET) + allowlist stretta
 * di soli elementi/attributi grafici statici (blocca XSS, SMIL <set>/<animate>, entità &#x6a;avascript:, XXE e risorse esterne).
 */
function pqa_validate_safe_svg(string $filePath): bool
{
    $raw = @file_get_contents($filePath);
    if ($raw === false || trim($raw) === '' || strlen($raw) > 2 * 1024 * 1024) {
        return false;
    }

    if (preg_match('/<!(DOCTYPE|ENTITY)\b|<\?xml-stylesheet\b/i', $raw)) {
        return false;
    }

    if (!class_exists('DOMDocument')) {
        return false;
    }

    $prevErrors = libxml_use_internal_errors(true);
    $dom = new DOMDocument();
    $loaded = $dom->loadXML($raw, LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING);
    libxml_clear_errors();
    libxml_use_internal_errors($prevErrors);

    if (!$loaded || $dom->doctype !== null || !$dom->documentElement) {
        return false;
    }

    if (strtolower((string) $dom->documentElement->localName) !== 'svg') {
        return false;
    }

    $allowedTags = [
        'svg', 'g', 'defs', 'symbol', 'title', 'desc', 'metadata',
        'lineargradient', 'radialgradient', 'stop', 'clippath', 'mask', 'pattern',
        'path', 'rect', 'circle', 'ellipse', 'line', 'polyline', 'polygon',
        'text', 'tspan', 'style',
    ];

    $blockedAttrs = [
        'href', 'xlink:href', 'src', 'attributename', 'attributetype',
        'values', 'from', 'to', 'by', 'begin', 'end',
    ];

    $nodes = $dom->getElementsByTagName('*');
    foreach ($nodes as $el) {
        $tag = strtolower((string) $el->localName);
        if (!in_array($tag, $allowedTags, true)) {
            return false;
        }

        if ($tag === 'style') {
            $cssText = strtolower((string) $el->textContent);
            if (preg_match('/(@import|expression\s*\(|javascript\s*:|vbscript\s*:|data\s*:|url\s*\()/i', $cssText)) {
                return false;
            }
        }

        if ($el->hasAttributes()) {
            foreach ($el->attributes as $attr) {
                $attrName = strtolower((string) $attr->nodeName);
                $attrLocal = strtolower((string) $attr->localName);
                // DOMAttr::$value restituisce già le entità XML/numeriche decodificate (es. &#x6a; -> j)
                $attrVal = trim((string) $attr->value);

                if (str_starts_with($attrName, 'on') || str_starts_with($attrLocal, 'on')) {
                    return false;
                }
                if (in_array($attrName, $blockedAttrs, true) || in_array($attrLocal, $blockedAttrs, true)) {
                    return false;
                }
                if (preg_match('/(javascript\s*:|vbscript\s*:|data\s*:|expression\s*\(|@import)/i', $attrVal)) {
                    return false;
                }
                if (preg_match('/url\s*\(\s*["\']?\s*(?!#)/i', $attrVal)) {
                    return false;
                }
            }
        }
    }

    return true;
}

// =========================================================================
// Gestione richieste POST
// =========================================================================
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    // Rilevamento payload eccedente post_max_size di php.ini
    $contentLength = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
    if (empty($_POST) && empty($_FILES) && $contentLength > 0) {
        if ($isLogged) {
            pqa_admin_redirect($activeTab, '', 'Il file caricato supera il limite massimo accettato dal server (post_max_size). Carica un PDF più leggero.');
        }
        $flashError = 'Richiesta troppo grande.';
    } else {
        $action = (string) ($_POST['action'] ?? '');
        $postTab = in_array($_POST['tab'] ?? '', $allowedTabs, true) ? (string) $_POST['tab'] : $activeTab;

        if (!pqa_verify_csrf((string) ($_POST['csrf_token'] ?? ''))) {
            if ($isLogged) {
                pqa_admin_redirect($postTab, '', 'Token di sicurezza scaduto o non valido. Riprova.');
            }
            $flashError = 'Sessione scaduta. Riprova ad accedere.';
        } elseif ($action === 'login') {
            $clientIp = pqa_client_ip();
            if (!pqa_rate_limit_check('admin_login', $clientIp, 5, 900, false)) {
                http_response_code(429);
                $flashError = 'Troppi tentativi di accesso errati. Attendi 15 minuti prima di riprovare.';
            } else {
                $password = (string) ($_POST['password'] ?? '');
                $hash = (string) ($config['security']['admin_password_hash'] ?? '');
                if ($password !== '' && $hash !== '' && password_verify($password, $hash)) {
                    pqa_rate_limit_clear('admin_login', $clientIp);
                    session_regenerate_id(true);
                    $_SESSION['pqa_admin_auth'] = true;
                    $_SESSION['pqa_admin_last_active'] = time();
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                    pqa_admin_redirect('documents', 'Accesso effettuato nell’Area Riservata P.Q.A.');
                } else {
                    pqa_rate_limit_check('admin_login', $clientIp, 5, 900, true);
                    http_response_code(401);
                    $flashError = 'Password non corretta.';
                }
            }
        } elseif (!$isLogged) {
            http_response_code(403);
            $flashError = 'Effettua l’accesso per eseguire questa operazione.';
        } else {
            // Azioni autenticate
            switch ($action) {
                case 'logout':
                    $_SESSION = [];
                    if (ini_get('session.use_cookies')) {
                        $params = session_get_cookie_params();
                        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
                    }
                    session_destroy();
                    header('Location: admin.php', true, 303);
                    exit;

                case 'save_document':
                    $docId = (string) ($_POST['doc_id'] ?? '');
                    $rawDocs = pqa_read_json(PQA_STORAGE_DIR . '/documents.json.php', pqa_default_documents());
                    $defaults = pqa_default_documents();
                    if (!isset($defaults[$docId])) {
                        pqa_admin_redirect('documents', '', 'Slot documento non riconosciuto.');
                    }
                    $currentDoc = array_replace($defaults[$docId], $rawDocs[$docId] ?? []);

                    $title = trim((string) ($_POST['title'] ?? ''));
                    $subtitle = trim((string) ($_POST['subtitle'] ?? ''));
                    $description = trim((string) ($_POST['description'] ?? ''));
                    $revision = trim((string) ($_POST['revision'] ?? ''));
                    $approvedDate = trim((string) ($_POST['approved_date'] ?? ''));
                    $visible = isset($_POST['visible']) && $_POST['visible'] === '1';

                    if ($title === '' || mb_strlen($title, 'UTF-8') > 160) {
                        pqa_admin_redirect('documents', '', 'Inserisci un titolo valido per il documento (max 160 caratteri).');
                    }
                    if ($approvedDate !== '') {
                        if (!preg_match('/^(\d{4})-(\d{2})-(\d{2})$/', $approvedDate, $m) || !checkdate((int) $m[2], (int) $m[3], (int) $m[1])) {
                            pqa_admin_redirect('documents', '', 'La data di approvazione non è valida.');
                        }
                    }

                    $currentDoc['title'] = $title;
                    $currentDoc['subtitle'] = mb_substr($subtitle, 0, 220, 'UTF-8');
                    $currentDoc['description'] = mb_substr($description, 0, 600, 'UTF-8');
                    $currentDoc['revision'] = mb_substr($revision, 0, 40, 'UTF-8');
                    $currentDoc['approved_date'] = $approvedDate;
                    $currentDoc['visible'] = $visible;

                    // Controllo eventuale file PDF caricato
                    if (isset($_FILES['pdf_file']) && (int) ($_FILES['pdf_file']['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE) {
                        $upErr = (int) $_FILES['pdf_file']['error'];
                        if ($upErr !== UPLOAD_ERR_OK) {
                            pqa_admin_redirect('documents', '', pqa_upload_error_message($upErr));
                        }

                        $tmpPath = (string) $_FILES['pdf_file']['tmp_name'];
                        $origName = (string) ($_FILES['pdf_file']['name'] ?? '');
                        $fileSize = (int) ($_FILES['pdf_file']['size'] ?? 0);

                        if ($fileSize <= 0 || $fileSize > 20 * 1024 * 1024) {
                            pqa_admin_redirect('documents', '', 'Il file PDF deve avere una dimensione compresa tra 1 KB e 20 MB.');
                        }

                        $ext = strtolower(pathinfo($origName, PATHINFO_EXTENSION));
                        if ($ext !== 'pdf') {
                            pqa_admin_redirect('documents', '', 'Formato non ammesso: è consentito esclusivamente il caricamento di file .pdf.');
                        }

                        $finfo = new finfo(FILEINFO_MIME_TYPE);
                        $mime = (string) $finfo->file($tmpPath);
                        $fh = @fopen($tmpPath, 'rb');
                        $magic = $fh ? (string) fread($fh, 5) : '';
                        if ($fh) {
                            fclose($fh);
                        }

                        if ($mime !== 'application/pdf' || $magic !== '%PDF-') {
                            pqa_admin_redirect('documents', '', 'Il file selezionato non è un documento PDF integro e valido.');
                        }

                        $newStoredName = 'doc_' . $docId . '_' . bin2hex(random_bytes(10)) . '.pdf';
                        $destPath = PQA_DOCS_DIR . '/' . $newStoredName;

                        if (!move_uploaded_file($tmpPath, $destPath)) {
                            pqa_admin_redirect('documents', '', 'Impossibile salvare il PDF sul server.');
                        }

                        // Rimuove il vecchio PDF su disco se presente
                        if (!empty($currentDoc['file']['stored_name'])) {
                            $oldPath = PQA_DOCS_DIR . '/' . basename((string) $currentDoc['file']['stored_name']);
                            if (is_file($oldPath) && $oldPath !== $destPath) {
                                @unlink($oldPath);
                            }
                        }

                        $currentDoc['file'] = [
                            'stored_name' => $newStoredName,
                            'size_bytes' => (int) filesize($destPath),
                            'sha256' => hash_file('sha256', $destPath) ?: '',
                            'uploaded_at' => date('c'),
                        ];
                    }

                    $rawDocs[$docId] = $currentDoc;
                    pqa_write_json(PQA_STORAGE_DIR . '/documents.json.php', $rawDocs);
                    pqa_admin_redirect('documents', 'Documento "' . $title . '" aggiornato correttamente.');

                case 'delete_document_file':
                    $docId = (string) ($_POST['doc_id'] ?? '');
                    $rawDocs = pqa_read_json(PQA_STORAGE_DIR . '/documents.json.php', pqa_default_documents());
                    if (!isset($rawDocs[$docId])) {
                        pqa_admin_redirect('documents', '', 'Documento non trovato.');
                    }
                    if (!empty($rawDocs[$docId]['file']['stored_name'])) {
                        $oldPath = PQA_DOCS_DIR . '/' . basename((string) $rawDocs[$docId]['file']['stored_name']);
                        if (is_file($oldPath)) {
                            @unlink($oldPath);
                        }
                    }
                    $rawDocs[$docId]['file'] = null;
                    pqa_write_json(PQA_STORAGE_DIR . '/documents.json.php', $rawDocs);
                    pqa_admin_redirect('documents', 'File PDF rimosso. Lo slot è ora impostato nello stato "In aggiornamento".');

                case 'save_whistleblowing':
                    $wbUrl = trim((string) ($_POST['wb_url'] ?? ''));
                    $wbBtn = trim((string) ($_POST['wb_button_label'] ?? ''));
                    $wbPending = trim((string) ($_POST['wb_pending_label'] ?? ''));
                    $wbSummary = trim((string) ($_POST['wb_summary'] ?? ''));
                    $emailOdv = trim((string) ($_POST['email_odv'] ?? ''));

                    if ($wbUrl !== '') {
                        if (!filter_var($wbUrl, FILTER_VALIDATE_URL) || !str_starts_with(strtolower($wbUrl), 'https://')) {
                            pqa_admin_redirect('whistleblowing', '', 'L’URL della piattaforma Whistleblowing deve iniziare obbligatoriamente con https:// (protocollo cifrato richiesto dal D.Lgs. 24/2023) oppure essere lasciato vuoto.');
                        }
                    }
                    if ($emailOdv !== '' && !filter_var($emailOdv, FILTER_VALIDATE_EMAIL)) {
                        pqa_admin_redirect('whistleblowing', '', 'Inserisci un indirizzo email valido per l’Organismo di Vigilanza.');
                    }

                    $config['whistleblowing']['url'] = $wbUrl;
                    $config['whistleblowing']['button_label'] = $wbBtn !== '' ? mb_substr($wbBtn, 0, 80, 'UTF-8') : 'Accedi alla Piattaforma Segnalazioni';
                    $config['whistleblowing']['pending_label'] = $wbPending !== '' ? mb_substr($wbPending, 0, 90, 'UTF-8') : 'Canale telematico crittografato in attivazione';
                    $config['whistleblowing']['summary'] = $wbSummary !== '' ? mb_substr($wbSummary, 0, 800, 'UTF-8') : $config['whistleblowing']['summary'];
                    $config['email_odv'] = $emailOdv;
                    $config['security']['updated_at'] = date('c');

                    pqa_write_json(PQA_STORAGE_DIR . '/config.json.php', $config);
                    pqa_admin_redirect('whistleblowing', 'Configurazione Whistleblowing e OdV salvata con successo.');

                case 'save_settings':
                    $companyName = trim((string) ($_POST['company_name'] ?? ''));
                    $directorName = trim((string) ($_POST['director_name'] ?? ''));
                    $street = trim((string) ($_POST['address_street'] ?? ''));
                    $city = trim((string) ($_POST['address_city'] ?? ''));
                    $vat = preg_replace('/\s+/', '', (string) ($_POST['vat_number'] ?? '')) ?? '';
                    $phoneDisplay = trim((string) ($_POST['phone_display'] ?? ''));
                    $emailInfo = trim((string) ($_POST['email_info'] ?? ''));
                    $emailLab = trim((string) ($_POST['email_lab'] ?? ''));
                    $pec = trim((string) ($_POST['pec'] ?? ''));

                    if ($companyName === '' || $street === '' || $city === '' || $vat === '') {
                        pqa_admin_redirect('settings', '', 'Ragione sociale, indirizzo e Partita IVA sono campi obbligatori.');
                    }
                    if (!filter_var($emailInfo, FILTER_VALIDATE_EMAIL) || !filter_var($pec, FILTER_VALIDATE_EMAIL)) {
                        pqa_admin_redirect('settings', '', 'Inserisci indirizzi validi per Email principale e PEC.');
                    }
                    if ($emailLab !== '' && !filter_var($emailLab, FILTER_VALIDATE_EMAIL)) {
                        pqa_admin_redirect('settings', '', 'Indirizzo email laboratorio non valido.');
                    }

                    $config['company_name'] = mb_substr($companyName, 0, 120, 'UTF-8');
                    $config['director_name'] = mb_substr($directorName, 0, 120, 'UTF-8');
                    $config['address_street'] = mb_substr($street, 0, 120, 'UTF-8');
                    $config['address_city'] = mb_substr($city, 0, 120, 'UTF-8');
                    $config['vat_number'] = mb_substr($vat, 0, 20, 'UTF-8');
                    $config['phone_display'] = mb_substr($phoneDisplay, 0, 40, 'UTF-8');
                    $config['phone_link'] = preg_replace('/[^0-9+]/', '', $phoneDisplay) ?: '+390931483018';
                    $config['email_info'] = $emailInfo;
                    $config['email_lab'] = $emailLab;
                    $config['pec'] = $pec;
                    $config['opening_hours'] = mb_substr(trim((string) ($_POST['opening_hours'] ?? '')), 0, 180, 'UTF-8');
                    $config['sample_hours'] = mb_substr(trim((string) ($_POST['sample_hours'] ?? '')), 0, 180, 'UTF-8');

                    $fullAddressQuery = trim($config['address_street'] . ', ' . $config['address_city']);
                    $config['map'] = [
                        'embed_url' => 'https://maps.google.com/maps?q=' . rawurlencode($fullAddressQuery) . '&hl=it&z=16&output=embed',
                        'external_url' => 'https://www.google.com/maps/search/?api=1&query=' . urlencode($fullAddressQuery),
                    ];

                    $config['accreditation'] = [
                        'enabled' => isset($_POST['acc_enabled']) && $_POST['acc_enabled'] === '1',
                        'standard' => mb_substr(trim((string) ($_POST['acc_standard'] ?? 'UNI CEI EN ISO/IEC 17025')), 0, 60, 'UTF-8'),
                        'body' => mb_substr(trim((string) ($_POST['acc_body'] ?? 'ACCREDIA')), 0, 40, 'UTF-8'),
                        'code' => mb_substr(trim((string) ($_POST['acc_code'] ?? '')), 0, 40, 'UTF-8'),
                        'title' => mb_substr(trim((string) ($_POST['acc_title'] ?? '')), 0, 140, 'UTF-8'),
                        'description' => mb_substr(trim((string) ($_POST['acc_description'] ?? '')), 0, 650, 'UTF-8'),
                    ];
                    $config['security']['updated_at'] = date('c');

                    pqa_write_json(PQA_STORAGE_DIR . '/config.json.php', $config);
                    pqa_admin_redirect('settings', 'Anagrafica, recapiti e box Qualità aggiornati correttamente.');

                case 'upload_logo':
                    $variant = ($_POST['variant'] ?? '') === 'dark' ? 'dark' : 'light';
                    $fieldKey = 'logo_file';
                    if (!isset($_FILES[$fieldKey]) || (int) ($_FILES[$fieldKey]['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
                        $errCode = (int) ($_FILES[$fieldKey]['error'] ?? UPLOAD_ERR_NO_FILE);
                        pqa_admin_redirect('branding', '', pqa_upload_error_message($errCode));
                    }

                    $tmpPath = (string) $_FILES[$fieldKey]['tmp_name'];
                    $fileSize = (int) ($_FILES[$fieldKey]['size'] ?? 0);
                    if ($fileSize <= 0 || $fileSize > 2 * 1024 * 1024) {
                        pqa_admin_redirect('branding', '', 'Il file del logo non può superare i 2 MB.');
                    }

                    $origName = (string) ($_FILES[$fieldKey]['name'] ?? '');
                    $origExt = strtolower(pathinfo($origName, PATHINFO_EXTENSION));
                    $finfo = new finfo(FILEINFO_MIME_TYPE);
                    $mime = (string) $finfo->file($tmpPath);

                    $ext = '';
                    if ($origExt === 'svg' && in_array($mime, ['image/svg+xml', 'image/svg', 'text/xml', 'application/xml', 'text/plain'], true)) {
                        if (!pqa_validate_safe_svg($tmpPath)) {
                            pqa_admin_redirect('branding', '', 'Il file SVG non è valido o contiene elementi attivi non ammessi per sicurezza.');
                        }
                        $ext = 'svg';
                    } elseif (in_array($origExt, ['png', 'webp', 'jpg', 'jpeg'], true)) {
                        $rasterMap = [
                            'image/png' => 'png',
                            'image/webp' => 'webp',
                            'image/jpeg' => 'jpg',
                        ];
                        if (!isset($rasterMap[$mime]) || @getimagesize($tmpPath) === false) {
                            pqa_admin_redirect('branding', '', 'Immagine non valida o formato non corrispondente all’estensione.');
                        }
                        $ext = $rasterMap[$mime];
                    } else {
                        pqa_admin_redirect('branding', '', 'Formato non supportato. Carica un file SVG, PNG, WEBP o JPG.');
                    }

                    $newFileName = 'logo-' . $variant . '-' . bin2hex(random_bytes(6)) . '.' . $ext;
                    $destPath = PQA_BRAND_DIR . '/' . $newFileName;
                    if (!move_uploaded_file($tmpPath, $destPath)) {
                        pqa_admin_redirect('branding', '', 'Errore durante il salvataggio del logo.');
                    }

                    $cfgKey = $variant === 'dark' ? 'logo_dark' : 'logo_light';
                    $flagKey = $variant === 'dark' ? 'is_custom_dark' : 'is_custom_light';

                    if (!empty($config['branding'][$flagKey]) && !empty($config['branding'][$cfgKey])) {
                        $oldBrand = PQA_ROOT_DIR . '/' . ltrim((string) $config['branding'][$cfgKey], '/');
                        if (is_file($oldBrand) && str_starts_with(realpath($oldBrand) ?: '', realpath(PQA_BRAND_DIR) ?: '')) {
                            @unlink($oldBrand);
                        }
                    }

                    $config['branding'][$cfgKey] = 'uploads/brand/' . $newFileName;
                    $config['branding'][$flagKey] = true;
                    pqa_write_json(PQA_STORAGE_DIR . '/config.json.php', $config);
                    pqa_admin_redirect('branding', 'Logo personalizzato (' . ($variant === 'dark' ? 'fondo scuro' : 'fondo chiaro') . ') attivato.');

                case 'reset_logos':
                    foreach (['logo_light' => 'is_custom_light', 'logo_dark' => 'is_custom_dark'] as $cfgKey => $flagKey) {
                        if (!empty($config['branding'][$flagKey]) && !empty($config['branding'][$cfgKey])) {
                            $oldBrand = PQA_ROOT_DIR . '/' . ltrim((string) $config['branding'][$cfgKey], '/');
                            if (is_file($oldBrand) && str_starts_with(realpath($oldBrand) ?: '', realpath(PQA_BRAND_DIR) ?: '')) {
                                @unlink($oldBrand);
                            }
                        }
                    }
                    $defaults = pqa_default_config();
                    $config['branding'] = $defaults['branding'];
                    pqa_write_json(PQA_STORAGE_DIR . '/config.json.php', $config);
                    pqa_admin_redirect('branding', 'Ripristinato il marchio ufficiale predefinito (Goccia Molecolare).');

                case 'delete_message':
                    $msgId = (string) ($_POST['msg_id'] ?? '');
                    $logFile = PQA_STORAGE_DIR . '/contacts_log.json.php';
                    $logs = pqa_read_json($logFile, []);
                    $logs = array_values(array_filter($logs, static fn($item) => ($item['id'] ?? '') !== $msgId));
                    pqa_write_json($logFile, $logs);
                    pqa_admin_redirect('messages', 'Richiesta rimossa dall’archivio.');

                case 'change_password':
                    $currentPass = (string) ($_POST['current_password'] ?? '');
                    $newPass = (string) ($_POST['new_password'] ?? '');
                    $confirmPass = (string) ($_POST['confirm_password'] ?? '');

                    if (!password_verify($currentPass, (string) ($config['security']['admin_password_hash'] ?? ''))) {
                        pqa_admin_redirect('security', '', 'La password attuale inserita non è corretta.');
                    }
                    if (mb_strlen($newPass, 'UTF-8') < 8 || mb_strlen($newPass, 'UTF-8') > 72) {
                        pqa_admin_redirect('security', '', 'La nuova password deve contenere tra 8 e 72 caratteri.');
                    }
                    if ($newPass !== $confirmPass) {
                        pqa_admin_redirect('security', '', 'La conferma della nuova password non coincide.');
                    }

                    $config['security']['admin_password_hash'] = password_hash($newPass, PASSWORD_BCRYPT);
                    $config['security']['password_changed_at'] = date('c');
                    $config['security']['updated_at'] = date('c');
                    pqa_write_json(PQA_STORAGE_DIR . '/config.json.php', $config);

                    session_regenerate_id(true);
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                    pqa_admin_redirect('security', 'Password dell’Area Riservata aggiornata con successo.');

                default:
                    pqa_admin_redirect($activeTab, '', 'Azione non riconosciuta.');
            }
        }
    }
}

$contactLogs = $isLogged ? pqa_read_json(PQA_STORAGE_DIR . '/contacts_log.json.php', []) : [];
?>
<!DOCTYPE html>
<html lang="it">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Area Riservata — <?= pqa_e($config['company_name']) ?></title>
  <meta name="robots" content="noindex, nofollow">
  <link rel="icon" type="image/svg+xml" href="assets/img/favicon.svg">
  <link rel="stylesheet" href="assets/css/fonts.css">
  <link rel="stylesheet" href="assets/css/style.css">
  <style>
    body { background-color: var(--pqa-ice); }
    .adm-header {
      background: var(--pqa-navy);
      color: var(--pqa-white);
      padding: 16px 0;
      border-bottom: 1px solid rgba(255,255,255,0.1);
    }
    .adm-header-inner {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      flex-wrap: wrap;
    }
    .adm-tabs {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin: 26px 0;
      border-bottom: 1px solid var(--pqa-border);
      padding-bottom: 14px;
    }
    .adm-tab {
      padding: 10px 16px;
      border-radius: var(--radius-sm);
      font-weight: 700;
      font-size: 0.88rem;
      color: var(--pqa-navy);
      background: var(--pqa-white);
      border: 1px solid var(--pqa-border);
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 8px;
    }
    .adm-tab:hover { border-color: var(--pqa-teal); color: var(--pqa-teal); }
    .adm-tab.is-active {
      background: var(--pqa-teal);
      color: var(--pqa-white);
      border-color: var(--pqa-teal);
    }
    .adm-card {
      background: var(--pqa-white);
      border: 1px solid var(--pqa-border);
      border-radius: var(--radius-md);
      padding: 28px;
      margin-bottom: 24px;
      box-shadow: var(--shadow-sm);
    }
    .adm-card h2, .adm-card h3 {
      font-family: var(--font-serif);
      color: var(--pqa-navy);
      margin-top: 0;
    }
    .adm-grid-2 {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 18px;
    }
    .adm-login-box {
      max-width: 440px;
      margin: 72px auto;
      background: var(--pqa-white);
      border: 1px solid var(--pqa-border);
      border-radius: var(--radius-lg);
      padding: 38px 34px;
      box-shadow: var(--shadow-md);
    }
    .adm-badge-count {
      background: rgba(11, 37, 69, 0.12);
      padding: 1px 7px;
      border-radius: 99px;
      font-size: 0.75rem;
    }
    .adm-tab.is-active .adm-badge-count {
      background: rgba(255,255,255,0.25);
    }
    @media (max-width: 780px) {
      .adm-grid-2 { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>

  <header class="adm-header">
    <div class="pqa-container adm-header-inner">
      <div style="display:flex; align-items:center; gap:16px;">
        <a href="index.php">
          <img src="<?= pqa_e($config['branding']['logo_dark']) ?>" alt="<?= pqa_e($config['company_name']) ?>" style="height:44px; width:auto;">
        </a>
        <span style="font-size:0.82rem; padding:4px 10px; border-radius:99px; background:rgba(52,211,153,0.18); color:#34D399; font-weight:700;">
          Gestione Documentale &amp; Contenuti
        </span>
      </div>

      <div style="display:flex; align-items:center; gap:10px;">
        <a href="index.php" class="pqa-btn pqa-btn-sm pqa-btn-outline" style="background:transparent; color:#FFFFFF; border-color:rgba(255,255,255,0.28);">
          Visualizza Sito Pubblico
        </a>
        <?php if ($isLogged): ?>
        <form method="post" action="admin.php" style="margin:0;">
          <input type="hidden" name="csrf_token" value="<?= pqa_e($csrfToken) ?>">
          <input type="hidden" name="action" value="logout">
          <button type="submit" class="pqa-btn pqa-btn-sm pqa-btn-light">Esci</button>
        </form>
        <?php endif; ?>
      </div>
    </div>
  </header>

  <main class="pqa-container" style="padding-bottom: 64px;">

    <?php if (!$isLogged): ?>
      <!-- ================================================================
           SCHERMATA LOGIN PROTETTA
           ================================================================ -->
      <div class="adm-login-box">
        <span class="pqa-eyebrow">Accesso Riservato</span>
        <h1 style="font-family:var(--font-serif); font-size:1.65rem; color:var(--pqa-navy); margin:0 0 10px;">Area Amministrazione</h1>
        <p style="font-size:0.9rem; color:var(--pqa-muted); margin:0 0 24px;">
          Inserisci la password amministrativa per aggiornare i documenti D.Lgs. 231, il Codice Etico, il canale Whistleblowing e i recapiti aziendali.
        </p>

        <?php if ($flashError !== ''): ?>
          <div class="pqa-alert pqa-alert-error"><?= pqa_e($flashError) ?></div>
        <?php endif; ?>
        <?php if ($flashSuccess !== ''): ?>
          <div class="pqa-alert pqa-alert-success"><?= pqa_e($flashSuccess) ?></div>
        <?php endif; ?>

        <form method="post" action="admin.php">
          <input type="hidden" name="csrf_token" value="<?= pqa_e($csrfToken) ?>">
          <input type="hidden" name="action" value="login">
          <div class="pqa-field">
            <label class="pqa-label" for="admin-password">Password Amministratore</label>
            <input type="password" id="admin-password" name="password" class="pqa-input" required autofocus autocomplete="current-password">
          </div>
          <button type="submit" class="pqa-btn pqa-btn-primary" style="width:100%;">Accedi al Pannello</button>
        </form>
      </div>

    <?php else: ?>
      <!-- ================================================================
           PANNELLO DI GESTIONE AUTENTICATO
           ================================================================ -->

      <?php if (empty($config['security']['password_changed_at'])): ?>
        <div class="pqa-alert" style="margin-top:24px; background:var(--pqa-warning-bg); color:var(--pqa-warning); border:1px solid #F7D7A8;">
          Promemoria sicurezza: stai utilizzando la password iniziale di configurazione. Prima della messa online definitiva ti consigliamo di personalizzarla nella scheda <a href="admin.php?tab=security" style="font-weight:800; color:inherit; text-decoration:underline;">Sicurezza &amp; Password</a>.
        </div>
      <?php endif; ?>

      <nav class="adm-tabs" aria-label="Sezioni pannello di controllo">
        <a href="admin.php?tab=documents" class="adm-tab <?= $activeTab === 'documents' ? 'is-active' : '' ?>">Documenti 231 &amp; PDF</a>
        <a href="admin.php?tab=whistleblowing" class="adm-tab <?= $activeTab === 'whistleblowing' ? 'is-active' : '' ?>">Canale Whistleblowing</a>
        <a href="admin.php?tab=settings" class="adm-tab <?= $activeTab === 'settings' ? 'is-active' : '' ?>">Azienda, Recapiti &amp; ISO</a>
        <a href="admin.php?tab=branding" class="adm-tab <?= $activeTab === 'branding' ? 'is-active' : '' ?>">Logo &amp; Brand</a>
        <a href="admin.php?tab=messages" class="adm-tab <?= $activeTab === 'messages' ? 'is-active' : '' ?>">
          Richieste Contatto
          <span class="adm-badge-count"><?= count($contactLogs) ?></span>
        </a>
        <a href="admin.php?tab=security" class="adm-tab <?= $activeTab === 'security' ? 'is-active' : '' ?>">Sicurezza &amp; Password</a>
      </nav>

      <?php if ($flashSuccess !== ''): ?>
        <div class="pqa-alert pqa-alert-success"><?= pqa_e($flashSuccess) ?></div>
      <?php endif; ?>
      <?php if ($flashError !== ''): ?>
        <div class="pqa-alert pqa-alert-error"><?= pqa_e($flashError) ?></div>
      <?php endif; ?>

      <?php if ($activeTab === 'documents'): ?>
        <!-- TAB 1: GESTIONE DOCUMENTI PDF -->
        <?php foreach ($documents as $docKey => $doc): ?>
          <section class="adm-card">
            <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:16px; flex-wrap:wrap; margin-bottom:18px;">
              <div>
                <span class="pqa-doc-cat"><?= pqa_e((string) $doc['category']) ?></span>
                <h2 style="font-size:1.35rem; margin:4px 0 0;"><?= pqa_e((string) $doc['title']) ?></h2>
              </div>
              <div>
                <?php if (!empty($doc['is_available'])): ?>
                  <span class="pqa-status-badge pqa-status-ready">PDF Online (<?= pqa_e((string) $doc['size_human']) ?>)</span>
                <?php else: ?>
                  <span class="pqa-status-badge pqa-status-pending">Nessun PDF caricato ("In aggiornamento")</span>
                <?php endif; ?>
              </div>
            </div>

            <form method="post" action="admin.php?tab=documents" enctype="multipart/form-data">
              <input type="hidden" name="csrf_token" value="<?= pqa_e($csrfToken) ?>">
              <input type="hidden" name="action" value="save_document">
              <input type="hidden" name="tab" value="documents">
              <input type="hidden" name="doc_id" value="<?= pqa_e($docKey) ?>">

              <div class="adm-grid-2">
                <div class="pqa-field">
                  <label class="pqa-label">Titolo Documento *</label>
                  <input type="text" name="title" class="pqa-input" value="<?= pqa_e((string) $doc['title']) ?>" required maxlength="160">
                </div>
                <div class="pqa-field">
                  <label class="pqa-label">Sottotitolo / Riferimento Normativo</label>
                  <input type="text" name="subtitle" class="pqa-input" value="<?= pqa_e((string) $doc['subtitle']) ?>" maxlength="220">
                </div>
              </div>

              <div class="pqa-field">
                <label class="pqa-label">Descrizione sintetica</label>
                <textarea name="description" class="pqa-textarea" style="min-height:82px;" maxlength="600"><?= pqa_e((string) $doc['description']) ?></textarea>
              </div>

              <div class="adm-grid-2">
                <div class="pqa-field">
                  <label class="pqa-label">Numero Revisione (es. Rev. 01)</label>
                  <input type="text" name="revision" class="pqa-input" value="<?= pqa_e((string) $doc['revision']) ?>" maxlength="40">
                </div>
                <div class="pqa-field">
                  <label class="pqa-label">Data di Approvazione</label>
                  <input type="date" name="approved_date" class="pqa-input" value="<?= pqa_e((string) $doc['approved_date']) ?>">
                </div>
              </div>

              <div class="pqa-field" style="padding:16px; background:var(--pqa-ice); border:1px dashed var(--pqa-border); border-radius:var(--radius-sm);">
                <label class="pqa-label">Carica o sostituisci file PDF ufficiale (max 20 MB — solo formato .pdf)</label>
                <input type="file" name="pdf_file" accept="application/pdf,.pdf" style="font-size:0.9rem;">
                <?php if (!empty($doc['is_available'])): ?>
                  <div style="margin-top:10px; font-size:0.83rem; color:var(--pqa-muted);">
                    File attuale attivo: <strong><?= pqa_e((string) $doc['download_name']) ?></strong> (<?= pqa_e((string) $doc['size_human']) ?>) —
                    <a href="<?= pqa_e((string) $doc['view_url']) ?>" target="_blank" rel="noopener">Apri anteprima</a>
                  </div>
                <?php endif; ?>
              </div>

              <div class="pqa-field">
                <label class="pqa-checkbox-label">
                  <input type="checkbox" name="visible" value="1" <?= !empty($doc['visible']) ? 'checked' : '' ?>>
                  <span><strong>Mostra questo slot documento sul sito pubblico</strong> (se attivo senza PDF mostrerà l’etichetta ordinata <em>“In aggiornamento”</em>)</span>
                </label>
              </div>

              <div style="display:flex; gap:12px; flex-wrap:wrap; align-items:center;">
                <button type="submit" class="pqa-btn pqa-btn-primary">Salva Modifiche Documento</button>
              </div>
            </form>

            <?php if (!empty($doc['is_available'])): ?>
              <form method="post" action="admin.php?tab=documents" style="margin-top:12px;" onsubmit="return confirm('Rimuovere il file PDF pubblicato per questo documento?');">
                <input type="hidden" name="csrf_token" value="<?= pqa_e($csrfToken) ?>">
                <input type="hidden" name="action" value="delete_document_file">
                <input type="hidden" name="tab" value="documents">
                <input type="hidden" name="doc_id" value="<?= pqa_e($docKey) ?>">
                <button type="submit" class="pqa-btn pqa-btn-sm pqa-btn-outline" style="color:var(--pqa-danger); border-color:#F5C2C0;">
                  Rimuovi PDF caricato
                </button>
              </form>
            <?php endif; ?>
          </section>
        <?php endforeach; ?>

      <?php elseif ($activeTab === 'whistleblowing'): ?>
        <!-- TAB 2: CANALE WHISTLEBLOWING & ODV -->
        <section class="adm-card">
          <h2>Configurazione Canale Segnalazioni Whistleblowing (D.Lgs. 24/2023)</h2>
          <p style="color:var(--pqa-muted); font-size:0.92rem; margin-bottom:24px;">
            Inserisci l’indirizzo HTTPS della piattaforma esterna crittografata fornita dal consulente 231/OdV. Finché il campo URL resta vuoto, il sito mostra automaticamente lo stato istituzionale <em>“Canale in attivazione”</em> senza link interrotti.
          </p>

          <form method="post" action="admin.php?tab=whistleblowing">
            <input type="hidden" name="csrf_token" value="<?= pqa_e($csrfToken) ?>">
            <input type="hidden" name="action" value="save_whistleblowing">
            <input type="hidden" name="tab" value="whistleblowing">

            <div class="pqa-field">
              <label class="pqa-label" for="wb_url">URL Piattaforma Esterna Whistleblowing (deve iniziare con https://)</label>
              <input type="url" id="wb_url" name="wb_url" class="pqa-input" placeholder="https://segnalazioni.esempio.it/centroanalisipqa" value="<?= pqa_e((string) ($config['whistleblowing']['url'] ?? '')) ?>">
              <small style="color:var(--pqa-muted); font-size:0.8rem;">Lascia vuoto se il portale esterno non è ancora attivo.</small>
            </div>

            <div class="adm-grid-2">
              <div class="pqa-field">
                <label class="pqa-label">Testo pulsante attivo</label>
                <input type="text" name="wb_button_label" class="pqa-input" value="<?= pqa_e((string) ($config['whistleblowing']['button_label'] ?? '')) ?>" maxlength="80">
              </div>
              <div class="pqa-field">
                <label class="pqa-label">Dicitura stato "In attivazione" (quando URL vuoto)</label>
                <input type="text" name="wb_pending_label" class="pqa-input" value="<?= pqa_e((string) ($config['whistleblowing']['pending_label'] ?? '')) ?>" maxlength="90">
              </div>
            </div>

            <div class="pqa-field">
              <label class="pqa-label">Sintesi tutele D.Lgs. 24/2023 mostrata nel box</label>
              <textarea name="wb_summary" class="pqa-textarea" maxlength="800"><?= pqa_e((string) ($config['whistleblowing']['summary'] ?? '')) ?></textarea>
            </div>

            <div class="pqa-field">
              <label class="pqa-label">Casella Email Organismo di Vigilanza (D.Lgs. 231/2001)</label>
              <input type="email" name="email_odv" class="pqa-input" value="<?= pqa_e((string) ($config['email_odv'] ?? 'odv@centroanalisipqa.it')) ?>">
            </div>

            <button type="submit" class="pqa-btn pqa-btn-primary">Salva Configurazione Whistleblowing</button>
          </form>
        </section>

      <?php elseif ($activeTab === 'settings'): ?>
        <!-- TAB 3: ANAGRAFICA, RECAPITI & ACCREDITAMENTO ISO 17025 -->
        <section class="adm-card">
          <h2>Anagrafica Societaria, Recapiti &amp; Qualità UNI CEI EN ISO/IEC 17025</h2>
          <form method="post" action="admin.php?tab=settings">
            <input type="hidden" name="csrf_token" value="<?= pqa_e($csrfToken) ?>">
            <input type="hidden" name="action" value="save_settings">
            <input type="hidden" name="tab" value="settings">

            <div class="adm-grid-2">
              <div class="pqa-field">
                <label class="pqa-label">Ragione Sociale *</label>
                <input type="text" name="company_name" class="pqa-input" value="<?= pqa_e((string) $config['company_name']) ?>" required>
              </div>
              <div class="pqa-field">
                <label class="pqa-label">Direzione Tecnica</label>
                <input type="text" name="director_name" class="pqa-input" value="<?= pqa_e((string) $config['director_name']) ?>">
              </div>
            </div>

            <div class="adm-grid-2">
              <div class="pqa-field">
                <label class="pqa-label">Indirizzo (Via / Corso e civico) *</label>
                <input type="text" name="address_street" class="pqa-input" value="<?= pqa_e((string) $config['address_street']) ?>" required>
              </div>
              <div class="pqa-field">
                <label class="pqa-label">CAP, Città e Provincia *</label>
                <input type="text" name="address_city" class="pqa-input" value="<?= pqa_e((string) $config['address_city']) ?>" required>
              </div>
            </div>

            <div class="adm-grid-2">
              <div class="pqa-field">
                <label class="pqa-label">Partita IVA / Codice Fiscale *</label>
                <input type="text" name="vat_number" class="pqa-input" value="<?= pqa_e((string) $config['vat_number']) ?>" required>
              </div>
              <div class="pqa-field">
                <label class="pqa-label">Telefono Ufficiale</label>
                <input type="text" name="phone_display" class="pqa-input" value="<?= pqa_e((string) $config['phone_display']) ?>">
              </div>
            </div>

            <div class="adm-grid-2">
              <div class="pqa-field">
                <label class="pqa-label">Email Segreteria &amp; Destinatario Form Contatti *</label>
                <input type="email" name="email_info" class="pqa-input" value="<?= pqa_e((string) $config['email_info']) ?>" required>
              </div>
              <div class="pqa-field">
                <label class="pqa-label">Email Laboratorio</label>
                <input type="email" name="email_lab" class="pqa-input" value="<?= pqa_e((string) $config['email_lab']) ?>">
              </div>
            </div>

            <div class="pqa-field">
              <label class="pqa-label">Casella PEC *</label>
              <input type="email" name="pec" class="pqa-input" value="<?= pqa_e((string) $config['pec']) ?>" required>
            </div>

            <div class="adm-grid-2">
              <div class="pqa-field">
                <label class="pqa-label">Orari di Apertura Segreteria</label>
                <input type="text" name="opening_hours" class="pqa-input" value="<?= pqa_e((string) $config['opening_hours']) ?>">
              </div>
              <div class="pqa-field">
                <label class="pqa-label">Orari Accettazione Campioni</label>
                <input type="text" name="sample_hours" class="pqa-input" value="<?= pqa_e((string) $config['sample_hours']) ?>">
              </div>
            </div>

            <hr style="border:none; border-top:1px solid var(--pqa-border); margin:28px 0;">

            <h3>Box Qualità &amp; Accreditamento ISO 17025</h3>
            <div class="pqa-field">
              <label class="pqa-checkbox-label">
                <input type="checkbox" name="acc_enabled" value="1" <?= !empty($config['accreditation']['enabled']) ? 'checked' : '' ?>>
                <span><strong>Mostra badge e sezione Qualità UNI CEI EN ISO/IEC 17025 sul sito</strong></span>
              </label>
            </div>

            <div class="adm-grid-2">
              <div class="pqa-field">
                <label class="pqa-label">Norma di riferimento</label>
                <input type="text" name="acc_standard" class="pqa-input" value="<?= pqa_e((string) ($config['accreditation']['standard'] ?? '')) ?>">
              </div>
              <div class="adm-grid-2">
                <div class="pqa-field">
                  <label class="pqa-label">Ente</label>
                  <input type="text" name="acc_body" class="pqa-input" value="<?= pqa_e((string) ($config['accreditation']['body'] ?? '')) ?>">
                </div>
                <div class="pqa-field">
                  <label class="pqa-label">Numero Laboratorio</label>
                  <input type="text" name="acc_code" class="pqa-input" value="<?= pqa_e((string) ($config['accreditation']['code'] ?? '')) ?>">
                </div>
              </div>
            </div>

            <div class="pqa-field">
              <label class="pqa-label">Titolo Box Qualità</label>
              <input type="text" name="acc_title" class="pqa-input" value="<?= pqa_e((string) ($config['accreditation']['title'] ?? '')) ?>">
            </div>

            <div class="pqa-field">
              <label class="pqa-label">Descrizione Qualità &amp; Competenza Tecnica</label>
              <textarea name="acc_description" class="pqa-textarea" style="min-height:92px;"><?= pqa_e((string) ($config['accreditation']['description'] ?? '')) ?></textarea>
            </div>

            <button type="submit" class="pqa-btn pqa-btn-primary">Salva Tutte le Impostazioni</button>
          </form>
        </section>

      <?php elseif ($activeTab === 'branding'): ?>
        <!-- TAB 4: SOSTITUZIONE / GESTIONE LOGO -->
        <section class="adm-card">
          <h2>Marchio Aziendale (Header &amp; Footer)</h2>
          <p style="color:var(--pqa-muted); font-size:0.92rem; margin-bottom:24px;">
            Il sito utilizza il marchio vettoriale <strong>Goccia Molecolare (Concept A)</strong> in doppia declinazione cromatica. In qualsiasi momento è possibile caricare un marchio sostitutivo (SVG, PNG, WEBP) o ripristinare quello predefinito.
          </p>

          <div class="adm-grid-2" style="margin-bottom:24px;">
            <!-- Variante Fondo Chiaro -->
            <div style="border:1px solid var(--pqa-border); border-radius:var(--radius-md); overflow:hidden;">
              <div style="background:#F6F9FB; height:120px; display:flex; align-items:center; justify-content:center; padding:16px;">
                <img src="<?= pqa_e($config['branding']['logo_light']) ?>" alt="Anteprima logo chiaro" style="max-height:62px; width:auto;">
              </div>
              <form method="post" action="admin.php?tab=branding" enctype="multipart/form-data" style="padding:18px;">
                <input type="hidden" name="csrf_token" value="<?= pqa_e($csrfToken) ?>">
                <input type="hidden" name="action" value="upload_logo">
                <input type="hidden" name="tab" value="branding">
                <input type="hidden" name="variant" value="light">
                <label class="pqa-label">Logo per Fondo Chiaro (Header)</label>
                <input type="file" name="logo_file" accept=".svg,.png,.webp,.jpg,.jpeg" required style="font-size:0.85rem; margin-bottom:12px; display:block;">
                <button type="submit" class="pqa-btn pqa-btn-sm pqa-btn-primary">Sostituisci Logo Chiaro</button>
              </form>
            </div>

            <!-- Variante Fondo Scuro -->
            <div style="border:1px solid var(--pqa-border); border-radius:var(--radius-md); overflow:hidden;">
              <div style="background:#172D21; height:120px; display:flex; align-items:center; justify-content:center; padding:16px;">
                <img src="<?= pqa_e($config['branding']['logo_dark']) ?>" alt="Anteprima logo scuro" style="max-height:62px; width:auto;">
              </div>
              <form method="post" action="admin.php?tab=branding" enctype="multipart/form-data" style="padding:18px;">
                <input type="hidden" name="csrf_token" value="<?= pqa_e($csrfToken) ?>">
                <input type="hidden" name="action" value="upload_logo">
                <input type="hidden" name="tab" value="branding">
                <input type="hidden" name="variant" value="dark">
                <label class="pqa-label">Logo per Fondo Scuro (Footer)</label>
                <input type="file" name="logo_file" accept=".svg,.png,.webp,.jpg,.jpeg" required style="font-size:0.85rem; margin-bottom:12px; display:block;">
                <button type="submit" class="pqa-btn pqa-btn-sm pqa-btn-primary">Sostituisci Logo Scuro</button>
              </form>
            </div>
          </div>

          <?php if (!empty($config['branding']['is_custom_light']) || !empty($config['branding']['is_custom_dark'])): ?>
            <form method="post" action="admin.php?tab=branding" onsubmit="return confirm('Ripristinare il logo ufficiale Goccia Molecolare predefinito?');">
              <input type="hidden" name="csrf_token" value="<?= pqa_e($csrfToken) ?>">
              <input type="hidden" name="action" value="reset_logos">
              <input type="hidden" name="tab" value="branding">
              <button type="submit" class="pqa-btn pqa-btn-outline">Ripristina Logo Predefinito (Goccia Molecolare)</button>
            </form>
          <?php endif; ?>
        </section>

      <?php elseif ($activeTab === 'messages'): ?>
        <!-- TAB 5: ARCHIVIO RICHIESTE CONTATTO -->
        <section class="adm-card">
          <h2>Richieste ricevute dal Modulo Contatti</h2>
          <p style="color:var(--pqa-muted); font-size:0.9rem; margin-bottom:22px;">
            Oltre all’inoltro automatico via email a <strong><?= pqa_e($config['email_info']) ?></strong>, le richieste inviate dal sito vengono custodite in copia di sicurezza in questo registro protetto.
          </p>

          <?php if (empty($contactLogs)): ?>
            <p style="padding:24px; background:var(--pqa-ice); border-radius:var(--radius-sm); color:var(--pqa-muted); text-align:center;">
              Nessuna richiesta registrata al momento.
            </p>
          <?php else: ?>
            <?php foreach ($contactLogs as $entry): ?>
              <div style="padding:18px 20px; border:1px solid var(--pqa-border); border-radius:var(--radius-sm); margin-bottom:14px; background:var(--pqa-ice);">
                <div style="display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap; margin-bottom:8px;">
                  <div>
                    <strong style="color:var(--pqa-navy);"><?= pqa_e((string) ($entry['name'] ?? '')) ?></strong>
                    • <a href="mailto:<?= pqa_e((string) ($entry['email'] ?? '')) ?>"><?= pqa_e((string) ($entry['email'] ?? '')) ?></a>
                    <?php if (!empty($entry['phone'])): ?>
                      • Tel: <a href="tel:<?= pqa_e((string) $entry['phone']) ?>"><?= pqa_e((string) $entry['phone']) ?></a>
                    <?php endif; ?>
                  </div>
                  <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
                    <?php if (!empty($entry['mail_sent'])): ?>
                      <span class="pqa-status-badge pqa-status-ready" style="font-size:0.72rem; padding:2px 9px;">Email inoltrata</span>
                    <?php else: ?>
                      <span class="pqa-status-badge pqa-status-pending" style="font-size:0.72rem; padding:2px 9px;" title="Il server di hosting non ha confermato l'invio tramite PHP mail(); la richiesta è comunque custodita qui.">Solo archivio locale</span>
                    <?php endif; ?>
                    <span style="font-size:0.8rem; color:var(--pqa-muted);"><?= pqa_e((string) ($entry['created_human'] ?? '')) ?></span>
                  </div>
                </div>
                <div style="font-size:0.83rem; font-weight:700; color:var(--pqa-teal); margin-bottom:8px;">
                  Ambito: <?= pqa_e((string) ($entry['subject'] ?? '')) ?>
                </div>
                <p style="margin:0 0 12px; white-space:pre-wrap; font-size:0.92rem; color:var(--pqa-text);"><?= pqa_e((string) ($entry['message'] ?? '')) ?></p>
                <form method="post" action="admin.php?tab=messages" style="margin:0;" onsubmit="return confirm('Eliminare questo messaggio dal registro?');">
                  <input type="hidden" name="csrf_token" value="<?= pqa_e($csrfToken) ?>">
                  <input type="hidden" name="action" value="delete_message">
                  <input type="hidden" name="tab" value="messages">
                  <input type="hidden" name="msg_id" value="<?= pqa_e((string) ($entry['id'] ?? '')) ?>">
                  <button type="submit" class="pqa-btn pqa-btn-sm pqa-btn-outline" style="padding:6px 12px; font-size:0.78rem;">Elimina</button>
                </form>
              </div>
            <?php endforeach; ?>
          <?php endif; ?>
        </section>

      <?php elseif ($activeTab === 'security'): ?>
        <!-- TAB 6: SICUREZZA & CAMBIO PASSWORD -->
        <section class="adm-card" style="max-width:620px;">
          <h2>Modifica Password Amministratore</h2>
          <p style="color:var(--pqa-muted); font-size:0.9rem; margin-bottom:22px;">
            La password viene archiviata esclusivamente in formato crittografico irreversibile (<code>bcrypt</code>). Scegli una password robusta di almeno 8 caratteri.
          </p>

          <form method="post" action="admin.php?tab=security">
            <input type="hidden" name="csrf_token" value="<?= pqa_e($csrfToken) ?>">
            <input type="hidden" name="action" value="change_password">
            <input type="hidden" name="tab" value="security">

            <div class="pqa-field">
              <label class="pqa-label" for="current_password">Password Attuale *</label>
              <input type="password" id="current_password" name="current_password" class="pqa-input" required autocomplete="current-password">
            </div>

            <div class="pqa-field">
              <label class="pqa-label" for="new_password">Nuova Password (minimo 8 caratteri) *</label>
              <input type="password" id="new_password" name="new_password" class="pqa-input" required minlength="8" maxlength="72" autocomplete="new-password">
            </div>

            <div class="pqa-field">
              <label class="pqa-label" for="confirm_password">Conferma Nuova Password *</label>
              <input type="password" id="confirm_password" name="confirm_password" class="pqa-input" required minlength="8" maxlength="72" autocomplete="new-password">
            </div>

            <button type="submit" class="pqa-btn pqa-btn-primary">Aggiorna Password</button>
          </form>
        </section>
      <?php endif; ?>

    <?php endif; ?>

  </main>
</body>
</html>
