<?php
declare(strict_types=1);

if (basename($_SERVER['SCRIPT_FILENAME'] ?? '') === basename(__FILE__)) {
    http_response_code(403);
    exit;
}

const PQA_JSON_GUARD = "<?php http_response_code(403); exit; ?>\n";

/**
 * Legge in modo atomico e sicuro (LOCK_SH) un file JSON protetto da guard PHP.
 */
function pqa_read_json(string $filepath, array $default = []): array
{
    if (!is_file($filepath)) {
        return $default;
    }

    $fp = @fopen($filepath, 'rb');
    if ($fp === false) {
        return $default;
    }

    $raw = '';
    if (flock($fp, LOCK_SH)) {
        $raw = stream_get_contents($fp) ?: '';
        flock($fp, LOCK_UN);
    }
    fclose($fp);

    if ($raw === '') {
        return $default;
    }

    if (str_starts_with($raw, '<?php')) {
        $newlinePos = strpos($raw, "\n");
        $raw = $newlinePos !== false ? substr($raw, $newlinePos + 1) : '';
    }

    $decoded = json_decode(trim($raw), true);
    return is_array($decoded) ? $decoded : $default;
}

/**
 * Scrive in modo atomico (file .lock con LOCK_EX + scrittura .tmp + rename) un file JSON protetto.
 */
function pqa_write_json(string $filepath, array $data): bool
{
    $dir = dirname($filepath);
    if (!is_dir($dir) && !@mkdir($dir, 0755, true) && !is_dir($dir)) {
        return false;
    }

    $lockFile = $filepath . '.lock';
    $lockFp = @fopen($lockFile, 'cb');
    if ($lockFp === false) {
        return false;
    }

    if (!flock($lockFp, LOCK_EX)) {
        fclose($lockFp);
        return false;
    }

    $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($json === false) {
        flock($lockFp, LOCK_UN);
        fclose($lockFp);
        return false;
    }

    $payload = PQA_JSON_GUARD . $json . "\n";
    $tmpFile = $filepath . '.' . bin2hex(random_bytes(6)) . '.tmp';

    $written = @file_put_contents($tmpFile, $payload, LOCK_EX);
    if ($written === false) {
        @unlink($tmpFile);
        flock($lockFp, LOCK_UN);
        fclose($lockFp);
        return false;
    }

    $renamed = @rename($tmpFile, $filepath);
    if (!$renamed) {
        // Fallback Windows nel caso di lock transitorio sul file di destinazione
        $renamed = @copy($tmpFile, $filepath);
        @unlink($tmpFile);
    }

    flock($lockFp, LOCK_UN);
    fclose($lockFp);

    return $renamed;
}

/**
 * Restituisce la configurazione predefinita del sito Centro Analisi P.Q.A. S.r.l.
 */
function pqa_default_config(): array
{
    return [
        'company_name' => 'Centro Analisi P.Q.A. S.r.l.',
        'director_name' => 'Dott.ssa Maria Grazia Micieli',
        'address_street' => 'Corso Gelone, 82',
        'address_city' => '96100 Siracusa (SR)',
        'vat_number' => '01624410898',
        'phone_display' => '+39 0931 483018',
        'phone_link' => '+390931483018',
        'email_info' => 'info@centroanalisipqa.it',
        'email_lab' => 'laboratorio@centroanalisipqa.it',
        'email_odv' => 'odv@centroanalisipqa.it',
        'pec' => 'centroanalisipqasrl@arubapec.it',
        'opening_hours' => 'Lun – Ven: 08:30 – 13:00 / 15:00 – 18:00',
        'sample_hours' => 'Accettazione campioni: Lun – Gio 08:30 – 12:30 (o su appuntamento tecnico)',
        'accreditation' => [
            'enabled' => true,
            'standard' => 'UNI CEI EN ISO/IEC 17025',
            'body' => 'ACCREDIA',
            'code' => 'Lab N. 00859',
            'title' => 'Sistema di Gestione della Qualità e Competenza Tecnica',
            'description' => 'Il laboratorio opera in conformità ai requisiti della norma internazionale UNI CEI EN ISO/IEC 17025, assicurando riferibilità metrologica, taratura certificata delle apparecchiature, partecipazione regolare a circuiti interlaboratorio (Proficiency Testing) e piena imparzialità del dato analitico.',
        ],
        'whistleblowing' => [
            'url' => '',
            'button_label' => 'Accedi alla Piattaforma Segnalazioni',
            'pending_label' => 'Canale telematico crittografato in attivazione',
            'summary' => 'In conformità al D.Lgs. 10 marzo 2023, n. 24, Centro Analisi P.Q.A. S.r.l. garantisce la massima tutela della riservatezza dell’identità del segnalante, della persona coinvolta e del contenuto della segnalazione, nonché il divieto assoluto di qualsiasi atto di ritorsione o discriminazione.',
        ],
        'branding' => [
            'logo_light' => 'assets/img/logo-light.svg',
            'logo_dark' => 'assets/img/logo-dark.svg',
            'is_custom_light' => false,
            'is_custom_dark' => false,
        ],
        'map' => [
            'embed_url' => 'https://maps.google.com/maps?q=Corso%20Gelone%2082%2C%2096100%20Siracusa%20SR&hl=it&z=16&output=embed',
            'external_url' => 'https://www.google.com/maps/search/?api=1&query=Corso+Gelone+82%2C+96100+Siracusa+SR',
        ],
        'security' => [
            'admin_password_hash' => '$2y$10$wP.O5L3x0jR1zS9l1f2MWe7U9k6Y2w0T8vE4xJ7qK5mN3pB1cD6aG', // Sovrascritto al bootstrap con password_hash reale
            'password_changed_at' => null,
            'updated_at' => date('c'),
        ],
    ];
}

/**
 * Restituisce il registro predefinito dei documenti societari 231 e Whistleblowing.
 */
function pqa_default_documents(): array
{
    return [
        'modello_231' => [
            'id' => 'modello_231',
            'category' => 'Governance & Compliance D.Lgs. 231/2001',
            'title' => 'Modello di Organizzazione, Gestione e Controllo',
            'subtitle' => 'Parte Generale — adottato ai sensi del D.Lgs. 8 giugno 2001, n. 231',
            'description' => 'Definisce l’assetto organizzativo, il sistema di presidi preventivi, le procedure decisionali e i flussi informativi verso l’Organismo di Vigilanza adottati dal Centro Analisi P.Q.A. S.r.l.',
            'revision' => 'Rev. 01',
            'approved_date' => '',
            'visible' => true,
            'optional' => false,
            'download_name' => 'Centro-Analisi-PQA-Modello-Organizzativo-231.pdf',
            'file' => null,
        ],
        'codice_etico' => [
            'id' => 'codice_etico',
            'category' => 'Deontologia & Integrità Tecnica',
            'title' => 'Codice Etico Aziendale',
            'subtitle' => 'Carta dei valori, indipendenza di giudizio e principi comportamentali',
            'description' => 'Stabilisce gli impegni etici, il rigore scientifico, la riservatezza del dato analitico e le regole di condotta vincolanti per Direzione, personale tecnico, collaboratori e fornitori.',
            'revision' => 'Rev. 01',
            'approved_date' => '',
            'visible' => true,
            'optional' => false,
            'download_name' => 'Centro-Analisi-PQA-Codice-Etico.pdf',
            'file' => null,
        ],
        'procedura_whistleblowing' => [
            'id' => 'procedura_whistleblowing',
            'category' => 'Tutela del Segnalante — D.Lgs. 24/2023',
            'title' => 'Informativa e Procedura Whistleblowing',
            'subtitle' => 'Disciplina delle segnalazioni di illeciti e garanzie di riservatezza',
            'description' => 'Dettaglia i soggetti tutelati, l’oggetto delle segnalazioni, le modalità operative di invio sicuro, i tempi di riscontro istruttorio e l’informativa privacy ex artt. 13-14 GDPR.',
            'revision' => 'Rev. 01',
            'approved_date' => '',
            'visible' => true,
            'optional' => true,
            'download_name' => 'Centro-Analisi-PQA-Procedura-Whistleblowing.pdf',
            'file' => null,
        ],
    ];
}

/**
 * Carica e inizializza la configurazione assicurando la presenza di tutte le chiavi attese.
 */
function pqa_get_config(): array
{
    $file = PQA_STORAGE_DIR . '/config.json.php';
    $defaults = pqa_default_config();

    if (!is_file($file)) {
        $defaults['security']['admin_password_hash'] = password_hash('PqaSiracusa2026!', PASSWORD_BCRYPT);
        pqa_write_json($file, $defaults);
        return $defaults;
    }

    $stored = pqa_read_json($file, []);
    $merged = array_replace_recursive($defaults, $stored);

    // Garantisce che logo custom esista davvero su disco, altrimenti ripristina fallback sicuro
    if (!empty($merged['branding']['is_custom_light'])) {
        $lightPath = PQA_ROOT_DIR . '/' . ltrim((string) $merged['branding']['logo_light'], '/');
        if (!is_file($lightPath)) {
            $merged['branding']['logo_light'] = $defaults['branding']['logo_light'];
            $merged['branding']['is_custom_light'] = false;
        }
    }
    if (!empty($merged['branding']['is_custom_dark'])) {
        $darkPath = PQA_ROOT_DIR . '/' . ltrim((string) $merged['branding']['logo_dark'], '/');
        if (!is_file($darkPath)) {
            $merged['branding']['logo_dark'] = $defaults['branding']['logo_dark'];
            $merged['branding']['is_custom_dark'] = false;
        }
    }

    return $merged;
}

/**
 * Carica il registro documenti calcolando dinamicamente esistenza e peso reale dei PDF su disco.
 */
function pqa_get_documents(): array
{
    $file = PQA_STORAGE_DIR . '/documents.json.php';
    $defaults = pqa_default_documents();

    if (!is_file($file)) {
        pqa_write_json($file, $defaults);
        $docs = $defaults;
    } else {
        $stored = pqa_read_json($file, []);
        $docs = [];
        foreach ($defaults as $key => $defDoc) {
            $docs[$key] = isset($stored[$key]) && is_array($stored[$key])
                ? array_replace($defDoc, $stored[$key])
                : $defDoc;
        }
    }

    foreach ($docs as $key => &$doc) {
        $isAvailable = false;
        $sizeBytes = 0;
        if (is_array($doc['file'] ?? null) && !empty($doc['file']['stored_name'])) {
            $pdfName = basename((string) $doc['file']['stored_name']);
            $pdfPath = PQA_DOCS_DIR . '/' . $pdfName;
            if (is_file($pdfPath) && is_readable($pdfPath)) {
                $realSize = @filesize($pdfPath);
                if ($realSize !== false && $realSize > 0) {
                    $isAvailable = true;
                    $sizeBytes = (int) $realSize;
                }
            }
        }
        $doc['is_available'] = $isAvailable;
        $doc['size_bytes'] = $sizeBytes;
        $doc['size_human'] = $isAvailable ? pqa_format_bytes($sizeBytes) : '';
        $doc['approved_date_human'] = pqa_format_date_it((string) ($doc['approved_date'] ?? ''));
        $doc['view_url'] = $isAvailable ? 'api/document.php?id=' . rawurlencode($key) . '&mode=inline' : '';
        $doc['download_url'] = $isAvailable ? 'api/document.php?id=' . rawurlencode($key) . '&mode=download' : '';
    }
    unset($doc);

    return $docs;
}

/**
 * Formatta una dimensione in byte in formato leggibile italiano (KB / MB).
 */
function pqa_format_bytes(int $bytes): string
{
    if ($bytes <= 0) {
        return '0 KB';
    }
    if ($bytes < 1024) {
        return $bytes . ' B';
    }
    if ($bytes < 1048576) {
        $kb = round($bytes / 1024, 1);
        return str_replace('.', ',', (string) $kb) . ' KB';
    }
    $mb = round($bytes / 1048576, 2);
    return str_replace('.', ',', (string) $mb) . ' MB';
}

/**
 * Formatta una data ISO (YYYY-MM-DD) nel formato istituzionale italiano (GG/MM/AAAA).
 */
function pqa_format_date_it(string $dateStr): string
{
    $dateStr = trim($dateStr);
    if ($dateStr === '') {
        return '';
    }
    if (preg_match('/^(\d{4})-(\d{2})-(\d{2})$/', $dateStr, $m)) {
        if (checkdate((int) $m[2], (int) $m[3], (int) $m[1])) {
            return $m[3] . '/' . $m[2] . '/' . $m[1];
        }
    }
    return $dateStr;
}

/**
 * Rate limiter leggero su file per protezione brute-force login e anti-flood form contatti.
 * Restituisce true se l'azione è consentita, false se il limite è stato superato.
 */
function pqa_rate_limit_check(string $bucket, string $identifier, int $maxAttempts, int $windowSeconds, bool $recordHit = true): bool
{
    $file = PQA_STORAGE_DIR . '/rate_limits.json.php';
    $now = time();
    $key = $bucket . ':' . hash('sha256', $identifier);

    $retention = max($windowSeconds, 3600);
    $all = pqa_read_json($file, []);
    // Pulizia record scaduti
    foreach ($all as $k => $timestamps) {
        if (!is_array($timestamps)) {
            unset($all[$k]);
            continue;
        }
        $all[$k] = array_values(array_filter($timestamps, static fn($ts) => is_int($ts) && ($now - $ts) < $retention));
        if (empty($all[$k])) {
            unset($all[$k]);
        }
    }

    $recent = array_values(array_filter(
        $all[$key] ?? [],
        static fn($ts) => is_int($ts) && ($now - $ts) < $windowSeconds
    ));

    if (count($recent) >= $maxAttempts) {
        pqa_write_json($file, $all);
        return false;
    }

    if ($recordHit) {
        $recent[] = $now;
        $all[$key] = $recent;
        pqa_write_json($file, $all);
    }

    return true;
}

/**
 * Azzera i tentativi registrati per un bucket/identificativo (es. dopo login riuscito).
 */
function pqa_rate_limit_clear(string $bucket, string $identifier): void
{
    $file = PQA_STORAGE_DIR . '/rate_limits.json.php';
    $key = $bucket . ':' . hash('sha256', $identifier);
    $all = pqa_read_json($file, []);
    if (isset($all[$key])) {
        unset($all[$key]);
        pqa_write_json($file, $all);
    }
}
