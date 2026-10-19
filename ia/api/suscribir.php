<?php
/**
 * IA en Español — newsletter signup endpoint (cPanel copy, https://mancolab.com/ia/api/suscribir.php)
 * - Stores subscribers OUTSIDE public_html: /home/<user>/ia_subs/subs.csv (dir 0700, files 0600)
 * - Email validation, honeypot, minimum fill time, per-IP + global rate limits, same-origin check
 * - Records consent (Ley N.º 29733): timestamp, consent version, page, salted IP hash
 * - JSON only. No cookies, no sessions.
 */
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('X-Robots-Tag: noindex');
header_remove('X-Powered-By');
ini_set('session.use_cookies', '0');

const PER_IP_PER_HOUR = 5;
const GLOBAL_PER_DAY  = 300;
const MIN_FILL_MS     = 1500;
const MAX_BODY        = 4096;
const CONSENT_TEXT    = 'Acepto que Manco Lab trate mi correo solo para enviarme este newsletter, según la Ley N.º 29733. Puedo darme de baja cuando quiera.';

function out(int $code, array $data): void { http_response_code($code); echo json_encode($data, JSON_UNESCAPED_UNICODE); exit; }

// public_html/ia/api -> /home/<user>; override with IA_SUBS_DIR (local tests only)
$dir = getenv('IA_SUBS_DIR') ?: dirname(__DIR__, 3) . '/ia_subs';

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { header('Allow: POST'); out(405, ['ok' => false, 'error' => 'Método no permitido.']); }

// Same-origin: if the browser sends Origin, its host must match this host
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin !== '') {
  $oh = strtolower((string) parse_url($origin, PHP_URL_HOST));
  $hh = strtolower(preg_replace('/:\d+$/', '', $_SERVER['HTTP_HOST'] ?? ''));
  $strip = fn($h) => preg_replace('/^www\./', '', $h);
  if ($oh === '' || $strip($oh) !== $strip($hh)) out(403, ['ok' => false, 'error' => 'Origen no permitido.']);
}

$raw = file_get_contents('php://input', false, null, 0, MAX_BODY + 1);
if ($raw === false || strlen($raw) > MAX_BODY) out(413, ['ok' => false, 'error' => 'Solicitud demasiado grande.']);
$ct = strtolower($_SERVER['CONTENT_TYPE'] ?? '');
$in = strpos($ct, 'application/json') !== false ? json_decode($raw, true) : $_POST;
if (!is_array($in)) out(400, ['ok' => false, 'error' => 'Solicitud no válida.']);

// Honeypot / timing: pretend success so bots learn nothing
$hp = trim((string) ($in['website'] ?? ''));
$elapsed = (int) ($in['elapsed'] ?? 0);
if ($hp !== '' || ($elapsed > 0 && $elapsed < MIN_FILL_MS)) out(200, ['ok' => true]);

$email = strtolower(trim((string) ($in['email'] ?? '')));
if (strlen($email) > 200 || !filter_var($email, FILTER_VALIDATE_EMAIL)
    || !preg_match('/^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$/', $email)) {
  out(400, ['ok' => false, 'error' => 'Correo no válido.']);
}
$consent = ($in['consent'] ?? false) === true || ($in['consent'] ?? '') === 'on' || ($in['consent'] ?? '') === '1';
if (!$consent) out(400, ['ok' => false, 'error' => 'Necesitamos tu consentimiento para enviarte el newsletter.']);
$cver = preg_replace('/[^a-zA-Z0-9.\-]/', '', substr((string) ($in['consent_version'] ?? 'v1'), 0, 32));
$page = preg_replace('/[^a-zA-Z0-9\/._\-]/', '', substr((string) ($in['page'] ?? ''), 0, 120));

// Storage dir outside the web root, private
umask(0077);
if (!is_dir($dir) && !@mkdir($dir, 0700, true)) out(503, ['ok' => false, 'error' => 'Suscripción temporalmente no disponible. Escríbenos a info@mancolab.com.']);
@chmod($dir, 0700);
if (!is_file("$dir/.htaccess")) { @file_put_contents("$dir/.htaccess", "Require all denied\nDeny from all\n"); @chmod("$dir/.htaccess", 0600); }

// Secret salt for IP hashing (generated once)
$saltFile = "$dir/.salt";
if (!is_file($saltFile)) { @file_put_contents($saltFile, bin2hex(random_bytes(32)), LOCK_EX); @chmod($saltFile, 0600); }
$salt = (string) @file_get_contents($saltFile);
$ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$ipHash = substr(hash_hmac('sha256', $ip, $salt), 0, 16);

// Rate limits (file-locked JSON)
$rlFile = "$dir/ratelimit.json";
$fh = @fopen($rlFile, 'c+');
if (!$fh) out(503, ['ok' => false, 'error' => 'Suscripción temporalmente no disponible.']);
@chmod($rlFile, 0600);
flock($fh, LOCK_EX);
$rl = json_decode(stream_get_contents($fh) ?: '{}', true) ?: [];
$now = time(); $day = gmdate('Y-m-d');
$rl['ip'] = array_filter($rl['ip'] ?? [], fn($ts) => is_array($ts) && count($ts) > 0);
foreach ($rl['ip'] as $k => $ts) { $rl['ip'][$k] = array_values(array_filter($ts, fn($t) => $t > $now - 3600)); if (!$rl['ip'][$k]) unset($rl['ip'][$k]); }
if (($rl['day'] ?? '') !== $day) { $rl['day'] = $day; $rl['count'] = 0; }
$mine = $rl['ip'][$ipHash] ?? [];
$limited = count($mine) >= PER_IP_PER_HOUR || ($rl['count'] ?? 0) >= GLOBAL_PER_DAY;
if (!$limited) { $mine[] = $now; $rl['ip'][$ipHash] = $mine; $rl['count'] = ($rl['count'] ?? 0) + 1; }
ftruncate($fh, 0); rewind($fh); fwrite($fh, json_encode($rl)); fflush($fh); flock($fh, LOCK_UN); fclose($fh);
if ($limited) { header('Retry-After: 3600'); out(429, ['ok' => false, 'error' => 'Demasiados intentos. Prueba de nuevo en una hora.']); }

// Append to CSV (dedupe; same answer either way so the endpoint does not reveal who is subscribed)
$csv = "$dir/subs.csv";
$fh = @fopen($csv, 'c+');
if (!$fh) out(503, ['ok' => false, 'error' => 'Suscripción temporalmente no disponible.']);
@chmod($csv, 0600);
flock($fh, LOCK_EX);
$exists = false; $first = true;
while (($row = fgetcsv($fh, 0, ',', '"', '\\')) !== false) { if ($first) { $first = false; continue; } if (($row[1] ?? '') === $email) { $exists = true; break; } }
if (!$exists) {
  fseek($fh, 0, SEEK_END);
  if (ftell($fh) === 0) fputcsv($fh, ['timestamp_utc', 'email', 'consent', 'consent_version', 'consent_text', 'source_page', 'ip_hash', 'status'], ',', '"', '\\');
  fputcsv($fh, [gmdate('c'), $email, 'si', $cver, CONSENT_TEXT, $page, $ipHash, 'activo'], ',', '"', '\\');
  fflush($fh);
}
flock($fh, LOCK_UN); fclose($fh);
out(200, ['ok' => true]);
