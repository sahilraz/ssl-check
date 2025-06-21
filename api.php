<?php
// db-api/api.php
// Secure PHP API for DB connection test and SSL check

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

function json_response($data, $code = 200) {
    http_response_code($code);
    echo json_encode($data);
    exit;
}

function get_path() {
    $uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
    return rtrim($uri, '/');
}

function log_request($endpoint, $body = null) {
    $log = [
        'time' => date('c'),
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'method' => $_SERVER['REQUEST_METHOD'],
        'endpoint' => $endpoint,
    ];
    if ($body) {
        $log['body'] = $body;
        if (isset($log['body']['db_pass'])) {
            $log['body']['db_pass'] = '[HIDDEN]';
        }
    }
    error_log(json_encode($log));
}

$path = get_path();

if ($path === '/api/test-connection' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    log_request($path, $input);

    $db_host = trim($input['db_host'] ?? '');
    $db_name = trim($input['db_name'] ?? '');
    $db_user = trim($input['db_user'] ?? '');
    $db_pass = $input['db_pass'] ?? '';

    if (!$db_host || !$db_name || !$db_user) {
        json_response([
            'success' => false,
            'message' => 'Missing required fields',
            'error' => 'Host, database name, and username are required'
        ]);
    }

    try {
        $dsn = "mysql:host=$db_host;dbname=$db_name;charset=utf8mb4";
        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_TIMEOUT => 10,
        ];
        $pdo = new PDO($dsn, $db_user, $db_pass, $options);
        // Test query
        $stmt = $pdo->query('SELECT 1');
        json_response([
            'success' => true,
            'message' => 'Database connection successful!',
            'details' => [
                'host' => $db_host,
                'database' => $db_name,
                'user' => $db_user
            ]
        ]);
    } catch (PDOException $e) {
        $errorMessage = $e->getMessage();
        $errorDetails = [
            'errorCode' => $e->getCode(),
        ];
        if (strpos($errorMessage, 'SQLSTATE[HY000] [1045]') !== false) {
            $errorMessage = 'Access denied. Please check your username and password.';
        } elseif (strpos($errorMessage, 'SQLSTATE[HY000] [2002]') !== false) {
            $errorMessage = 'Could not connect to database server. Please check if the server is running and the host is correct.';
        } elseif (strpos($errorMessage, 'Unknown database') !== false) {
            $errorMessage = 'Database does not exist.';
        } elseif (strpos($errorMessage, 'SQLSTATE[HY000] [2006]') !== false) {
            $errorMessage = 'Connection timed out. Please check your host and port.';
        }
        json_response([
            'success' => false,
            'message' => 'Database connection failed',
            'error' => $errorMessage,
            'details' => $errorDetails
        ]);
    }
}

if ($path === '/check-ssl' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    $domain = trim($_GET['domain'] ?? '');
    log_request($path, ['domain' => $domain]);
    if (!$domain) {
        json_response(['error' => 'Please provide ?domain=example.com'], 400);
    }
    $context = stream_context_create([
        'ssl' => [
            'capture_peer_cert' => true,
            'verify_peer' => false,
            'verify_peer_name' => false,
            'SNI_enabled' => true,
            'SNI_server_name' => $domain,
        ]
    ]);
    $client = @stream_socket_client(
        "ssl://$domain:443",
        $errno,
        $errstr,
        10,
        STREAM_CLIENT_CONNECT,
        $context
    );
    if (!$client) {
        json_response([
            'domain' => $domain,
            'ssl' => false,
            'score' => 0,
            'error' => $errstr,
            'last_checked' => gmdate('c')
        ]);
    }
    $params = stream_context_get_params($client);
    $cert = $params['options']['ssl']['peer_certificate'] ?? null;
    if (!$cert) {
        json_response([
            'domain' => $domain,
            'ssl' => false,
            'score' => 0,
            'message' => 'No valid SSL certificate found.',
            'last_checked' => gmdate('c')
        ]);
    }
    $certInfo = openssl_x509_parse($cert);
    $validFrom = isset($certInfo['validFrom_time_t']) ? gmdate('c', $certInfo['validFrom_time_t']) : null;
    $validTo = isset($certInfo['validTo_time_t']) ? gmdate('c', $certInfo['validTo_time_t']) : null;
    $now = time();
    $daysRemaining = isset($certInfo['validTo_time_t']) ? round(($certInfo['validTo_time_t'] - $now) / 86400) : 0;
    $issuer = $certInfo['issuer']['CN'] ?? (is_array($certInfo['issuer']) ? json_encode($certInfo['issuer']) : 'Unknown');
    $issuedTo = $certInfo['subject']['CN'] ?? (is_array($certInfo['subject']) ? json_encode($certInfo['subject']) : 'Unknown');
    $protocol = stream_get_meta_data($client)['stream_type'] ?? 'TLS';
    // Simple scoring
    $score = 100;
    if ($daysRemaining < 30) $score -= 30;
    elseif ($daysRemaining < 90) $score -= 10;
    if (isset($certInfo['signatureTypeLN']) && stripos($certInfo['signatureTypeLN'], 'sha1') !== false) $score -= 20;
    json_response([
        'domain' => $domain,
        'ssl' => true,
        'score' => $score,
        'valid_from' => $validFrom,
        'valid_to' => $validTo,
        'days_remaining' => $daysRemaining,
        'issuer' => $issuer,
        'issuedTo' => $issuedTo,
        'protocol' => $protocol,
        'last_checked' => gmdate('c')
    ]);
}

// 404 fallback
json_response(['error' => 'Not found'], 404); 