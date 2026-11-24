<?php

declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);
ini_set('zlib.output_compression', '0');

require __DIR__ . '/lib/urls.php';
require __DIR__ . '/lib/rewrite.php';
require __DIR__ . '/lib/security.php';
require __DIR__ . '/lib/http.php';

header('Cache-Control: private, no-store');
header('X-Content-Type-Options: nosniff');
header('Origin-Agent-Cluster: ?1');
header('Strict-Transport-Security: max-age=31536000');

$routes = configured_routes();
$endpoint = current_endpoint($routes);
[$user, $passwordHash] = authenticate();
$directory = private_directory();
umask(0077);
limit_requests($directory, $user);

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if (!in_array($method, ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'], true)) {
    header('Allow: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS');
    proxy_error(405, 'Method not allowed');
}
$crossOrigin = is_cross_origin($endpoint);
if ($crossOrigin && !in_array($method, ['GET', 'HEAD', 'OPTIONS'], true)) {
    proxy_error(403, 'Cross-origin write is forbidden');
}

$target = $_GET['url'] ?? '';
if (!is_string($target) || strlen($target) > 8192 || ($parts = http_url_parts($target)) === null) {
    proxy_error(400, 'Usage: /run.php?url=https://example.com/');
}
$origin = url_origin($parts);
if (($routes[$origin] ?? null) !== $endpoint) {
    proxy_error(403, 'Destination is not allowed on this proxy endpoint');
}
$target = explode('#', $target, 2)[0];

if (is_blocked_url($target)) {
    header('Content-Type: application/javascript; charset=utf-8');
    header('Content-Length: 0');
    exit;
}

$cookieFile = $crossOrigin ? null : session_cookie_file($directory, $user, $passwordHash, $origin);
[$status, $headers, $body, $bytes] = fetch_upstream($target, $parts, $method, $routes, $cookieFile);
send_upstream_response($status, $headers, $body, $bytes, $target, $method, $routes, $endpoint, $crossOrigin);
fclose($body);
