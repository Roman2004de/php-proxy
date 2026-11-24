<?php

declare(strict_types=1);

function upstream_request_headers(array $routes): array
{
    $allowed = [
        'accept', 'accept-language', 'content-type', 'range', 'if-range',
        'if-match', 'if-none-match', 'if-modified-since', 'if-unmodified-since',
        'access-control-request-method', 'access-control-request-headers', 'x-requested-with',
        'x-csrf-token', 'x-xsrf-token',
    ];
    $headers = ['Accept-Encoding: identity'];
    foreach ($allowed as $name) {
        $key = $name === 'content-type' ? 'CONTENT_TYPE' : 'HTTP_' . strtoupper(str_replace('-', '_', $name));
        $value = $_SERVER[$key] ?? '';
        if ($value !== '' && !preg_match('~[\x00-\x1f\x7f]~', $value)) {
            $headers[] = $name . ': ' . $value;
        }
    }
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin !== '') {
        $headers[] = 'Origin: ' . (upstream_origin_for_browser($origin, $routes) ?? 'null');
    }
    $referer = proxied_target($_SERVER['HTTP_REFERER'] ?? '', $routes);
    if ($referer !== null) {
        $headers[] = 'Referer: ' . explode('#', $referer, 2)[0];
    }
    return $headers;
}

function fetch_upstream(string $target, array $parts, string $method, array $routes, ?string $cookieFile): array
{
    $maximum = configured_limit('PHP_PROXY_MAX_RESPONSE_BYTES', 32 * 1024 * 1024, 256 * 1024 * 1024);
    $maximumInput = 2 * 1024 * 1024;
    $input = null;
    if ($method !== 'GET' && $method !== 'HEAD' && $method !== 'OPTIONS') {
        $input = file_get_contents('php://input', false, null, 0, $maximumInput + 1);
        if ($input === false) {
            proxy_error(400, 'Cannot read request body');
        }
        if (strlen($input) > $maximumInput) {
            proxy_error(413, 'Request body too large');
        }
    }

    $host = strtolower($parts['host']);
    $port = $parts['port'] ?? (strtolower($parts['scheme']) === 'https' ? 443 : 80);
    $address = pinned_address($host);
    $body = fopen('php://temp/maxmemory:1048576', 'w+b');
    if ($body === false) {
        config_error('Cannot open response buffer');
    }

    $responseHeaders = [];
    $headerBytes = 0;
    $bytes = 0;
    $exceeded = false;
    $ch = curl_init($target);
    $options = [
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_NOBODY => $method === 'HEAD',
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_PROXY => '',
        CURLOPT_RESOLVE => [$host . ':' . $port . ':' . $address],
        CURLOPT_HTTPHEADER => upstream_request_headers($routes),
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_USERAGENT => $_SERVER['HTTP_USER_AGENT'] ?? 'Mozilla/5.0',
        CURLOPT_TIMEOUT => 40,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_HEADERFUNCTION => static function ($handle, string $line) use (&$responseHeaders, &$headerBytes): int {
            $length = strlen($line);
            $headerBytes += $length;
            if ($headerBytes > 64 * 1024) {
                return 0;
            }
            if (str_starts_with($line, 'HTTP/')) {
                $responseHeaders = [];
            } elseif (($colon = strpos($line, ':')) !== false) {
                $name = strtolower(substr($line, 0, $colon));
                $value = trim(substr($line, $colon + 1));
                if (preg_match('~\A[a-z0-9-]+\z~', $name) && !preg_match('~[\x00-\x08\x0a-\x1f\x7f]~', $value)) {
                    $responseHeaders[$name][] = $value;
                }
            }
            return $length;
        },
        CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use ($body, $maximum, &$bytes, &$exceeded): int {
            $length = strlen($chunk);
            if ($length > $maximum - $bytes) {
                $exceeded = true;
                return 0;
            }
            $written = fwrite($body, $chunk);
            $bytes += (int) $written;
            return (int) $written;
        },
    ];
    if ($input !== null) {
        $options[CURLOPT_POSTFIELDS] = $input;
    }

    // A bounded set of locks protects jars without creating a file for every visitor.
    $lock = null;
    $hasCookieFile = false;
    if ($cookieFile !== null) {
        $lockFile = dirname($cookieFile) . '/cookie-lock-' . substr(basename($cookieFile), 4, 3);
        $lock = fopen($lockFile, 'c+');
        if ($lock === false || !flock($lock, LOCK_EX)) {
            config_error('Cannot lock the upstream cookie jar');
        }
        $hasCookieFile = is_file($cookieFile);
        $options[CURLOPT_COOKIEFILE] = $hasCookieFile ? $cookieFile : '';
    }
    // CURLOPT_PROTOCOLS_STR supersedes CURLOPT_PROTOCOLS on newer PHP/libcurl.
    if (defined('CURLOPT_PROTOCOLS_STR')) {
        unset($options[CURLOPT_PROTOCOLS]);
        $options[CURLOPT_PROTOCOLS_STR] = 'http,https';
    }
    if (!curl_setopt_array($ch, $options)) {
        config_error('Cannot configure cURL');
    }
    $result = curl_exec($ch);
    $curlError = curl_errno($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    if ($result !== false && $cookieFile !== null) {
        $cookies = curl_getinfo($ch, CURLINFO_COOKIELIST);
        if ($cookies) {
            if (!curl_setopt($ch, CURLOPT_COOKIEJAR, $cookieFile)) {
                config_error('Cannot save the upstream cookie jar');
            }
        } elseif ($hasCookieFile && is_array($cookies) && !unlink($cookieFile)) {
            config_error('Cannot remove an empty upstream cookie jar');
        }
    }
    // Destroy the handle (and flush its cookie jar) while the lock is held.
    unset($ch);
    if (is_resource($lock)) {
        fclose($lock);
    }
    if ($result === false || $status < 200 || $status > 599) {
        fclose($body);
        if ($exceeded) {
            proxy_error(502, 'Upstream response exceeds the configured limit');
        }
        error_log('PHP proxy: upstream transfer failed (' . $curlError . ') for ' . $host);
        proxy_error(502, 'Upstream request failed');
    }

    rewind($body);
    return [$status, $responseHeaders, $body, $bytes];
}

function detect_body_kind(string $contentType, string $url): string
{
    $mediaType = strtolower(trim(explode(';', $contentType, 2)[0]));
    if ($mediaType === '') {
        $extension = strtolower(pathinfo(parse_url($url, PHP_URL_PATH) ?? '', PATHINFO_EXTENSION));
        return match ($extension) {
            'htm', 'html' => 'html',
            'css' => 'css',
            'js', 'mjs' => 'js',
            'svg' => 'svg',
            default => 'binary',
        };
    }
    return match ($mediaType) {
        'text/html' => 'html',
        'text/css' => 'css',
        'application/javascript', 'application/x-javascript', 'text/javascript',
        'application/ecmascript', 'text/ecmascript', 'text/jscript' => 'js',
        'image/svg+xml' => 'svg',
        default => 'binary',
    };
}

function response_headers(array $headers, array $routes, bool $rewritten, bool $crossOrigin, bool $allowLength): void
{
    $forward = [
        'content-language', 'content-disposition', 'content-security-policy', 'content-security-policy-report-only',
        'x-frame-options', 'cross-origin-embedder-policy', 'cross-origin-opener-policy', 'cross-origin-resource-policy',
        'cross-origin-embedder-policy-report-only', 'cross-origin-opener-policy-report-only',
        'permissions-policy', 'referrer-policy', 'timing-allow-origin',
        'access-control-allow-methods', 'access-control-allow-headers', 'access-control-expose-headers',
        'access-control-max-age', 'retry-after',
    ];
    if (!$rewritten) {
        array_push($forward, 'content-encoding', 'content-range', 'accept-ranges', 'etag', 'last-modified');
    }
    if ($allowLength && isset($headers['content-length'][0]) && count($headers['content-length']) === 1 &&
        preg_match('~\A[0-9]+\z~', $headers['content-length'][0])) {
        $forward[] = 'content-length';
    }
    foreach ($forward as $name) {
        foreach ($headers[$name] ?? [] as $value) {
            header($name . ': ' . $value, false);
        }
    }
    $allowedOrigin = $headers['access-control-allow-origin'][0] ?? null;
    if ($allowedOrigin === '*') {
        header('Access-Control-Allow-Origin: *');
    } elseif (isset($routes[$allowedOrigin])) {
        header('Access-Control-Allow-Origin: ' . url_origin(parse_url($routes[$allowedOrigin])));
        if (!$crossOrigin && ($headers['access-control-allow-credentials'][0] ?? '') === 'true') {
            header('Access-Control-Allow-Credentials: true');
        }
    }
}

function send_upstream_response(
    int $status, array $headers, $body, int $bytes, string $target, string $method,
    array $routes, string $endpoint, bool $crossOrigin
): void {
    $location = null;
    if (in_array($status, [300, 301, 302, 303, 307, 308], true) && isset($headers['location'][0])) {
        $location = absolute_url($headers['location'][0], $target);
        $locationParts = http_url_parts($location);
        if ($locationParts === null || !isset($routes[url_origin($locationParts)])) {
            proxy_error(403, 'Redirect destination is forbidden');
        }
        // An absolute target is needed here even for a fragment-only Location.
        $location = proxy_url($location, $target, $routes, $endpoint);
        if (!str_starts_with($location, 'https://')) {
            proxy_error(403, 'Redirect destination is forbidden');
        }
    }

    $contentType = $headers['content-type'][0] ?? '';
    $kind = detect_body_kind($contentType, $target);
    $encoding = strtolower(trim(implode(',', $headers['content-encoding'] ?? [])));
    $rewrite = $kind !== 'binary' && $status !== 206 && ($encoding === '' || $encoding === 'identity') &&
        !preg_match('~;\s*charset\s*=\s*["\']?(?:utf-(?:16|32)|ucs-)~i', $contentType);
    $withoutBody = in_array($status, [204, 205, 304], true);
    $text = null;
    if ($method !== 'HEAD' && !$withoutBody && $rewrite && $location === null) {
        // Whole-document rewriting needs bounded memory even when binary transfers spill to disk.
        $content = $bytes <= 2 * 1024 * 1024 ? stream_get_contents($body) : false;
        try {
            $text = $content === false ? null : rewrite_text_urls($content, $target, $kind, $routes, $endpoint);
        } catch (LengthException) {
            $text = null;
        }
        if ($text === null || strlen($text) > 8 * 1024 * 1024) {
            proxy_error(502, 'Upstream text cannot be rewritten within the configured limits');
        }
    }

    http_response_code($status);
    $replacesRepresentation = $rewrite || $location !== null;
    $preserveLength = $method === 'HEAD' && !$replacesRepresentation && !$withoutBody;
    response_headers($headers, $routes, $replacesRepresentation, $crossOrigin, $preserveLength);
    if ($location !== null) {
        header('Location: ' . $location, true, $status);
        if (!$withoutBody && $method !== 'HEAD') {
            header('Content-Length: 0');
        }
        return;
    }

    if ($contentType === '') {
        $contentType = match ($kind) {
            'html' => 'text/html; charset=utf-8',
            'css' => 'text/css; charset=utf-8',
            'js' => 'application/javascript; charset=utf-8',
            'svg' => 'image/svg+xml; charset=utf-8',
            default => 'application/octet-stream',
        };
    }
    header('Content-Type: ' . $contentType);
    if ($status === 205) {
        header('Content-Length: 0');
    }
    if ($method === 'HEAD' || $withoutBody) {
        return;
    }
    if ($text !== null) {
        header('Content-Length: ' . strlen($text));
        echo $text;
    } else {
        header('Content-Length: ' . $bytes);
        fpassthru($body);
    }
}
