<?php

declare(strict_types=1);

function run_proxy(): void
{
    ini_set('display_errors', '0');
    ini_set('display_startup_errors', '0');
    ini_set('log_errors', '1');
    error_reporting(E_ALL);
    ini_set('zlib.output_compression', '0');

    header('Cache-Control: private, no-store');
    header('X-Content-Type-Options: nosniff');
    header('Origin-Agent-Cluster: ?1');
    header('Strict-Transport-Security: max-age=31536000');

    $routes = configured_routes();
    $endpoint = current_endpoint($routes);
    $directory = private_directory();
    umask(0077);
    $secret = state_secret($directory);
    limit_requests($directory, $secret, $_SERVER['REMOTE_ADDR'] ?? '');

    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if (!in_array($method, ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'], true)) {
        header('Allow: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS');
        proxy_error(405, 'Method not allowed');
    }
    $crossOrigin = is_cross_origin($endpoint);
    if ($crossOrigin && !in_array($method, ['GET', 'HEAD', 'OPTIONS'], true)) {
        proxy_error(403, 'Cross-origin write is forbidden');
    }

    $pathInfo = $_SERVER['PATH_INFO'] ?? '';
    if ($pathInfo !== '') {
        $target = form_target($pathInfo, $method === 'GET' ? ($_SERVER['QUERY_STRING'] ?? '') : null);
    } else {
        $target = $_GET['url'] ?? '';
    }
    if (!is_string($target) || strlen($target) > 8192 || ($parts = http_url_parts($target)) === null) {
        proxy_error(400, 'Usage: /proxy.php?url=https://example.com/');
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

    $cookieFile = $crossOrigin || $method === 'OPTIONS' ? null : session_cookie_file($directory, $secret, $origin);
    $response = fetch_upstream($target, $parts, $method, $routes, $cookieFile, $crossOrigin);
    if ($response !== null) {
        [$status, $headers, $body, $bytes] = $response;
        send_upstream_response($status, $headers, $body, $bytes, $target, $method, $routes, $endpoint, $crossOrigin);
        fclose($body);
    }
}

// Configuration, public access and session state.

function proxy_error(int $status, string $message): never
{
    http_response_code($status);
    header('Content-Type: text/plain; charset=utf-8');
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'HEAD') {
        echo $message . "\n";
    }
    exit;
}

function config_error(string $details): never
{
    error_log('PHP proxy: ' . $details);
    proxy_error(503, 'Proxy configuration unavailable');
}

function config_map(string $key): array
{
    $value = json_decode((string) getenv($key), true);
    if (!is_array($value) || $value === [] || array_is_list($value)) {
        config_error('Invalid ' . $key);
    }
    return $value;
}

function configured_routes(): array
{
    $routes = [];
    $usedHosts = [];
    foreach (config_map('PHP_PROXY_ORIGINS') as $origin => $endpoint) {
        $upstream = http_url_parts($origin);
        $proxy = is_string($endpoint) ? http_url_parts($endpoint) : null;
        if ($upstream === null || !is_dns_hostname($upstream['host']) || url_origin($upstream) !== $origin ||
            $proxy === null || !is_dns_hostname($proxy['host']) || $proxy['scheme'] !== 'https' ||
            !preg_match('~\A/(?:[a-zA-Z0-9_-]+/)*proxy\.php\z~', $proxy['path'] ?? '') ||
            $endpoint !== url_origin($proxy) . $proxy['path'] || isset($usedHosts[$proxy['host']])) {
            config_error('Invalid or shared endpoint in PHP_PROXY_ORIGINS');
        }
        $usedHosts[$proxy['host']] = true;
        $routes[$origin] = $endpoint;
    }
    foreach ($routes as $origin => $endpoint) {
        $host = parse_url($origin, PHP_URL_HOST);
        if (isset($usedHosts[$host])) {
            config_error('Upstream and proxy hostnames must be distinct');
        }
    }
    return $routes;
}

function current_endpoint(array $routes): string
{
    $https = strtolower((string) ($_SERVER['HTTPS'] ?? ''));
    if ($https !== 'on' && $https !== '1') {
        proxy_error(400, 'HTTPS is required');
    }
    $script = $_SERVER['SCRIPT_NAME'] ?? '';
    $pathInfo = $_SERVER['PATH_INFO'] ?? '';
    if ($pathInfo !== '' && str_ends_with($script, $pathInfo)) {
        $script = substr($script, 0, -strlen($pathInfo));
    }
    $endpoint = 'https://' . strtolower($_SERVER['HTTP_HOST'] ?? '') . $script;
    if (!in_array($endpoint, $routes, true)) {
        proxy_error(421, 'Unknown proxy endpoint');
    }
    return $endpoint;
}

function private_directory(): string
{
    $config = (string) getenv('PHP_PROXY_STATE_DIR');
    $directory = $config !== '' && $config[0] === '/' ? realpath($config) : false;
    $documentRoot = !empty($_SERVER['DOCUMENT_ROOT']) ? realpath($_SERVER['DOCUMENT_ROOT']) : false;
    if ($directory === false || $documentRoot === false || !is_dir($directory) ||
        str_starts_with($directory . '/', rtrim($documentRoot, '/') . '/') ||
        str_starts_with($directory . '/', __DIR__ . '/') ||
        (fileperms($directory) & 0777) !== 0700 || !is_writable($directory)) {
        config_error('PHP_PROXY_STATE_DIR must be a writable directory with mode 0700 outside the document root');
    }
    return $directory;
}

function state_secret(string $directory): string
{
    $file = fopen($directory . '/session.key', 'c+b');
    if ($file === false || !flock($file, LOCK_EX)) {
        config_error('Cannot lock the state key');
    }
    $key = stream_get_contents($file, 33);
    if ($key === '') {
        $key = random_bytes(32);
        if (fwrite($file, $key) !== 32 || !fflush($file)) {
            config_error('Cannot save the state key');
        }
    }
    fclose($file);
    if ($key === false || strlen($key) !== 32) {
        config_error('Invalid state key');
    }
    return $key;
}

function configured_limit(string $name, int $default, int $maximum): int
{
    $setting = getenv($name);
    if ($setting === false) {
        return $default;
    }
    $value = filter_var($setting, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => $maximum]]);
    if ($value === false) {
        config_error('Invalid ' . $name);
    }
    return $value;
}

function client_network(string $address): string
{
    $packed = filter_var($address, FILTER_VALIDATE_IP) !== false ? inet_pton($address) : false;
    if ($packed === false) {
        return '';
    }
    if (strlen($packed) === 4) {
        return $packed;
    }
    if (str_starts_with($packed, str_repeat("\0", 10) . "\xff\xff")) {
        return substr($packed, 12);
    }
    // Group temporary IPv6 addresses in the same /64.
    return substr($packed, 0, 8);
}

function rate_count($file, int $offset, int $window): int
{
    if (fseek($file, $offset) !== 0 || ($record = fread($file, 8)) === false) {
        config_error('Cannot read rate counters');
    }
    if (strlen($record) !== 8) {
        return 0;
    }
    $saved = unpack('Nwindow/Ncount', $record);
    return $saved['window'] === $window ? $saved['count'] : 0;
}

function write_rate_count($file, int $offset, int $window, int $count): void
{
    if (fseek($file, $offset) !== 0 || fwrite($file, pack('NN', $window, $count)) !== 8) {
        config_error('Cannot update rate counters');
    }
}

function limit_requests(string $directory, string $secret, string $address): void
{
    $perClient = configured_limit('PHP_PROXY_REQUESTS_PER_MINUTE', 240, 100000);
    $global = configured_limit('PHP_PROXY_GLOBAL_REQUESTS_PER_MINUTE', 2400, 100000);
    // Record zero is the global counter. Fixed-size buckets cap disk usage regardless of client count.
    $bucket = hexdec(substr(hash_hmac('sha256', client_network($address), $secret), 0, 4));
    $clientOffset = ($bucket + 1) * 8;
    $file = fopen($directory . '/rates.bin', 'c+b');
    if ($file === false || !flock($file, LOCK_EX)) {
        config_error('Cannot lock rate counters');
    }
    $window = intdiv(time(), 60);
    $total = rate_count($file, 0, $window);
    $count = rate_count($file, $clientOffset, $window);
    if ($total >= $global || $count >= $perClient) {
        fclose($file);
        header('Retry-After: ' . max(1, ($window + 1) * 60 - time()));
        proxy_error(429, 'Request limit exceeded');
    }
    write_rate_count($file, 0, $window, $total + 1);
    write_rate_count($file, $clientOffset, $window, $count + 1);
    if (!fflush($file)) {
        config_error('Cannot save rate counters');
    }
    fclose($file);
}

function ip_in_range(string $address, string $network, int $bits): bool
{
    $address = inet_pton($address);
    $network = inet_pton($network);
    $bytes = intdiv($bits, 8);
    $rest = $bits % 8;
    return substr($address, 0, $bytes) === substr($network, 0, $bytes) &&
        ($rest === 0 || ((ord($address[$bytes]) ^ ord($network[$bytes])) >> (8 - $rest)) === 0);
}

function is_public_ip(string $address): bool
{
    if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_GLOBAL_RANGE) === false) {
        return false;
    }
    if (!str_contains($address, ':')) {
        return !ip_in_range($address, '224.0.0.0', 4);
    }
    // Exclude translation/tunnel and special-purpose ranges as well as non-global addresses.
    return ip_in_range($address, '2000::', 3) &&
        !ip_in_range($address, '2001::', 23) &&
        !ip_in_range($address, '2002::', 16) &&
        !ip_in_range($address, '3fff::', 20);
}

function pinned_address(string $host): string
{
    $records = dns_get_record($host . '.', DNS_A | DNS_AAAA);
    $addresses = [];
    foreach ($records ?: [] as $record) {
        $address = $record['ip'] ?? $record['ipv6'] ?? null;
        if ($address === null) {
            continue;
        }
        if (!is_public_ip($address)) {
            proxy_error(403, 'Destination address is forbidden');
        }
        $addresses[] = $address;
    }
    if ($addresses === []) {
        proxy_error(502, 'Cannot resolve upstream hostname');
    }
    foreach ($addresses as $address) {
        if (!str_contains($address, ':')) {
            return $address;
        }
    }
    return '[' . $addresses[0] . ']';
}

function upstream_origin_for_browser(string $value, array $routes): ?string
{
    $parts = http_url_parts($value);
    if ($parts === null) {
        return null;
    }
    $publicOrigin = url_origin($parts);
    foreach ($routes as $upstream => $endpoint) {
        if (url_origin(parse_url($endpoint)) === $publicOrigin) {
            return $upstream;
        }
    }
    return null;
}

function is_cross_origin(string $endpoint): bool
{
    $site = strtolower($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '');
    if ($site === 'same-site' || $site === 'cross-site') {
        return true;
    }
    $expected = url_origin(parse_url($endpoint));
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin !== '') {
        return $origin !== $expected;
    }
    $referer = http_url_parts($_SERVER['HTTP_REFERER'] ?? '');
    return $referer !== null && url_origin($referer) !== $expected;
}

function session_cookie_file(string $directory, string $secret, string $origin): string
{
    $name = '__Host-PHP_PROXY_SESSION';
    $key = static fn(string $data): string => hash_hmac('sha256', $origin . "\n" . $data, $secret);
    $cookie = $_COOKIE[$name] ?? null;
    if (is_string($cookie) && preg_match('~\A([a-f0-9]{64})\.([0-9]{1,12})\.([a-f0-9]{64})\z~', $cookie, $match) &&
        (int) $match[2] > time() && hash_equals($key($match[1] . '.' . $match[2]), $match[3])) {
        $sid = $match[1];
    } else {
        $sid = bin2hex(random_bytes(32));
        $expiry = time() + 30 * 86400;
        $data = $sid . '.' . $expiry;
        setcookie($name, $data . '.' . $key($data), [
            'expires' => $expiry,
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
    }
    return $directory . '/jar-' . hash('sha256', $origin . "\n" . $sid);
}

function cookie_records(array $lines): array
{
    $records = [];
    $now = time();
    foreach ($lines as $line) {
        $fields = explode("\t", rtrim($line, "\r\n"), 7);
        if (count($fields) !== 7 || ($fields[4] !== '0' && (int) $fields[4] <= $now)) {
            continue;
        }
        $domain = str_starts_with($fields[0], '#HttpOnly_') ? substr($fields[0], 10) : $fields[0];
        if ($domain === '' || $domain[0] === '#') {
            continue;
        }
        $id = strtolower(ltrim($domain, '.')) . "\t" . $fields[2] . "\t" . $fields[5];
        $records[$id] = implode("\t", $fields);
    }
    return $records;
}

function scan_cookie_storage(string $directory, int $now): array
{
    $total = 0;
    $count = 0;
    foreach (new DirectoryIterator($directory) as $file) {
        if (!preg_match('~\Ajar-[0-9a-f]{64}(\.tmp)?\z~', $file->getFilename(), $match) || !$file->isFile()) {
            continue;
        }
        $path = $file->getPathname();
        if (isset($match[1])) {
            unlink($path);
            continue;
        }
        if ($file->getMTime() <= $now - 30 * 86400 && unlink($path)) {
            continue;
        }
        $total += $file->getSize();
        ++$count;
    }
    return [$now + 60, $total, $count];
}

function write_cookie_usage($lock, array $usage): void
{
    $record = implode(' ', $usage) . "\n";
    if (!rewind($lock) || fwrite($lock, $record) !== strlen($record) ||
        !ftruncate($lock, strlen($record)) || !fflush($lock)) {
        config_error('Cannot save cookie storage statistics');
    }
}

function with_cookie_storage(string $path, callable $operation): mixed
{
    $directory = dirname($path);
    $lock = fopen($directory . '/jars.lock', 'c+b');
    if ($lock === false) {
        config_error('Cannot open cookie storage lock');
    }
    try {
        $deadline = hrtime(true) + 250_000_000;
        while (!flock($lock, LOCK_EX | LOCK_NB)) {
            if (hrtime(true) >= $deadline) {
                header('Retry-After: 1');
                proxy_error(503, 'Cookie storage busy');
            }
            usleep(2000);
        }
        $now = time();
        $state = stream_get_contents($lock, 128);
        if (preg_match('~\A([0-9]+) ([0-9]+) ([0-9]+)\n\z~', (string) $state, $match) && (int) $match[1] > $now) {
            $usage = [(int) $match[1], (int) $match[2], (int) $match[3]];
        } else {
            $usage = scan_cookie_storage($directory, $now);
            write_cookie_usage($lock, $usage);
        }
        clearstatcache(true, $path);
        $size = is_file($path) ? filesize($path) : false;
        $contents = $size !== false && $size <= 65536 ? file_get_contents($path, false, null, 0, 65537) : false;
        $records = $contents === false ? [] : cookie_records(explode("\n", $contents));
        return $operation($records, $size, $usage, $lock);
    } finally {
        fclose($lock);
    }
}

function load_cookie_snapshot(string $path): array
{
    return with_cookie_storage($path, static fn(array $records): array => $records);
}

function save_cookie_changes(string $path, array $before, array $after): void
{
    $added = array_diff_assoc($after, $before);
    $removed = array_diff_key($before, $after);
    if ($added === [] && $removed === []) {
        return;
    }
    $quota = configured_limit('PHP_PROXY_MAX_COOKIE_STORAGE_BYTES', 16 * 1024 * 1024, 256 * 1024 * 1024);
    with_cookie_storage($path, static function (array $latest, int|false $oldSize, array $usage, $lock) use (
        $added, $removed, $path, $quota
    ): void {
        foreach ($removed as $id => $record) {
            // Keep a cookie refreshed by a different response while this request was in flight.
            if (($latest[$id] ?? null) === $record) {
                unset($latest[$id]);
            }
        }
        $merged = array_replace($latest, $added);
        if ($merged === [] && $oldSize !== false) {
            if (unlink($path)) {
                $usage[1] = max(0, $usage[1] - $oldSize);
                $usage[2] = max(0, $usage[2] - 1);
                write_cookie_usage($lock, $usage);
            }
            return;
        }
        if ($merged === [] || $merged === $latest && $removed === []) {
            return;
        }
        $data = implode("\n", $merged) . "\n";
        $size = strlen($data);
        $growth = $size - (int) $oldSize;
        if ($size > 65536 || ($growth > 0 && $usage[1] + $growth > $quota) || ($oldSize === false && $usage[2] >= 4096)) {
            return;
        }

        // Reserve additional space first. After an interrupted write, the next scan corrects the overcount.
        $temp = $path . '.tmp';
        if ($growth > 0 || $oldSize === false) {
            $usage[1] += max(0, $growth);
            $usage[2] += (int) ($oldSize === false);
            write_cookie_usage($lock, $usage);
        }
        if (file_put_contents($temp, $data) !== $size || !rename($temp, $path)) {
            if (is_file($temp)) {
                unlink($temp);
            }
            error_log('PHP proxy: cannot update upstream cookie jar');
            return;
        }
        if ($growth < 0) {
            $usage[1] = max(0, $usage[1] + $growth);
            write_cookie_usage($lock, $usage);
        }
    });
}

// URL resolution and proxy routing.

function url_origin(array $parts): string
{
    $scheme = strtolower($parts['scheme']);
    $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);
    $default = ($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80);
    return $scheme . '://' . strtolower($parts['host']) . ($default ? '' : ':' . $port);
}

function http_url_parts(string $url): ?array
{
    if (preg_match('~[\x00-\x20\x7f\\\\]~', $url)) {
        return null;
    }
    $parts = parse_url($url);
    if ($parts === false || !isset($parts['scheme'], $parts['host']) ||
        !in_array(strtolower($parts['scheme']), ['http', 'https'], true) ||
        isset($parts['user']) || isset($parts['pass']) || ($parts['port'] ?? 1) === 0) {
        return null;
    }
    return $parts;
}

function is_dns_hostname(string $host): bool
{
    return strlen($host) <= 253 && preg_match(
        '~\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\z~i',
        $host
    ) === 1;
}

// RFC 3986 section 5.2.4. Preserve empty segments and the trailing slash.
function remove_dot_segments(string $path): string
{
    $segments = explode('/', $path);
    $last = count($segments) - 1;
    $output = [];
    foreach ($segments as $index => $segment) {
        $dots = str_ireplace('%2e', '.', $segment);
        if ($dots === '..' && count($output) > 1) {
            array_pop($output);
        }
        if ($dots !== '.' && $dots !== '..') {
            $output[] = $segment;
        } elseif ($index === $last) {
            $output[] = '';
        }
    }
    return implode('/', $output);
}

function absolute_url(string $reference, string $base): string
{
    $reference = str_replace(' ', '%20', trim($reference));
    if (preg_match('~\A[a-z][a-z0-9+.-]*:~i', $reference)) {
        return $reference;
    }

    $baseParts = http_url_parts($base);
    if ($baseParts === null) {
        return $reference;
    }
    if (str_starts_with($reference, '//')) {
        return strtolower($baseParts['scheme']) . ':' . $reference;
    }
    $parts = parse_url($reference);
    if ($parts === false) {
        return $reference;
    }

    $basePath = $baseParts['path'] ?? '/';
    $path = $parts['path'] ?? '';
    $query = $parts['query'] ?? null;
    if ($path === '') {
        $path = $basePath;
        $query ??= $baseParts['query'] ?? null;
    } else {
        if ($path[0] !== '/') {
            $path = substr($basePath, 0, strrpos($basePath, '/') + 1) . $path;
        }
        $path = remove_dot_segments($path);
    }

    return url_origin($baseParts) . $path . ($query === null ? '' : '?' . $query)
        . (isset($parts['fragment']) ? '#' . $parts['fragment'] : '');
}

function is_blocked_url(string $url): bool
{
    $host = strtolower(parse_url($url, PHP_URL_HOST) ?: '');
    $path = strtolower(parse_url($url, PHP_URL_PATH) ?: '');
    return $host === 'mc.yandex.ru' || str_ends_with($host, '.mc.yandex.ru') ||
        $host === 'mc.webvisor.org' || str_ends_with($host, '.mc.webvisor.org') ||
        str_contains($host, 'metrika') || preg_match('~metrika|watch\.js|tag\.js|webvisor~', $path) === 1;
}

function form_target(string $pathInfo, ?string $query): ?string
{
    if (!preg_match('~\A/_form/([a-zA-Z0-9_-]{1,10923})\z~', $pathInfo, $match)) {
        return null;
    }
    $target = base64_decode(strtr($match[1], '-_', '+/'), true);
    if ($target === false || strlen($target) > 8192 || str_contains($target, '#') || http_url_parts($target) === null) {
        return null;
    }
    if ($query !== null) {
        return explode('?', $target, 2)[0] . ($query === '' ? '' : '?' . $query);
    }
    return $target;
}

function proxied_target(string $url, array $routes): ?string
{
    $parts = http_url_parts($url);
    if ($parts === null) {
        return null;
    }
    $path = $parts['path'] ?? '/';
    $form = strrpos($path, '/proxy.php/_form/');
    if ($form !== false) {
        $form += strlen('/proxy.php');
        $target = form_target(substr($path, $form), null);
        if ($target === null) {
            return null;
        }
        $path = substr($path, 0, $form);
    } else {
        $query = $parts['query'] ?? '';
        if (str_contains($query, '&') || preg_match('~\Aurl=https?%3a%2f%2f~i', $query) !== 1) {
            return null;
        }
        $target = rawurldecode(substr($query, 4));
    }
    $targetParts = http_url_parts($target);
    $endpoint = $targetParts === null ? null : ($routes[url_origin($targetParts)] ?? null);
    if ($endpoint !== url_origin($parts) . $path) {
        return null;
    }
    return $target . (isset($parts['fragment']) ? '#' . $parts['fragment'] : '');
}

function proxy_url(string $url, string $base, array $routes, string $endpoint, bool $form = false): string
{
    $url = trim($url);
    if ((!$form && ($url === '' || $url[0] === '#')) || preg_match('~\A(?!https?:)[a-z][a-z0-9+.-]*:~i', $url)) {
        return $url;
    }
    $alreadyProxied = proxied_target($url, $routes);
    if ($alreadyProxied !== null && (!$form || str_contains(parse_url($url, PHP_URL_PATH) ?? '', '/proxy.php/_form/'))) {
        return $url;
    }

    $absolute = $alreadyProxied ?? absolute_url($url, $base);
    if (is_blocked_url($absolute)) {
        return 'data:text/javascript,';
    }
    $parts = http_url_parts($absolute);
    $route = $parts === null ? $endpoint : ($routes[url_origin($parts)] ?? $endpoint);
    $pieces = explode('#', $absolute, 2);
    $location = $form ? '/_form/' . rtrim(strtr(base64_encode($pieces[0]), '+/', '-_'), '=')
        : '?url=' . rawurlencode($pieces[0]);
    return $route . $location . (isset($pieces[1]) ? '#' . $pieces[1] : '');
}

// HTML, CSS and JavaScript rewriting.

function rewrite_srcset(string $value, callable $rewrite): string
{
    // The HTML algorithm reads a URL up to whitespace, including any internal commas.
    $pattern = '~[ \t\n\r\f,]*([^ \t\n\r\f]+)~A';
    $offset = 0;
    $items = [];
    while (preg_match($pattern, $value, $match, 0, $offset) === 1) {
        $offset += strlen($match[0]);
        $url = $match[1];
        $descriptors = '';
        if (str_ends_with($url, ',')) {
            $url = rtrim($url, ',');
        } elseif (preg_match('~(?:\([^)]*\)|[^,(]++)*+~A', $value, $descriptor, 0, $offset) === 1) {
            $descriptors = trim($descriptor[0]);
            $offset += strlen($descriptor[0]);
        }
        if ($url !== '') {
            $items[] = $rewrite($url) . ($descriptors === '' ? '' : ' ' . $descriptors);
        }
    }
    return implode(', ', $items);
}

function rewrite_css_urls(string $text, callable $rewrite): ?string
{
    $pattern = <<<'REGEX'
~ /\* .*? \*/ (*SKIP)(*F)
  | (?<import>@import\s+) (?<import_value>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')
  | "(?:\\.|[^"\\])*" (*SKIP)(*F) | '(?:\\.|[^'\\])*' (*SKIP)(*F)
  | (?<![\w-]) url\(\s* (?<url_value>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^()"'\s]+) \s*\)
~isx
REGEX;
    return preg_replace_callback($pattern, function (array $match) use ($rewrite): string {
        $import = $match['import'] ?? '';
        $raw = $import !== '' ? $match['import_value'] : $match['url_value'];
        $value = ($raw[0] === '"' || $raw[0] === "'") ? substr($raw, 1, -1) : $raw;
        if (str_contains($value, '\\')) {
            return $match[0];
        }
        $rewritten = $rewrite($value);
        if ($rewritten === $value) {
            return $match[0];
        }
        $quoted = '"' . addcslashes($rewritten, "\\\"\n\r\f") . '"';
        return $import !== '' ? $import . $quoted : 'url(' . $quoted . ')';
    }, $text);
}

function rewrite_js_urls(string $text, callable $rewrite): ?string
{
    // Match literal module specifiers and preserve the base of new URL().
    $pattern = <<<'REGEX'
~ /\* [\s\S]*? \*/ (*SKIP)(*F) | //[^\r\n]* (*SKIP)(*F)
  | (?<prefix>
        (?<![.\w$]) import\b (?&gap)
        (?:(?:(?:[\w$\x80-\xff]+ (?&gap) , (?&gap))?
        (?:\{[^{}]*\}|\* (?&gap) as\b (?&gap) [\w$\x80-\xff]+)
        |[\w$\x80-\xff]+) (?&gap) from\b (?&gap))?
      | (?<![.\w$]) export\b (?&gap) (?:\{[^{}]*\}|\*(?:(?&gap)as\b(?&gap)[\w$\x80-\xff]+)?)
        (?&gap) from\b (?&gap)
      | (?<![.\w$]) import\b (?&gap) \( (?&gap)
      | \bnew\s+URL\s*\(\s*
  )
  (?<quote>["']) (?<specifier>[^"'\\\r\n]+) \k<quote>
  (?<base>\s*,\s*import\.meta\.url\s*\))?
  | "(?:\\[\s\S]|[^"\\]++)*" (*SKIP)(*F)
  | '(?:\\[\s\S]|[^'\\]++)*' (*SKIP)(*F)
  | `(?:\\[\s\S]|[^`\\]++)*` (*SKIP)(*F)
  (?(DEFINE)(?<gap>(?:\s++|/\*[\s\S]*?\*/|//[^\r\n]*)*+))
~x
REGEX;
    return preg_replace_callback($pattern, function (array $match) use ($rewrite): string {
        $url = $match['specifier'];
        $base = $match['base'] ?? '';
        if (str_starts_with($match['prefix'], 'new') && $base === '') {
            return $match[0];
        }
        if ($base === '' && !preg_match('~\A(?:\.{1,2}/|/|https?://)~i', $url)) {
            return $match[0];
        }
        $value = $rewrite($url);
        if ($value === $url) {
            return $match[0];
        }
        return $match['prefix'] . json_encode($value, JSON_INVALID_UTF8_SUBSTITUTE | JSON_HEX_TAG) . $base;
    }, $text);
}

function markup_attribute_pattern(): string
{
    return <<<'REGEX'
~ (^</?[a-z][\w:-]*)
  | (\s+)([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^>\s]+)))?
~ix
REGEX;
}

function markup_attribute(string $tag, string $name): ?string
{
    preg_match_all(markup_attribute_pattern(), $tag, $attributes, PREG_SET_ORDER | PREG_UNMATCHED_AS_NULL);
    foreach ($attributes as $match) {
        if (strtolower($match[3] ?? '') === $name) {
            return html_entity_decode($match[4] ?? $match[5] ?? $match[6] ?? '', ENT_QUOTES | ENT_HTML5, 'UTF-8');
        }
    }
    return null;
}

function rewrite_markup_tag(string $tag, callable $rewrite, ?callable $form = null, bool $defaultAction = false): ?string
{
    $hasAction = false;
    $result = preg_replace_callback(markup_attribute_pattern(), function (array $match) use ($rewrite, $form, &$hasAction): string {
        if (!isset($match[3])) {
            return $match[0];
        }
        $name = strtolower($match[3]);
        $value = $match[4] ?? $match[5] ?? $match[6] ?? null;
        if ($form !== null && ($name === 'action' || $name === 'formaction')) {
            $hasAction = $hasAction || $name === 'action';
            $result = $form(html_entity_decode($value ?? '', ENT_QUOTES | ENT_HTML5, 'UTF-8'));
        } else {
            if ($value === null) {
                return $match[0];
            }
            $value = html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            $result = match ($name) {
                'href', 'src', 'action', 'formaction', 'poster', 'data-src', 'data-href', 'xlink:href' => $rewrite($value),
                'srcset', 'imagesrcset' => rewrite_srcset($value, $rewrite),
                'style' => rewrite_css_urls($value, $rewrite),
                default => $value,
            };
        }
        if ($result === $value || $result === null) {
            return $match[0];
        }
        return $match[2] . $match[3] . '="' . htmlspecialchars($result, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '"';
    }, $tag, -1, $count, PREG_UNMATCHED_AS_NULL);
    if ($result !== null && $defaultAction && !$hasAction && $form !== null) {
        $action = ' action="' . htmlspecialchars($form(''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '"';
        $end = str_ends_with($result, '/>') ? -2 : -1;
        $result = substr_replace($result, $action, $end, 0);
    }
    return $result;
}

function html_base_url(string $html, string $pattern, string $document): ?string
{
    $offset = 0;
    $templates = 0;
    while (($matched = preg_match($pattern, $html, $match, PREG_OFFSET_CAPTURE, $offset)) === 1) {
        $offset = $match[0][1] + strlen($match[0][0]);
        $name = strtolower($match['name'][0] ?? '');
        if (($match['template_end'][0] ?? '') !== '') {
            $templates = max(0, $templates - 1);
        } elseif ($name === 'template') {
            ++$templates;
        } elseif ($name === 'base' && $templates === 0) {
            $href = markup_attribute($match['tag'][0], 'href');
            if ($href !== null) {
                $base = absolute_url($href, $document);
                return http_url_parts($base) === null ? $document : $base;
            }
        }
    }
    return $matched === false ? null : $document;
}

function rewrite_text_urls(string $text, string $base, string $kind, array $routes, string $endpoint): ?string
{
    // Consume raw text elements as a unit so their contents are not parsed as HTML attributes.
    $pattern = <<<'REGEX'
~ <!--.*?--> | <!\[CDATA\[.*?\]\]> | <!doctype[^>]*>
  | (?<head_end></head\s*>) | (?<template_end></template\s*>)
  | (?<raw><(?<raw_name>script|style|textarea|title)(?=[\s/>])(?:[^>"']++|"[^"]*"|'[^']*')*+>)
    (?<content>.*?) (?<close></\k<raw_name>\s*>|\z)
  | (?<tag><(?<name>[a-z][\w:-]*)(?=[\s/>])(?:[^>"']++|"[^"]*"|'[^']*')*+>)
~isx
REGEX;
    $document = $base;
    if ($kind === 'html') {
        $base = html_base_url($text, $pattern, $document);
        if ($base === null) {
            return null;
        }
    }
    $remaining = 8 * 1024 * 1024 - strlen($text);
    $rewrite = static function (string $url, bool $form = false, bool $documentBase = false)
        use ($base, $document, $routes, $endpoint, &$remaining): string {
        $resolvedBase = $documentBase || ($form && trim($url) === '') ? $document : $base;
        $result = proxy_url($url, $resolvedBase, $routes, $endpoint, $form);
        $remaining -= max(0, strlen($result) - strlen($url));
        if ($remaining < 0) {
            throw new LengthException('Rewritten text exceeds the output limit');
        }
        return $result;
    };
    if ($kind === 'css' || $kind === 'js') {
        return $kind === 'css' ? rewrite_css_urls($text, $rewrite) : rewrite_js_urls($text, $rewrite);
    }

    $injected = false;
    $hasMetaCsp = $kind === 'html' && preg_match(
        '~<meta\b[^>]*\bhttp-equiv\s*=\s*["\']?content-security-policy(?=[\s>"\'])~i', $text
    );
    $failed = false;
    $result = preg_replace_callback($pattern, function (array $match) use (
        $base, $document, $kind, $routes, $endpoint, $rewrite, $hasMetaCsp, &$injected, &$failed
    ): string {
        if (($match['head_end'] ?? '') !== '' && $hasMetaCsp && !$injected) {
            $injected = true;
            return injected_js($base, $routes, $endpoint, $document) . $match[0];
        }
        $tag = ($match['raw'] ?? '') ?: ($match['tag'] ?? '');
        if ($tag === '') {
            return $match[0];
        }

        $name = strtolower(($match['raw_name'] ?? '') ?: $match['name']);
        $tagRewrite = $name === 'base' ? fn(string $url): string => $rewrite($url, false, true) : $rewrite;
        $formRewrite = $kind === 'html' ? fn(string $url): string => $rewrite($url, true) : null;
        $opening = rewrite_markup_tag($tag, $tagRewrite, $formRewrite, $name === 'form');
        $content = $match['content'] ?? '';
        if ($name === 'style') {
            $content = rewrite_css_urls($content, $rewrite);
        } elseif ($name === 'script' && !preg_match('~\btype\s*=\s*["\']?(?:importmap|application/(?:ld\+)?json)(?=[\s>"\'])~i', $tag)) {
            $content = rewrite_js_urls($content, $rewrite);
        }
        if ($opening === null || $content === null) {
            $failed = true;
            return '';
        }
        if ($kind === 'html' && $name === 'head' && !$hasMetaCsp && !$injected) {
            $injected = true;
            $opening .= injected_js($base, $routes, $endpoint, $document);
        }
        return $opening . $content . ($match['close'] ?? '');
    }, $text);

    if ($result === null || $failed) {
        return null;
    }
    if ($kind === 'html' && !$hasMetaCsp && !$injected) {
        $runtime = injected_js($base, $routes, $endpoint, $document);
        $result = preg_replace_callback('~\A(?:\xef\xbb\xbf)?\s*(?:<!doctype[^>]*>)?~i', fn(array $match): string =>
            $match[0] . $runtime, $result, 1);
    }
    return $result;
}

function injected_js(string $base, array $routes, string $endpoint, ?string $document = null): string
{
    $flags = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_INVALID_UTF8_SUBSTITUTE;
    return strtr(<<<'HTML'
<script>
(function () {
    const ROUTES = __PROXY_ROUTES__;
    const ENDPOINT = __PROXY_ENDPOINT__;
    const BASE = __PROXY_BASE__;
    const DOCUMENT_URL = __PROXY_DOCUMENT__;

    function isBlocked(url) {
        try {
            const u = new URL(url);
            const h = u.hostname.toLowerCase();
            const p = u.pathname.toLowerCase();

            return (
                h === "mc.yandex.ru" ||
                h.endsWith(".mc.yandex.ru") ||
                h === "mc.webvisor.org" ||
                h.endsWith(".mc.webvisor.org") ||
                h.includes("metrika") ||
                p.includes("metrika") ||
                p.includes("watch.js") ||
                p.includes("tag.js") ||
                p.includes("webvisor")
            );
        } catch (e) {
            return false;
        }
    }

    function proxyTarget(url) {
        try {
            const candidate = new URL(url, location.href);
            const formIndex = candidate.pathname.lastIndexOf("/proxy.php/_form/");
            const index = formIndex === -1 ? -1 : formIndex + "/proxy.php".length;
            let upstream;
            let endpoint;
            if (index !== -1) {
                const encoded = candidate.pathname.slice(index + 7);
                upstream = new URL(atob(encoded.replace(/-/g, "+").replace(/_/g, "/")));
                endpoint = candidate.origin + candidate.pathname.slice(0, index);
            } else if (/^\?url=https?%3a%2f%2f/i.test(candidate.search) && !candidate.search.includes("&")) {
                upstream = new URL(candidate.searchParams.get("url"));
                endpoint = candidate.origin + candidate.pathname;
            }
            if (upstream && ROUTES[upstream.origin] === endpoint) {
                upstream.hash = candidate.hash;
                return { upstream, form: index !== -1 };
            }
        } catch (e) {}
        return null;
    }

    function proxify(url, form = false) {
        if (typeof url !== "string") return url;
        url = url.trim();
        if ((!form && (!url || url.startsWith("#"))) || /^(?!https?:)[a-z][a-z0-9+.-]*:/i.test(url)) {
            return url;
        }
        const existing = url ? proxyTarget(url) : null;
        if (existing && (!form || existing.form)) {
            return url;
        }
        try {
            let target = existing ? existing.upstream : new URL(url || DOCUMENT_URL, BASE);
            if (!existing && target.origin === location.origin) {
                target = new URL(target.pathname + target.search + target.hash, BASE);
            }
            if (isBlocked(target.href)) {
                return "data:text/javascript,";
            }
            const href = target.href;
            const fragment = href.indexOf("#");
            const upstream = fragment < 0 ? href : href.slice(0, fragment);
            const path = form ? "/_form/" + btoa(upstream).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
                : "?url=" + encodeURIComponent(upstream);
            return (ROUTES[target.origin] || ENDPOINT) + path + (fragment < 0 ? "" : href.slice(fragment));
        } catch (e) {
            return url;
        }
    }

    function proxifySrcset(value) {
        value = String(value);
        const urls = /[ \t\n\r\f,]*([^ \t\n\r\f]+)/y;
        const descriptors = /(?:\([^)]*\)|[^,(])*/y;
        const result = [];
        let match;
        while ((match = urls.exec(value))) {
            let url = match[1];
            let descriptor = "";
            if (url.endsWith(",")) {
                url = url.replace(/,+$/, "");
            } else {
                descriptors.lastIndex = urls.lastIndex;
                descriptor = descriptors.exec(value)[0].trim();
                urls.lastIndex = descriptors.lastIndex;
            }
            if (url) {
                result.push(proxify(url) + (descriptor ? " " + descriptor : ""));
            }
        }
        return result.join(", ");
    }

    window.__proxyUrl = proxify;

    const NativeRequest = window.Request;
    if (NativeRequest) {
        window.Request = class extends NativeRequest {
            constructor(resource, options) {
                if (typeof resource === "string" || resource instanceof URL) {
                    resource = proxify(String(resource));
                }
                super(resource, options);
            }
        };
    }

    const NativeEventSource = window.EventSource;
    if (NativeEventSource) {
        window.EventSource = class extends NativeEventSource {
            constructor(url, options) {
                super(proxify(String(url)), options);
            }
        };
    }

    const oldFetch = window.fetch;

    if (oldFetch) {
        window.fetch = function(resource, options) {
            if (typeof resource === "string") {
                resource = proxify(resource);
            } else if (resource instanceof URL) {
                resource = proxify(resource.href);
            } else if (resource instanceof NativeRequest) {
                const url = proxify(resource.url);
                if (url !== resource.url) {
                    resource = new NativeRequest(url, resource);
                }
            }

            return oldFetch.call(this, resource, options);
        };
    }

    const oldOpen = XMLHttpRequest.prototype.open;

    XMLHttpRequest.prototype.open = function(method, url) {
        arguments[1] = proxify(String(url));
        return oldOpen.apply(this, arguments);
    };

    const oldSendBeacon = navigator.sendBeacon;

    if (oldSendBeacon) {
        navigator.sendBeacon = function(url, data) {
            return oldSendBeacon.call(this, proxify(String(url)), data);
        };
    }

    const oldSetAttribute = Element.prototype.setAttribute;

    Element.prototype.setAttribute = function(name, value) {
        if (/^(action|formaction)$/i.test(name)) {
            value = proxify(String(value), true);
        } else if (/^(src|href|poster|data-src|data-href)$/i.test(name)) {
            value = proxify(String(value));
        } else if (/^srcset$/i.test(name)) {
            value = proxifySrcset(value);
        }

        return oldSetAttribute.call(this, name, value);
    };

    function patchUrlProperty(proto, prop, form = false) {
        try {
            const desc = Object.getOwnPropertyDescriptor(proto, prop);

            if (!desc || !desc.set || !desc.get) {
                return;
            }

            Object.defineProperty(proto, prop, {
                get: function() {
                    return desc.get.call(this);
                },
                set: function(value) {
                    return desc.set.call(this, proxify(String(value), form));
                }
            });
        } catch (e) {}
    }

    if (window.HTMLScriptElement) patchUrlProperty(HTMLScriptElement.prototype, "src");
    if (window.HTMLImageElement) patchUrlProperty(HTMLImageElement.prototype, "src");
    if (window.HTMLIFrameElement) patchUrlProperty(HTMLIFrameElement.prototype, "src");
    if (window.HTMLLinkElement) patchUrlProperty(HTMLLinkElement.prototype, "href");
    if (window.HTMLAnchorElement) patchUrlProperty(HTMLAnchorElement.prototype, "href");
    if (window.HTMLFormElement) {
        patchUrlProperty(HTMLFormElement.prototype, "action", true);
        const submit = HTMLFormElement.prototype.submit;
        HTMLFormElement.prototype.submit = function() {
            oldSetAttribute.call(this, "action", proxify(this.getAttribute("action") || "", true));
            return submit.call(this);
        };
        document.addEventListener("submit", function(event) {
            const form = event.target;
            if (form instanceof HTMLFormElement) {
                oldSetAttribute.call(form, "action", proxify(form.getAttribute("action") || "", true));
                const button = event.submitter;
                if (button && button.hasAttribute("formaction")) {
                    oldSetAttribute.call(button, "formaction", proxify(button.getAttribute("formaction"), true));
                }
            }
        }, true);
    }
    if (window.HTMLButtonElement) patchUrlProperty(HTMLButtonElement.prototype, "formAction", true);
    if (window.HTMLInputElement) patchUrlProperty(HTMLInputElement.prototype, "formAction", true);
    if (window.HTMLSourceElement) patchUrlProperty(HTMLSourceElement.prototype, "src");

    function proxifyNode(node) {
        try {
            if (!node || !node.tagName) return;

            const src = node.getAttribute("src");
            if (src) node.setAttribute("src", proxify(src));

            const href = node.getAttribute("href");
            if (href) node.setAttribute("href", proxify(href));

            const action = node.getAttribute("action");
            if (action) node.setAttribute("action", action);

            const poster = node.getAttribute("poster");
            if (poster) node.setAttribute("poster", proxify(poster));

            const dataSrc = node.getAttribute("data-src");
            if (dataSrc) node.setAttribute("data-src", proxify(dataSrc));

            const dataHref = node.getAttribute("data-href");
            if (dataHref) node.setAttribute("data-href", proxify(dataHref));

            const srcset = node.getAttribute("srcset");
            if (srcset) node.setAttribute("srcset", proxifySrcset(srcset));
        } catch (e) {}
    }

    const oldAppendChild = Node.prototype.appendChild;

    Node.prototype.appendChild = function(node) {
        proxifyNode(node);
        return oldAppendChild.call(this, node);
    };

    const oldInsertBefore = Node.prototype.insertBefore;

    Node.prototype.insertBefore = function(node, ref) {
        proxifyNode(node);
        return oldInsertBefore.call(this, node, ref);
    };

    const oldReplaceChild = Node.prototype.replaceChild;

    Node.prototype.replaceChild = function(node, oldNode) {
        proxifyNode(node);
        return oldReplaceChild.call(this, node, oldNode);
    };

    const observer = new MutationObserver(function(mutations) {
        for (const mutation of mutations) {
            for (const node of mutation.addedNodes) {
                proxifyNode(node);

                if (node && node.querySelectorAll) {
                    node.querySelectorAll("script,img,iframe,link,source,a,form,video,audio").forEach(proxifyNode);
                }
            }
        }
    });

    observer.observe(document.documentElement, {
        childList: true,
        subtree: true
    });
})();
</script>
HTML, [
        '__PROXY_ROUTES__' => json_encode($routes, $flags),
        '__PROXY_ENDPOINT__' => json_encode($endpoint, $flags),
        '__PROXY_BASE__' => json_encode($base, $flags),
        '__PROXY_DOCUMENT__' => json_encode($document ?? $base, $flags),
    ]);
}

// Upstream HTTP transport and response handling.

function upstream_request_headers(array $routes): array
{
    $allowed = [
        'accept', 'accept-language', 'content-type', 'range', 'if-range',
        'if-match', 'if-none-match', 'if-modified-since', 'if-unmodified-since',
        'access-control-request-method', 'access-control-request-headers', 'x-requested-with',
        'x-csrf-token', 'x-xsrf-token', 'last-event-id',
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

function start_event_stream(array $headers, array $routes, bool $crossOrigin): void
{
    http_response_code(200);
    response_headers($headers, $routes, false, $crossOrigin, false);
    header('Content-Type: ' . $headers['content-type'][0]);
    header('X-Accel-Buffering: no');
    while (ob_get_level() > 0) {
        if (!ob_end_flush()) {
            break;
        }
    }
    flush();
}

function fetch_upstream(
    string $target, array $parts, string $method, array $routes, ?string $cookieFile, bool $crossOrigin
): ?array
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
    $streaming = false;
    $started = hrtime(true);
    $streamTimeout = configured_limit('PHP_PROXY_MAX_SSE_SECONDS', 300, 3600);
    $cookiesBefore = [];
    $ch = curl_init($target);
    $persistCookies = static function ($handle) use ($cookieFile, &$cookiesBefore): void {
        if ($cookieFile !== null) {
            $cookies = curl_getinfo($handle, CURLINFO_COOKIELIST);
            if (is_array($cookies)) {
                save_cookie_changes($cookieFile, $cookiesBefore, cookie_records($cookies));
            }
        }
    };
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
        CURLOPT_TIMEOUT => max(40, $streamTimeout),
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_NOPROGRESS => false,
        CURLOPT_XFERINFOFUNCTION => static function () use (&$streaming, $started, $streamTimeout): int {
            $limit = $streaming ? $streamTimeout : 40;
            return (int) (hrtime(true) - $started >= $limit * 1_000_000_000 || connection_aborted());
        },
        CURLOPT_HEADERFUNCTION => static function ($handle, string $line) use (
            &$responseHeaders, &$headerBytes, &$streaming, $method, $routes, $crossOrigin, $persistCookies
        ): int {
            $length = strlen($line);
            $headerBytes += $length;
            if ($headerBytes > 64 * 1024) {
                return 0;
            }
            if (str_starts_with($line, 'HTTP/')) {
                $responseHeaders = [];
            } elseif (!$streaming && $method === 'GET' && trim($line) === '' &&
                curl_getinfo($handle, CURLINFO_RESPONSE_CODE) === 200 &&
                strtolower(trim(explode(';', $responseHeaders['content-type'][0] ?? '', 2)[0])) === 'text/event-stream') {
                $persistCookies($handle);
                $streaming = true;
                start_event_stream($responseHeaders, $routes, $crossOrigin);
            } elseif (($colon = strpos($line, ':')) !== false) {
                $name = strtolower(substr($line, 0, $colon));
                $value = trim(substr($line, $colon + 1));
                if (preg_match('~\A[a-z0-9-]+\z~', $name) && !preg_match('~[\x00-\x08\x0a-\x1f\x7f]~', $value)) {
                    $responseHeaders[$name][] = $value;
                }
            }
            return $length;
        },
        CURLOPT_WRITEFUNCTION => static function ($handle, string $chunk) use ($body, $maximum, &$bytes, &$exceeded, &$streaming): int {
            $length = strlen($chunk);
            if ($length > $maximum - $bytes) {
                $exceeded = true;
                return 0;
            }
            if ($streaming) {
                $bytes += $length;
                echo $chunk;
                flush();
                return connection_aborted() ? 0 : $length;
            }
            $written = fwrite($body, $chunk);
            $bytes += (int) $written;
            return (int) $written;
        },
    ];
    if ($input !== null) {
        $options[CURLOPT_POSTFIELDS] = $input;
    }

    if ($cookieFile !== null) {
        $options[CURLOPT_COOKIEFILE] = '';
    }
    // CURLOPT_PROTOCOLS_STR supersedes CURLOPT_PROTOCOLS on newer PHP/libcurl.
    if (defined('CURLOPT_PROTOCOLS_STR')) {
        unset($options[CURLOPT_PROTOCOLS]);
        $options[CURLOPT_PROTOCOLS_STR] = 'http,https';
    }
    if (!curl_setopt_array($ch, $options)) {
        config_error('Cannot configure cURL');
    }
    if ($cookieFile !== null) {
        foreach (load_cookie_snapshot($cookieFile) as $cookie) {
            if (!curl_setopt($ch, CURLOPT_COOKIELIST, $cookie)) {
                config_error('Cannot load upstream cookies');
            }
        }
        $cookiesBefore = cookie_records(curl_getinfo($ch, CURLINFO_COOKIELIST) ?: []);
    }
    $result = curl_exec($ch);
    $curlError = curl_errno($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    if ($streaming) {
        fclose($body);
        return null;
    }
    if ($result !== false) {
        $persistCookies($ch);
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

// Allow CLI regression tests to load the functions without handling a request.
if (PHP_SAPI !== 'cli' || realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === __FILE__) {
    run_proxy();
}
