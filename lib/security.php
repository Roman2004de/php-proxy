<?php

declare(strict_types=1);

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
    $endpoint = 'https://' . strtolower($_SERVER['HTTP_HOST'] ?? '') . ($_SERVER['SCRIPT_NAME'] ?? '');
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
        str_starts_with($directory . '/', dirname(__DIR__) . '/') ||
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
