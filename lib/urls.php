<?php

declare(strict_types=1);

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

function proxied_target(string $url, array $routes): ?string
{
    $parts = http_url_parts($url);
    if ($parts === null || !isset($parts['query']) || !str_starts_with($parts['query'], 'url=')) {
        return null;
    }
    $encoded = substr($parts['query'], 4);
    $target = rawurldecode($encoded);
    if (str_contains($encoded, '&') || preg_match('~\Ahttps?%3a%2f%2f~i', $encoded) !== 1) {
        return null;
    }
    $targetParts = http_url_parts($target);
    $endpoint = $targetParts === null ? null : ($routes[url_origin($targetParts)] ?? null);
    if ($endpoint !== url_origin($parts) . ($parts['path'] ?? '/')) {
        return null;
    }
    return $target . (isset($parts['fragment']) ? '#' . $parts['fragment'] : '');
}

function proxy_url(string $url, string $base, array $routes, string $endpoint): string
{
    $url = trim($url);
    if ($url === '' || $url[0] === '#' || preg_match('~\A(?!https?:)[a-z][a-z0-9+.-]*:~i', $url)) {
        return $url;
    }
    if (proxied_target($url, $routes) !== null) {
        return $url;
    }

    $absolute = absolute_url($url, $base);
    if (is_blocked_url($absolute)) {
        return 'data:text/javascript,';
    }
    $parts = http_url_parts($absolute);
    $route = $parts === null ? $endpoint : ($routes[url_origin($parts)] ?? $endpoint);
    $pieces = explode('#', $absolute, 2);
    return $route . '?url=' . rawurlencode($pieces[0]) . (isset($pieces[1]) ? '#' . $pieces[1] : '');
}
