<?php
// run.php
// PHP reverse proxy через ?url=
// Пример: /run.php?url=https%3A%2F%2Fd-element.ru

ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(0);

while (ob_get_level()) {
    ob_end_clean();
}

$target = isset($_GET['url']) ? $_GET['url'] : '';

if (!$target || !preg_match('~^https?://~i', $target)) {
    http_response_code(400);
    header('Content-Type: text/plain; charset=utf-8');
    exit('Usage: /run.php?url=https://example.com/');
}

/**
 * PHP 7-compatible helpers
 */
function s_contains($haystack, $needle) {
    return $needle !== '' && strpos($haystack, $needle) !== false;
}

function s_starts($haystack, $needle) {
    return substr($haystack, 0, strlen($needle)) === $needle;
}

function s_ends($haystack, $needle) {
    if ($needle === '') return true;
    return substr($haystack, -strlen($needle)) === $needle;
}

function request_headers_all() {
    if (function_exists('getallheaders')) {
        $headers = getallheaders();
        if (is_array($headers)) {
            return $headers;
        }
    }

    $headers = [];

    foreach ($_SERVER as $name => $value) {
        if (substr($name, 0, 5) === 'HTTP_') {
            $key = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))));
            $headers[$key] = $value;
        }
    }

    if (isset($_SERVER['CONTENT_TYPE'])) {
        $headers['Content-Type'] = $_SERVER['CONTENT_TYPE'];
    }

    if (isset($_SERVER['CONTENT_LENGTH'])) {
        $headers['Content-Length'] = $_SERVER['CONTENT_LENGTH'];
    }

    return $headers;
}

function proxy_prefix() {
    $script = isset($_SERVER['SCRIPT_NAME']) ? $_SERVER['SCRIPT_NAME'] : '/run.php';
    return $script . '?url=';
}

function is_already_proxied($url) {
    return
        s_contains($url, '/run.php?url=') ||
        s_contains($url, '?url=http%3A') ||
        s_contains($url, '?url=https%3A') ||
        s_contains($url, '?url=http://') ||
        s_contains($url, '?url=https://');
}

function is_blocked_url($url) {
    $host = strtolower(parse_url($url, PHP_URL_HOST) ?: '');
    $path = strtolower(parse_url($url, PHP_URL_PATH) ?: '');

    // Вырезаем Яндекс.Метрику / Webvisor.
    return
        $host === 'mc.yandex.ru' ||
        s_ends($host, '.mc.yandex.ru') ||
        $host === 'mc.webvisor.org' ||
        s_ends($host, '.mc.webvisor.org') ||
        s_contains($host, 'metrika') ||
        s_contains($path, 'metrika') ||
        s_contains($path, 'watch.js') ||
        s_contains($path, 'tag.js') ||
        s_contains($path, 'webvisor');
}

function remove_dot_segments($path) {
    $out = [];

    foreach (explode('/', $path) as $seg) {
        if ($seg === '' || $seg === '.') {
            continue;
        }

        if ($seg === '..') {
            array_pop($out);
        } else {
            $out[] = $seg;
        }
    }

    return '/' . implode('/', $out);
}

function absolute_url($url, $base) {
    $url = trim(html_entity_decode($url, ENT_QUOTES | ENT_HTML5, 'UTF-8'));

    if ($url === '') {
        return $url;
    }

    if (preg_match('~^(data:|blob:|mailto:|tel:|javascript:|#)~i', $url)) {
        return $url;
    }

    $b = parse_url($base);

    $scheme = isset($b['scheme']) ? $b['scheme'] : 'https';
    $host = isset($b['host']) ? $b['host'] : '';
    $port = isset($b['port']) ? ':' . $b['port'] : '';

    $origin = $scheme . '://' . $host . $port;

    if (s_starts($url, '//')) {
        return $scheme . ':' . $url;
    }

    if (preg_match('~^https?://~i', $url)) {
        return $url;
    }

    if (s_starts($url, '/')) {
        return $origin . $url;
    }

    $path = isset($b['path']) ? $b['path'] : '/';
    $dir = preg_replace('~/[^/]*$~', '/', $path);
    $fullPath = remove_dot_segments($dir . $url);

    return $origin . $fullPath;
}

function proxy_url($url, $base) {
    $url = trim($url);

    if ($url === '') {
        return $url;
    }

    if (is_already_proxied($url)) {
        return $url;
    }

    if (preg_match('~^(data:|blob:|mailto:|tel:|javascript:|#)~i', $url)) {
        return $url;
    }

    $abs = absolute_url($url, $base);

    if (is_blocked_url($abs)) {
        return 'data:text/javascript,';
    }

    return proxy_prefix() . rawurlencode($abs);
}

function js_import_url_should_rewrite($url) {
    $url = trim($url);

    if ($url === '') {
        return false;
    }

    if (
        s_starts($url, './') ||
        s_starts($url, '../') ||
        s_starts($url, '/') ||
        s_starts($url, '//') ||
        preg_match('~^https?://~i', $url)
    ) {
        return true;
    }

    return preg_match('~\.(js|mjs|css|json|wasm|svg|png|jpg|jpeg|webp|gif)(\?|#|$)~i', $url);
}

function rewrite_html_attrs($text, $base) {
    return preg_replace_callback(
        '~\b(href|src|action|poster|data-src|data-href|xlink:href)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^>\s]+))~i',
        function ($m) use ($base) {
            $url = '';

            if (isset($m[2]) && $m[2] !== '') {
                $url = $m[2];
            } elseif (isset($m[3]) && $m[3] !== '') {
                $url = $m[3];
            } elseif (isset($m[4])) {
                $url = $m[4];
            }

            return $m[1] . '="' . proxy_url($url, $base) . '"';
        },
        $text
    );
}

function rewrite_srcset($text, $base) {
    return preg_replace_callback(
        '~\bsrcset\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^>\s]+))~i',
        function ($m) use ($base) {
            $srcset = '';

            if (isset($m[1]) && $m[1] !== '') {
                $srcset = $m[1];
            } elseif (isset($m[2]) && $m[2] !== '') {
                $srcset = $m[2];
            } elseif (isset($m[3])) {
                $srcset = $m[3];
            }

            $items = array_map('trim', explode(',', $srcset));

            foreach ($items as &$item) {
                if ($item === '') {
                    continue;
                }

                $parts = preg_split('~\s+~', $item, 2);
                $parts[0] = proxy_url($parts[0], $base);
                $item = implode(' ', $parts);
            }

            return 'srcset="' . implode(', ', $items) . '"';
        },
        $text
    );
}

function rewrite_css_urls($text, $base) {
    $text = preg_replace_callback(
        '~url\(\s*(["\']?)([^)"\']+)\1\s*\)~i',
        function ($m) use ($base) {
            return 'url("' . proxy_url(trim($m[2]), $base) . '")';
        },
        $text
    );

    $text = preg_replace_callback(
        '~@import\s+(?:"([^"]*)"|\'([^\']*)\'|([^;\s]+))~i',
        function ($m) use ($base) {
            $url = '';

            if (isset($m[1]) && $m[1] !== '') {
                $url = $m[1];
            } elseif (isset($m[2]) && $m[2] !== '') {
                $url = $m[2];
            } elseif (isset($m[3])) {
                $url = $m[3];
            }

            return '@import "' . proxy_url($url, $base) . '"';
        },
        $text
    );

    return $text;
}

function rewrite_js_urls($text, $base) {
    // import X from './x.js'
    // export X from './x.js'
    $text = preg_replace_callback(
        '~\b(import|export)\s+([^;\n]*?\s+from\s*)?(["\'])([^"\']+)\3~i',
        function ($m) use ($base) {
            $type = $m[1];
            $middle = isset($m[2]) ? $m[2] : '';
            $quote = $m[3];
            $url = $m[4];

            if (!js_import_url_should_rewrite($url)) {
                return $m[0];
            }

            return $type . ' ' . $middle . $quote . proxy_url($url, $base) . $quote;
        },
        $text
    );

    // import './x.js'
    $text = preg_replace_callback(
        '~\bimport\s*(["\'])([^"\']+)\1~i',
        function ($m) use ($base) {
            $quote = $m[1];
            $url = $m[2];

            if (!js_import_url_should_rewrite($url)) {
                return $m[0];
            }

            return 'import ' . $quote . proxy_url($url, $base) . $quote;
        },
        $text
    );

    // import('./x.js')
    $text = preg_replace_callback(
        '~\bimport\s*\(\s*(["\'])([^"\']+)\1\s*\)~i',
        function ($m) use ($base) {
            $url = $m[2];

            if (!js_import_url_should_rewrite($url)) {
                return $m[0];
            }

            return 'import("' . proxy_url($url, $base) . '")';
        },
        $text
    );

    // new URL('./asset.png', import.meta.url)
    $text = preg_replace_callback(
        '~new\s+URL\s*\(\s*(["\'])([^"\']+)\1\s*,\s*import\.meta\.url\s*\)~i',
        function ($m) use ($base) {
            $url = $m[2];

            if (!js_import_url_should_rewrite($url)) {
                return $m[0];
            }

            return 'new URL("' . proxy_url($url, $base) . '")';
        },
        $text
    );

    return $text;
}

function rewrite_text_urls($text, $base, $kind) {
    if ($kind === 'html') {
        $text = rewrite_html_attrs($text, $base);
        $text = rewrite_srcset($text, $base);
        $text = rewrite_css_urls($text, $base);
        $text = rewrite_js_urls($text, $base);
        return $text;
    }

    if ($kind === 'css') {
        return rewrite_css_urls($text, $base);
    }

    if ($kind === 'js') {
        return rewrite_js_urls($text, $base);
    }

    if ($kind === 'svg') {
        $text = rewrite_html_attrs($text, $base);
        $text = rewrite_css_urls($text, $base);
        return $text;
    }

    return $text;
}

function injected_js($effectiveUrl) {
    $proxy = proxy_prefix();
    $base = addslashes($effectiveUrl);

    return <<<HTML
<script>
(function () {
    const PROXY = "{$proxy}";
    const BASE = "{$base}";

    function absoluteUrl(url) {
        try {
            return new URL(url, BASE).href;
        } catch (e) {
            return url;
        }
    }

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

    function isAlreadyProxied(url) {
        return (
            url.includes("/run.php?url=") ||
            url.includes("?url=http%3A") ||
            url.includes("?url=https%3A") ||
            url.includes("?url=http://") ||
            url.includes("?url=https://")
        );
    }

    function proxify(url) {
        if (!url || typeof url !== "string") return url;

        if (/^(data:|blob:|mailto:|tel:|javascript:|#)/i.test(url)) {
            return url;
        }

        if (isAlreadyProxied(url)) {
            return url;
        }

        const abs = absoluteUrl(url);

        if (isBlocked(abs)) {
            return "data:text/javascript,";
        }

        return PROXY + encodeURIComponent(abs);
    }

    function proxifySrcset(value) {
        return String(value).split(",").map(item => {
            const parts = item.trim().split(/\\s+/, 2);

            if (parts[0]) {
                parts[0] = proxify(parts[0]);
            }

            return parts.join(" ");
        }).join(", ");
    }

    window.__proxyUrl = proxify;

    const oldFetch = window.fetch;

    if (oldFetch) {
        window.fetch = function(resource, options) {
            if (typeof resource === "string") {
                resource = proxify(resource);
            } else if (resource && resource.url) {
                resource = new Request(proxify(resource.url), resource);
            }

            return oldFetch.call(this, resource, options || {});
        };
    }

    const oldOpen = XMLHttpRequest.prototype.open;

    XMLHttpRequest.prototype.open = function(method, url) {
        arguments[1] = proxify(url);
        return oldOpen.apply(this, arguments);
    };

    const oldSendBeacon = navigator.sendBeacon;

    if (oldSendBeacon) {
        navigator.sendBeacon = function(url, data) {
            return oldSendBeacon.call(this, proxify(url), data);
        };
    }

    const oldSetAttribute = Element.prototype.setAttribute;

    Element.prototype.setAttribute = function(name, value) {
        if (/^(src|href|action|poster|data-src|data-href)$/i.test(name)) {
            value = proxify(value);
        } else if (/^srcset$/i.test(name)) {
            value = proxifySrcset(value);
        }

        return oldSetAttribute.call(this, name, value);
    };

    function patchUrlProperty(proto, prop) {
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
                    return desc.set.call(this, proxify(value));
                }
            });
        } catch (e) {}
    }

    if (window.HTMLScriptElement) patchUrlProperty(HTMLScriptElement.prototype, "src");
    if (window.HTMLImageElement) patchUrlProperty(HTMLImageElement.prototype, "src");
    if (window.HTMLIFrameElement) patchUrlProperty(HTMLIFrameElement.prototype, "src");
    if (window.HTMLLinkElement) patchUrlProperty(HTMLLinkElement.prototype, "href");
    if (window.HTMLAnchorElement) patchUrlProperty(HTMLAnchorElement.prototype, "href");
    if (window.HTMLFormElement) patchUrlProperty(HTMLFormElement.prototype, "action");
    if (window.HTMLSourceElement) patchUrlProperty(HTMLSourceElement.prototype, "src");

    function proxifyNode(node) {
        try {
            if (!node || !node.tagName) return;

            const src = node.getAttribute("src");
            if (src) node.setAttribute("src", proxify(src));

            const href = node.getAttribute("href");
            if (href) node.setAttribute("href", proxify(href));

            const action = node.getAttribute("action");
            if (action) node.setAttribute("action", proxify(action));

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

    const oldCreateElement = document.createElement;

    document.createElement = function(tagName, options) {
        const el = oldCreateElement.call(document, tagName, options);

        try {
            const oldSet = el.setAttribute.bind(el);

            el.setAttribute = function(name, value) {
                if (/^(src|href|action|poster|data-src|data-href)$/i.test(name)) {
                    value = proxify(value);
                } else if (/^srcset$/i.test(name)) {
                    value = proxifySrcset(value);
                }

                return oldSet(name, value);
            };
        } catch (e) {}

        return el;
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
HTML;
}

function detect_body_kind($contentType, $url) {
    $ct = strtolower($contentType);
    $path = strtolower(parse_url($url, PHP_URL_PATH) ?: '');

    if (s_contains($ct, 'text/html') || preg_match('~\.html?$~i', $path)) {
        return 'html';
    }

    if (s_contains($ct, 'text/css') || preg_match('~\.css($|\?)~i', $path)) {
        return 'css';
    }

    if (
        s_contains($ct, 'javascript') ||
        s_contains($ct, 'ecmascript') ||
        preg_match('~\.(js|mjs)($|\?)~i', $path)
    ) {
        return 'js';
    }

    if (s_contains($ct, 'image/svg') || preg_match('~\.svg($|\?)~i', $path)) {
        return 'svg';
    }

    return 'binary';
}

/**
 * Блокируем Метрику сразу.
 */
if (is_blocked_url($target)) {
    header('Content-Type: application/javascript; charset=utf-8');
    header('Content-Length: 0');
    exit('');
}

/**
 * OPTIONS / CORS
 */
$method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';

if ($method === 'OPTIONS') {
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: *');
    header('Access-Control-Max-Age: 86400');
    exit;
}

$input = file_get_contents('php://input');

$targetParts = parse_url($target);
$targetHost = isset($targetParts['host']) ? $targetParts['host'] : '';
$targetScheme = isset($targetParts['scheme']) ? $targetParts['scheme'] : 'https';
$targetOrigin = $targetScheme . '://' . $targetHost;

if (!$targetHost) {
    http_response_code(400);
    header('Content-Type: text/plain; charset=utf-8');
    exit('Bad target URL');
}

/**
 * Готовим заголовки к upstream.
 * Важно: не пересылаем IP клиента.
 */
$headers = [];

foreach (request_headers_all() as $name => $value) {
    $lower = strtolower($name);

    if (in_array($lower, [
        'host',
        'content-length',
        'connection',
        'accept-encoding',
        'origin',
        'referer',
        'cookie',

        'x-forwarded-for',
        'x-real-ip',
        'forwarded',
        'client-ip',
        'x-client-ip',
        'x-cluster-client-ip',
        'cf-connecting-ip',
        'true-client-ip',
        'fastly-client-ip',
        'x-original-forwarded-for',
        'x-forwarded',
        'x-forwarded-host',
        'x-forwarded-proto',
        'via'
    ], true)) {
        continue;
    }

    $headers[] = $name . ': ' . $value;
}

$headers[] = 'Host: ' . $targetHost;
$headers[] = 'Origin: ' . $targetOrigin;
$headers[] = 'Referer: ' . $targetOrigin . '/';
$headers[] = 'Accept-Language: ru-RU,ru;q=0.9,en;q=0.8';
$headers[] = 'Accept-Encoding:';

/**
 * Серверные cookies отдельно по посетителю и домену.
 */
$sessionCookie = 'PHP_PROXY_SESSION';

if (!isset($_COOKIE[$sessionCookie]) || !preg_match('~^[a-f0-9]{32}$~', $_COOKIE[$sessionCookie])) {
    $sid = md5(uniqid('', true) . mt_rand());
    setcookie($sessionCookie, $sid, time() + 86400 * 30, '/', '', isset($_SERVER['HTTPS']), true);
} else {
    $sid = $_COOKIE[$sessionCookie];
}

$cookieDir = __DIR__ . '/cookies';

if (!is_dir($cookieDir)) {
    @mkdir($cookieDir, 0777, true);
}

$cookieFile = $cookieDir . '/' . md5($sid . '|' . $targetHost) . '.txt';

$responseHeaders = [];

$ch = curl_init($target);

curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_FOLLOWLOCATION => false,
    CURLOPT_CUSTOMREQUEST => $method,
    CURLOPT_HTTPHEADER => $headers,
    CURLOPT_ENCODING => '',
    CURLOPT_SSL_VERIFYPEER => false,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_USERAGENT => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'Mozilla/5.0',
    CURLOPT_COOKIEFILE => $cookieFile,
    CURLOPT_COOKIEJAR => $cookieFile,
    CURLOPT_TIMEOUT => 120,
    CURLOPT_CONNECTTIMEOUT => 30,
    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
    CURLOPT_HEADERFUNCTION => function ($ch, $header) use (&$responseHeaders) {
        $len = strlen($header);
        $header = trim($header);

        if ($header !== '') {
            $responseHeaders[] = $header;
        }

        return $len;
    },
]);

if (!in_array($method, ['GET', 'HEAD'], true)) {
    curl_setopt($ch, CURLOPT_POSTFIELDS, $input);
}

$body = curl_exec($ch);

if ($body === false) {
    $err = curl_error($ch);
    curl_close($ch);

    http_response_code(502);
    header('Content-Type: text/plain; charset=utf-8');
    exit($err);
}

$status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$contentType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE) ?: '';
$effectiveUrl = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL) ?: $target;

curl_close($ch);

/**
 * Redirects
 */
if ($status >= 300 && $status < 400) {
    foreach ($responseHeaders as $h) {
        if (stripos($h, 'Location:') === 0) {
            $loc = trim(substr($h, 9));
            header('Location: ' . proxy_url($loc, $effectiveUrl));
            exit;
        }
    }
}

$kind = detect_body_kind($contentType, $effectiveUrl);

http_response_code($status);

/**
 * Пробрасываем безопасные заголовки.
 * Content-Type и Content-Length выставляем сами.
 */
foreach ($responseHeaders as $h) {
    if (
        stripos($h, 'HTTP/') === 0 ||
        stripos($h, 'Content-Length:') === 0 ||
        stripos($h, 'Transfer-Encoding:') === 0 ||
        stripos($h, 'Content-Encoding:') === 0 ||
        stripos($h, 'Connection:') === 0 ||
        stripos($h, 'Location:') === 0 ||
        stripos($h, 'Set-Cookie:') === 0 ||
        stripos($h, 'Content-Type:') === 0 ||
        stripos($h, 'Content-Security-Policy:') === 0 ||
        stripos($h, 'Content-Security-Policy-Report-Only:') === 0 ||
        stripos($h, 'X-Frame-Options:') === 0 ||
        stripos($h, 'Cross-Origin-') === 0 ||
        stripos($h, 'Report-To:') === 0 ||
        stripos($h, 'NEL:') === 0
    ) {
        continue;
    }

    header($h, false);
}

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: *');

/**
 * HEAD без body.
 */
if ($method === 'HEAD') {
    if ($contentType) {
        header('Content-Type: ' . $contentType);
    }
    header('Content-Length: 0');
    exit;
}

/**
 * Текстовые ответы переписываем.
 */
if ($kind !== 'binary') {
    $body = rewrite_text_urls((string)$body, $effectiveUrl, $kind);

    if ($kind === 'html') {
        $inject = injected_js($effectiveUrl);

        if (preg_match('~<head[^>]*>~i', $body)) {
            $body = preg_replace('~<head([^>]*)>~i', '<head$1>' . $inject, $body, 1);
        } else {
            $body = $inject . $body;
        }
    }

    if ($contentType) {
        header('Content-Type: ' . $contentType);
    } else {
        if ($kind === 'html') {
            header('Content-Type: text/html; charset=utf-8');
        } elseif ($kind === 'css') {
            header('Content-Type: text/css; charset=utf-8');
        } elseif ($kind === 'js') {
            header('Content-Type: application/javascript; charset=utf-8');
        } elseif ($kind === 'svg') {
            header('Content-Type: image/svg+xml; charset=utf-8');
        } else {
            header('Content-Type: text/plain; charset=utf-8');
        }
    }

    header('Content-Length: ' . strlen($body));
    echo $body;
    exit;
}

/**
 * Бинарные файлы отдаём байт-в-байт.
 * Никаких regex, никаких echo debug, никаких преобразований.
 */
if ($contentType) {
    header('Content-Type: ' . $contentType);
} else {
    header('Content-Type: application/octet-stream');
}

header('Content-Length: ' . strlen($body));

echo $body;
exit;