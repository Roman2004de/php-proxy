<?php

declare(strict_types=1);

require dirname(__DIR__) . '/proxy.php';

function same(mixed $expected, mixed $actual): void
{
    if ($actual !== $expected) {
        throw new RuntimeException('Expected ' . var_export($expected, true) . ', got ' . var_export($actual, true));
    }
}

$base = 'https://site.example/dir/current.html?old=1';
$endpoint = 'https://site.proxy.example/proxy.php';
$assetsEndpoint = 'https://assets.proxy.example/proxy.php';
$routes = ['https://site.example' => $endpoint, 'https://assets.example' => $assetsEndpoint];
$encode = fn(string $target): string => $endpoint . '?url=' . rawurlencode($target);
$rewrite = fn(string $url): string => proxy_url($url, $base, $routes, $endpoint);

same('<?php', file_get_contents(dirname(__DIR__) . '/proxy.php', false, null, 0, 5));
foreach ([
    '?v=2' => 'https://site.example/dir/current.html?v=2',
    '?' => 'https://site.example/dir/current.html?',
    './sub/' => 'https://site.example/dir/sub/',
    './file name.png' => 'https://site.example/dir/file%20name.png',
    '../a//b/..' => 'https://site.example/a//',
    '/a/./b/../' => 'https://site.example/a/',
    '//assets.example/font.woff' => 'https://assets.example/font.woff',
    '#fragment' => $base . '#fragment',
    '' => $base,
] as $relative => $absolute) {
    same($absolute, absolute_url($relative, $base));
}

$nested = 'https://site.example/proxy.php?url=https%3A%2F%2Fassets.example';
same($encode($nested), $rewrite($nested));
same($encode($nested), $rewrite($encode($nested)));
same($assetsEndpoint . '?url=' . rawurlencode('https://assets.example/font.woff') . '#x', $rewrite('//assets.example/font.woff#x'));
same($encode('https://site.example/dir/current.html?v=2') . '#x', $rewrite('?v=2#x'));
same(null, http_url_parts('https://user:secret@site.example/file'));
same(null, http_url_parts("https://site.example/file\r\n"));
same(null, http_url_parts('https://site.example\\file'));

$cssUrl = $encode('https://site.example/dir/style.css');
same('@import url("' . $cssUrl . '") screen;', rewrite_css_urls('@import url("style.css") screen;', $rewrite));
same('@import "' . $cssUrl . '";', rewrite_css_urls("@import 'style.css';", $rewrite));
same('/* url(a.css) */ a::after { content: "url(b.css)"; }',
    rewrite_css_urls('/* url(a.css) */ a::after { content: "url(b.css)"; }', $rewrite));

$jsUrl = fn(string $file): string => json_encode($encode('https://site.example/dir/' . $file));
same('new URL(' . $jsUrl('asset.png') . ', import.meta.url)', rewrite_js_urls("new URL('./asset.png', import.meta.url)", $rewrite));
same('import x from ' . $jsUrl('module.mjs') . '; import(' . $jsUrl('dynamic.mjs') . ');',
    rewrite_js_urls("import x from './module.mjs'; import('./dynamic.mjs');", $rewrite));
same('// import("./ignored.js")' . "\n" . "import 'package.js';", rewrite_js_urls('// import("./ignored.js")' . "\n" . "import 'package.js';", $rewrite));

$compact = [
    'import{value}from"./module.mjs";' => 'import{value}from' . $jsUrl('module.mjs') . ';',
    'import"./module.mjs";' => 'import' . $jsUrl('module.mjs') . ';',
    'export*from"./module.mjs";' => 'export*from' . $jsUrl('module.mjs') . ';',
    "import/* comment */{value}\nfrom './module.mjs';" => "import/* comment */{value}\nfrom " . $jsUrl('module.mjs') . ';',
];
foreach ($compact as $source => $expected) {
    same($expected, rewrite_js_urls($source, $rewrite));
}

$formUrl = proxy_url('/search?old=1#results', $base, $routes, $endpoint, true);
$formPath = substr(parse_url($formUrl, PHP_URL_PATH), strlen('/proxy.php'));
same('results', parse_url($formUrl, PHP_URL_FRAGMENT));
same('https://site.example/search?old=1', form_target($formPath, null));
same('https://site.example/search?q=one&q=two&url=field', form_target($formPath, 'q=one&q=two&url=field'));
same('https://site.example/search', form_target($formPath, ''));
same(null, form_target('/_form/bad/extra', ''));
same($formUrl, proxy_url($formUrl, $base, $routes, $endpoint, true));
same('https://site.example/search?old=1#results', proxied_target($formUrl, $routes));

$withBase = rewrite_text_urls(
    '<html><head><!-- <base href="/ignored/"> --><template><base href="/ignored/"></template><base href="../assets/"></head>'
    . '<body><img src="photo.png"><form><button formaction="find">Search</button></form></body></html>',
    $base, 'html', $routes, $endpoint
);
same(true, str_contains($withBase, rawurlencode('https://site.example/assets/photo.png')));
same(true, str_contains($withBase, '<base href="' . $encode('https://site.example/assets/') . '">'));
same(true, str_contains($withBase, '<form action="' . proxy_url($base, $base, $routes, $endpoint, true) . '">'));
same(true, str_contains($withBase, 'formaction="' . proxy_url('https://site.example/assets/find', $base, $routes, $endpoint, true) . '"'));

$data = 'data:image/png;base64,iVBORw0KGgo=';
$srcset = $data . ' 1x, photo.png 2x';
same($data . ' 1x, ' . $encode('https://site.example/dir/photo.png') . ' 2x', rewrite_srcset($srcset, $rewrite));
same('<img alt="href=ignored" srcset="' . rewrite_srcset($srcset, $rewrite) . '">',
    rewrite_markup_tag('<img alt="href=ignored" srcset="' . $srcset . '">', $rewrite));

$html = rewrite_text_urls(
    '<!doctype html><head><meta http-equiv="Content-Security-Policy" content="script-src \'none\'"></head><body></body>',
    $base, 'html', $routes, $endpoint
);
same(true, strpos($html, 'Content-Security-Policy') < strpos($html, '<script>'));
same(true, strpos($html, '<script>') < strpos($html, '</head>'));
same(1, substr_count(injected_js('https://site.example/#</script>', $routes, $endpoint), '</script>'));

same('binary', detect_body_kind('application/octet-stream', 'https://site.example/file.js'));
same('binary', detect_body_kind('image/png', 'https://site.example/file.html'));
same('js', detect_body_kind('text/javascript; charset=utf-8', $base));

foreach (['127.0.0.1', '10.0.0.1', '100.64.0.1', '169.254.169.254', '192.0.2.1', '198.18.0.1',
    '224.0.0.1', '::1', '::ffff:8.8.8.8', 'fc00::1', 'fe80::1', '2001:db8::1', '2002::1', '3fff::1'] as $blocked) {
    same(false, is_public_ip($blocked));
}
same(client_network('192.0.2.10'), client_network('::ffff:192.0.2.10'));
same(client_network('2001:db8:1234:5678::1'), client_network('2001:db8:1234:5678::ab'));
same(false, client_network('2001:db8:1234:5678::1') === client_network('2001:db8:1234:5679::1'));
same(true, is_public_ip('8.8.8.8'));
same(true, is_public_ip('2606:4700::1111'));
$cookieDirectory = sys_get_temp_dir() . '/proxy-test-' . bin2hex(random_bytes(8));
mkdir($cookieDirectory, 0700);
$oldCookieQuota = getenv('PHP_PROXY_MAX_COOKIE_STORAGE_BYTES');
try {
    putenv('PHP_PROXY_MAX_COOKIE_STORAGE_BYTES=16384');
    $jar = $cookieDirectory . '/jar-' . str_repeat('a', 64);
    $expired = $cookieDirectory . '/jar-' . str_repeat('b', 64);
    file_put_contents($expired, 'old');
    touch($expired, time() - 31 * 86400);
    same([], load_cookie_snapshot($jar));
    same(false, is_file($expired));
    $one = cookie_records(["#HttpOnly_site.example\tFALSE\t/\tTRUE\t0\tfirst\tone"]);
    $two = cookie_records(["site.example\tFALSE\t/\tTRUE\t0\tsecond\ttwo"]);
    save_cookie_changes($jar, [], $one);
    save_cookie_changes($jar, [], $two);
    same($one + $two, load_cookie_snapshot($jar));
    save_cookie_changes($jar, $one, []);
    same($two, load_cookie_snapshot($jar));

    putenv('PHP_PROXY_MAX_COOKIE_STORAGE_BYTES=1');
    save_cookie_changes($jar, $two, $two + $one);
    same($two, load_cookie_snapshot($jar));
    $newJar = $cookieDirectory . '/jar-' . str_repeat('c', 64);
    save_cookie_changes($newJar, [], $one);
    same(false, is_file($newJar));
} finally {
    putenv($oldCookieQuota === false ? 'PHP_PROXY_MAX_COOKIE_STORAGE_BYTES'
        : 'PHP_PROXY_MAX_COOKIE_STORAGE_BYTES=' . $oldCookieQuota);
    foreach (glob($cookieDirectory . '/*') as $file) {
        unlink($file);
    }
    rmdir($cookieDirectory);
}
echo "Regression checks passed.\n";
