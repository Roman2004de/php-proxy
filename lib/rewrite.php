<?php

declare(strict_types=1);

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
        \b(?:import|export)\s+(?:[^;\n'"]*?\s+from\s*)?
      | \bimport\s*\(\s*
      | \bnew\s+URL\s*\(\s*
  )
  (?<quote>["']) (?<specifier>[^"'\\\r\n]+) \k<quote>
  (?<base>\s*,\s*import\.meta\.url\s*\))?
  | "(?:\\[\s\S]|[^"\\]++)*" (*SKIP)(*F)
  | '(?:\\[\s\S]|[^'\\]++)*' (*SKIP)(*F)
  | `(?:\\[\s\S]|[^`\\]++)*` (*SKIP)(*F)
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

function rewrite_markup_tag(string $tag, callable $rewrite): ?string
{
    $pattern = <<<'REGEX'
~ (^</?[a-z][\w:-]*)
  | (\s+)([^\s"'<>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^>\s]+)))?
~ix
REGEX;
    return preg_replace_callback($pattern, function (array $match) use ($rewrite): string {
        if (!isset($match[3]) || (!isset($match[4]) && !isset($match[5]) && !isset($match[6]))) {
            return $match[0];
        }
        $value = html_entity_decode($match[4] ?? $match[5] ?? $match[6], ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $result = match (strtolower($match[3])) {
            'href', 'src', 'action', 'formaction', 'poster', 'data-src', 'data-href', 'xlink:href' => $rewrite($value),
            'srcset', 'imagesrcset' => rewrite_srcset($value, $rewrite),
            'style' => rewrite_css_urls($value, $rewrite),
            default => $value,
        };
        if ($result === $value || $result === null) {
            return $match[0];
        }
        return $match[2] . $match[3] . '="' . htmlspecialchars($result, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . '"';
    }, $tag, -1, $count, PREG_UNMATCHED_AS_NULL);
}

function rewrite_text_urls(string $text, string $base, string $kind, array $routes, string $endpoint): ?string
{
    $remaining = 8 * 1024 * 1024 - strlen($text);
    $rewrite = static function (string $url) use ($base, $routes, $endpoint, &$remaining): string {
        $result = proxy_url($url, $base, $routes, $endpoint);
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
    // Consume raw text elements as a unit so their contents are not parsed as HTML attributes.
    $pattern = <<<'REGEX'
~ <!--.*?--> | <!\[CDATA\[.*?\]\]> | <!doctype[^>]*>
  | (?<head_end></head\s*>)
  | (?<raw><(?<raw_name>script|style|textarea|title)(?=[\s/>])(?:[^>"']++|"[^"]*"|'[^']*')*+>)
    (?<content>.*?) (?<close></\k<raw_name>\s*>|\z)
  | (?<tag><(?<name>[a-z][\w:-]*)(?=[\s/>])(?:[^>"']++|"[^"]*"|'[^']*')*+>)
~isx
REGEX;
    $result = preg_replace_callback($pattern, function (array $match) use (
        $base, $kind, $routes, $endpoint, $rewrite, $hasMetaCsp, &$injected, &$failed
    ): string {
        if (($match['head_end'] ?? '') !== '' && $hasMetaCsp && !$injected) {
            $injected = true;
            return injected_js($base, $routes, $endpoint) . $match[0];
        }
        $tag = ($match['raw'] ?? '') ?: ($match['tag'] ?? '');
        if ($tag === '') {
            return $match[0];
        }

        $name = strtolower(($match['raw_name'] ?? '') ?: $match['name']);
        $opening = rewrite_markup_tag($tag, $rewrite);
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
            $opening .= injected_js($base, $routes, $endpoint);
        }
        return $opening . $content . ($match['close'] ?? '');
    }, $text);

    if ($result === null || $failed) {
        return null;
    }
    if ($kind === 'html' && !$hasMetaCsp && !$injected) {
        $runtime = injected_js($base, $routes, $endpoint);
        $result = preg_replace_callback('~\A(?:\xef\xbb\xbf)?\s*(?:<!doctype[^>]*>)?~i', fn(array $match): string =>
            $match[0] . $runtime, $result, 1);
    }
    return $result;
}

function injected_js(string $base, array $routes, string $endpoint): string
{
    $flags = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_INVALID_UTF8_SUBSTITUTE;
    return strtr(<<<'HTML'
<script>
(function () {
    const ROUTES = __PROXY_ROUTES__;
    const ENDPOINT = __PROXY_ENDPOINT__;
    const BASE = __PROXY_BASE__;

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
        try {
            const candidate = new URL(url, location.href);
            if (!/^\?url=https?%3a%2f%2f/i.test(candidate.search) || candidate.search.includes("&")) {
                return false;
            }
            const upstream = new URL(candidate.searchParams.get("url"));
            return ROUTES[upstream.origin] === candidate.origin + candidate.pathname;
        } catch (e) {
            return false;
        }
    }

    function proxify(url) {
        if (!url || typeof url !== "string") return url;
        url = url.trim();
        if (!url || /^(#|(?!https?:)[a-z][a-z0-9+.-]*:)/i.test(url) || isAlreadyProxied(url)) {
            return url;
        }
        try {
            let target = new URL(url, BASE);
            if (target.origin === location.origin) {
                target = new URL(target.pathname + target.search + target.hash, BASE);
            }
            if (isBlocked(target.href)) {
                return "data:text/javascript,";
            }
            const href = target.href;
            const fragment = href.indexOf("#");
            const upstream = fragment < 0 ? href : href.slice(0, fragment);
            return (ROUTES[target.origin] || ENDPOINT) + "?url=" + encodeURIComponent(upstream) +
                (fragment < 0 ? "" : href.slice(fragment));
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

    const oldFetch = window.fetch;

    if (oldFetch) {
        window.fetch = function(resource, options) {
            if (typeof resource === "string") {
                resource = proxify(resource);
            } else if (resource instanceof URL) {
                resource = proxify(resource.href);
            } else if (resource instanceof Request) {
                const url = proxify(resource.url);
                if (url !== resource.url) {
                    resource = new Request(url, resource);
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
        if (/^(src|href|action|poster|data-src|data-href)$/i.test(name)) {
            value = proxify(String(value));
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
    ]);
}
