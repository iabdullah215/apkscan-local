"""Synthetic Android code generator with rule-checked labels.

Every snippet template has a vulnerable form and safe look-alike forms. A sample is one
Java/manifest/network-config file assembled from filler members plus 0 to 2 snippets.
Labels come from the template itself and are then re-checked by rules in checks.py.

Each template has a stable id. Train/validation separation is by template variant id
(see builder.py), so near-identical code never sits on both sides.

Written for this repository (MIT). It deliberately avoids identifiers and strings from
the held-out test apps.
"""

from __future__ import annotations

import random
import string
from dataclasses import dataclass, field

COMPANIES = ["acme", "northwind", "bluefin", "kitebank", "medrix", "parcelly", "zentro", "farmlink", "quickcab",
             "lumen", "tasko", "rivet", "orbita", "pocketfi", "civic", "greengrocer", "shipyard", "edupath"]
APPS = ["wallet", "health", "delivery", "notes", "chat", "shop", "fitness", "travel", "rides", "learn", "bank",
        "insure", "pharmacy", "tickets", "loyalty", "payroll", "clinic", "news"]
MODULES = ["ui", "auth", "net", "data", "core", "account", "payments", "profile", "sync", "web", "storage",
           "security", "settings", "util", "feature.checkout", "feature.login"]
NOUNS = ["Account", "Profile", "Payment", "Session", "Order", "Ticket", "Wallet", "Report", "Invoice", "Message",
         "Card", "Coupon", "Booking", "Patient", "Receipt", "Device", "Course", "Trip"]
SUFFIX_ACT = ["Activity", "Screen", "Activity"]


def _ident(rng, base):
    return base + rng.choice(["", "Helper", "Manager", "Util", "Store", "Client", "Repo"])


def _rand_token(rng, n, alphabet=string.ascii_letters + string.digits):
    return "".join(rng.choice(alphabet) for _ in range(n))


@dataclass
class Snip:
    """A block of code lines; `label` (if any) marks lines [l0, l1] within the block (0-based)."""
    tid: str  # template id, used for leakage-safe splitting
    lines: list[str]
    imports: list[str] = field(default_factory=list)
    label: dict | None = None  # {vuln_class, severity, rel: (l0, l1), evidence, why, fix, cwe}
    fields: list[str] = field(default_factory=list)  # class-level fields (go at top of class)
    field_label: dict | None = None  # label on a field line (rel index into fields)


# ---------------------------------------------------------------- filler (benign) members
def filler(rng, cls):
    n = rng.choice(NOUNS)
    opts = [
        ([f"    private void bind{n}(TextView view, String value) {{",
          "        if (value == null || value.isEmpty()) {",
          "            view.setVisibility(View.GONE);",
          "            return;",
          "        }",
          "        view.setText(value);",
          "        view.setVisibility(View.VISIBLE);",
          "    }"], ["android.widget.TextView", "android.view.View"]),
        ([f"    public int count{n}s(List<String> items) {{",
          "        int total = 0;",
          "        for (String item : items) {",
          "            if (item != null && !item.trim().isEmpty()) {",
          "                total++;",
          "            }",
          "        }",
          "        return total;",
          "    }"], ["java.util.List"]),
        ([f"    private String format{n}Amount(long cents) {{",
          "        long major = cents / 100;",
          "        long minor = Math.abs(cents % 100);",
          '        return String.format(Locale.US, "%d.%02d", major, minor);',
          "    }"], ["java.util.Locale"]),
        (["    @Override",
          "    protected void onResume() {",
          "        super.onResume();",
          f"        refresh{n}List();",
          "    }",
          "",
          f"    private void refresh{n}List() {{",
          "        if (this.adapter != null) {",
          "            this.adapter.notifyDataSetChanged();",
          "        }",
          "    }"], []),
        ([f"    private boolean is{n}Valid(String input) {{",
          "        if (input == null) {",
          "            return false;",
          "        }",
          "        String trimmed = input.trim();",
          "        return trimmed.length() >= 3 && trimmed.length() <= 64;",
          "    }"], []),
        ([f"    private void show{n}Error(String message) {{",
          "        Toast.makeText(this, message, Toast.LENGTH_SHORT).show();",
          "    }"], ["android.widget.Toast"]),
        ([f"    private static String {n.lower()}CacheKey(String id) {{",
          '        return "cache_" + id.toLowerCase(Locale.ROOT);',
          "    }"], ["java.util.Locale"]),
        ([f"    public void on{n}Clicked(View v) {{",
          f"        Intent intent = new Intent(this, {n}DetailActivity.class);",
          f'        intent.putExtra("{n.lower()}_id", v.getTag().toString());',
          "        startActivity(intent);",
          "    }"], ["android.content.Intent", "android.view.View"]),
    ]
    lines, imps = rng.choice(opts)
    return [l.replace("{{", "{").replace("}}", "}") for l in lines], imps


# ---------------------------------------------------------------- snippet templates
def webview_snips(rng):
    v = rng.choice(["webView", "mWebView", "browser", "contentView"])
    bridge = rng.choice(["JsBridge", "NativeApi", "AppInterface", "WebBridge"])
    jsname = rng.choice(["Android", "native", "app", "bridge"])
    extra = rng.choice(["url", "link", "target_url", "page"])
    trusted = rng.choice(["trusted.com", "mycompany.com", "partner.io", "secure-pay.net"])
    out = []
    # V1 JS interface + JS enabled + loads intent URL
    out.append(Snip("webview.js_interface.v", [
        "    private void setupWebView() {",
        f"        WebView {v} = (WebView) findViewById(R.id.web);",
        f"        {v}.getSettings().setJavaScriptEnabled(true);",
        f'        {v}.addJavascriptInterface(new {bridge}(this), "{jsname}");',
        f'        {v}.loadUrl(getIntent().getStringExtra("{extra}"));',
        "    }"], ["android.webkit.WebView"],
        {"vuln_class": "insecure_webview", "severity": "high", "rel": (2, 4), "cwe": "CWE-749",
         "evidence": f'{v}.addJavascriptInterface(new {bridge}(this), "{jsname}") with JavaScript on and a URL from the intent',
         "why": f"Any page the caller passes in the \"{extra}\" extra runs JavaScript that can call {bridge} methods as \"{jsname}\".",
         "fix": "Load only allowlisted https origins, and remove the bridge or expose only harmless methods with @JavascriptInterface."}))
    # V2 file access flags
    flag = rng.choice(["setAllowFileAccessFromFileURLs", "setAllowUniversalAccessFromFileURLs", "setAllowFileAccess"])
    out.append(Snip("webview.file_access.v", [
        f"    private void configure(WebView {v}) {{",
        f"        WebSettings settings = {v}.getSettings();",
        "        settings.setJavaScriptEnabled(true);",
        f"        settings.{flag}(true);",
        "        settings.setDomStorageEnabled(true);",
        "    }"], ["android.webkit.WebSettings", "android.webkit.WebView"],
        {"vuln_class": "insecure_webview", "severity": "medium" if flag == "setAllowFileAccess" else "high", "rel": (2, 3),
         "cwe": "CWE-200" if False else "CWE-749",
         "evidence": f"settings.{flag}(true) with JavaScript enabled",
         "why": "JavaScript in a file:// page can read other local files (and with universal access, any origin), so a loaded HTML file can steal app data.",
         "fix": f"Call settings.{flag}(false) and serve local content through WebViewAssetLoader over https://appassets.androidplatform.net."}))
    # V3 weak host validation
    check = rng.choice([f'host.endsWith("{trusted}")', f'url.contains("{trusted}")', f'url.startsWith("https://{trusted}")'])
    out.append(Snip("webview.weak_host_check.v", [
        "    private void openLink(Uri data) {",
        f'        String url = data.getQueryParameter("{extra}");',
        "        String host = Uri.parse(url).getHost();",
        f"        if (url != null && host != null && {check}) {{",
        f"            {v}.loadUrl(url);",
        "        }",
        "    }"], ["android.net.Uri"],
        {"vuln_class": "insecure_webview", "severity": "medium", "rel": (3, 4), "cwe": "CWE-939",
         "evidence": f"if ({check}) {v}.loadUrl(url)",
         "why": f"The check is bypassable (for example evil{trusted.split('.')[0]}.com, https://{trusted}.evil.net or https://{trusted}@evil.net), so an attacker URL loads in the WebView.",
         "fix": "Parse the URI, require scheme https and compare the host for exact equality against an allowlist."}))
    # V4 shouldOverrideUrlLoading loads anything
    out.append(Snip("webview.override_loads_any.v", [
        "    private final WebViewClient client = new WebViewClient() {",
        "        @Override",
        "        public boolean shouldOverrideUrlLoading(WebView view, String url) {",
        "            view.loadUrl(url);",
        "            return true;",
        "        }",
        "    };"], ["android.webkit.WebView", "android.webkit.WebViewClient"],
        {"vuln_class": "insecure_webview", "severity": "low", "rel": (2, 4), "cwe": "CWE-939",
         "evidence": "shouldOverrideUrlLoading calls view.loadUrl(url) for every URL",
         "why": "Any link or redirect, including attacker pages and javascript: or file: URLs, is loaded inside the app WebView with its settings.",
         "fix": "Only load allowlisted https hosts in the WebView and open everything else in the browser, returning true."}))
    # Safe forms
    out.append(Snip("webview.safe_allowlist", [
        "    private static final Set<String> ALLOWED_HOSTS = new HashSet<>(Arrays.asList(\"" + trusted + "\", \"www." + trusted + "\"));",
        "",
        "    private void openLink(Uri data) {",
        f'        Uri target = Uri.parse(data.getQueryParameter("{extra}"));',
        '        if ("https".equals(target.getScheme()) && ALLOWED_HOSTS.contains(target.getHost())) {',
        f"            {v}.loadUrl(target.toString());",
        "        }",
        "    }"], ["android.net.Uri", "java.util.Arrays", "java.util.HashSet", "java.util.Set"]))
    out.append(Snip("webview.safe_settings", [
        f"    private void configure(WebView {v}) {{",
        f"        WebSettings settings = {v}.getSettings();",
        "        settings.setJavaScriptEnabled(false);",
        "        settings.setAllowFileAccess(false);",
        "        settings.setAllowContentAccess(false);",
        f'        {v}.loadUrl("https://{trusted}/help");',
        "    }"], ["android.webkit.WebSettings", "android.webkit.WebView"]))
    out.append(Snip("webview.safe_override", [
        "    private final WebViewClient client = new WebViewClient() {",
        "        @Override",
        "        public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {",
        f'            if ("{trusted}".equals(request.getUrl().getHost())) {{',
        "                return false;",
        "            }",
        "            startActivity(new Intent(Intent.ACTION_VIEW, request.getUrl()));",
        "            return true;",
        "        }",
        "    };"], ["android.webkit.WebResourceRequest", "android.webkit.WebView", "android.webkit.WebViewClient", "android.content.Intent"]))
    return out


def secret_snips(rng):
    kind = rng.choice(["api", "aws", "password", "aes", "jwt", "stripe"])
    if kind == "api":
        name, val = rng.choice(["API_KEY", "MAPS_KEY", "apiKey", "SERVICE_KEY"]), "AIza" + _rand_token(rng, 35)
    elif kind == "aws":
        name, val = rng.choice(["AWS_SECRET", "awsSecretKey", "S3_SECRET"]), _rand_token(rng, 40, string.ascii_letters + string.digits + "/+")
    elif kind == "password":
        name, val = rng.choice(["ADMIN_PASSWORD", "DB_PASSWORD", "defaultPass", "SUPPORT_PIN"]), rng.choice(["Winter", "Admin", "Sup3r", "Pa55"]) + _rand_token(rng, 6) + "!"
    elif kind == "aes":
        name, val = rng.choice(["AES_KEY", "SECRET_KEY", "encKey", "CIPHER_KEY"]), _rand_token(rng, 16 if rng.random() < .5 else 32)
    elif kind == "jwt":
        name, val = rng.choice(["JWT_SECRET", "SIGNING_SECRET", "hmacSecret"]), _rand_token(rng, 32)
    else:
        name, val = rng.choice(["STRIPE_SECRET", "PAYMENT_SECRET"]), "sk_live_" + _rand_token(rng, 24)
    mod = rng.choice(["private static final String", "static final String", "public static final String", "private final String"])
    out = [Snip(f"secret.{kind}.v", [], [], None, [f'    {mod} {name} = "{val}";'],
                {"vuln_class": "hardcoded_secret", "severity": "high" if kind in ("aws", "stripe", "aes", "jwt") else "medium",
                 "rel": 0, "cwe": "CWE-321" if kind == "aes" else "CWE-798",
                 "evidence": f'{name} = "{val[:12]}..."',
                 "why": f"Anyone can unpack the APK and read {name}; the same value ships to every install and cannot be rotated without an update.",
                 "fix": ("Generate the key in the Android Keystore instead of embedding it." if kind == "aes" else
                         "Remove the secret from the app; keep it on the server and issue short-lived, per-user tokens.")})]
    # safe look-alikes: constants that are not secrets
    out.append(Snip("secret.safe_constants", [], [], None, [
        f'    private static final String PREFS_NAME = "{rng.choice(APPS)}_prefs";',
        f'    private static final String KEY_PASSWORD_HINT_SHOWN = "password_hint_shown";',
        f'    private static final String BASE_URL = "https://api.{rng.choice(COMPANIES)}.com/v2/";',
        '    private static final int REQUEST_CODE = 4021;']))
    out.append(Snip("secret.safe_keystore", [
        "    private SecretKey getOrCreateKey() throws GeneralSecurityException, IOException {",
        '        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");',
        "        ks.load(null);",
        f'        if (ks.containsAlias("{rng.choice(APPS)}_key")) {{',
        f'            return (SecretKey) ks.getKey("{rng.choice(APPS)}_key", null);',
        "        }",
        '        KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");',
        f'        kg.init(new KeyGenParameterSpec.Builder("{rng.choice(APPS)}_key", KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)',
        "                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)",
        "                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)",
        "                .build());",
        "        return kg.generateKey();",
        "    }"], ["java.security.KeyStore", "javax.crypto.KeyGenerator", "javax.crypto.SecretKey",
              "android.security.keystore.KeyGenParameterSpec", "android.security.keystore.KeyProperties"]))
    return out


def crypto_snips(rng):
    out = []
    algo = rng.choice(['"AES"', '"AES/ECB/PKCS5Padding"', '"DES/ECB/PKCS5Padding"', '"DESede/ECB/NoPadding"', '"AES/ECB/NoPadding"'])
    out.append(Snip("crypto.ecb_or_des.v", [
        "    public byte[] encrypt(byte[] plain, byte[] keyBytes) throws GeneralSecurityException {",
        f'        SecretKeySpec spec = new SecretKeySpec(keyBytes, {"\"DES\"" if "DES/" in algo else ("\"DESede\"" if "DESede" in algo else "\"AES\"")});',
        f"        Cipher cipher = Cipher.getInstance({algo});",
        "        cipher.init(Cipher.ENCRYPT_MODE, spec);" if rng.random() < .5 else "        cipher.init(1, spec);",
        "        return cipher.doFinal(plain);",
        "    }"], ["javax.crypto.Cipher", "javax.crypto.spec.SecretKeySpec", "java.security.GeneralSecurityException"],
        {"vuln_class": "weak_crypto", "severity": "medium", "rel": (2, 2), "cwe": "CWE-327",
         "evidence": f"Cipher.getInstance({algo})",
         "why": ("ECB encrypts equal blocks to equal ciphertext, leaking patterns, and gives no integrity." if "DES" not in algo else
                 "DES/3DES use small keys and block sizes and are deprecated; ECB also leaks plaintext patterns."),
         "fix": 'Use Cipher.getInstance("AES/GCM/NoPadding") with a random 12-byte IV per message and a Keystore key.'}))
    ivexpr = rng.choice(["new byte[16]", '"0000000000000000".getBytes()', "STATIC_IV", "{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}"])
    lines = ["    public byte[] seal(byte[] data, SecretKey key) throws GeneralSecurityException {"]
    if ivexpr.startswith("{"):
        lines.append(f"        byte[] iv = {ivexpr};")
        lines.append("        IvParameterSpec ivSpec = new IvParameterSpec(iv);")
    else:
        lines.append(f"        IvParameterSpec ivSpec = new IvParameterSpec({ivexpr});")
    lines += ['        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");',
              "        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);",
              "        return cipher.doFinal(data);",
              "    }"]
    fl = ['    private static final byte[] STATIC_IV = "' + _rand_token(rng, 16) + '".getBytes();'] if ivexpr == "STATIC_IV" else []
    out.append(Snip("crypto.static_iv.v", lines, ["javax.crypto.Cipher", "javax.crypto.SecretKey", "javax.crypto.spec.IvParameterSpec"],
                    {"vuln_class": "weak_crypto", "severity": "medium", "rel": (1, 2 if ivexpr.startswith("{") else 1), "cwe": "CWE-329",
                     "evidence": f"IvParameterSpec built from a constant IV ({ivexpr if len(ivexpr) < 30 else 'fixed byte array'})",
                     "why": "A fixed IV makes CBC deterministic, so identical plaintexts and shared prefixes are visible to anyone who sees the ciphertext.",
                     "fix": "Generate a fresh random IV with SecureRandom for every encryption and store it with the ciphertext, or switch to AES-GCM."}, fl))
    h = rng.choice(['"MD5"', '"SHA-1"', '"SHA1"'])
    out.append(Snip("crypto.weak_hash_password.v", [
        "    public static String hashPassword(String password) throws NoSuchAlgorithmException {",
        f"        MessageDigest md = MessageDigest.getInstance({h});",
        "        byte[] digest = md.digest(password.getBytes(StandardCharsets.UTF_8));",
        "        return Base64.encodeToString(digest, Base64.NO_WRAP);",
        "    }"], ["java.security.MessageDigest", "java.security.NoSuchAlgorithmException", "java.nio.charset.StandardCharsets", "android.util.Base64"],
        {"vuln_class": "weak_crypto", "severity": "medium", "rel": (1, 2), "cwe": "CWE-328",
         "evidence": f"MessageDigest.getInstance({h}) used to hash a password",
         "why": f"{h.strip(chr(34))} is fast and unsalted, so leaked hashes are cracked quickly with GPUs or lookup tables.",
         "fix": "Do password hashing on the server with a slow salted KDF such as Argon2 or PBKDF2 with a high iteration count."}))
    out.append(Snip("crypto.insecure_random.v", [
        "    public String newResetCode() {",
        "        Random random = new Random();",
        "        int code = 100000 + random.nextInt(900000);",
        "        return String.valueOf(code);",
        "    }"], ["java.util.Random"],
        {"vuln_class": "weak_crypto", "severity": "medium", "rel": (1, 2), "cwe": "CWE-330",
         "evidence": "new Random().nextInt(...) generates a security code",
         "why": "java.util.Random is predictable from a few outputs or the seed time, so codes can be guessed.",
         "fix": "Use java.security.SecureRandom for codes, tokens and keys."}))
    # safe
    out.append(Snip("crypto.safe_gcm", [
        "    public byte[] encrypt(byte[] plain, SecretKey key) throws GeneralSecurityException {",
        "        byte[] iv = new byte[12];",
        "        new SecureRandom().nextBytes(iv);",
        '        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");',
        "        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));",
        "        byte[] body = cipher.doFinal(plain);",
        "        return ByteBuffer.allocate(iv.length + body.length).put(iv).put(body).array();",
        "    }"], ["javax.crypto.Cipher", "javax.crypto.SecretKey", "javax.crypto.spec.GCMParameterSpec", "java.security.SecureRandom", "java.nio.ByteBuffer"]))
    out.append(Snip("crypto.safe_md5_cache", [
        "    private String cacheFileName(String imageUrl) {",
        "        try {",
        '            MessageDigest md = MessageDigest.getInstance("MD5");',
        "            byte[] d = md.digest(imageUrl.getBytes(StandardCharsets.UTF_8));",
        "            return String.format(\"%032x\", new BigInteger(1, d));",
        "        } catch (NoSuchAlgorithmException e) {",
        "            return String.valueOf(imageUrl.hashCode());",
        "        }",
        "    }"], ["java.security.MessageDigest", "java.math.BigInteger", "java.nio.charset.StandardCharsets"]))
    out.append(Snip("crypto.safe_random_ui", [
        "    private int pickTipIndex(int count) {",
        "        return new Random().nextInt(count);",
        "    }"], ["java.util.Random"]))
    out.append(Snip("crypto.safe_securerandom", [
        "    public String newResetCode() {",
        "        SecureRandom random = new SecureRandom();",
        "        return String.valueOf(100000 + random.nextInt(900000));",
        "    }"], ["java.security.SecureRandom"]))
    return out


def network_snips(rng):
    host = f"api.{rng.choice(COMPANIES)}.com"
    out = []
    path = rng.choice(["/login", "/v1/payments", "/session", "/user/profile", "/upload"])
    out.append(Snip("net.http_url.v", [
        "    public Response send(Request body) throws IOException {",
        f'        URL url = new URL("http://{host}{path}");',
        "        HttpURLConnection conn = (HttpURLConnection) url.openConnection();",
        '        conn.setRequestMethod("POST");',
        "        conn.setDoOutput(true);",
        "        conn.getOutputStream().write(body.toJson().getBytes());",
        "        return Response.from(conn);",
        "    }"], ["java.net.URL", "java.net.HttpURLConnection", "java.io.IOException"],
        {"vuln_class": "insecure_network", "severity": "high" if path in ("/login", "/v1/payments", "/session") else "medium",
         "rel": (1, 1), "cwe": "CWE-319",
         "evidence": f'new URL("http://{host}{path}")',
         "why": "Requests go over cleartext HTTP, so anyone on the network path can read or modify them.",
         "fix": "Use https:// and keep cleartextTrafficPermitted=\"false\" in the network security config."}))
    out.append(Snip("net.trust_all.v", [
        "    private static final TrustManager[] TRUST_ALL = new TrustManager[]{new X509TrustManager() {",
        "        public void checkClientTrusted(X509Certificate[] chain, String authType) {",
        "        }",
        "",
        "        public void checkServerTrusted(X509Certificate[] chain, String authType) {",
        "        }",
        "",
        "        public X509Certificate[] getAcceptedIssuers() {",
        "            return new X509Certificate[0];",
        "        }",
        "    }};"], ["javax.net.ssl.TrustManager", "javax.net.ssl.X509TrustManager", "java.security.cert.X509Certificate"],
        {"vuln_class": "insecure_network", "severity": "high", "rel": (4, 5), "cwe": "CWE-295",
         "evidence": "X509TrustManager.checkServerTrusted is empty",
         "why": "Every certificate is accepted, so a man-in-the-middle with any self-signed certificate can read and change TLS traffic.",
         "fix": "Remove the custom TrustManager and use the platform default; for private CAs or pinning use network_security_config.xml."}))
    hv = rng.choice(["lambda", "anon"])
    hv_lines = (["    private void configureClient(OkHttpClient.Builder builder) {",
                 "        builder.hostnameVerifier((hostname, session) -> true);",
                 "    }"] if hv == "lambda" else
                ["    private final HostnameVerifier verifier = new HostnameVerifier() {",
                 "        @Override",
                 "        public boolean verify(String hostname, SSLSession session) {",
                 "            return true;",
                 "        }",
                 "    };"])
    out.append(Snip("net.hostname_any.v", hv_lines, ["javax.net.ssl.HostnameVerifier", "javax.net.ssl.SSLSession"],
                    {"vuln_class": "insecure_network", "severity": "high", "rel": (1, 1) if hv == "lambda" else (2, 3), "cwe": "CWE-295",
                     "evidence": "HostnameVerifier that always returns true",
                     "why": "A valid certificate for any other domain is accepted, which enables man-in-the-middle attacks.",
                     "fix": "Remove the custom verifier so the default hostname check applies."}))
    out.append(Snip("net.ssl_error_proceed.v", [
        "    private final WebViewClient client = new WebViewClient() {",
        "        @Override",
        "        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {",
        "            handler.proceed();",
        "        }",
        "    };"], ["android.webkit.SslErrorHandler", "android.net.http.SslError", "android.webkit.WebView", "android.webkit.WebViewClient"],
        {"vuln_class": "insecure_network", "severity": "high", "rel": (2, 3), "cwe": "CWE-295",
         "evidence": "onReceivedSslError calls handler.proceed()",
         "why": "The WebView ignores certificate errors, so pages can be intercepted and modified by anyone on the network.",
         "fix": "Call handler.cancel() (the default) and fix the server certificate instead."}))
    out.append(Snip("net.safe_https", [
        "    public Response send(Request body) throws IOException {",
        f'        URL url = new URL("https://{host}{path}");',
        "        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();",
        '        conn.setRequestMethod("POST");',
        "        conn.setDoOutput(true);",
        "        conn.getOutputStream().write(body.toJson().getBytes());",
        "        return Response.from(conn);",
        "    }"], ["java.net.URL", "javax.net.ssl.HttpsURLConnection", "java.io.IOException"]))
    out.append(Snip("net.safe_ssl_cancel", [
        "    private final WebViewClient client = new WebViewClient() {",
        "        @Override",
        "        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {",
        "            handler.cancel();",
        '            Log.w(TAG, "TLS error " + error.getPrimaryError());',
        "        }",
        "    };"], ["android.webkit.SslErrorHandler", "android.net.http.SslError", "android.webkit.WebView", "android.webkit.WebViewClient", "android.util.Log"]))
    out.append(Snip("net.safe_pinning", [
        "    private OkHttpClient buildClient() {",
        "        CertificatePinner pinner = new CertificatePinner.Builder()",
        f'                .add("{host}", "sha256/{_rand_token(rng, 43)}=")',
        "                .build();",
        "        return new OkHttpClient.Builder().certificatePinner(pinner).build();",
        "    }"], ["okhttp3.CertificatePinner", "okhttp3.OkHttpClient"]))
    return out


def storage_snips(rng):
    out = []
    key = rng.choice(["password", "auth_token", "pin", "access_token", "card_number", "refresh_token"])
    var = {"password": "password", "auth_token": "token", "pin": "pin", "access_token": "accessToken",
           "card_number": "cardNumber", "refresh_token": "refreshToken"}[key]
    mode = rng.choice(["0", "Context.MODE_PRIVATE", "MODE_PRIVATE"])
    out.append(Snip("storage.prefs_plain_secret.v", [
        f"    public void remember(String user, String {var}) {{",
        f'        SharedPreferences prefs = getSharedPreferences("{rng.choice(APPS)}_session", {mode});',
        "        prefs.edit()",
        '                .putString("user", user)',
        f'                .putString("{key}", {var})',
        "                .apply();",
        "    }"], ["android.content.SharedPreferences", "android.content.Context"],
        {"vuln_class": "insecure_storage", "severity": "high" if key in ("password", "card_number", "pin") else "medium",
         "rel": (1, 5), "cwe": "CWE-312",
         "evidence": f'putString("{key}", {var}) in plain SharedPreferences',
         "why": f"The {key.replace('_', ' ')} is stored as plaintext XML in the app sandbox, readable from backups, rooted devices or any file-read bug.",
         "fix": "Do not store it, or store it with EncryptedSharedPreferences / a Keystore-backed key; prefer short-lived tokens over passwords."}))
    wr = rng.choice(["1", "Context.MODE_WORLD_READABLE", "MODE_WORLD_READABLE", "2", "Context.MODE_WORLD_WRITEABLE"])
    api = rng.choice(["prefs", "file"])
    if api == "prefs":
        lines = [f"    private SharedPreferences settings() {{",
                 f'        return getSharedPreferences("{rng.choice(APPS)}_settings", {wr});',
                 "    }"]
        rel = (1, 1)
    else:
        lines = ["    private void writeExport(String data) throws IOException {",
                 f'        FileOutputStream out = openFileOutput("{rng.choice(NOUNS).lower()}_export.txt", {wr});',
                 "        out.write(data.getBytes());",
                 "        out.close();",
                 "    }"]
        rel = (1, 1)
    out.append(Snip("storage.world_mode.v", lines, ["android.content.SharedPreferences", "java.io.FileOutputStream", "java.io.IOException"],
                    {"vuln_class": "insecure_storage", "severity": "medium", "rel": rel, "cwe": "CWE-276",
                     "evidence": f"opened with mode {wr} (world {'writeable' if 'WRITE' in wr or wr == '2' else 'readable'})",
                     "why": "World-accessible files in the app sandbox can be read or changed by every other app on older Android versions.",
                     "fix": "Use MODE_PRIVATE; share data with other apps only through a FileProvider with explicit grants."}))
    ext = rng.choice(["Environment.getExternalStorageDirectory()", "getExternalFilesDir(null)",
                      'Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)'])
    what = rng.choice(["statement", "session_log", "receipt", "medical_report", "backup"])
    out.append(Snip("storage.external_sensitive.v", [
        f"    private void save{what.title().replace('_', '')}(String content) throws IOException {{",
        f'        File out = new File({ext}, "{what}_" + userId + ".txt");',
        "        FileWriter writer = new FileWriter(out);",
        "        writer.write(content);",
        "        writer.close();",
        "    }"], ["android.os.Environment", "java.io.File", "java.io.FileWriter", "java.io.IOException"],
        {"vuln_class": "insecure_storage", "severity": "medium", "rel": (1, 3), "cwe": "CWE-922",
         "evidence": f"writes {what.replace('_', ' ')} for the user to {ext}",
         "why": "External storage is shared; other apps with storage access (and anyone with the device over USB) can read it.",
         "fix": "Write sensitive files to getFilesDir() or encrypt them, and share them only through a FileProvider."}))
    out.append(Snip("storage.safe_encrypted_prefs", [
        f"    private SharedPreferences securePrefs() throws GeneralSecurityException, IOException {{",
        "        MasterKey masterKey = new MasterKey.Builder(this)",
        "                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)",
        "                .build();",
        f'        return EncryptedSharedPreferences.create(this, "{rng.choice(APPS)}_secure", masterKey,',
        "                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,",
        "                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);",
        "    }",
        "",
        f"    public void remember(String {var}) throws GeneralSecurityException, IOException {{",
        f'        securePrefs().edit().putString("{key}", {var}).apply();',
        "    }"], ["androidx.security.crypto.EncryptedSharedPreferences", "androidx.security.crypto.MasterKey"]))
    out.append(Snip("storage.safe_plain_nonsensitive", [
        "    private void saveUiState(boolean darkMode, int lastTab) {",
        '        SharedPreferences prefs = getSharedPreferences("ui_state", MODE_PRIVATE);',
        '        prefs.edit().putBoolean("dark_mode", darkMode).putInt("last_tab", lastTab).apply();',
        "    }"], ["android.content.SharedPreferences"]))
    out.append(Snip("storage.safe_internal_file", [
        "    private void cacheThumbnail(String name, byte[] png) throws IOException {",
        '        File dir = new File(getCacheDir(), "thumbs");',
        "        dir.mkdirs();",
        "        try (FileOutputStream out = new FileOutputStream(new File(dir, name))) {",
        "            out.write(png);",
        "        }",
        "    }"], ["java.io.File", "java.io.FileOutputStream", "java.io.IOException"]))
    return out


def provider_snips(rng):
    table = rng.choice(["notes", "orders", "contacts", "messages", "accounts", "items"])
    out = []
    variant = rng.choice(["segment", "selection", "sort"])
    if variant == "segment":
        lines = ["    @Override",
                 "    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {",
                 "        SQLiteDatabase db = this.helper.getReadableDatabase();",
                 "        String id = uri.getLastPathSegment();",
                 f'        return db.rawQuery("SELECT * FROM {table} WHERE id = " + id, null);',
                 "    }"]
        rel, ev = (3, 4), f'rawQuery("SELECT * FROM {table} WHERE id = " + uri.getLastPathSegment())'
    elif variant == "selection":
        lines = ["    @Override",
                 "    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {",
                 "        SQLiteDatabase db = this.helper.getReadableDatabase();",
                 f'        String sql = "SELECT * FROM {table} WHERE owner = \'" + getCallingPackage() + "\'";',
                 "        if (selection != null) {",
                 '            sql = sql + " AND " + selection;',
                 "        }",
                 "        return db.rawQuery(sql, selectionArgs);",
                 "    }"]
        rel, ev = (5, 7), 'sql + " AND " + selection passed to rawQuery'
    else:
        lines = ["    @Override",
                 "    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {",
                 "        SQLiteQueryBuilder qb = new SQLiteQueryBuilder();",
                 f'        qb.setTables("{table}");',
                 "        return qb.query(this.helper.getReadableDatabase(), projection, selection, selectionArgs, null, null, sortOrder);",
                 "    }"]
        rel, ev = (2, 4), "caller projection, selection and sortOrder passed to SQLiteQueryBuilder.query without setStrict or a projection map"
    out.append(Snip(f"provider.sqli_{variant}.v", lines, ["android.database.Cursor", "android.database.sqlite.SQLiteDatabase", "android.database.sqlite.SQLiteQueryBuilder", "android.net.Uri"],
                    {"vuln_class": "provider_sqli", "severity": "high", "rel": rel, "cwe": "CWE-89", "evidence": ev,
                     "why": f"A calling app controls part of the SQL, so it can read rows or tables beyond {table} (for example with UNION SELECT or a subquery in the selection).",
                     "fix": "Use parameterized selections with selectionArgs, a fixed projection map, qb.setStrict(true) and setStrictColumns, and require a permission on the provider."}))
    out.append(Snip("provider.safe_parameterized", [
        "    @Override",
        "    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {",
        "        SQLiteQueryBuilder qb = new SQLiteQueryBuilder();",
        f'        qb.setTables("{table}");',
        "        qb.setProjectionMap(PROJECTION);",
        "        qb.setStrict(true);",
        "        qb.setStrictColumns(true);",
        '        return qb.query(this.helper.getReadableDatabase(), null, "id = ?", new String[]{uri.getLastPathSegment()}, null, null, "id ASC");',
        "    }"], ["android.database.Cursor", "android.database.sqlite.SQLiteQueryBuilder", "android.net.Uri"]))
    out.append(Snip("provider.safe_dao", [
        f"    public Cursor findByName(String name) {{",
        f'        return this.db.query("{table}", new String[]{{"id", "name"}}, "name = ?", new String[]{{name}}, null, null, "name");',
        "    }"], ["android.database.Cursor"]))
    return out


def intent_snips(rng):
    extra = rng.choice(["next_intent", "forward", "target", "EXTRA_INTENT", "pending_action", "return_to"])
    out = []
    call = rng.choice(["startActivity", "startService", "sendBroadcast"])
    out.append(Snip("intent.redirect_extra.v", [
        "    @Override",
        "    protected void onCreate(Bundle savedInstanceState) {",
        "        super.onCreate(savedInstanceState);",
        f'        Intent forward = (Intent) getIntent().getParcelableExtra("{extra}");',
        "        if (forward != null) {",
        f"            {call}(forward);",
        "        }",
        "        finish();",
        "    }"], ["android.content.Intent", "android.os.Bundle"],
        {"vuln_class": "intent_redirection", "severity": "high", "rel": (3, 5), "cwe": "CWE-940",
         "evidence": f'{call}((Intent) getIntent().getParcelableExtra("{extra}"))',
         "why": f"A caller can nest any Intent in \"{extra}\"; the app then launches it with its own identity, reaching non-exported components or granting URI access.",
         "fix": "Do not launch Intents from extras; if needed, accept only an allowlisted action and set the component yourself, and strip FLAG_GRANT_* flags."}))
    out.append(Snip("intent.setresult_passthrough.v", [
        "    @Override",
        "    protected void onCreate(Bundle savedInstanceState) {",
        "        super.onCreate(savedInstanceState);",
        "        setResult(RESULT_OK, getIntent());",
        "        finish();",
        "    }"], ["android.os.Bundle"],
        {"vuln_class": "intent_redirection", "severity": "medium", "rel": (3, 3), "cwe": "CWE-940",
         "evidence": "setResult(RESULT_OK, getIntent()) returns the caller-supplied intent",
         "why": "The caller controls the returned intent's data and grant flags, so it can obtain URI permissions to this app's providers.",
         "fix": "Return a new Intent with only the fields you need, and never echo flags or data URIs from the incoming intent."}))
    secret = rng.choice(["token", "session_id", "password", "otp"])
    out.append(Snip("intent.implicit_sensitive.v", [
        f"    private void publish{secret.title().replace('_', '')}(String value) {{",
        f'        Intent i = new Intent("com.{rng.choice(COMPANIES)}.action.{secret.upper()}_UPDATED");',
        f'        i.putExtra("{secret}", value);',
        "        sendBroadcast(i);",
        "    }"], ["android.content.Intent"],
        {"vuln_class": "intent_redirection", "severity": "high" if secret in ("password", "otp") else "medium",
         "rel": (1, 3), "cwe": "CWE-927",
         "evidence": f'implicit broadcast carrying "{secret}"',
         "why": f"Any installed app can register for this action and receive the {secret.replace('_', ' ')}.",
         "fix": "Use an explicit intent (setPackage(getPackageName()) or setComponent), a signature permission on sendBroadcast, or an in-process callback."}))
    action = rng.choice(["deleteAccount()", "sendSms(intent.getStringExtra(\"to\"), intent.getStringExtra(\"body\"))", "wipeLocalData()", "setAdminMode(true)"])
    out.append(Snip("intent.receiver_sensitive_action.v", [
        "    @Override",
        "    public void onReceive(Context context, Intent intent) {",
        f'        if ("com.{rng.choice(COMPANIES)}.ACTION_{rng.choice(["RESET", "SYNC", "ADMIN", "NOTIFY"])}".equals(intent.getAction())) {{',
        f"            {action};",
        "        }",
        "    }"], ["android.content.Context", "android.content.Intent"],
        {"vuln_class": "intent_redirection", "severity": "high", "rel": (2, 3), "cwe": "CWE-925",
         "evidence": f"onReceive runs {action.split('(')[0]} for any sender of the action",
         "why": "The receiver trusts the broadcast without checking the sender, so any app that sends this action triggers the sensitive operation.",
         "fix": "Protect the receiver with a signature permission or make it non-exported, and validate extras before acting."}))
    out.append(Snip("intent.mutable_pendingintent.v", [
        "    private PendingIntent buildReplyAction() {",
        "        Intent base = new Intent();",
        "        return PendingIntent.getActivity(this, 0, base, PendingIntent.FLAG_MUTABLE);",
        "    }"], ["android.app.PendingIntent", "android.content.Intent"],
        {"vuln_class": "intent_redirection", "severity": "medium", "rel": (1, 2), "cwe": "CWE-927",
         "evidence": "PendingIntent.getActivity with an empty implicit Intent and FLAG_MUTABLE",
         "why": "Whoever receives the PendingIntent can fill in the empty intent and run it with this app's identity and permissions.",
         "fix": "Use an explicit intent (setClass/setComponent) and FLAG_IMMUTABLE unless mutability is required."}))
    # safe
    out.append(Snip("intent.safe_explicit", [
        f"    private void openDetails(String id) {{",
        f"        Intent i = new Intent(this, {rng.choice(NOUNS)}DetailActivity.class);",
        '        i.putExtra("id", id);',
        "        startActivity(i);",
        "    }"], ["android.content.Intent"]))
    out.append(Snip("intent.safe_local_broadcast", [
        f"    private void publishRefresh() {{",
        f'        Intent i = new Intent("com.{rng.choice(COMPANIES)}.action.REFRESH");',
        "        i.setPackage(getPackageName());",
        "        sendBroadcast(i);",
        "    }"], ["android.content.Intent"]))
    out.append(Snip("intent.safe_validated_redirect", [
        "    private void continueFlow() {",
        f'        String next = getIntent().getStringExtra("{extra}");',
        '        if ("orders".equals(next)) {',
        "            startActivity(new Intent(this, OrdersActivity.class));",
        "        } else {",
        "            startActivity(new Intent(this, HomeActivity.class));",
        "        }",
        "    }"], ["android.content.Intent"]))
    out.append(Snip("intent.safe_immutable_pi", [
        "    private PendingIntent buildOpenAction() {",
        "        Intent open = new Intent(this, InboxActivity.class);",
        "        return PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE);",
        "    }"], ["android.app.PendingIntent", "android.content.Intent"]))
    return out


POOLS = {"insecure_webview": webview_snips, "hardcoded_secret": secret_snips, "weak_crypto": crypto_snips,
         "insecure_network": network_snips, "insecure_storage": storage_snips, "provider_sqli": provider_snips,
         "intent_redirection": intent_snips}


# ---------------------------------------------------------------- assembly
@dataclass
class Sample:
    file: str
    text: str
    findings: list[dict]
    tids: list[str]


def _class_header(rng, base_kind):
    noun = rng.choice(NOUNS)
    if base_kind == "provider":
        return f"{noun}Provider", "extends ContentProvider", ["android.content.ContentProvider"]
    if base_kind == "receiver":
        return f"{noun}Receiver", "extends BroadcastReceiver", ["android.content.BroadcastReceiver"]
    if base_kind == "client":
        return f"{noun}{rng.choice(['Api', 'Client', 'Service', 'Repository'])}", "", []
    if base_kind == "util":
        return f"{noun}{rng.choice(['Crypto', 'Security', 'Util', 'Helper'])}", "", []
    return f"{noun}{rng.choice(SUFFIX_ACT)}", rng.choice(["extends AppCompatActivity", "extends Activity"]), ["androidx.appcompat.app.AppCompatActivity"]


def _kind_for_snip(tid):
    if tid.startswith("provider."):
        return "provider"
    if tid.startswith("intent.receiver"):
        return "receiver"
    if tid.startswith(("net.http", "net.trust", "net.hostname", "net.safe_https", "net.safe_pinning")):
        return "client"
    if tid.startswith(("crypto.", "secret.")):
        return "util"
    return "activity"


def assemble(rng, snips: list[Snip]) -> Sample:
    kind = _kind_for_snip(snips[0].tid) if snips else rng.choice(["activity", "util", "client"])
    cls, ext, imps = _class_header(rng, kind)
    pkg = f"com.{rng.choice(COMPANIES)}.{rng.choice(APPS)}.{rng.choice(MODULES)}"
    imports = set(imps)
    for s in snips:
        imports.update(s.imports)
    body_members: list[tuple[list[str], dict | None]] = []
    fields: list[tuple[str, dict | None]] = []
    if kind == "activity":
        fields.append(("    private RecyclerView.Adapter<?> adapter;", None))
        imports.add("androidx.recyclerview.widget.RecyclerView")
    if kind == "provider":
        fields.append(("    private DbHelper helper;", None))
    if any("TAG" in l for s in snips for l in s.lines):
        fields.append((f'    private static final String TAG = "{cls}";', None))
    if any("userId" in l for s in snips for l in s.lines):
        fields.append(("    private String userId;", None))
    for s in snips:
        for i, f in enumerate(s.fields):
            lab = s.field_label if (s.field_label and s.field_label["rel"] == i) else None
            fields.append((f, lab))
        body_members.append((s.lines, s.label))
    seen_heads = set()
    for _ in range(rng.randint(1, 3)):
        for _try in range(10):
            fl, fi = filler(rng, cls)
            head = fl[0] if not fl[0].strip().startswith("@") else fl[1]
            head = head.split("(")[0].split()[-1] if "(" in head else head
            if head not in seen_heads and not (head == "onResume" and "onResume" in seen_heads):
                break
        if head in seen_heads:
            continue
        seen_heads.add(head)
        imports.update(fi)
        body_members.insert(rng.randint(0, len(body_members)), (fl, None))
    rng.shuffle(fields)

    lines = [f"package {pkg};", ""]
    lines += [f"import {i};" for i in sorted(imports)]
    lines += ["", f"public class {cls} {ext}".rstrip() + " {"]
    findings = []
    for f, lab in fields:
        lines.append(f)
        if lab:
            n = len(lines)
            findings.append(_finding(lab, n, n))
    for member, lab in body_members:
        lines.append("")
        base = len(lines) + 1
        lines.extend(member)
        if lab:
            r0, r1 = lab["rel"]
            findings.append(_finding(lab, base + r0, base + r1))
    lines.append("}")
    path = pkg.replace(".", "/") + f"/{cls}.java"
    for f in findings:
        f["file"] = path
    return Sample(path, "\n".join(lines) + "\n", findings, [s.tid for s in snips])


def _finding(lab, a, b):
    from apkscan.schema import make_finding
    return make_finding(lab["vuln_class"], lab["severity"], "", [a, b], lab["evidence"], lab["why"], lab["fix"], lab.get("cwe"))


# ---------------------------------------------------------------- manifest and network config samples
def manifest_sample(rng) -> tuple[Sample, list[str]]:
    company, app = rng.choice(COMPANIES), rng.choice(APPS)
    pkg = f"com.{company}.{app}"
    target = rng.choice([23, 28, 30, 33, 34, 35])
    cleartext = rng.random() < 0.25
    lines = ['<?xml version="1.0" encoding="utf-8"?>',
             f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{pkg}">',
             f'    <uses-sdk android:minSdkVersion="{rng.choice([21, 23, 24, 26])}" android:targetSdkVersion="{target}"/>',
             '    <uses-permission android:name="android.permission.INTERNET"/>']
    perm_name = f"{pkg}.permission.INTERNAL"
    if rng.random() < 0.5:
        lines.append(f'    <permission android:name="{perm_name}" android:protectionLevel="signature"/>')
    app_line = f'    <application android:name="{pkg}.App" android:label="@string/app_name" android:icon="@mipmap/ic_launcher"'
    if cleartext:
        app_line += ' android:usesCleartextTraffic="true"'
    lines.append(app_line + ">")
    findings, tids = [], []
    if cleartext:
        findings.append(make_finding_safe("insecure_network", "medium", [len(lines), len(lines)],
                                          'android:usesCleartextTraffic="true" on <application>',
                                          "The app allows cleartext HTTP for every host, so traffic can be read and modified on the network.",
                                          'Remove usesCleartextTraffic or set it to "false", and allow cleartext only for specific debug hosts in network_security_config.xml.', "CWE-319"))
        tids.append("manifest.cleartext.v")
    # launcher
    launcher = f"{pkg}.ui.{rng.choice(['Splash', 'Main', 'Launch'])}Activity"
    lines += [f'        <activity android:name="{launcher}" android:exported="true">',
              "            <intent-filter>",
              '                <action android:name="android.intent.action.MAIN"/>',
              '                <category android:name="android.intent.category.LAUNCHER"/>',
              "            </intent-filter>",
              "        </activity>"]
    comps = rng.sample(["activity", "activity", "service", "receiver", "provider", "activity", "service"], k=rng.randint(2, 5))
    for c in comps:
        noun = rng.choice(NOUNS)
        name = {"activity": f"{pkg}.ui.{noun}Activity", "service": f"{pkg}.sync.{noun}SyncService",
                "receiver": f"{pkg}.push.{noun}Receiver", "provider": f"{pkg}.data.{noun}Provider"}[c]
        mode = rng.choices(["exported_open", "exported_perm", "not_exported", "implicit_old"], weights=[4, 2, 3, 1])[0]
        if mode == "implicit_old" and target >= 31:
            mode = "not_exported"
        attrs = f'android:name="{name}"'
        if c == "provider":
            attrs += f' android:authorities="{pkg}.{noun.lower()}s"'
        if mode == "exported_open":
            attrs += ' android:exported="true"'
        elif mode == "exported_perm":
            attrs += f' android:exported="true" android:permission="{perm_name}"'
        elif mode == "not_exported":
            attrs += ' android:exported="false"'
        has_filter = c in ("service", "receiver") and rng.random() < 0.7 or mode == "implicit_old"
        start = len(lines) + 1
        if has_filter:
            lines.append(f"        <{c} {attrs}>")
            lines += ["            <intent-filter>",
                      f'                <action android:name="{pkg}.action.{noun.upper()}_{rng.choice(["SYNC", "OPEN", "UPDATE", "PUSH"])}"/>',
                      "            </intent-filter>",
                      f"        </{c}>"]
        else:
            lines.append(f"        <{c} {attrs}/>")
        end = len(lines)
        if mode in ("exported_open", "implicit_old"):
            sev = "high" if c in ("provider", "service", "receiver") else "medium"
            why = {"activity": f"Any app can start {noun}Activity directly, skipping the screens and checks that normally lead to it.",
                   "service": f"Any app can start or bind {noun}SyncService and trigger its work with crafted intents.",
                   "receiver": f"Any app can send broadcasts to {noun}Receiver and drive its logic with forged extras.",
                   "provider": f"Any app can query or modify {noun.lower()}s through this provider."}[c]
            ev = f'<{c} {name.split(".")[-1]}> exported' + (' via intent-filter on targetSdk ' + str(target) if mode == "implicit_old" else '="true"') + " without android:permission"
            findings.append(make_finding_safe("exported_component", sev, [start, end], ev, why,
                                              'Set android:exported="false" unless other apps need it; otherwise add android:permission with a signature-level permission.'))
            tids.append(f"manifest.exported_{c}.v")
        else:
            tids.append(f"manifest.{mode}_{c}")
    lines += ["    </application>", "</manifest>"]
    s = Sample("AndroidManifest.xml", "\n".join(lines) + "\n", findings, tids)
    for f in s.findings:
        f["file"] = "AndroidManifest.xml"
    return s, tids


def netconfig_sample(rng) -> Sample:
    host = f"api.{rng.choice(COMPANIES)}.com"
    vuln = rng.random() < 0.5
    scope = rng.choice(["base", "domain"])
    lines = ['<?xml version="1.0" encoding="utf-8"?>', "<network-security-config>"]
    findings = []
    if scope == "base":
        lines.append(f'    <base-config android:cleartextTrafficPermitted="{"true" if vuln else "false"}">' if False else
                     f'    <base-config cleartextTrafficPermitted="{"true" if vuln else "false"}">')
        start = len(lines)
        lines += ["        <trust-anchors>", '            <certificates src="system"/>', "        </trust-anchors>", "    </base-config>"]
    else:
        lines.append(f'    <domain-config cleartextTrafficPermitted="{"true" if vuln else "false"}">')
        start = len(lines)
        lines += [f'        <domain includeSubdomains="true">{host}</domain>', "    </domain-config>"]
    if vuln:
        findings.append(make_finding_safe("insecure_network", "medium", [start, start],
                                          f'cleartextTrafficPermitted="true" on {scope}-config',
                                          "Cleartext HTTP is allowed" + (" for every host" if scope == "base" else f" to {host}") + ", so this traffic can be intercepted and modified.",
                                          'Set cleartextTrafficPermitted="false" and serve the endpoints over HTTPS.', "CWE-319"))
    if rng.random() < 0.4:
        lines += [f'    <domain-config>', f'        <domain includeSubdomains="true">{host}</domain>',
                  '        <pin-set expiration="2027-01-01">', f'            <pin digest="SHA-256">{_rand_token(rng, 43)}=</pin>',
                  "        </pin-set>", "    </domain-config>"]
    lines.append("</network-security-config>")
    s = Sample("res/xml/network_security_config.xml", "\n".join(lines) + "\n", findings,
               ["netconfig.cleartext.v" if vuln else f"netconfig.safe_{scope}"])
    for f in s.findings:
        f["file"] = s.file
    return s


def make_finding_safe(vc, sev, lr, ev, why, fix, cwe=None):
    from apkscan.schema import make_finding
    return make_finding(vc, sev, "", lr, ev, why, fix, cwe)


def generate(seed: int, n_java: int, n_manifest: int, n_netconfig: int, clean_ratio: float = 0.4) -> list[Sample]:
    rng = random.Random(seed)
    out: list[Sample] = []
    classes = list(POOLS.keys())
    for i in range(n_java):
        r = rng.random()
        snips = []
        if r < clean_ratio:
            # clean file: 0 to 2 safe look-alike snippets
            for _ in range(rng.randint(0, 2)):
                pool = POOLS[rng.choice(classes)](rng)
                safe = [s for s in pool if not s.label and not s.field_label]
                snips.append(rng.choice(safe))
        else:
            k = 1 if rng.random() < 0.75 else 2
            for c in rng.sample(classes, k):
                pool = POOLS[c](rng)
                vul = [s for s in pool if s.label or s.field_label]
                snips.append(rng.choice(vul))
            if rng.random() < 0.5:
                pool = POOLS[rng.choice(classes)](rng)
                snips.append(rng.choice([s for s in pool if not s.label and not s.field_label]))
        out.append(assemble(rng, snips))
    for _ in range(n_manifest):
        out.append(manifest_sample(rng)[0])
    for _ in range(n_netconfig):
        out.append(netconfig_sample(rng))
    return out
