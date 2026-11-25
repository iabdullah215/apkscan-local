# apkscan-local report: ovaa-1.0.0-debug.apk

Model: `tuned-verifier-v1-Q8_0.gguf` (verify mode). Scanned 22 files, 43 pattern candidates verified in 51.8 s, fully offline.

Findings: 10 high, 9 medium, 0 low

| Severity | Class | Location | Evidence |
|---|---|---|---|
| high | exported_component (CWE-926) | `AndroidManifest.xml:24-29` | <activity LoginActivity> exported="true" without android:permission |
| high | exported_component (CWE-926) | `AndroidManifest.xml:30-35` | <activity EntranceActivity> exported="true" without android:permission |
| high | exported_component (CWE-926) | `AndroidManifest.xml:36-41` | <activity MainActivity> exported="true" without android:permission |
| high | exported_component (CWE-926) | `AndroidManifest.xml:48-52` | <service oversecured.ovaa.services.InsecureLoggerService> exported="true" without android:permission |
| high | exported_component (CWE-926) | `AndroidManifest.xml:53-53` | The provider exported="true" without permission |
| high | insecure_network (CWE-319) | `oversecured/ovaa/network/RetrofitInstance.java:8-8` | BASE_URL = "http://example.com./api/v1/" |
| high | intent_redirection (CWE-925) | `oversecured/ovaa/receivers/UselessReceiver.java:10-10` | onReceive runs any installed receiver of a given action and executes its code with the app's identity |
| high | hardcoded_secret (CWE-925) | `oversecured/ovaa/services/InsecureLoggerService.java:18-18` | onHandleIntent runs dumpLogs for any sender of the action |
| high | hardcoded_secret (CWE-798) | `oversecured/ovaa/utils/LoginUtils.java:11-13` | PASSWORD_KEY = "password" |
| high | hardcoded_secret (CWE-321) | `oversecured/ovaa/utils/WeakCrypto.java:9-9` | KEY = "49u5gh249gh24985ghf429gh4ch8f23f..." |
| medium | intent_redirection (CWE-940) | `oversecured/ovaa/activities/DeeplinkActivity.java:64-64` | on return from startActivityForResult, the caller chooses whether to accept the result or not |
| medium | insecure_network (CWE-319) | `oversecured/ovaa/activities/MainActivity.java:50-50` | Intent i = new Intent("oversecured.ovaa.action.WEBVIEW") |
| medium | insecure_webview (CWE-749) | `oversecured/ovaa/activities/WebViewActivity.java:18-18` | JavaScript-enabled WebView loads the "url" extra into the WebView's view hierarchy |
| medium | intent_redirection (CWE-939) | `oversecured/ovaa/activities/WebViewActivity.java:18-18` | JavaScript-enabled WebView loads the "url" extra into the WebView's view hierarchy |
| medium | insecure_webview (CWE-749) | `oversecured/ovaa/activities/WebViewActivity.java:24-25` | JavaScript-enabled WebView loads any URL passed to it, including file:// URLs |
| medium | insecure_storage (CWE-922) | `oversecured/ovaa/providers/TheftOverwriteProvider.java:46-46` | opened with mode 805306368 (world writeable) |
| medium | insecure_storage (CWE-922) | `oversecured/ovaa/services/InsecureLoggerService.java:43-43` | writes logcat to get the logs |
| medium | insecure_storage (CWE-922) | `oversecured/ovaa/utils/FileUtils.java:27-29` | opened with context.openInputStream(uri) and then written to the cache dir |
| medium | weak_crypto (CWE-327) | `oversecured/ovaa/utils/WeakCrypto.java:16-17` | Cipher.getInstance("AES") |

## 1. exported_component in `AndroidManifest.xml` lines 24-29

- Severity: high, CWE-926, MASVS-PLATFORM-1
- Evidence: `<activity LoginActivity> exported="true" without android:permission`
- Why it matters: Any app can start LoginActivity directly, skipping the screens and checks that normally lead to it.
- Fix: Set android:exported="false" unless other apps need it; otherwise add android:permission with a signature-level permission.

## 2. exported_component in `AndroidManifest.xml` lines 30-35

- Severity: high, CWE-926, MASVS-PLATFORM-1
- Evidence: `<activity EntranceActivity> exported="true" without android:permission`
- Why it matters: Any app can start EntranceActivity directly, skipping the screens and checks that normally lead to it.
- Fix: Set android:exported="false" unless other apps need it; otherwise add android:permission with a signature-level permission.

## 3. exported_component in `AndroidManifest.xml` lines 36-41

- Severity: high, CWE-926, MASVS-PLATFORM-1
- Evidence: `<activity MainActivity> exported="true" without android:permission`
- Why it matters: Any app can start MainActivity directly, skipping the screens and checks that normally lead to it.
- Fix: Set android:exported="false" unless other apps need it; otherwise add android:permission with a signature-level permission.

## 4. exported_component in `AndroidManifest.xml` lines 48-52

- Severity: high, CWE-926, MASVS-PLATFORM-1
- Evidence: `<service oversecured.ovaa.services.InsecureLoggerService> exported="true" without android:permission`
- Why it matters: Any app can query or modify the exported services and receive the app's identity, so other apps can steal app data.
- Fix: Set android:exported="false" unless other apps need it; otherwise add android:permission with a signature-level permission.

## 5. exported_component in `AndroidManifest.xml` lines 53-53

- Severity: high, CWE-926, MASVS-PLATFORM-1
- Evidence: `The provider exported="true" without permission`
- Why it matters: Any app can query or modify the private data of other apps through content://oversecured.ovaa.theftoverwrite/oversecured.ovaa.theftoverwrite/credentials, bypassing the PIN screen.
- Fix: Set android:exported="false" unless other apps need it; otherwise protect it with a signature-level android:permission.

## 6. insecure_network in `oversecured/ovaa/network/RetrofitInstance.java` lines 8-8

- Severity: high, CWE-319, MASVS-NETWORK-1
- Evidence: `BASE_URL = "http://example.com./api/v1/"`
- Why it matters: Anyone can unpack the APK and read BASE_URL; the same value ships to every install and cannot be rotated without an update.
- Fix: Remove the secret from the app; keep it on the server and issue short-lived, per-user tokens.

## 7. intent_redirection in `oversecured/ovaa/receivers/UselessReceiver.java` lines 10-10

- Severity: high, CWE-925, MASVS-PLATFORM-1
- Evidence: `onReceive runs any installed receiver of a given action and executes its code with the app's identity`
- Why it matters: Any app can send broadcasts to this receiver and drive its logic with forged extras.
- Fix: Do not take the app out of the sandbox; keep it on the device and allow only trusted packages to send broadcasts.

## 8. hardcoded_secret in `oversecured/ovaa/services/InsecureLoggerService.java` lines 18-18

- Severity: high, CWE-925, MASVS-CRYPTO-2
- Evidence: `onHandleIntent runs dumpLogs for any sender of the action`
- Why it matters: The receiver of the broadcast (any app that sends this action) can register for it and drive the sensitive operation with crafted intents.
- Fix: Use an explicit intent (setPackage(getPackageName()) or setComponent), a signature permission on send, or an in-process callback.

## 9. hardcoded_secret in `oversecured/ovaa/utils/LoginUtils.java` lines 11-13

- Severity: high, CWE-798, MASVS-CRYPTO-2
- Evidence: `PASSWORD_KEY = "password"`
- Why it matters: Anyone can read the password by decompiling the APK and extracting it, or the password can be guessed.
- Fix: Remove it from the app; keep secrets server-side or generate keys in the Android Keystore.

## 10. hardcoded_secret in `oversecured/ovaa/utils/WeakCrypto.java` lines 9-9

- Severity: high, CWE-321, MASVS-CRYPTO-2
- Evidence: `KEY = "49u5gh249gh24985ghf429gh4ch8f23f..."`
- Why it matters: Anyone can unpack the APK and read KEY; the same value ships to every install and cannot be rotated without an update.
- Fix: Remove the secret from the app; keep it on the server and issue short-lived, per-user tokens.

## 11. intent_redirection in `oversecured/ovaa/activities/DeeplinkActivity.java` lines 64-64

- Severity: medium, CWE-940, MASVS-PLATFORM-1
- Evidence: `on return from startActivityForResult, the caller chooses whether to accept the result or not`
- Why it matters: The caller controls whether the result is returned to the caller app or not, so it can obtain the URI itself without a deep link.
- Fix: Return the result to the caller app, never echo it, and require explicit user confirmation.

## 12. insecure_network in `oversecured/ovaa/activities/MainActivity.java` lines 50-50

- Severity: medium, CWE-319, MASVS-NETWORK-1
- Evidence: `Intent i = new Intent("oversecured.ovaa.action.WEBVIEW")`
- Why it matters: Whoever receives the broadcast (for example through an IntentFilter) runs arbitrary HTML and JavaScript, so the page can steal the token.
- Fix: Do not launch Intents for non-exported components or send broadcasts to other apps; map intents to inner classes or services only.

## 13. insecure_webview in `oversecured/ovaa/activities/WebViewActivity.java` lines 18-18

- Severity: medium, CWE-749, MASVS-PLATFORM-2
- Evidence: `JavaScript-enabled WebView loads the "url" extra into the WebView's view hierarchy`
- Why it matters: Attacker-controlled content loaded in this WebView can run script with the app's WebView privileges.
- Fix: Do not render HTML from intent extras; keep JavaScript off for untrusted content.

## 14. intent_redirection in `oversecured/ovaa/activities/WebViewActivity.java` lines 18-18

- Severity: medium, CWE-939, MASVS-PLATFORM-1
- Evidence: `JavaScript-enabled WebView loads the "url" extra into the WebView's view hierarchy`
- Why it matters: Attacker-controlled content loaded in this WebView can run script with the app's WebView privileges.
- Fix: Do not render HTML from intent extras; keep JavaScript off for untrusted content.

## 15. insecure_webview in `oversecured/ovaa/activities/WebViewActivity.java` lines 24-25

- Severity: medium, CWE-749, MASVS-PLATFORM-2
- Evidence: `JavaScript-enabled WebView loads any URL passed to it, including file:// URLs`
- Why it matters: JavaScript in a file:// page can read other local files (and with universal access, any origin), so a loaded HTML file can steal app data.
- Fix: Call setAllowFileAccessFromFileURLs(false) and serve local content through WebViewAssetLoader over https://appassets.androidplatform.net.

## 16. insecure_storage in `oversecured/ovaa/providers/TheftOverwriteProvider.java` lines 46-46

- Severity: medium, CWE-922, MASVS-STORAGE-1
- Evidence: `opened with mode 805306368 (world writeable)`
- Why it matters: World-accessible files in the app sandbox can be read or changed by every other app on older Android versions.
- Fix: Use MODE_PRIVATE; share data with other apps only through a FileProvider with explicit grants.

## 17. insecure_storage in `oversecured/ovaa/services/InsecureLoggerService.java` lines 43-43

- Severity: medium, CWE-922, MASVS-STORAGE-1
- Evidence: `writes logcat to get the logs`
- Why it matters: Sensitive data is stored where other apps, backups or anyone with device access can read it.
- Fix: Write sensitive data to getFilesDir() or encrypt it, and share it only through a FileProvider.

## 18. insecure_storage in `oversecured/ovaa/utils/FileUtils.java` lines 27-29

- Severity: medium, CWE-922, MASVS-STORAGE-1
- Evidence: `opened with context.openInputStream(uri) and then written to the cache dir`
- Why it matters: Sensitive data is stored where other apps, backups or anyone with device access can read it.
- Fix: Avoid storing it, or encrypt it with a Keystore-backed key (EncryptedSharedPreferences/EncryptedFile) in internal storage.

## 19. weak_crypto in `oversecured/ovaa/utils/WeakCrypto.java` lines 16-17

- Severity: medium, CWE-327, MASVS-CRYPTO-1
- Evidence: `Cipher.getInstance("AES")`
- Why it matters: This algorithm or mode is broken or deterministic, so encrypted data can be recovered or patterns leak.
- Fix: Use AES/GCM/NoPadding with a random IV and a Keystore key, SecureRandom for random values, and a slow salted KDF for passwords.

Model output; verify each finding before acting on it.
