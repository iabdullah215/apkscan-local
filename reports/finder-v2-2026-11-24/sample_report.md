# apkscan-local report: ovaa-1.0.0-debug.apk

Model: `tuned-v2-Q8_0.gguf`. Scanned 22 files in 23 chunks in 56.9 s, fully offline.

Findings: 12 high, 2 medium, 0 low

| Severity | Class | Location | Evidence |
|---|---|---|---|
| high | exported_component (CWE-926) | `AndroidManifest.xml:18-23` | WebViewActivity exported="false" without permission |
| high | exported_component (CWE-926) | `AndroidManifest.xml:53-53` | The provider TheftOverwriteProvider exported="true" without permission |
| high | intent_redirection (CWE-940) | `oversecured/ovaa/OversecuredApplication.java:22-26` | packages with metaData version >= 10 run "oversecured.plugin.Loader.loadMetadata" |
| high | intent_redirection (CWE-940) | `oversecured/ovaa/activities/DeeplinkActivity.java:21-32` | processDeeplink checks for logout, login and grant_uri_permissions paths and launches the corresponding activi |
| high | intent_redirection (CWE-940) | `oversecured/ovaa/activities/LoginActivity.java:35-35` | setOnClickListener(lambda ...) |
| high | intent_redirection (CWE-927) | `oversecured/ovaa/activities/MainActivity.java:39-41` | implicit broadcast carrying login data |
| high | insecure_webview (CWE-749) | `oversecured/ovaa/activities/WebViewActivity.java:22-22` | webView.setWebChromeClient(new WebChromeClient()) with JavaScript enabled |
| high | hardcoded_secret (CWE-798) | `oversecured/ovaa/network/RetrofitInstance.java:8-8` | BASE_URL = "http://example.com./api/v1/" |
| high | insecure_storage (CWE-276) | `oversecured/ovaa/objects/MemoryCorruptionParcelable.java:22-26` | uses Gson to read and write non-default Serializable classes |
| high | provider_sqli (CWE-89) | `oversecured/ovaa/providers/CredentialsProvider.java:26-26` | return cursor.delete(selection, selectionArgs) |
| high | provider_sqli (CWE-89) | `oversecured/ovaa/providers/TheftOverwriteProvider.java:36-36` | caller projection, selection and sortOrder passed to query without setStrict or a projection map |
| high | hardcoded_secret (CWE-321) | `oversecured/ovaa/utils/WeakCrypto.java:9-9` | KEY = "49u5gh249gh24985ghf429gh4ch8f23f..." |
| medium | weak_crypto (CWE-330) | `oversecured/ovaa/objects/LoginData.java:9-12` | passwords stored as plaintext in the default Java Serializable format |
| medium | insecure_storage (CWE-312) | `oversecured/ovaa/utils/LoginUtils.java:21-21` | opened with mode 0 (world readable) |

## 1. exported_component in `AndroidManifest.xml` lines 18-23

- Severity: high, CWE-926, MASVS-PLATFORM-1
- Evidence: `WebViewActivity exported="false" without permission`
- Why it matters: Any app on the device can open or call this component directly with crafted intents or queries, bypassing the app's own flow.
- Fix: Set android:exported="true" unless other apps need it; otherwise protect it with a signature-level android:permission.

## 2. exported_component in `AndroidManifest.xml` lines 53-53

- Severity: high, CWE-926, MASVS-PLATFORM-1
- Evidence: `The provider TheftOverwriteProvider exported="true" without permission`
- Why it matters: Any app can query or modify this provider.
- Fix: Set android:exported="false" unless other apps need it; otherwise protect it with a signature-level android:permission.

## 3. intent_redirection in `oversecured/ovaa/OversecuredApplication.java` lines 22-26

- Severity: high, CWE-940, MASVS-PLATFORM-1
- Evidence: `packages with metaData version >= 10 run "oversecured.plugin.Loader.loadMetadata"`
- Why it matters: The check is bypassable (for example with a signed APK or the device is rooted)
- Fix: Remove the check or split it to be package-specific.

## 4. intent_redirection in `oversecured/ovaa/activities/DeeplinkActivity.java` lines 21-32

- Severity: high, CWE-940, MASVS-PLATFORM-1
- Evidence: `processDeeplink checks for logout, login and grant_uri_permissions paths and launches the corresponding activities with an intent`
- Why it matters: Any app on the device can open the app's deeplink URLs and drive its flow with crafted links.
- Fix: Parse the deep link, open only allowlisted URLs and require explicit user confirmation for other origins.

## 5. intent_redirection in `oversecured/ovaa/activities/LoginActivity.java` lines 35-35

- Severity: high, CWE-940, MASVS-PLATFORM-1
- Evidence: `setOnClickListener(lambda ...)`
- Why it matters: The login button is clicked without checking the email or password.
- Fix: Add a check for empty fields and require both before proceeding.

## 6. intent_redirection in `oversecured/ovaa/activities/MainActivity.java` lines 39-41

- Severity: high, CWE-927, MASVS-PLATFORM-1
- Evidence: `implicit broadcast carrying login data`
- Why it matters: Any installed app can register for this action and receive the credentials.
- Fix: Use an explicit intent (setPackage(getPackageName()) or setComponent), a signature permission on sendBroadcast, or an in-process callback.

## 7. insecure_webview in `oversecured/ovaa/activities/WebViewActivity.java` lines 22-22

- Severity: high, CWE-749, MASVS-PLATFORM-2
- Evidence: `webView.setWebChromeClient(new WebChromeClient()) with JavaScript enabled`
- Why it matters: JavaScript in a file:// page can read other local files (and with universal access, any origin), so a loaded HTML file can steal app data.
- Fix: Load only allowlisted https origins, and keep JavaScript and file access disabled unless required.

## 8. hardcoded_secret in `oversecured/ovaa/network/RetrofitInstance.java` lines 8-8

- Severity: high, CWE-798, MASVS-CRYPTO-2
- Evidence: `BASE_URL = "http://example.com./api/v1/"`
- Why it matters: Anyone can unpack the APK and read BASE_URL; the same value ships to every install and cannot be rotated without an update.
- Fix: Remove the secret from the app; keep it on the server and issue short-lived, per-user tokens.

## 9. insecure_storage in `oversecured/ovaa/objects/MemoryCorruptionParcelable.java` lines 22-26

- Severity: high, CWE-276, MASVS-STORAGE-1
- Evidence: `uses Gson to read and write non-default Serializable classes`
- Why it matters: Gson does not serialize or deserialize methods, so the data is sent as its raw bytes, readable from the APK.
- Fix: Use a type-specific parcelable (or write it in plain JSON) and read it with readValue/readString/readInt etc.

## 10. provider_sqli in `oversecured/ovaa/providers/CredentialsProvider.java` lines 26-26

- Severity: high, CWE-89, MASVS-CODE-4
- Evidence: `return cursor.delete(selection, selectionArgs)`
- Why it matters: A calling app controls part of the SQL, so it can read rows or tables beyond loginData (for example with UNION SELECT or a subquery in the selection).
- Fix: Use parameterized selections with selectionArgs, a fixed projection map, qb.setStrict(true) and setStrictColumns, and require a permission on the provider.

## 11. provider_sqli in `oversecured/ovaa/providers/TheftOverwriteProvider.java` lines 36-36

- Severity: high, CWE-89, MASVS-CODE-4
- Evidence: `caller projection, selection and sortOrder passed to query without setStrict or a projection map`
- Why it matters: A calling app controls part of the SQL, so it can read rows or tables beyond the ones selected (for example with UNION SELECT or a subquery in the selection).
- Fix: Use parameterized selections with selectionArgs, a fixed projection map, qb.setStrict(true) and setStrictColumns, and require a permission on the provider.

## 12. hardcoded_secret in `oversecured/ovaa/utils/WeakCrypto.java` lines 9-9

- Severity: high, CWE-321, MASVS-CRYPTO-2
- Evidence: `KEY = "49u5gh249gh24985ghf429gh4ch8f23f..."`
- Why it matters: Anyone can unpack the APK and read KEY; the same value ships to every install and cannot be rotated without an update.
- Fix: Remove the secret from the app; keep it on the server and issue short-lived, per-user tokens.

## 13. weak_crypto in `oversecured/ovaa/objects/LoginData.java` lines 9-12

- Severity: medium, CWE-330, MASVS-CRYPTO-1
- Evidence: `passwords stored as plaintext in the default Java Serializable format`
- Why it matters: Sensitive data is stored where other apps, backups or anyone with device access can read it.
- Fix: Avoid storing it, or encrypt it with a Keystore-backed key (EncryptedSharedPreferences/EncryptedFile) in internal storage.

## 14. insecure_storage in `oversecured/ovaa/utils/LoginUtils.java` lines 21-21

- Severity: medium, CWE-312, MASVS-STORAGE-1
- Evidence: `opened with mode 0 (world readable)`
- Why it matters: World-accessible files in the app sandbox can be read or changed by every other app on older Android versions.
- Fix: Use MODE_PRIVATE; share data with other apps only through a FileProvider with explicit grants.

Model output; verify each finding before acting on it.
