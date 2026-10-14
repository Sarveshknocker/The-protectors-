// Rule corpus (Android / Kotlin).
class MainActivity : AppCompatActivity() {
    override fun onCreate(state: Bundle?) {
        super.onCreate(state)
        // ruleid: mobile.webview-js-bridge
        webView.addJavascriptInterface(Bridge(), "Android")
        // ok: mobile.webview-js-bridge
        webView.settings.allowFileAccess = false
        // ruleid: mobile.logging-release
        Log.d(TAG, "user signed in")
        // ok: mobile.logging-release
        Timber.i("user signed in")
    }
}
