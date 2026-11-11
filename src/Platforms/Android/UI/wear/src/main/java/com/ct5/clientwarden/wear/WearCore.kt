package com.ct5.clientwarden.wear

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.ct5.clientwarden.Native
import com.ct5.clientwarden.SecretVault
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Executors
import kotlin.coroutines.cancellation.CancellationException

class BridgeError(message: String) : Exception(message)

/*
 * One row in the watch's item list. Deliberately smaller than the phone's ItemElement: a
 * watch list only has room for a name and a subtitle, and icons are skipped entirely
 * (downloading them is the slowest thing the phone UI does).
 */
data class WearItem(
    val id: String,
    val name: String,
    val type: String,
    val subtitle: String,
    val favorite: Boolean,
)

/*
 * The watch's connection to the native core.
 *
 * Same JSON bridge as the phone app (Native.call returns {"ok": true, "result": ...} or
 * {"ok": false, "error": "..."}), but with none of the phone's UI coupling: no
 * FragmentActivity, no autofill service, no biometric prompt, no file pickers. Calls run on
 * a dedicated thread because they block and can hit the network.
 */
object WearCore {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    /*
     * Syncing and anything else that waits on the network gets its own thread so it can't
     * stall the calls the UI is waiting on.
     */
    private val worker = Executors.newSingleThreadExecutor { Thread(it, "clientwarden-core") }.asCoroutineDispatcher()
    private val slowWorker = Executors.newSingleThreadExecutor { Thread(it, "clientwarden-sync") }.asCoroutineDispatcher()
    private val ready = CompletableDeferred<Unit>()

    private var initialised = false

    var state by mutableStateOf("Unknown")
        private set
    var online by mutableStateOf(true)
        private set
    var busy by mutableStateOf(false)
        private set
    var message by mutableStateOf<String?>(null)
        private set

    val unlocked: Boolean
        get() = state == "Unlocked"

    /*
     * Startup
     */

    fun init(context: Context): Boolean {
        if (initialised) {
            return ready.isCompleted && !ready.isCancelled
        }
        initialised = true
        val ctx = context.applicationContext

        try {
            Native.listener = { event -> scope.launch { onEvent(event) } }
        } catch (e: Throwable) {
            ready.completeExceptionally(BridgeError("This build is missing Clientwarden's native library"))
            message = "This build is missing Clientwarden's native library"
            return false
        }

        SecretVault.init(ctx)

        scope.launch {
            try {
                withContext(worker) {
                    val data = File(ctx.filesDir, "vault").apply { mkdirs() }
                    val resources = File(ctx.filesDir, "resources").apply { mkdirs() }
                    copyAsset(ctx, "clientgen.txt", File(resources, "clientgen.txt"))
                    Native.nativeInit(data.absolutePath, resources.absolutePath)
                }
                ready.complete(Unit)
                refreshState()
            } catch (e: Exception) {
                ready.completeExceptionally(BridgeError("Clientwarden couldn't start"))
                message = "Clientwarden couldn't start"
            }
        }
        return true
    }

    private fun copyAsset(context: Context, name: String, target: File) {
        context.assets.open(name).use { input ->
            val bytes = input.readBytes()
            if (target.exists() && target.length() == bytes.size.toLong()) {
                return
            }
            target.writeBytes(bytes)
        }
    }

    /*
     * Calling the core
     */

    /*
     * Runs a bridge method and returns its "result" (JSONObject, JSONArray, String, Boolean,
     * Number or null). Throws BridgeError with the core's message on failure.
     */
    suspend fun call(method: String, args: JSONObject? = null, slow: Boolean = false): Any? {
        ready.await()
        val response = withContext(if (slow) slowWorker else worker) {
            Native.call(method, args?.toString() ?: "{}")
        }
        val parsed = try {
            JSONObject(response)
        } catch (e: JSONException) {
            throw BridgeError("Unexpected response from the vault")
        }
        if (!parsed.optBoolean("ok")) {
            throw BridgeError(parsed.optString("error", "Something went wrong"))
        }
        return if (parsed.isNull("result")) null else parsed.get("result")
    }

    fun json(vararg pairs: Pair<String, Any?>): JSONObject {
        return JSONObject().apply {
            for ((key, value) in pairs) {
                put(key, when (value) {
                    null -> JSONObject.NULL
                    is Collection<*> -> JSONArray(value)
                    else -> value
                })
            }
        }
    }

    /*
     * Runs UI work that calls the core, turning failures into a message on screen
     */
    fun perform(block: suspend CoroutineScope.() -> Unit): Job {
        return scope.launch {
            busy = true
            try {
                block()
            } catch (e: CancellationException) {
                throw e
            } catch (e: BridgeError) {
                message = e.message ?: "Something went wrong"
            } catch (e: JSONException) {
                message = "Unexpected response from the vault"
            } finally {
                busy = false
            }
        }
    }

    fun clearMessage() {
        message = null
    }

    /*
     * Vault state
     */

    private fun onEvent(event: String) {
        val parsed = try {
            JSONObject(event)
        } catch (e: JSONException) {
            return
        }
        if (parsed.optString("event") == "state") {
            applyState(parsed.optString("state"), "")
        }
    }

    suspend fun refreshState() {
        val result = call("state.get") as? JSONObject ?: return
        online = result.optBoolean("online", true)
        applyState(result.optString("state"), result.optString("failure"))
    }

    private fun applyState(newState: String, failure: String) {
        state = newState
        if (failure.isNotEmpty()) {
            message = failure
        }
    }

    /*
     * Signing in
     */

    fun login(email: String, password: String, server: String) = perform {
        val vault = server.trim().ifEmpty { "https://vault.bitwarden.com" }
        call("auth.setServer", json("vault" to vault, "api" to vault))
        val result = call("auth.login", json("email" to email.trim(), "password" to password)) as JSONObject
        handleLoginResult(result.optString("result"))
    }

    fun submitCode(code: String) = perform {
        val result = call("auth.submitCode", json("code" to code.trim())) as JSONObject
        handleLoginResult(result.optString("result"))
    }

    private suspend fun handleLoginResult(result: String) {
        when (result) {
            "Success" -> refreshState()
            "NeedsTotp" -> state = "WaitingForTotp"
            "NeedsDeviceVerification" -> {
                state = "WaitingForDeviceVerification"
                message = "Check your email for a code"
            }
            "NeedsPasskey" -> {
                state = "WaitingForPasskey"
                message = "Passkeys aren't supported on the watch; use the phone app"
            }
            "InvalidCredentials" -> message = "Incorrect email or master password"
            "Offline" -> message = "Can't reach the server"
            else -> message = "Login failed"
        }
    }

    fun unlock(password: String) = perform {
        val result = (call("auth.unlock", json("password" to password)) as JSONObject).optString("result")
        if (result == "Success") {
            refreshState()
        } else {
            message = "Incorrect master password"
        }
    }

    fun lock() = perform {
        call("auth.lock")
        refreshState()
    }

    fun logout() = perform {
        call("auth.logout")
        refreshState()
    }

    fun sync() = perform {
        call("vault.sync", slow = true)
        refreshState()
    }

    /*
     * Items
     */

    suspend fun listItems(search: String): List<WearItem> {
        val args = json("filter" to "", "value" to "", "search" to search.trim(), "icons" to false)
        val list = call("items.list", args) as? JSONArray ?: JSONArray()
        return (0 until list.length()).map {
            val o = list.getJSONObject(it)
            WearItem(
                id = o.getString("id"),
                name = o.optString("name"),
                type = o.optString("type"),
                subtitle = o.optString("subtitle"),
                favorite = o.optBoolean("favorite"),
            )
        }
    }

    suspend fun getItem(id: String): JSONObject {
        return call("items.get", json("id" to id)) as? JSONObject ?: JSONObject()
    }

    suspend fun totp(id: String): String? {
        val result = call("items.totp", json("id" to id)) as? JSONObject ?: return null
        return result.optString("code").ifEmpty { null }
    }

    /*
     * Copies a secret to the clipboard. Wear OS has no clipboard preview to hide, but the
     * value is still marked sensitive so it isn't synced or logged by anything that reads
     * the clip description.
     */
    fun copy(context: Context, label: String, value: String) {
        if (value.isEmpty()) {
            return
        }
        val manager = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager ?: return
        manager.setPrimaryClip(ClipData.newPlainText(label, value))
        message = "Copied"
    }
}
