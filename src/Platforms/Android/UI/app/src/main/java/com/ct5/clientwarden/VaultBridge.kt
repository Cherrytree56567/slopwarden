package com.ct5.clientwarden

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.view.WindowManager
import android.view.autofill.AutofillManager
import android.widget.Toast
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.net.toUri
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.io.File
import java.lang.ref.WeakReference
import java.text.DateFormat
import java.util.Date
import java.util.concurrent.Executors
import kotlin.coroutines.cancellation.CancellationException

class BridgeError(message: String) : Exception(message)

/*
 * A yes/no question shown over whatever screen is up (permanent deletes, logging out)
 */
data class Confirmation(val title: String, val message: String, val action: String, val onConfirm: () -> Unit)

/*
 * Connects the Compose screens to the native core through the shared JSON bridge.
 *
 * Screens expose cb_* callbacks and observable state; this wires every callback to a bridge
 * method, runs the (blocking) native calls off the main thread, and pushes results back into
 * the screens' state. When the vault locks or logs out, every decrypted value held by the UI
 * is dropped.
 */
object VaultBridge {
    private val scope: CoroutineScope = MainScope()

    /*
     * Calls run one at a time on a dedicated thread; syncing and icon downloads (which can
     * take a while on a slow network) get their own so they don't stall the UI's calls.
     */
    private val worker = Executors.newSingleThreadExecutor { Thread(it, "clientwarden-core") }.asCoroutineDispatcher()
    private val slowWorker = Executors.newSingleThreadExecutor { Thread(it, "clientwarden-sync") }.asCoroutineDispatcher()
    private val ready = CompletableDeferred<Unit>()

    private var appContext: Context? = null
    private var activity: WeakReference<FragmentActivity>? = null
    private var initialised = false
    private var wired = false

    private var state = "Unknown"
    private var schema: Map<String, List<Pair<String, Boolean>>> = emptyMap()
    private var itemsGeneration = 0
    private var queryJob: Job? = null
    private var lastActivityNote = 0L
    private var biometricPrompted = false
    private var pendingSendFile: Uri? = null

    var confirmation by mutableStateOf<Confirmation?>(null)

    val unlocked: Boolean
        get() = state == "Unlocked"

    /*
     * Startup
     */

    /*
     * Loads the native library and points the core at its folders. Safe to call more than
     * once and from the autofill service (which can start the process without the activity).
     */
    fun init(context: Context): Boolean {
        if (initialised) {
            return ready.isCompleted && !ready.isCancelled
        }
        initialised = true
        val ctx = context.applicationContext
        appContext = ctx

        try {
            Native.listener = { event -> scope.launch { onEvent(event) } }
        } catch (e: Throwable) {
            ready.completeExceptionally(BridgeError("This build is missing Clientwarden's native library"))
            toast("This build is missing Clientwarden's native library")
            return false
        }

        SecretVault.init(ctx)
        Clipboard.init(ctx)

        scope.launch {
            try {
                withContext(worker) {
                    Files.wipeStaging(ctx)
                    val data = File(ctx.filesDir, "vault").apply { mkdirs() }
                    val resources = File(ctx.filesDir, "resources").apply { mkdirs() }
                    copyAsset(ctx, "clientgen.txt", File(resources, "clientgen.txt"))
                    Native.nativeInit(data.absolutePath, resources.absolutePath)
                }
                ready.complete(Unit)
                refreshState()
            } catch (e: Exception) {
                ready.completeExceptionally(BridgeError("Clientwarden couldn't start"))
                toast("Clientwarden couldn't start")
            }
        }
        return true
    }

    fun attach(activity: FragmentActivity) {
        this.activity = WeakReference(activity)
        init(activity)
        wire()
        applySecureFlag()
    }

    fun onForeground(activity: FragmentActivity) {
        this.activity = WeakReference(activity)
        SettingsScreen.autofillEnabled.value = autofillEnabled()
        if (ready.isCompleted) {
            launch { refreshState() }
        }
    }

    /*
     * "Immediately" means locking as soon as the app leaves the screen
     */
    fun onBackground() {
        if (!unlocked || Files.picking || Biometrics.prompting || LocalNetwork.prompting || SettingsScreen.autoLockSeconds.value > 5) {
            return
        }
        launch {
            call(if (SettingsScreen.timeoutAction.value == "logout") "auth.logout" else "auth.lock")
        }
    }

    fun noteActivity() {
        val now = System.currentTimeMillis()
        if (!unlocked || now - lastActivityNote < 10_000) {
            return
        }
        lastActivityNote = now
        scope.launch {
            try {
                call("activity.note")
            } catch (e: BridgeError) {
                // locked in the meantime
            }
        }
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
     * Runs UI work that calls the core, turning failures into a toast
     */
    fun launch(onDone: () -> Unit = {}, block: suspend CoroutineScope.() -> Unit): Job {
        return scope.launch {
            try {
                block()
            } catch (e: CancellationException) {
                throw e
            } catch (e: BridgeError) {
                toast(e.message ?: "Something went wrong")
            } catch (e: JSONException) {
                toast("Unexpected response from the vault")
            } finally {
                onDone()
            }
        }
    }

    fun toast(message: String) {
        val ctx = appContext ?: return
        scope.launch {
            Toast.makeText(ctx, message, Toast.LENGTH_SHORT).show()
        }
    }

    private fun confirm(title: String, message: String, action: String, onConfirm: () -> Unit) {
        confirmation = Confirmation(title, message, action, onConfirm)
    }

    @Composable
    fun ConfirmHost() {
        val l_confirmation = confirmation ?: return
        AlertDialog(
            onDismissRequest = { confirmation = null },
            title = { Text(l_confirmation.title) },
            text = { Text(l_confirmation.message) },
            confirmButton = {
                TextButton(onClick = {
                    confirmation = null
                    l_confirmation.onConfirm()
                }) { Text(l_confirmation.action) }
            },
            dismissButton = {
                TextButton(onClick = { confirmation = null }) { Text("Cancel") }
            }
        )
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
        applyState(result.optString("state"), result.optString("failure"))
    }

    private fun applyState(newState: String, failure: String) {
        val previous = state
        state = newState
        when (newState) {
            "LoggedOut" -> {
                clearVaultUi()
                LoginScreen.s_type.value = LoginScreenType.Generic
                MainActivityObject.c_view.value = MainViews.LoginUI
            }
            "WaitingForTotp" -> {
                LoginScreen.s_type.value = LoginScreenType.TOTP
                MainActivityObject.c_view.value = MainViews.LoginUI
            }
            "WaitingForDeviceVerification" -> {
                LoginScreen.s_type.value = LoginScreenType.DeviceVerify
                MainActivityObject.c_view.value = MainViews.LoginUI
            }
            "WaitingForPasskey" -> {
                LoginScreen.s_type.value = LoginScreenType.Passkey
                MainActivityObject.c_view.value = MainViews.LoginUI
            }
            "Unlockable" -> {
                clearVaultUi()
                MainActivityObject.c_view.value = MainViews.UnlockUI
                if (previous != "Unlockable") {
                    biometricPrompted = false
                    prepareUnlock()
                }
            }
            "Unlocked" -> {
                LoginScreen.email.value = ""
                if (MainActivityObject.c_view.value != MainViews.VaultUI || previous != "Unlocked") {
                    MainActivityObject.c_view.value = MainViews.VaultUI
                    loadVault()
                }
            }
            "Failed" -> {
                clearVaultUi()
                if (failure.isNotEmpty()) {
                    toast(failure)
                } else if (previous != "Failed") {
                    launch { refreshState() }
                }
                LoginScreen.s_type.value = LoginScreenType.Generic
                MainActivityObject.c_view.value = MainViews.LoginUI
            }
        }
    }

    /*
     * Drops everything decrypted the UI was holding
     */
    private fun clearVaultUi() {
        itemsGeneration++
        DetailsScreen.clear()
        ItemsScreen.SetItems(emptyList())
        ItemsScreen.rp_item = null
        NavScreen.folders.clear()
        NavScreen.organizations.clear()
        NavScreen.c_item = NavItem.AllItems
        TopBar.query = ""
        SendScreen.sends.clear()
        SendScreen.editing = null
        SendScreen.received = null
        SendScreen.receiving = false
        SendScreen.newPassword = ""
        pendingSendFile = null
        HomeScreen.c_panel.value = HomeScreenPanel.NavPanelLoading
        confirmation = null
        Clipboard.clearIfOurs()
    }

    private fun prepareUnlock() {
        launch {
            val enabled = call("auth.biometrics") as? Boolean ?: false
            val l_activity = activity?.get()
            UnlockScreen.biometrics.value = enabled && l_activity != null && Biometrics.available(l_activity)
            UnlockScreen.email.value = try {
                (call("vault.profile") as? JSONObject)?.optString("email") ?: ""
            } catch (e: BridgeError) {
                ""
            }
            if (UnlockScreen.biometrics.value && !biometricPrompted) {
                biometricPrompted = true
                unlockWithBiometrics()
            }
        }
    }

    private fun loadVault() {
        launch(onDone = {
            if (unlocked && HomeScreen.c_panel.value == HomeScreenPanel.NavPanelLoading) {
                HomeScreen.c_panel.value = HomeScreenPanel.NavPanel
            }
        }) {
            loadSettings()
            loadProfile()
            if (schema.isEmpty()) {
                loadSchema()
            }
            reloadNav()
            reloadItems()
            syncInBackground(quiet = true)
        }
    }

    private fun syncInBackground(quiet: Boolean) {
        launch {
            val synced = call("vault.sync", slow = true) as? Boolean ?: false
            if (!unlocked) {
                return@launch
            }
            if (!synced && !quiet) {
                toast("Couldn't sync; showing what's on this device")
            } else if (!quiet) {
                toast("Vault synced")
            }
            reloadNav()
            reloadItems()
            if (HomeScreen.c_panel.value == HomeScreenPanel.DetailsScreen && !DetailsScreen.editable &&
                DetailsScreen.id.isNotEmpty()) {
                openItemById(DetailsScreen.id)
            }
            reloadSends()
        }
    }

    private suspend fun loadSettings() {
        val s = call("settings.get") as? JSONObject ?: return
        SettingsScreen.autoLockSeconds.value = s.optInt("autoLockSeconds", 300)
        SettingsScreen.clipboardSeconds.value = s.optInt("clipboardClearSeconds", 30)
        SettingsScreen.allowScreenshots.value = s.optBoolean("allowScreenshots", false)
        SettingsScreen.timeoutAction.value = s.optString("timeoutAction", "lock")
        SettingsScreen.biometrics.value = s.optBoolean("biometrics", false)
        Clipboard.clearSeconds = SettingsScreen.clipboardSeconds.value
        applySecureFlag()
    }

    private suspend fun loadProfile() {
        val p = call("vault.profile") as? JSONObject ?: return
        SettingsScreen.email.value = p.optString("email")
        TopBar.extendedTypes = p.optBoolean("extendedItemTypes", false)
    }

    private suspend fun loadSchema() {
        val types = call("schema.types") as? JSONArray ?: return
        val out = mutableMapOf<String, List<Pair<String, Boolean>>>()
        for (i in 0 until types.length()) {
            val type = types.getJSONObject(i)
            val fields = type.getJSONArray("fields")
            out[type.getString("type")] = (0 until fields.length()).map {
                val field = fields.getJSONObject(it)
                field.getString("key") to field.optBoolean("secret")
            }
        }
        schema = out
    }

    private fun applySecureFlag() {
        val window = activity?.get()?.window ?: return
        if (SettingsScreen.allowScreenshots.value) {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
            activity?.get()?.setRecentsScreenshotEnabled(true)
        } else {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
            activity?.get()?.setRecentsScreenshotEnabled(false)
        }
    }

    /*
     * Wiring
     */

    private fun wire() {
        if (wired) {
            return
        }
        wired = true

        /*
         * Login and unlock
         */
        LoginScreen.cb_login = { email, password, vaultURL, _, apiURL, iconURL, wssURL ->
            if (email.isBlank() || password.isEmpty()) {
                toast("Enter your email and master password")
            } else {
                LoginScreen.busy.value = true
                launch(onDone = { LoginScreen.busy.value = false }) {
                    val ctx = appContext ?: return@launch
                    if (!LocalNetwork.ensure(ctx, vaultURL) || !LocalNetwork.ensure(ctx, apiURL)) {
                        toast("Clientwarden needs the local network permission to reach this server")
                        return@launch
                    }
                    call("auth.setServer", json("vault" to vaultURL.trim(), "api" to apiURL.trim(),
                        "icons" to iconURL.trim(), "notifications" to wssURL.trim()))
                    val result = call("auth.login", json("email" to email.trim(), "password" to password)) as JSONObject
                    handleLoginResult(result.optString("result"))
                }
            }
        }
        LoginScreen.cb_loginCode = { code ->
            LoginScreen.busy.value = true
            launch(onDone = { LoginScreen.busy.value = false }) {
                val result = call("auth.submitCode", json("code" to code.trim())) as JSONObject
                handleLoginResult(result.optString("result"))
            }
        }
        LoginScreen.cb_cancel = {
            launch { call("auth.logout") }
        }

        UnlockScreen.cb_unlock = { password ->
            UnlockScreen.busy.value = true
            launch(onDone = { UnlockScreen.busy.value = false }) {
                val result = (call("auth.unlock", json("password" to password)) as JSONObject).optString("result")
                when (result) {
                    "Success" -> refreshState()
                    "InvalidPassword" -> toast("Incorrect master password")
                    else -> toast("Couldn't unlock the vault")
                }
            }
        }
        UnlockScreen.cb_biometric = { unlockWithBiometrics() }
        UnlockScreen.cb_logout = {
            confirm("Log Out", "You'll need your master password to log in again.", "Log Out") {
                launch { call("auth.logout") }
            }
        }

        /*
         * Home: navigation, items and details
         */
        NavScreen.cb_open = { item ->
            NavScreen.c_item = item
            HomeScreen.c_panel.value = HomeScreenPanel.ItemsPanel
            launch { reloadItems() }
        }
        NavScreen.cb_NewFolder = { name ->
            launch {
                call("folders.create", json("name" to name.trim()))
                reloadNav()
            }
        }
        NavScreen.cb_RenameFolder = { id, name ->
            launch {
                call("folders.rename", json("id" to id, "name" to name.trim()))
                reloadNav()
            }
        }
        NavScreen.cb_DeleteFolder = { id ->
            launch {
                call("folders.delete", json("id" to id))
                if (NavScreen.c_item == NavItem.Folder(id)) {
                    NavScreen.c_item = NavItem.AllItems
                }
                reloadNav()
                reloadItems()
            }
        }
        NavScreen.cb_NewCollection = { organization, name ->
            launch {
                call("collections.create", json("organizationId" to organization, "name" to name.trim()))
                    ?: throw BridgeError("Couldn't create the collection")
                reloadNav()
            }
        }
        NavScreen.cb_RenameCollection = { id, name ->
            launch {
                check(call("collections.rename", json("id" to id, "name" to name.trim())), "rename the collection")
                reloadNav()
            }
        }
        NavScreen.cb_DeleteCollection = { id ->
            launch {
                check(call("collections.delete", json("id" to id)), "delete the collection")
                reloadNav()
                reloadItems()
            }
        }

        HomeScreen.cb_back = {
            if (HomeScreen.c_panel.value == HomeScreenPanel.DetailsScreen) {
                if (DetailsScreen.editable) {
                    cancelEdit()
                } else {
                    HomeScreen.c_panel.value = HomeScreenPanel.ItemsPanel
                    DetailsScreen.clear()
                }
            } else if (HomeScreen.c_panel.value == HomeScreenPanel.ItemsPanel) {
                HomeScreen.c_panel.value = HomeScreenPanel.NavPanel
            }
        }

        TopBar.cb_query = { query ->
            queryJob?.cancel()
            queryJob = launch {
                delay(250)
                if (HomeScreen.c_panel.value == HomeScreenPanel.NavPanel && query.isNotBlank()) {
                    NavScreen.c_item = NavItem.AllItems
                    HomeScreen.c_panel.value = HomeScreenPanel.ItemsPanel
                }
                reloadItems()
            }
        }
        TopBar.cb_new = { type -> newItem(type) }
        TopBar.cb_save = { saveItem() }
        TopBar.cb_cancel = { cancelEdit() }
        TopBar.cb_bin = { id -> itemAction(id, "items.bin", "move the item to the trash") }
        TopBar.cb_restore = { id -> itemAction(id, "items.restore", "restore the item") }
        TopBar.cb_archive = { id -> itemAction(id, "items.archive", "archive the item") }
        TopBar.cb_unarchive = { id -> itemAction(id, "items.unarchive", "unarchive the item") }
        TopBar.cb_delete = { id ->
            confirm("Delete Permanently", "This item will be deleted forever.", "Delete") {
                itemAction(id, "items.delete", "delete the item")
            }
        }

        ItemsScreen.cb_view = { item ->
            if (item.reprompt) {
                ItemsScreen.rp_failure = ""
                ItemsScreen.rp_item = item.id
            } else {
                launch { openItemById(item.id) }
            }
        }
        ItemsScreen.cb_repromptView = { id, password ->
            launch {
                if (call("auth.verifyPassword", json("password" to password)) == true) {
                    ItemsScreen.rp_item = null
                    ItemsScreen.rp_failure = ""
                    openItemById(id)
                } else {
                    ItemsScreen.rp_failure = "Incorrect master password"
                }
            }
        }

        DetailsScreen.cb_favorite = { favorite ->
            val id = DetailsScreen.id
            if (id.isNotEmpty()) {
                launch {
                    call("items.save", json("id" to id, "favorite" to favorite))
                    reloadItems()
                }
            }
        }
        DetailsScreen.cb_folder = { folder ->
            val id = DetailsScreen.id
            if (id.isNotEmpty()) {
                launch {
                    call("items.save", json("id" to id, "folderId" to folder))
                    reloadItems()
                }
            }
        }
        DetailsScreen.cb_share = { organization, collections ->
            val id = DetailsScreen.id
            launch {
                check(call("items.share", json("id" to id, "organizationId" to organization,
                    "collectionIds" to collections)), "move the item to the organisation")
                openItemById(id)
                reloadItems()
            }
        }
        DetailsScreen.cb_setCollections = { collections ->
            val id = DetailsScreen.id
            launch {
                check(call("items.setCollections", json("id" to id, "collectionIds" to collections)),
                    "change the item's collections")
                openItemById(id)
                reloadItems()
            }
        }
        DetailsScreen.cb_duplicate = {
            val id = DetailsScreen.id
            launch {
                val result = call("items.duplicate", json("id" to id))
                if (result == false) {
                    throw BridgeError("Couldn't duplicate the item")
                }
                toast("Duplicated")
                reloadItems()
            }
        }
        DetailsScreen.cb_addAttachment = { addAttachment() }
        DetailsScreen.cb_downloadAttachment = { attachment -> downloadAttachment(attachment) }
        DetailsScreen.cb_removeAttachment = { attachment ->
            val id = DetailsScreen.id
            confirm("Delete Attachment", "The file will be removed from this item.", "Delete") {
                launch {
                    check(call("attachments.remove", json("id" to id, "attachmentId" to attachment)),
                        "delete the attachment")
                    openItemById(id, edit = DetailsScreen.editable)
                }
            }
        }

        GenericItem.cb_copy = { value, sensitive ->
            Clipboard.copy(value, sensitive)
            /*
             * Android 13+ shows its own confirmation
             */
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                toast("Copied")
            }
        }
        GenericItem.cb_generate = {
            try {
                call("generator.password", json("length" to 20, "uppercase" to true, "numbers" to true,
                    "symbols" to true)) as? String
            } catch (e: BridgeError) {
                toast(e.message ?: "Couldn't generate a password")
                null
            }
        }

        /*
         * Send
         */
        SendScreen.cb_reload = { launch { reloadSends() } }
        SendScreen.cb_save = { send, password -> saveSend(send, password) }
        SendScreen.cb_delete = { id ->
            launch {
                check(call("sends.delete", json("id" to id)), "delete the Send")
                SendScreen.editing = null
                reloadSends()
            }
        }
        SendScreen.cb_removePassword = { id ->
            launch {
                check(call("sends.removePassword", json("id" to id)), "remove the password")
                reloadSends()
                SendScreen.editing = SendScreen.editing?.copy(hasPassword = false)
            }
        }
        SendScreen.cb_pickFile = {
            Files.pick { uri ->
                val ctx = appContext ?: return@pick
                pendingSendFile = uri
                SendScreen.pendingFileName = Files.displayName(ctx, uri)
                SendScreen.editing?.let {
                    if (it.name.isEmpty()) {
                        SendScreen.editing = it.copy(name = SendScreen.pendingFileName)
                    }
                }
            }
        }
        SendScreen.cb_open = { link, password -> openSend(link, password) }
        SendScreen.cb_downloadReceived = { downloadReceivedSend() }

        /*
         * Settings
         */
        SettingsScreen.cb_set = { key, value ->
            launch {
                call("settings.set", json(key to value))
                loadSettings()
            }
        }
        SettingsScreen.cb_biometrics = { enabled -> setBiometrics(enabled) }
        SettingsScreen.cb_lock = { launch { call("auth.lock") } }
        SettingsScreen.cb_logout = {
            confirm("Log Out", "You'll need your master password to log in again.", "Log Out") {
                launch { call("auth.logout") }
            }
        }
        SettingsScreen.cb_sync = { syncInBackground(quiet = false) }
        SettingsScreen.cb_autofill = { toggleAutofill() }
        SettingsScreen.cb_generate = { kind, options ->
            try {
                call("generator.$kind", JSONObject(options)) as? String
            } catch (e: BridgeError) {
                toast(e.message ?: "Couldn't generate")
                null
            }
        }
    }

    private fun check(result: Any?, what: String) {
        if (result == false || result == null) {
            throw BridgeError("Couldn't $what")
        }
    }

    private suspend fun handleLoginResult(result: String) {
        when (result) {
            "Success" -> {
                LoginScreen.email.value = ""
                refreshState()
            }
            "NeedsTotp" -> LoginScreen.s_type.value = LoginScreenType.TOTP
            "NeedsDeviceVerification" -> {
                LoginScreen.s_type.value = LoginScreenType.DeviceVerify
                toast("Check your email for a verification code")
            }
            "NeedsPasskey" -> LoginScreen.s_type.value = LoginScreenType.Passkey
            "InvalidCredentials" -> toast(if (LoginScreen.s_type.value == LoginScreenType.Generic)
                "Incorrect email or master password" else "Incorrect code")
            "Offline" -> toast("Can't reach the server")
            else -> toast("Login failed")
        }
    }

    private fun unlockWithBiometrics() {
        val l_activity = activity?.get() ?: return
        Biometrics.authenticate(l_activity, "Unlock Clientwarden", "Use your fingerprint, face or screen lock",
            onSuccess = {
                UnlockScreen.busy.value = true
                launch(onDone = { UnlockScreen.busy.value = false }) {
                    val result = (call("auth.unlockBiometric") as JSONObject).optString("result")
                    if (result == "Success") {
                        refreshState()
                    } else {
                        toast("Biometric unlock didn't work; use your master password")
                    }
                }
            },
            onFailure = { message -> message?.let { toast(it) } })
    }

    private fun setBiometrics(enabled: Boolean) {
        if (!enabled) {
            launch {
                SettingsScreen.biometrics.value = call("auth.biometrics", json("enabled" to false)) as? Boolean ?: false
            }
            return
        }
        val l_activity = activity?.get() ?: return
        if (!Biometrics.available(l_activity)) {
            toast("Set up a fingerprint, face or screen lock first")
            return
        }
        /*
         * Storing the biometric key needs the Keystore key, which needs a fresh prompt
         */
        SecretVault.prepareAuthKey()
        Biometrics.authenticate(l_activity, "Enable biometric unlock", "Confirm it's you",
            onSuccess = {
                launch {
                    SettingsScreen.biometrics.value = call("auth.biometrics", json("enabled" to true)) as? Boolean ?: false
                }
            },
            onFailure = { message -> message?.let { toast(it) } })
    }

    /*
     * Folders, organisations and item lists
     */

    private suspend fun reloadNav() {
        val folders = call("folders.list") as? JSONArray ?: JSONArray()
        NavScreen.folders.clear()
        for (i in 0 until folders.length()) {
            val folder = folders.getJSONObject(i)
            NavScreen.folders.add(ClientwardenFolder(folder.getString("id"), folder.optString("name")))
        }

        val organizations = call("organizations.list") as? JSONArray ?: JSONArray()
        NavScreen.organizations.clear()
        for (i in 0 until organizations.length()) {
            val org = organizations.getJSONObject(i)
            val collections = org.optJSONArray("collections") ?: JSONArray()
            NavScreen.organizations.add(VaultOrganization(
                id = org.getString("id"),
                name = org.optString("name"),
                role = org.optInt("role"),
                enabled = org.optBoolean("enabled", true),
                canManageCollections = org.optBoolean("canManageCollections"),
                keyAvailable = org.optBoolean("keyAvailable", true),
                collections = (0 until collections.length()).map {
                    val c = collections.getJSONObject(it)
                    VaultCollection(c.getString("id"), org.getString("id"), c.optString("name"),
                        c.optBoolean("readOnly"), c.optBoolean("hidePasswords"), c.optBoolean("manage"))
                }
            ))
        }
    }

    private fun filterFor(item: NavItem): Pair<String, String> {
        return when (item) {
            NavItem.Favorites -> "favorites" to ""
            NavItem.Trash -> "trash" to ""
            NavItem.Archived -> "archived" to ""
            NavItem.Login -> "type" to ItemType.Login.key
            NavItem.Card -> "type" to ItemType.Card.key
            NavItem.Identity -> "type" to ItemType.Identity.key
            NavItem.Note -> "type" to ItemType.Note.key
            NavItem.SshKey -> "type" to ItemType.SSHKey.key
            NavItem.BankAccount -> "type" to ItemType.BankAccount.key
            NavItem.DriversLicense -> "type" to ItemType.DriversLicense.key
            NavItem.Passport -> "type" to ItemType.Passport.key
            is NavItem.Folder -> "folder" to item.id
            NavItem.Personal -> "personal" to ""
            is NavItem.Organization -> "organization" to item.id
            is NavItem.Collection -> "collection" to item.id
            else -> "all" to ""
        }
    }

    private fun parseItems(list: JSONArray): List<ItemElement> {
        return (0 until list.length()).map {
            val o = list.getJSONObject(it)
            val type = ItemType.fromKey(o.optString("type"))
            ItemElement(
                id = o.getString("id"),
                name = o.optString("name"),
                type = type,
                icon = type.icon,
                subtitle = o.optString("subtitle"),
                iconPath = if (o.isNull("icon")) null else o.optString("icon"),
                reprompt = o.optBoolean("reprompt"),
                favorite = o.optBoolean("favorite"),
                organizationId = if (o.isNull("organizationId")) null else o.optString("organizationId")
            )
        }
    }

    /*
     * Lists the current nav entry's items: first without icons (instant), then again with
     * the website icons, which may need downloading.
     */
    suspend fun reloadItems() {
        if (!unlocked) {
            return
        }
        val generation = ++itemsGeneration
        val (filter, value) = filterFor(NavScreen.c_item)
        val args = json("filter" to filter, "value" to value, "search" to TopBar.query.trim(), "icons" to false)

        ItemsScreen.loading = true
        try {
            val items = parseItems(call("items.list", args) as? JSONArray ?: JSONArray())
            if (generation != itemsGeneration) {
                return
            }
            ItemsScreen.SetItems(items)
        } finally {
            if (generation == itemsGeneration) {
                ItemsScreen.loading = false
            }
        }

        if (itemsHaveLogins()) {
            args.put("icons", true)
            val withIcons = try {
                parseItems(call("items.list", args, slow = true) as? JSONArray ?: return)
            } catch (e: BridgeError) {
                return
            }
            if (generation == itemsGeneration) {
                ItemsScreen.SetItems(withIcons)
            }
        }
    }

    private fun itemsHaveLogins(): Boolean = ItemsScreen.f_items.any { it.type == ItemType.Login }

    private fun itemAction(id: String, method: String, what: String) {
        launch {
            check(call(method, json("id" to id)), what)
            if (DetailsScreen.id == id && HomeScreen.c_panel.value == HomeScreenPanel.DetailsScreen) {
                HomeScreen.c_panel.value = HomeScreenPanel.ItemsPanel
                DetailsScreen.clear()
            }
            reloadItems()
        }
    }

    /*
     * Item details
     */

    private val c_labels = mapOf(
        "ssn" to "Social Security Number", "pin" to "PIN", "iban" to "IBAN", "swiftCode" to "SWIFT Code",
        "code" to "Security Code", "expMonth" to "Expiration Month", "expYear" to "Expiration Year",
        "keyFingerprint" to "Fingerprint", "address1" to "Address 1", "address2" to "Address 2",
        "address3" to "Address 3", "postalCode" to "Postcode", "dateOfBirth" to "Date of Birth",
        "nationalIdentificationNumber" to "National ID Number"
    )

    private fun labelFor(key: String): String {
        c_labels[key]?.let { return it }
        val words = key.replace(Regex("([a-z0-9])([A-Z])"), "$1 $2")
        return words.replaceFirstChar { it.uppercase() }
    }

    private fun fieldFor(key: String, secret: Boolean, value: String): GenericItemData {
        val type = when {
            key == "privateKey" -> GenericItemType.ML_Password
            key == "publicKey" -> GenericItemType.ML_Generic
            secret -> GenericItemType.Password
            else -> GenericItemType.Generic
        }
        return GenericItemData(labelFor(key), value, type).apply { this.key = key }
    }

    private fun formatDate(seconds: Long): String {
        return DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(seconds * 1000))
    }

    private fun totpFor(id: String): suspend () -> TOTPResult? = {
        try {
            (call("items.totp", json("id" to id)) as? JSONObject)?.let {
                TOTPResult(it.getLong("validUntil"), it.optInt("period", 30), it.getString("code"))
            }
        } catch (e: BridgeError) {
            null
        }
    }

    private fun loginExtras(uris: List<String>, totp: String?, id: String): List<GenericItemData> {
        val out = mutableListOf(
            GenericItemData("Websites", uris.joinToString("\n"), GenericItemType.Website).apply { key = "uris" }
        )
        if (totp != null) {
            out.add(GenericItemData("Authenticator Key (TOTP)", totp, GenericItemType.TOTP,
                if (id.isEmpty()) null else totpFor(id)).apply {
                key = "totp"
            })
        }
        return out
    }

    suspend fun openItemById(id: String, edit: Boolean = false) {
        val item = call("items.get", json("id" to id)) as? JSONObject ?: throw BridgeError("Item not found")
        showItem(item, edit)
        HomeScreen.c_panel.value = HomeScreenPanel.DetailsScreen
    }

    private fun showItem(o: JSONObject, edit: Boolean) {
        val d = DetailsScreen
        d.clear()
        d.id = o.getString("id")
        d.type = ItemType.fromKey(o.optString("type"))
        d.name = o.optString("name")
        d.icon = ItemsScreen.f_items.firstOrNull { it.id == d.id }?.iconPath
            ?.let { ClientwardenImage.Uri("file://$it") } ?: ClientwardenImage.ImageIcon(d.type.icon)
        d.folderId = if (o.isNull("folderId")) "" else o.optString("folderId")
        d.favorite = o.optBoolean("favorite")
        d.reprompt = o.optBoolean("reprompt")
        d.canEdit = o.optBoolean("canEdit", true)
        d.deleted = o.optLong("deleted") > 0
        d.archived = o.optLong("archived") > 0
        d.organizationId = if (o.isNull("organizationId")) null else o.optString("organizationId")
        o.optJSONArray("collectionIds")?.let { ids -> (0 until ids.length()).forEach { d.collectionIds.add(ids.getString(it)) } }
        d.notesData = GenericItemData("Notes", o.optString("notes"), GenericItemType.ML_Generic).apply { key = "notes" }

        val fields = o.optJSONArray("fields") ?: JSONArray()
        for (i in 0 until fields.length()) {
            val field = fields.getJSONObject(i)
            val key = field.getString("key")
            if (field.isNull("value")) {
                /*
                 * The organisation hides this from the user; show that it exists, never save it
                 */
                d.genericItems.add(GenericItemData(labelFor(key), "Hidden by your organisation",
                    GenericItemType.Generic).apply { copyable = false })
            } else {
                d.genericItems.add(fieldFor(key, field.optBoolean("secret"), field.getString("value")))
            }
        }

        if (d.type == ItemType.Login) {
            val login = o.optJSONObject("login") ?: JSONObject()
            val uris = login.optJSONArray("uris") ?: JSONArray()
            val totp = if (login.isNull("totp")) null else login.optString("totp")
            d.genericItems.addAll(loginExtras((0 until uris.length()).map { uris.getString(it) }, totp, d.id))

            val history = login.optJSONArray("passwordHistory") ?: JSONArray()
            for (i in 0 until history.length()) {
                val entry = history.getJSONObject(i)
                d.passwordHistory.add(PasswordHistoryItem(formatDate(entry.optLong("date")), entry.optString("password")))
            }
            val passkeys = login.optJSONArray("passkeys") ?: JSONArray()
            for (i in 0 until passkeys.length()) {
                d.itemHistory.add("Passkey created ${formatDate(passkeys.optLong(i))}")
            }
        }

        val custom = o.optJSONArray("customFields") ?: JSONArray()
        for (i in 0 until custom.length()) {
            val field = custom.getJSONObject(i)
            val type = FieldItemType.entries.getOrElse(field.optInt("type")) { FieldItemType.Text }
            d.fieldItems.add(FieldItemData(field.optString("name"),
                if (field.isNull("value")) "" else field.optString("value"), type, d.type))
        }

        val attachments = o.optJSONArray("attachments") ?: JSONArray()
        for (i in 0 until attachments.length()) {
            val attachment = attachments.getJSONObject(i)
            d.attachmentItems.add(AttachmentItemData(attachment.getString("id"), attachment.optString("name")))
        }

        o.optLong("created").takeIf { it > 0 }?.let { d.itemHistory.add(0, "Created ${formatDate(it)}") }
        o.optLong("revised").takeIf { it > 0 }?.let { d.itemHistory.add("Updated ${formatDate(it)}") }
        o.optLong("deleted").takeIf { it > 0 }?.let { d.itemHistory.add("Moved to trash ${formatDate(it)}") }
        d.editable = edit && d.canEdit
    }

    private fun newItem(type: ItemType) {
        val d = DetailsScreen
        val nav = NavScreen.c_item
        d.clear()
        d.type = type
        d.icon = ClientwardenImage.ImageIcon(type.icon)

        when (nav) {
            is NavItem.Folder -> d.folderId = nav.id
            NavItem.Favorites -> d.favorite = true
            is NavItem.Organization, is NavItem.Collection -> {
                val orgId = if (nav is NavItem.Organization) nav.id else (nav as NavItem.Collection).organizationId
                val org = NavScreen.organizations.firstOrNull { it.id == orgId }
                val collection = if (nav is NavItem.Collection) nav.id
                    else org?.collections?.firstOrNull { !it.readOnly }?.id
                if (org == null || collection == null) {
                    toast("You can't add items to this organisation")
                    return
                }
                d.organizationId = orgId
                d.collectionIds.add(collection)
            }
            else -> {}
        }

        for ((key, secret) in schema[type.key] ?: emptyList()) {
            if (key != "totp") {
                d.genericItems.add(fieldFor(key, secret, ""))
            }
        }
        if (type == ItemType.Login) {
            d.genericItems.addAll(loginExtras(emptyList(), "", ""))
        }
        d.notesData = GenericItemData("Notes", "", GenericItemType.ML_Generic).apply { key = "notes" }
        d.editable = true
        HomeScreen.c_panel.value = HomeScreenPanel.DetailsScreen
    }

    private fun cancelEdit() {
        val id = DetailsScreen.id
        if (id.isEmpty()) {
            DetailsScreen.clear()
            HomeScreen.c_panel.value = HomeScreenPanel.ItemsPanel
        } else {
            launch { openItemById(id) }
        }
    }

    private fun saveItem() {
        val d = DetailsScreen
        if (d.name.isBlank()) {
            toast("Give the item a name")
            return
        }

        val args = JSONObject()
        if (d.id.isEmpty()) {
            args.put("type", d.type.key)
            d.organizationId?.let {
                args.put("organizationId", it)
                args.put("collectionIds", JSONArray(d.collectionIds.toList()))
            }
        } else {
            args.put("id", d.id)
        }
        args.put("name", d.name.trim())
        args.put("notes", d.notesData.value)
        args.put("folderId", d.folderId)
        args.put("favorite", d.favorite)
        args.put("reprompt", d.reprompt)

        val fields = JSONObject()
        val login = JSONObject()
        for (field in d.genericItems) {
            when (field.key) {
                "" -> {}
                "uris" -> login.put("uris", JSONArray(field.value.lines().map { it.trim() }
                    .filter { it.isNotEmpty() && it != "https://" }))
                "totp" -> login.put("totp", field.value.trim())
                else -> fields.put(field.key, field.value)
            }
        }
        args.put("fields", fields)
        if (d.type == ItemType.Login) {
            args.put("login", login)
        }

        val custom = JSONArray()
        for (field in d.fieldItems) {
            custom.put(json("type" to field.type.ordinal, "name" to field.title, "value" to field.value))
        }
        args.put("customFields", custom)

        launch {
            val result = call("items.save", args) as? JSONObject ?: throw BridgeError("Couldn't save the item")
            if (!result.optBoolean("synced", true)) {
                toast("Saved on this device; it'll sync when you're back online")
            }
            openItemById(result.getString("id"))
            reloadItems()
        }
    }

    private fun addAttachment() {
        val id = DetailsScreen.id
        Files.pick { uri ->
            val ctx = appContext ?: return@pick
            launch {
                Files.withImported(ctx, uri) { file, name ->
                    call("attachments.add", json("id" to id, "path" to file.absolutePath, "name" to name))
                        ?: throw BridgeError("Couldn't upload the attachment")
                }
                openItemById(id)
            }
        }
    }

    private fun downloadAttachment(attachment: String) {
        val id = DetailsScreen.id
        val name = DetailsScreen.attachmentItems.firstOrNull { it.id == attachment }?.name ?: "attachment"
        Files.saveAs(name) { uri ->
            val ctx = appContext ?: return@saveAs
            launch {
                val ok = Files.withExport(ctx, uri) { file ->
                    call("attachments.download", json("id" to id, "attachmentId" to attachment,
                        "path" to file.absolutePath), slow = true) == true
                }
                toast(if (ok) "Saved $name" else "Couldn't download the attachment")
            }
        }
    }

    /*
     * Send
     */

    private fun parseSend(o: JSONObject): SendData {
        return SendData(
            id = o.optString("id"),
            type = o.optString("type", "text"),
            name = o.optString("name"),
            notes = o.optString("notes"),
            text = o.optString("text"),
            textHidden = o.optBoolean("textHidden"),
            fileName = o.optString("fileName"),
            fileSize = o.optString("fileSize"),
            maxAccessCount = if (o.isNull("maxAccessCount")) 0 else o.optInt("maxAccessCount"),
            accessCount = o.optInt("accessCount"),
            expirationDate = o.optLong("expirationDate"),
            deletionDate = o.optLong("deletionDate"),
            disabled = o.optBoolean("disabled"),
            hideEmail = o.optBoolean("hideEmail"),
            hasPassword = o.optBoolean("hasPassword"),
            shareUrl = o.optString("shareUrl")
        )
    }

    private suspend fun reloadSends() {
        if (!unlocked) {
            return
        }
        val sends = call("sends.list") as? JSONArray ?: JSONArray()
        SendScreen.sends.clear()
        for (i in 0 until sends.length()) {
            SendScreen.sends.add(parseSend(sends.getJSONObject(i)))
        }
    }

    private fun saveSend(send: SendData, password: String) {
        if (send.name.isBlank()) {
            toast("Give the Send a name")
            return
        }
        val args = json("type" to send.type, "name" to send.name.trim(), "notes" to send.notes,
            "maxAccessCount" to send.maxAccessCount, "expirationDate" to send.expirationDate,
            "deletionDate" to send.deletionDate, "disabled" to send.disabled, "hideEmail" to send.hideEmail)
        if (send.id.isNotEmpty()) {
            args.put("id", send.id)
        }
        if (send.type == "text") {
            args.put("text", send.text)
            args.put("textHidden", send.textHidden)
        }
        if (password.isNotEmpty()) {
            args.put("password", password)
        }

        launch {
            val result = if (send.type == "file" && send.id.isEmpty()) {
                val uri = pendingSendFile ?: throw BridgeError("Choose a file to send")
                val ctx = appContext ?: return@launch
                Files.withImported(ctx, uri) { file, _ ->
                    args.put("path", file.absolutePath)
                    call("sends.save", args, slow = true)
                }
            } else {
                call("sends.save", args)
            }
            val saved = parseSend(result as? JSONObject ?: throw BridgeError("Couldn't save the Send"))
            pendingSendFile = null
            SendScreen.pendingFileName = ""
            SendScreen.newPassword = ""
            SendScreen.editing = saved
            reloadSends()
            if (send.id.isEmpty() && saved.shareUrl.isNotEmpty()) {
                Clipboard.copy(saved.shareUrl, true)
                toast("Send created; link copied")
            }
        }
    }

    private fun openSend(link: String, password: String) {
        launch {
            val result = call("sends.open", json("link" to link, "password" to password), slow = true) as JSONObject
            SendScreen.receiveMessage = ""
            when (result.optString("result")) {
                "Success" -> {
                    val s = result.getJSONObject("send")
                    SendScreen.received = ReceivedSendData(s.optString("type"), s.optString("name"), s.optString("text"),
                        s.optBoolean("textHidden"), s.optString("fileName"), s.optString("fileSize"),
                        s.optString("creator"))
                }
                "NeedsPassword" -> {
                    SendScreen.receiveNeedsPassword = true
                    SendScreen.receiveMessage = "This Send is password protected."
                }
                "WrongPassword" -> {
                    SendScreen.receiveNeedsPassword = true
                    SendScreen.receiveMessage = "Wrong password."
                }
                "NotAvailable" -> SendScreen.receiveMessage = "This Send has expired, been deleted or reached its view limit."
                "InvalidLink" -> SendScreen.receiveMessage = "That isn't a Send link."
                "Offline" -> SendScreen.receiveMessage = "Can't reach the server."
                else -> SendScreen.receiveMessage = "Couldn't open this Send."
            }
        }
    }

    private fun downloadReceivedSend() {
        val name = SendScreen.received?.fileName?.ifEmpty { null } ?: "send"
        Files.saveAs(name) { uri ->
            val ctx = appContext ?: return@saveAs
            launch {
                val ok = Files.withExport(ctx, uri) { file ->
                    call("sends.downloadReceived", json("path" to file.absolutePath), slow = true) == true
                }
                toast(if (ok) "Saved $name" else "Couldn't download the file")
            }
        }
    }

    /*
     * Autofill
     */

    private fun autofillEnabled(): Boolean {
        val manager = appContext?.getSystemService(AutofillManager::class.java) ?: return false
        return manager.hasEnabledAutofillServices()
    }

    private fun toggleAutofill() {
        val l_activity = activity?.get() ?: return
        val manager = l_activity.getSystemService(AutofillManager::class.java) ?: return
        if (manager.hasEnabledAutofillServices()) {
            manager.disableAutofillServices()
            SettingsScreen.autofillEnabled.value = false
        } else {
            try {
                l_activity.startActivity(Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE)
                    .setData("package:${l_activity.packageName}".toUri()))
            } catch (e: Exception) {
                toast("Choose Clientwarden in Settings › Passwords & autofill")
            }
        }
    }
}
