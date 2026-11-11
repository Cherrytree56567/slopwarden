package com.ct5.clientwarden.wear

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.wear.compose.foundation.lazy.ScalingLazyColumn
import androidx.wear.compose.foundation.lazy.rememberScalingLazyListState
import kotlinx.coroutines.delay
import org.json.JSONObject

/*
 * Signing in, including the two extra steps Bitwarden can ask for (a TOTP code, or an email
 * code for an unrecognised device). Passkey login is reported but not offered: there is no
 * passkey provider on Wear OS.
 */
@Composable
fun LoginScreen() {
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var server by remember { mutableStateOf("https://vault.bitwarden.com") }
    var code by remember { mutableStateOf("") }
    val state = WearCore.state
    val busy = WearCore.busy

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 10.dp, vertical = 18.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Label("Clientwarden", size = 18.sp, weight = FontWeight.SemiBold)

        when (state) {
            "WaitingForTotp", "WaitingForDeviceVerification" -> {
                Label(
                    if (state == "WaitingForTotp") "Two-step code" else "Email code",
                    size = 12.sp,
                    color = Palette.Muted,
                )
                WatchField(code, { code = it }, "123456", keyboardType = KeyboardType.Number)
                WatchButton(
                    label = if (busy) "Checking" else "Continue",
                    enabled = !busy && code.isNotEmpty(),
                ) {
                    WearCore.submitCode(code)
                    code = ""
                }
            }

            "WaitingForPasskey" -> {
                Label("Finish signing in on the phone app.", size = 13.sp, color = Palette.Muted)
                WatchButton("Back", danger = true) { WearCore.logout() }
            }

            else -> {
                WatchField(email, { email = it }, "Email", keyboardType = KeyboardType.Email)
                WatchField(password, { password = it }, "Master password", password = true)
                WatchField(server, { server = it }, "Server", keyboardType = KeyboardType.Uri)
                WatchButton(
                    label = if (busy) "Signing in" else "Sign in",
                    enabled = !busy && email.isNotEmpty() && password.isNotEmpty(),
                ) {
                    WearCore.login(email, password, server)
                    password = ""
                }
            }
        }
    }
}

@Composable
fun UnlockScreen() {
    var password by remember { mutableStateOf("") }
    val busy = WearCore.busy

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 10.dp, vertical = 18.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Label("Locked", size = 18.sp, weight = FontWeight.SemiBold)
        WatchField(password, { password = it }, "Master password", password = true)
        WatchButton(
            label = if (busy) "Unlocking" else "Unlock",
            enabled = !busy && password.isNotEmpty(),
        ) {
            WearCore.unlock(password)
            password = ""
        }
        WatchButton("Log out", danger = true, enabled = !busy) { WearCore.logout() }
    }
}

/*
 * The item list. Search is a single field above the list rather than a separate screen,
 * because a watch has no room for a search bar that expands.
 */
@Composable
fun VaultScreen(onOpen: (WearItem) -> Unit, onSettings: () -> Unit) {
    var search by remember { mutableStateOf("") }
    var items by remember { mutableStateOf<List<WearItem>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }
    val state = WearCore.state
    val listState = rememberScalingLazyListState()

    LaunchedEffect(state, search) {
        if (state != "Unlocked") {
            return@LaunchedEffect
        }
        loading = true
        error = null
        try {
            items = WearCore.listItems(search)
        } catch (e: BridgeError) {
            error = e.message
        } finally {
            loading = false
        }
    }

    ScalingLazyColumn(
        modifier = Modifier.fillMaxSize(),
        state = listState,
        contentPadding = PaddingValues(horizontal = 8.dp, vertical = 22.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        item {
            WatchField(search, { search = it }, "Search", imeAction = ImeAction.Search)
        }

        if (error != null) {
            item { Label(error!!, size = 12.sp, color = Palette.Danger) }
        } else if (loading && items.isEmpty()) {
            item { Label("Loading", size = 12.sp, color = Palette.Muted) }
        } else if (items.isEmpty()) {
            item { Label("Nothing here", size = 12.sp, color = Palette.Muted) }
        }

        items.forEach { row ->
            item {
                Panel(onClick = { onOpen(row) }) {
                    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Label(
                            text = (if (row.favorite) "* " else "") + row.name.ifEmpty { "Untitled" },
                            size = 15.sp,
                            maxLines = 1,
                        )
                        if (row.subtitle.isNotEmpty()) {
                            Label(row.subtitle, size = 11.sp, color = Palette.Muted, maxLines = 1)
                        }
                    }
                }
            }
        }

        item {
            WatchButton("Settings") { onSettings() }
        }
    }
}

/*
 * One item. The core hands back a "fields" array of {key, secret, value}; for a login the
 * two that matter on a watch are username and password, plus a live TOTP code.
 */
@Composable
fun ItemDetail(item: WearItem, onBack: () -> Unit) {
    val context = LocalContext.current
    var detail by remember(item.id) { mutableStateOf<JSONObject?>(null) }
    var error by remember(item.id) { mutableStateOf<String?>(null) }
    var revealed by remember(item.id) { mutableStateOf(false) }
    var totp by remember(item.id) { mutableStateOf<String?>(null) }

    LaunchedEffect(item.id) {
        try {
            detail = WearCore.getItem(item.id)
        } catch (e: BridgeError) {
            error = e.message
        }
    }

    /*
     * TOTP codes roll over on their own; five seconds is often enough to be right when the
     * user looks, and cheap enough not to matter on a watch.
     */
    LaunchedEffect(item.id) {
        while (true) {
            if (detail?.optString("type") == "Login") {
                totp = try {
                    WearCore.totp(item.id)
                } catch (e: BridgeError) {
                    null
                }
            }
            delay(5_000)
        }
    }

    val username = fieldValue(detail, "username")
    val password = fieldValue(detail, "password")
    val notes = detail?.optString("notes").orEmpty()

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 10.dp, vertical = 18.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Label(item.name.ifEmpty { "Untitled" }, size = 17.sp, weight = FontWeight.SemiBold, maxLines = 2)

        if (error != null) {
            Label(error!!, size = 12.sp, color = Palette.Danger)
        }

        if (username.isNotEmpty()) {
            CopyRow("Username", username) { WearCore.copy(context, "username", username) }
        }

        if (password.isNotEmpty()) {
            CopyRow("Password", if (revealed) password else "••••••••") {
                if (revealed) {
                    WearCore.copy(context, "password", password)
                } else {
                    revealed = true
                }
            }
        }

        if (totp != null) {
            CopyRow("One-time code", totp!!) { WearCore.copy(context, "code", totp!!) }
        }

        if (notes.isNotEmpty()) {
            Panel {
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Label("Notes", size = 11.sp, color = Palette.Muted)
                    Label(notes, size = 13.sp, maxLines = 6)
                }
            }
        }

        WatchButton("Back") { onBack() }
    }
}

@Composable
fun SettingsScreen(onBack: () -> Unit) {
    val busy = WearCore.busy
    val online = WearCore.online

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 10.dp, vertical = 18.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Label("Settings", size = 18.sp, weight = FontWeight.SemiBold)
        Label(if (online) "Online" else "Offline", size = 12.sp, color = Palette.Muted)

        WatchButton(if (busy) "Syncing" else "Sync now", enabled = !busy) { WearCore.sync() }
        WatchButton("Lock", enabled = !busy) { WearCore.lock() }
        WatchButton("Log out", danger = true, enabled = !busy) { WearCore.logout() }
        WatchButton("Back") { onBack() }
    }
}

@Composable
fun LoadingScreen(what: String) {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Label(what, size = 13.sp, color = Palette.Muted)
    }
}

private fun fieldValue(detail: JSONObject?, key: String): String {
    val fields = detail?.optJSONArray("fields") ?: return ""
    for (i in 0 until fields.length()) {
        val field = fields.optJSONObject(i) ?: continue
        if (field.optString("key") == key) {
            return if (field.isNull("value")) "" else field.optString("value")
        }
    }
    return ""
}
