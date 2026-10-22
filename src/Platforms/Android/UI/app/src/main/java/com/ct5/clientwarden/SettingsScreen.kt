package com.ct5.clientwarden

import androidx.compose.foundation.background
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Slider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.text.font.FontFamily
import com.composables.icons.lucide.Copy
import com.composables.icons.lucide.Dices
import com.composables.icons.lucide.RefreshCw

import android.content.res.Configuration
import android.widget.Space
import androidx.compose.animation.core.MutableTransitionState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Devices
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.Popup
import com.composables.icons.lucide.AArrowDown
import com.composables.icons.lucide.ArrowDown
import com.composables.icons.lucide.ArrowRight
import com.composables.icons.lucide.BadgeCheck
import com.composables.icons.lucide.Check
import com.composables.icons.lucide.ChevronDown
import com.composables.icons.lucide.EllipsisVertical
import com.composables.icons.lucide.Lucide
import com.composables.icons.lucide.Shield
import com.ct5.clientwarden.NavScreen.c_item
import com.ct5.clientwarden.NavScreen.cb_DeleteFolder
import com.ct5.clientwarden.NavScreen.cb_RenameFolder
import com.ct5.clientwarden.ui.theme.ClientwardenTheme
import java.util.UUID
import android.net.Uri
import android.content.Intent
import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.clickable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.core.net.toUri
import kotlinx.coroutines.launch

enum class SettingsSelection {
    Security,
    AutoFill,
    Generator,
    About,
    NONE
}

object SettingsScreen {
    var c_item = mutableStateOf(SettingsSelection.NONE)

    var email = mutableStateOf("")
    var biometrics = mutableStateOf(false)
    var autoLockSeconds = mutableStateOf(300)
    var timeoutAction = mutableStateOf("lock")
    var clipboardSeconds = mutableStateOf(30)
    var allowScreenshots = mutableStateOf(false)
    var autofillEnabled = mutableStateOf(false)

    /*
     * cb_set(key, value) changes one of the core's settings (settings.set)
     */
    var cb_set: ((String, Any) -> Unit)? = null
    var cb_biometrics: ((Boolean) -> Unit)? = null
    var cb_lock: (() -> Unit)? = null
    var cb_logout: (() -> Unit)? = null
    var cb_sync: (() -> Unit)? = null
    var cb_autofill: (() -> Unit)? = null

    /*
     * cb_generate(kind, options) with kind password, passphrase or pin
     */
    var cb_generate: (suspend (String, Map<String, Any>) -> String?)? = null

    private val c_timeouts = listOf(
        5 to "Immediately",
        60 to "1 minute",
        300 to "5 minutes",
        900 to "15 minutes",
        1800 to "30 minutes",
        3600 to "1 hour",
        14400 to "4 hours",
        86400 to "1 day",
        604800 to "7 days"
    )

    private val c_clipboard = listOf(
        10 to "10 seconds",
        20 to "20 seconds",
        30 to "30 seconds",
        60 to "1 minute",
        120 to "2 minutes",
        300 to "5 minutes"
    )

    private fun label(options: List<Pair<Int, String>>, value: Int): String {
        return options.firstOrNull { it.first == value }?.second ?: "$value seconds"
    }

    @Composable
    fun SettingButton(text: String, icon: ImageVector = Lucide.AArrowDown, onClick: () -> Unit = {},
                      start: Boolean = false, end: Boolean = false) {
        /*
         * A Mat You Button with a custom BG Color
         */
        FilledTonalButton(onClick = { onClick() },
            modifier = Modifier.fillMaxWidth()
                .height(52.dp)
                .drawWithContent {
                    drawContent()
                },
            shape = RoundedCornerShape(
                topStart = if (start) 12.dp else 0.dp,
                topEnd = if (start) 12.dp else 0.dp,
                bottomStart = if (end) 12.dp else 0.dp,
                bottomEnd = if (end) 12.dp else 0.dp
            ),
            contentPadding = PaddingValues(16.dp, 0.dp, 0.dp, 0.dp),
            colors = ButtonDefaults.filledTonalButtonColors(
                containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                contentColor = MaterialTheme.colorScheme.surfaceContainerHigh
            )) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Start,
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (icon != Lucide.AArrowDown) {
                    /*
                     * Nav Item Icon
                     */
                    Icon(
                        icon,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSecondaryContainer,
                        modifier = Modifier.size(20.dp)
                    )

                    Spacer(Modifier.width(8.dp))
                }

                /*
                 * Nav Item Name
                 */
                Text(text,
                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                    overflow = TextOverflow.Ellipsis,
                    maxLines = 1)

                Spacer(Modifier.weight(1f).fillMaxWidth())
            }
        }
    }

    @Composable
    fun SettingsSwitch(text: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit,
                      start: Boolean = false, end: Boolean = false) {
        /*
         * A Mat You Button with a custom BG Color
         */
        FilledTonalButton(onClick = { onCheckedChange(!checked) },
            modifier = Modifier.fillMaxWidth()
                .height(52.dp)
                .drawWithContent {
                    drawContent()
                },
            shape = RoundedCornerShape(
                topStart = if (start) 12.dp else 0.dp,
                topEnd = if (start) 12.dp else 0.dp,
                bottomStart = if (end) 12.dp else 0.dp,
                bottomEnd = if (end) 12.dp else 0.dp
            ),
            contentPadding = PaddingValues(16.dp, 0.dp, 0.dp, 0.dp),
            colors = ButtonDefaults.filledTonalButtonColors(
                containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                contentColor = MaterialTheme.colorScheme.surfaceContainerHigh
            )) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Start,
                verticalAlignment = Alignment.CenterVertically
            ) {
                /*
                 * Item Name
                 */
                Text(text,
                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                    overflow = TextOverflow.Ellipsis,
                    maxLines = 1)

                Spacer(Modifier.weight(1f).fillMaxWidth())

                Switch(
                    checked = checked,
                    onCheckedChange = { onCheckedChange(it) },
                    modifier = Modifier.scale(0.75f)
                )

                Spacer(Modifier.width(8.dp))
            }
        }
    }

    @Composable
    fun SettingsDropdown(text: String, options: List<String>, selected: String,
        onSelectedChange: (String) -> Unit, start: Boolean = false,
        end: Boolean = false) {
        var m_expanded by remember { mutableStateOf(false) }

        FilledTonalButton(
            onClick = { m_expanded = true },
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
            shape = RoundedCornerShape(
                topStart = if (start) 12.dp else 0.dp,
                topEnd = if (start) 12.dp else 0.dp,
                bottomStart = if (end) 12.dp else 0.dp,
                bottomEnd = if (end) 12.dp else 0.dp
            ),
            contentPadding = PaddingValues(16.dp, 0.dp, 0.dp, 0.dp),
            colors = ButtonDefaults.filledTonalButtonColors(
                containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
                contentColor = MaterialTheme.colorScheme.surfaceContainerHigh
            )
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Start,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column() {
                    Text(
                        text,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        style = MaterialTheme.typography.bodySmall
                    )

                    Text(
                        selected,
                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                        overflow = TextOverflow.Ellipsis,
                        maxLines = 1
                    )
                }

                Spacer(Modifier.weight(1f).fillMaxWidth())

                Icon(
                    Lucide.ChevronDown,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSecondaryContainer,
                    modifier = Modifier.size(24.dp)
                )

                Spacer(Modifier.width(16.dp))
            }

            if (m_expanded) {
                AlertDialog(
                    onDismissRequest = { m_expanded = false },
                    title = { Text("Select an option") },
                    text = {
                        Column {
                            options.forEach { option ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable {
                                            onSelectedChange(option)
                                            m_expanded = false
                                        }
                                        .padding(vertical = 12.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(option, modifier = Modifier.weight(1f))
                                    if (option == selected) {
                                        Icon(
                                            Lucide.Check,
                                            contentDescription = null,
                                            modifier = Modifier.size(18.dp)
                                        )
                                    }
                                }
                            }
                        }
                    },
                    confirmButton = {
                        TextButton(onClick = { m_expanded = false }) {
                            Text("Cancel")
                        }
                    }
                )
            }
        }
    }

    @Composable
    fun GeneratorView() {
        var l_kind by remember { mutableStateOf("password") }
        var l_length by remember { mutableStateOf(20f) }
        var l_words by remember { mutableStateOf(5f) }
        var l_digits by remember { mutableStateOf(6f) }
        var l_upper by remember { mutableStateOf(true) }
        var l_numbers by remember { mutableStateOf(true) }
        var l_symbols by remember { mutableStateOf(true) }
        var l_capitalize by remember { mutableStateOf(true) }
        var l_result by remember { mutableStateOf("") }
        var l_nonce by remember { mutableStateOf(0) }

        LaunchedEffect(l_kind, l_length.toInt(), l_words.toInt(), l_digits.toInt(), l_upper, l_numbers,
            l_symbols, l_capitalize, l_nonce) {
            val l_options: Map<String, Any> = when (l_kind) {
                "passphrase" -> mapOf("words" to l_words.toInt(), "capitalize" to l_capitalize)
                "pin" -> mapOf("digits" to l_digits.toInt())
                else -> mapOf("length" to l_length.toInt(), "uppercase" to l_upper,
                    "numbers" to l_numbers, "symbols" to l_symbols)
            }
            l_result = cb_generate?.invoke(l_kind, l_options) ?: ""
        }

        Column(modifier = Modifier.verticalScroll(rememberScrollState())) {
            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                val l_kinds = listOf("password" to "Password", "passphrase" to "Passphrase", "pin" to "PIN")
                l_kinds.forEachIndexed { i, (kind, text) ->
                    SegmentedButton(
                        selected = l_kind == kind,
                        onClick = { l_kind = kind },
                        shape = SegmentedButtonDefaults.itemShape(index = i, count = l_kinds.size)
                    ) {
                        Text(text)
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            Row(verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .background(MaterialTheme.colorScheme.surfaceContainerHigh)
                    .padding(12.dp)) {
                Text(l_result, modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.bodyLarge.copy(fontFamily = FontFamily.Monospace))
                IconButton(onClick = { l_nonce++ }) {
                    Icon(Lucide.RefreshCw, contentDescription = "Regenerate", modifier = Modifier.size(18.dp))
                }
                IconButton(onClick = { GenericItem.cb_copy?.invoke(l_result, true) }) {
                    Icon(Lucide.Copy, contentDescription = "Copy", modifier = Modifier.size(18.dp))
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            when (l_kind) {
                "passphrase" -> {
                    Text("Words: ${l_words.toInt()}")
                    Slider(value = l_words, onValueChange = { l_words = it }, valueRange = 3f..20f)
                    SettingsSwitch("Capitalise", l_capitalize, { l_capitalize = it }, true, true)
                }
                "pin" -> {
                    Text("Digits: ${l_digits.toInt()}")
                    Slider(value = l_digits, onValueChange = { l_digits = it }, valueRange = 4f..12f)
                }
                else -> {
                    Text("Length: ${l_length.toInt()}")
                    Slider(value = l_length, onValueChange = { l_length = it }, valueRange = 5f..128f)
                    SettingsSwitch("A-Z", l_upper, { l_upper = it }, true)
                    SettingsSwitch("0-9", l_numbers, { l_numbers = it })
                    SettingsSwitch("!@#$%^&*", l_symbols, { l_symbols = it }, end = true)
                }
            }
        }
    }

    @Composable
    fun view(modifier: Modifier = Modifier) {
        var context = LocalContext.current
        var scope = rememberCoroutineScope()
        var rotation = remember { Animatable(0f) }
        var c_count by remember { mutableStateOf(0) }
        var l_time by remember { mutableStateOf(0L) }

        BackHandler(enabled = c_item.value != SettingsSelection.NONE) {
            c_item.value = SettingsSelection.NONE
        }

        Box(
            modifier = Modifier.fillMaxSize(),
            contentAlignment = Alignment.TopStart
        ) {
            AnimatedContent(
                targetState = c_item.value,
                transitionSpec = {
                    if (targetState == SettingsSelection.NONE) {
                        slideInHorizontally(
                            initialOffsetX = { -it },
                            animationSpec = tween(250)
                        ) + fadeIn(
                            animationSpec = tween(250)
                        ) togetherWith
                                slideOutHorizontally(
                                    targetOffsetX = { it },
                                    animationSpec = tween(250)
                                ) + fadeOut(
                            animationSpec = tween(150)
                        )
                    } else {
                        slideInHorizontally(
                            initialOffsetX = { it },
                            animationSpec = tween(250)
                        ) + fadeIn(
                            animationSpec = tween(250)
                        ) togetherWith
                                slideOutHorizontally(
                                    targetOffsetX = { -it },
                                    animationSpec = tween(250)
                                ) + fadeOut(
                            animationSpec = tween(150)
                        )
                    }
                },
                label = "settings_nav"
            ) { item ->
                Column(modifier = Modifier.padding(16.dp)) {
                    if (item == SettingsSelection.NONE) {
                        if (email.value.isNotEmpty()) {
                            Text(email.value, style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(start = 4.dp, bottom = 12.dp))
                        }

                        SettingButton("Security", Lucide.Shield, {
                            c_item.value = SettingsSelection.Security
                        }, true)

                        SettingButton("AutoFill", Lucide.Check, {
                            c_item.value = SettingsSelection.AutoFill
                        })

                        SettingButton("Generator", Lucide.Dices, {
                            c_item.value = SettingsSelection.Generator
                        })

                        SettingButton("Sync Now", Lucide.RefreshCw, {
                            cb_sync?.invoke()
                        })

                        SettingButton("About", Lucide.BadgeCheck, {
                            c_item.value = SettingsSelection.About
                        }, false, true)
                    } else if (item == SettingsSelection.Security) {
                        SettingsSwitch("Unlock with Biometrics", biometrics.value, {
                            cb_biometrics?.invoke(it)
                        }, true)

                        SettingsDropdown(
                            text = "Session Timeout",
                            options = c_timeouts.map { it.second },
                            selected = label(c_timeouts, autoLockSeconds.value),
                            onSelectedChange = { l_label ->
                                c_timeouts.firstOrNull { it.second == l_label }?.let {
                                    autoLockSeconds.value = it.first
                                    cb_set?.invoke("autoLockSeconds", it.first)
                                }
                            }
                        )

                        SettingsDropdown(
                            text = "On Timeout",
                            options = listOf("Lock", "Log Out"),
                            selected = if (timeoutAction.value == "logout") "Log Out" else "Lock",
                            onSelectedChange = {
                                timeoutAction.value = if (it == "Log Out") "logout" else "lock"
                                cb_set?.invoke("timeoutAction", timeoutAction.value)
                            }
                        )

                        SettingsDropdown(
                            text = "Clear Clipboard",
                            options = c_clipboard.map { it.second },
                            selected = label(c_clipboard, clipboardSeconds.value),
                            onSelectedChange = { l_label ->
                                c_clipboard.firstOrNull { it.second == l_label }?.let {
                                    clipboardSeconds.value = it.first
                                    cb_set?.invoke("clipboardClearSeconds", it.first)
                                }
                            }
                        )

                        SettingsSwitch("Allow Screenshots", allowScreenshots.value, {
                            allowScreenshots.value = it
                            cb_set?.invoke("allowScreenshots", it)
                        })

                        SettingButton("Lock", onClick = {
                            cb_lock?.invoke()
                        })

                        SettingButton("Log Out", onClick = {
                            cb_logout?.invoke()
                        }, end = true)
                    } else if (item == SettingsSelection.AutoFill) {
                        SettingsSwitch("AutoFill", autofillEnabled.value, {
                            cb_autofill?.invoke()
                        }, true, true)

                        Text("Clientwarden fills logins in other apps and browsers while your vault " +
                            "is unlocked. Android lets you change the autofill service in system settings.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(12.dp))
                    } else if (item == SettingsSelection.Generator) {
                        GeneratorView()
                    } else if (item == SettingsSelection.About) {
                        Column(
                            modifier = Modifier.fillMaxWidth().padding(top = 32.dp),
                            horizontalAlignment = Alignment.CenterHorizontally,
                            verticalArrangement = Arrangement.Center
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(128.dp)
                                    .clip(RoundedCornerShape(30))
                                    .clickable {
                                        val now = System.currentTimeMillis()
                                        if (now - l_time > 500) {
                                            c_count = 1
                                        } else {
                                            c_count++
                                        }
                                        l_time = now

                                        if (c_count == 3) {
                                            c_count = 0
                                            if (!rotation.isRunning) {
                                                scope.launch {
                                                    rotation.animateTo(
                                                        targetValue = rotation.value + 360f,
                                                        animationSpec = tween(
                                                            durationMillis = 600,
                                                            easing = FastOutSlowInEasing
                                                        )
                                                    )

                                                    rotation.snapTo(rotation.value % 360f)
                                                }
                                            }
                                        }
                                    }
                                    .graphicsLayer { rotationZ = rotation.value }
                            ) {
                                Image(
                                    painter = painterResource(id = R.mipmap.ic_launcher_background),
                                    contentDescription = null,
                                    modifier = Modifier.fillMaxSize()
                                        .scale(1.5f)
                                )
                                Image(
                                    painter = painterResource(id = R.mipmap.ic_launcher_foreground),
                                    contentDescription = "App icon",
                                    modifier = Modifier
                                        .fillMaxSize()
                                        .scale(1.5f)
                                )
                            }

                            Spacer(modifier = Modifier.height(32.dp))

                            ClientwardenEasterText()

                            Spacer(modifier = Modifier.height(2.dp))

                            Text(
                                "Version 0482A1A Release",
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                style = MaterialTheme.typography.bodyMedium
                            )

                            Spacer(modifier = Modifier.weight(1f).fillMaxHeight())

                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(
                                    "Github",
                                    color = MaterialTheme.colorScheme.primary,
                                    style = MaterialTheme.typography.bodyMedium,
                                    modifier = Modifier.clickable {
                                        val intent = Intent(
                                            Intent.ACTION_VIEW,
                                            "https://github.com/Cherrytree56567/ClientWarden".toUri()
                                        )
                                        context.startActivity(intent)
                                    })

                                Spacer(modifier = Modifier.weight(1f).fillMaxWidth())

                                Text(
                                    "Made By CT5",
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    style = MaterialTheme.typography.bodyMedium
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Preview(
    showBackground = true,
    showSystemUi = true,
    device = Devices.PIXEL_9,
    uiMode = Configuration.UI_MODE_NIGHT_YES
)
@Composable
fun PreviewSettings() {
    ClientwardenTheme {
        VaultUI()
    }
}