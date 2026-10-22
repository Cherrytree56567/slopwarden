package com.ct5.clientwarden

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.composables.icons.lucide.Ban
import com.composables.icons.lucide.Copy
import com.composables.icons.lucide.File
import com.composables.icons.lucide.FileText
import com.composables.icons.lucide.KeyRound
import com.composables.icons.lucide.Link
import com.composables.icons.lucide.Lucide
import com.composables.icons.lucide.Save
import com.composables.icons.lucide.Trash2
import com.composables.icons.lucide.X
import java.text.DateFormat
import java.util.Date

/*
 * One of the user's Sends. Dates are seconds since 1970, 0 = not set;
 * maxAccessCount 0 = unlimited.
 */
data class SendData(
    val id: String = "",
    val type: String = "text",
    val name: String = "",
    val notes: String = "",
    val text: String = "",
    val textHidden: Boolean = false,
    val fileName: String = "",
    val fileSize: String = "",
    val maxAccessCount: Int = 0,
    val accessCount: Int = 0,
    val expirationDate: Long = 0,
    val deletionDate: Long = 0,
    val disabled: Boolean = false,
    val hideEmail: Boolean = false,
    val hasPassword: Boolean = false,
    val shareUrl: String = ""
)

/*
 * A Send someone shared with us, opened from its link
 */
data class ReceivedSendData(
    val type: String,
    val name: String,
    val text: String,
    val textHidden: Boolean,
    val fileName: String,
    val fileSize: String,
    val creator: String
)

object SendScreen {
    var sends = mutableStateListOf<SendData>()
    var editing by mutableStateOf<SendData?>(null)
    var newPassword by mutableStateOf("")
    var pendingFileName by mutableStateOf("")

    var receiving by mutableStateOf(false)
    var received by mutableStateOf<ReceivedSendData?>(null)
    var receiveNeedsPassword by mutableStateOf(false)
    var receiveMessage by mutableStateOf("")

    var cb_reload: (() -> Unit)? = null

    /*
     * cb_save(send, newPassword) creates or updates a Send; a new file Send uses the file
     * picked through cb_pickFile
     */
    var cb_save: ((SendData, String) -> Unit)? = null
    var cb_delete: ((String) -> Unit)? = null
    var cb_removePassword: ((String) -> Unit)? = null
    var cb_pickFile: (() -> Unit)? = null
    var cb_open: ((String, String) -> Unit)? = null
    var cb_downloadReceived: (() -> Unit)? = null

    private const val c_day = 86400L

    private val c_deletion = listOf(1 to "1 day", 2 to "2 days", 3 to "3 days", 7 to "7 days",
        14 to "14 days", 30 to "30 days")
    private val c_expiration = listOf(0 to "Never", 1 to "1 day", 2 to "2 days", 3 to "3 days",
        7 to "7 days", 30 to "30 days")

    private fun now(): Long = System.currentTimeMillis() / 1000

    fun formatDate(seconds: Long): String {
        return DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(seconds * 1000))
    }

    fun create(type: String) {
        editing = SendData(type = type, deletionDate = now() + 7 * c_day)
        newPassword = ""
        pendingFileName = ""
    }

    @Composable
    fun view() {
        BackHandler(enabled = editing != null) {
            editing = null
        }

        if (editing != null) {
            EditView()
        } else {
            ListView()
        }

        if (receiving) {
            ReceiveDialog()
        }
    }

    @Composable
    private fun ListView() {
        Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Send", style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f))

                IconButton(onClick = {
                    received = null
                    receiveMessage = ""
                    receiveNeedsPassword = false
                    receiving = true
                }) {
                    Icon(Lucide.Link, contentDescription = "Open a Send link", modifier = Modifier.size(20.dp))
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            Row {
                Button(onClick = { create("text") }, modifier = Modifier.weight(1f)) {
                    Icon(Lucide.FileText, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Text")
                }
                Spacer(modifier = Modifier.width(12.dp))
                Button(onClick = { create("file") }, modifier = Modifier.weight(1f)) {
                    Icon(Lucide.File, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("File")
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            Column(modifier = Modifier.clip(RoundedCornerShape(16.dp)).verticalScroll(rememberScrollState())) {
                if (sends.isEmpty()) {
                    Text("Share text or a file securely with a link. Your Sends appear here.",
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(16.dp))
                }

                for ((i, send) in sends.withIndex()) {
                    FilledTonalButton(
                        onClick = {
                            editing = send
                            newPassword = ""
                        },
                        modifier = Modifier.fillMaxWidth().height(64.dp),
                        shape = RoundedCornerShape(
                            topStart = if (i == 0) 12.dp else 0.dp,
                            topEnd = if (i == 0) 12.dp else 0.dp,
                            bottomStart = if (i == sends.lastIndex) 12.dp else 0.dp,
                            bottomEnd = if (i == sends.lastIndex) 12.dp else 0.dp
                        ),
                        contentPadding = PaddingValues(start = 16.dp, end = 16.dp),
                        colors = ButtonDefaults.filledTonalButtonColors(
                            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
                        )
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
                            Icon(if (send.type == "file") Lucide.File else Lucide.FileText, contentDescription = null,
                                tint = MaterialTheme.colorScheme.onSecondaryContainer, modifier = Modifier.size(20.dp))
                            Spacer(modifier = Modifier.width(12.dp))
                            Column(modifier = Modifier.weight(1f)) {
                                Text(send.name.ifEmpty { "Untitled" }, maxLines = 1, overflow = TextOverflow.Ellipsis,
                                    color = MaterialTheme.colorScheme.onSecondaryContainer)
                                val l_views = if (send.maxAccessCount > 0) "${send.accessCount}/${send.maxAccessCount} views"
                                    else "${send.accessCount} views"
                                Text("$l_views · deleted ${formatDate(send.deletionDate)}",
                                    style = MaterialTheme.typography.bodySmall, maxLines = 1,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            if (send.hasPassword) {
                                Icon(Lucide.KeyRound, contentDescription = "Password protected",
                                    modifier = Modifier.size(16.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                            if (send.disabled) {
                                Icon(Lucide.Ban, contentDescription = "Disabled",
                                    modifier = Modifier.size(16.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }

                    if (i != sends.lastIndex) {
                        HorizontalDivider(modifier = Modifier.background(MaterialTheme.colorScheme.surfaceContainerHigh)
                            .padding(horizontal = 12.dp))
                    }
                }
            }
        }
    }

    @Composable
    private fun EditView() {
        val send = editing ?: return
        var l_confirmDelete by remember { mutableStateOf(false) }

        Column(modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                FilledIconButton(onClick = { editing = null }, modifier = Modifier.size(48.dp)) {
                    Icon(Lucide.X, contentDescription = "Close", modifier = Modifier.size(20.dp))
                }
                Spacer(modifier = Modifier.weight(1f))
                if (send.id.isNotEmpty()) {
                    FilledIconButton(onClick = { l_confirmDelete = true }, modifier = Modifier.size(48.dp)) {
                        Icon(Lucide.Trash2, contentDescription = "Delete", modifier = Modifier.size(20.dp))
                    }
                    Spacer(modifier = Modifier.width(16.dp))
                }
                FilledIconButton(onClick = { cb_save?.invoke(send, newPassword) }, modifier = Modifier.size(48.dp)) {
                    Icon(Lucide.Save, contentDescription = "Save", modifier = Modifier.size(20.dp))
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            OutlinedTextField(value = send.name, onValueChange = { editing = send.copy(name = it) },
                label = { Text("Name") }, singleLine = true, modifier = Modifier.fillMaxWidth())

            Spacer(modifier = Modifier.height(8.dp))

            if (send.type == "text") {
                OutlinedTextField(value = send.text, onValueChange = { editing = send.copy(text = it) },
                    label = { Text("Text") }, minLines = 3, modifier = Modifier.fillMaxWidth())
                SettingsScreen.SettingsSwitch("Hide the text by default", send.textHidden,
                    { editing = send.copy(textHidden = it) }, true, true)
            } else if (send.id.isEmpty()) {
                Row(verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(MaterialTheme.colorScheme.surfaceContainerHigh)
                        .padding(horizontal = 16.dp, vertical = 8.dp)) {
                    Text(pendingFileName.ifEmpty { "No file chosen" }, modifier = Modifier.weight(1f),
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                    TextButton(onClick = { cb_pickFile?.invoke() }) { Text("Choose File") }
                }
            } else {
                Text("File: ${send.fileName} (${send.fileSize})", modifier = Modifier.padding(4.dp))
            }

            Spacer(modifier = Modifier.height(16.dp))

            val l_deletionDays = ((send.deletionDate - now() + c_day - 1) / c_day).toInt()
            SettingsScreen.SettingsDropdown(
                text = "Deletion",
                options = c_deletion.map { it.second },
                selected = if (send.deletionDate > 0) formatDate(send.deletionDate) else "7 days",
                onSelectedChange = { l_label ->
                    c_deletion.firstOrNull { it.second == l_label }?.let {
                        editing = send.copy(deletionDate = now() + it.first * c_day)
                    }
                },
                start = true
            )

            SettingsScreen.SettingsDropdown(
                text = "Expiration",
                options = c_expiration.map { it.second },
                selected = if (send.expirationDate > 0) formatDate(send.expirationDate) else "Never",
                onSelectedChange = { l_label ->
                    c_expiration.firstOrNull { it.second == l_label }?.let {
                        editing = send.copy(expirationDate = if (it.first == 0) 0 else now() + it.first * c_day)
                    }
                }
            )

            SettingsScreen.SettingsSwitch("Hide my email from recipients", send.hideEmail,
                { editing = send.copy(hideEmail = it) })
            SettingsScreen.SettingsSwitch("Disable this Send", send.disabled,
                { editing = send.copy(disabled = it) }, end = true)

            Spacer(modifier = Modifier.height(16.dp))

            OutlinedTextField(
                value = if (send.maxAccessCount > 0) send.maxAccessCount.toString() else "",
                onValueChange = { editing = send.copy(maxAccessCount = it.filter(Char::isDigit).take(6).toIntOrNull() ?: 0) },
                label = { Text("Maximum views (empty = unlimited)") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                singleLine = true, modifier = Modifier.fillMaxWidth())

            Spacer(modifier = Modifier.height(8.dp))

            OutlinedTextField(
                value = newPassword, onValueChange = { newPassword = it },
                label = { Text(if (send.hasPassword) "New password (empty keeps it)" else "Password (optional)") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                singleLine = true, modifier = Modifier.fillMaxWidth())

            if (send.hasPassword && send.id.isNotEmpty()) {
                TextButton(onClick = { cb_removePassword?.invoke(send.id) }) { Text("Remove Password") }
            }

            Spacer(modifier = Modifier.height(8.dp))

            OutlinedTextField(value = send.notes, onValueChange = { editing = send.copy(notes = it) },
                label = { Text("Private notes") }, minLines = 2, modifier = Modifier.fillMaxWidth())

            if (send.shareUrl.isNotEmpty()) {
                Spacer(modifier = Modifier.height(16.dp))

                Row(verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(MaterialTheme.colorScheme.surfaceContainerHigh)
                        .padding(horizontal = 16.dp, vertical = 8.dp)) {
                    Text(send.shareUrl, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f),
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                    IconButton(onClick = {
                        /*
                         * The link carries the Send's key
                         */
                        GenericItem.cb_copy?.invoke(send.shareUrl, true)
                    }) {
                        Icon(Lucide.Copy, contentDescription = "Copy link", modifier = Modifier.size(18.dp))
                    }
                }
            }

            if (send.id.isNotEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))
                Text("${send.accessCount} views", style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (l_deletionDays > 0) {
                    Text("Deleted in $l_deletionDays days", style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }

        if (l_confirmDelete) {
            AlertDialog(
                onDismissRequest = { l_confirmDelete = false },
                title = { Text("Delete Send") },
                text = { Text("The link will stop working.") },
                confirmButton = {
                    TextButton(onClick = {
                        l_confirmDelete = false
                        cb_delete?.invoke(send.id)
                    }) { Text("Delete") }
                },
                dismissButton = {
                    TextButton(onClick = { l_confirmDelete = false }) { Text("Cancel") }
                }
            )
        }
    }

    @Composable
    private fun ReceiveDialog() {
        var l_link by remember { mutableStateOf("") }
        var l_password by remember { mutableStateOf("") }
        var l_revealed by remember { mutableStateOf(false) }
        val l_received = received

        AlertDialog(
            onDismissRequest = {
                receiving = false
                received = null
            },
            title = { Text(l_received?.name ?: "Open a Send") },
            text = {
                Column(modifier = Modifier.heightIn(max = 420.dp).verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (l_received != null) {
                        if (l_received.creator.isNotEmpty()) {
                            Text("Shared by ${l_received.creator}", style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        if (l_received.type == "text") {
                            if (l_received.textHidden && !l_revealed) {
                                TextButton(onClick = { l_revealed = true }) { Text("Reveal text") }
                            } else {
                                Text(l_received.text, modifier = Modifier.clickable {
                                    GenericItem.cb_copy?.invoke(l_received.text, true)
                                })
                                TextButton(onClick = { GenericItem.cb_copy?.invoke(l_received.text, true) }) {
                                    Text("Copy")
                                }
                            }
                        } else {
                            Text("${l_received.fileName} (${l_received.fileSize})")
                            TextButton(onClick = { cb_downloadReceived?.invoke() }) { Text("Save File") }
                        }
                    } else {
                        OutlinedTextField(value = l_link, onValueChange = { l_link = it },
                            label = { Text("Send link") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                        if (receiveNeedsPassword) {
                            OutlinedTextField(value = l_password, onValueChange = { l_password = it },
                                label = { Text("Password") },
                                visualTransformation = PasswordVisualTransformation(),
                                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                                singleLine = true, modifier = Modifier.fillMaxWidth())
                        }
                        if (receiveMessage.isNotEmpty()) {
                            Text(receiveMessage, color = MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            },
            confirmButton = {
                if (l_received == null) {
                    TextButton(enabled = l_link.isNotBlank(), onClick = { cb_open?.invoke(l_link.trim(), l_password) }) {
                        Text("Open")
                    }
                } else {
                    TextButton(onClick = {
                        receiving = false
                        received = null
                    }) { Text("Done") }
                }
            },
            dismissButton = {
                if (l_received == null) {
                    TextButton(onClick = { receiving = false }) { Text("Close") }
                }
            }
        )
    }
}
