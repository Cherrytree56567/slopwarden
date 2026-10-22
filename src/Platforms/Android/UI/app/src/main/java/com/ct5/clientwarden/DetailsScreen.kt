package com.ct5.clientwarden

import androidx.compose.material3.Checkbox
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.runtime.key
import androidx.compose.ui.draw.scale
import com.composables.icons.lucide.Building2
import com.composables.icons.lucide.Copy
import com.composables.icons.lucide.Paperclip
import com.composables.icons.lucide.Share2
import com.composables.icons.lucide.X

import android.content.res.Configuration
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
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
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DatePicker
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberDatePickerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableDoubleStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Devices
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.composables.icons.lucide.Eye
import com.composables.icons.lucide.EyeOff
import com.composables.icons.lucide.Folder
import com.composables.icons.lucide.Globe
import com.composables.icons.lucide.GripVertical
import com.composables.icons.lucide.Lucide
import com.composables.icons.lucide.Star
import com.composables.icons.lucide.StarOff
import com.ct5.clientwarden.AttachmentItem
import com.ct5.clientwarden.FieldItem
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import sh.calvin.reorderable.ReorderableItem
import sh.calvin.reorderable.rememberReorderableLazyListState
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID
import kotlin.time.Duration.Companion.milliseconds

object DetailsScreen {
    var cb_removeAttachment: ((String) -> Unit)? = null
    var cb_downloadAttachment: ((String) -> Unit)? = null
    var cb_addAttachment: (() -> Unit)? = null
    var cb_favorite: ((Boolean) -> Unit)? = null
    var cb_folder: ((String) -> Unit)? = null

    /*
     * cb_share(organizationId, collectionIds) moves a personal item into an organisation,
     * cb_setCollections(collectionIds) changes an organisation item's collections
     */
    var cb_share: ((String, List<String>) -> Unit)? = null
    var cb_setCollections: ((List<String>) -> Unit)? = null
    var cb_duplicate: (() -> Unit)? = null

    var name by mutableStateOf("")

    /*
     * id "" is a new item that hasn't been saved yet
     */
    var id by mutableStateOf("")
    var folderId by mutableStateOf("")
    var type by mutableStateOf(ItemType.Login)
    var icon by mutableStateOf<ClientwardenImage>(ClientwardenImage.ImageIcon(Lucide.Globe))
    var editable by mutableStateOf(false)
    var favorite by mutableStateOf(false)
    var reprompt by mutableStateOf(false)
    var canEdit by mutableStateOf(true)
    var deleted by mutableStateOf(false)
    var archived by mutableStateOf(false)
    var organizationId by mutableStateOf<String?>(null)
    var collectionIds = mutableStateListOf<String>()

    var itemHistory = mutableStateListOf<String>()
    var passwordHistory = mutableStateListOf<PasswordHistoryItem>()
    var notesData by mutableStateOf(GenericItemData("Notes", "", GenericItemType.ML_Generic))

    var genericItems = mutableStateListOf<GenericItemData>()
    var fieldItems = mutableStateListOf<FieldItemData>()
    var attachmentItems = mutableStateListOf<AttachmentItemData>()

    fun clear() {
        id = ""
        name = ""
        folderId = ""
        editable = false
        favorite = false
        reprompt = false
        canEdit = true
        deleted = false
        archived = false
        organizationId = null
        collectionIds.clear()
        itemHistory.clear()
        passwordHistory.clear()
        notesData = GenericItemData("Notes", "", GenericItemType.ML_Generic)
        genericItems.clear()
        fieldItems.clear()
        attachmentItems.clear()
    }

    @Composable
    fun folderButton(e_change: (Boolean) -> Unit, option: ClientwardenFolder) {
        TextButton(
            onClick = {
                folderId = option.id
                cb_folder?.invoke(option.id)
                e_change(false)
            },
            modifier = Modifier.fillMaxWidth(),
            shape = RectangleShape
        ) {
            Row(
                modifier = Modifier.fillMaxWidth()
                    .padding(start = 6.dp),
                horizontalArrangement = Arrangement.Start,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = Lucide.Folder,
                    contentDescription = null,
                    modifier = Modifier.size(ButtonDefaults.IconSize)
                )
                Spacer(modifier = Modifier.size(ButtonDefaults.IconSpacing))
                Text(
                    option.name
                )
            }
        }
    }
    
    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    fun view() {
        var f_expanded by remember { mutableStateOf(false) }
        var pw_expanded by remember { mutableStateOf(false) }
        var s_expanded by remember { mutableStateOf(false) }
        var c_expanded by remember { mutableStateOf(false) }
        val l_org = NavScreen.organizations.firstOrNull { it.id == organizationId }

        Column(modifier = Modifier.fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp, 0.dp, 16.dp, 16.dp), horizontalAlignment = Alignment.Start) {
            /*
             * First Row - Item Detail
             * This contains the Item's Icon, Name/Type, Favorite
             */
            Row(modifier = Modifier.fillMaxWidth()
                .clip(RoundedCornerShape(16.dp))
                .background(MaterialTheme.colorScheme.surfaceContainerHigh),
                verticalAlignment = Alignment.CenterVertically) {
                Column {
                    /*
                     * Details Row
                     */
                    Row(modifier = Modifier.padding(top = 16.dp, start = 16.dp, end = 16.dp, bottom = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .size(38.dp)
                                .background(
                                    color = MaterialTheme.colorScheme.primary,
                                    shape = CircleShape
                                ),
                            contentAlignment = Alignment.Center
                        ) {
                            icon.view(contentDesc = "Item Icon")
                        }

                        /*
                         * Item Name/Type
                         */
                        Column(modifier = Modifier.padding(start = 12.dp)) {
                            AnimatedContent(
                                targetState = editable,
                                transitionSpec = {
                                    fadeIn(tween(200, delayMillis = 80)) togetherWith fadeOut(tween(80))
                                },
                                label = "nameEditable"
                            ) { i_editable ->
                                if (i_editable) {
                                    BasicTextView(name, { name = it },
                                        modifier = Modifier.size(200.dp, 32.dp).padding(bottom = 4.dp),
                                        textStyle = MaterialTheme.typography.bodySmall)
                                } else {
                                    Text(name, fontSize = 20.sp, lineHeight = 20.sp)
                                }
                            }
                            Text(type.desc, fontSize = 12.sp, lineHeight = 12.sp)
                        }

                        Spacer(modifier = Modifier.weight(1f).fillMaxWidth())

                        /*
                         * Favorite Button
                         *
                         * Here, we are using Button instead of Icon Button,
                         * because I want to use a more transparent ripple
                         * effect.
                         */
                        Button(
                            onClick = {
                                favorite = !favorite
                                cb_favorite?.invoke(favorite)
                            },
                            modifier = Modifier.size(42.dp),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = Color.Transparent
                            ),
                            contentPadding = PaddingValues(0.dp),
                            elevation = null
                        ) {
                            Icon(
                                if (favorite) Lucide.Star else Lucide.StarOff,
                                contentDescription = "Favorite",
                                tint = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.size(22.dp)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    HorizontalDivider(modifier = Modifier.padding(horizontal = 12.dp))

                    /*
                     * Folder Row
                     */
                    Row(modifier = Modifier.fillMaxWidth()) {
                        ExposedDropdownMenuBox(
                            expanded = f_expanded,
                            onExpandedChange = { f_expanded = it },
                            modifier = Modifier.fillMaxWidth().height(48.dp)
                        ) {
                            TextButton(onClick = { },
                                modifier = Modifier.fillMaxWidth()
                                    .weight(1f)
                                    .fillMaxHeight()
                                    .menuAnchor(MenuAnchorType.PrimaryNotEditable, true),
                                shape = RectangleShape) {
                                Row(
                                    modifier = Modifier.fillMaxWidth().padding(start = 6.dp),
                                    horizontalArrangement = Arrangement.Start,
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        imageVector = Lucide.Folder,
                                        contentDescription = null,
                                        modifier = Modifier.size(ButtonDefaults.IconSize)
                                    )
                                    Spacer(modifier = Modifier.size(ButtonDefaults.IconSpacing))

                                    val l_folder = NavScreen.folders.firstOrNull { it.id == folderId }
                                        ?: ClientwardenFolder(id = "", name = "No Folder")

                                    Text(
                                        l_folder.name
                                    )
                                }
                            }
                        }
                    }

                    if (f_expanded) {
                        /*
                         * I've decided to move the divider outside
                         * bc otherwise it gets lost when the user
                         * scrolls down
                         */
                        HorizontalDivider(
                            modifier = Modifier.padding(
                                horizontal = 12.dp,
                                vertical = 0.dp
                            )
                        )
                    }

                    /*
                     * Animated Folder View thing
                     */
                    AnimatedVisibility(
                        visible = f_expanded,
                        enter = expandVertically() + fadeIn(),
                        exit = shrinkVertically() + fadeOut()
                    ) {
                        Column(modifier = Modifier.heightIn(max = 200.dp)
                            .verticalScroll(rememberScrollState())) {
                            folderButton(e_change = { f_expanded = it }, ClientwardenFolder(id = "", name = "No Folder"))

                            NavScreen.folders.forEach { option ->
                                folderButton(e_change = { f_expanded = it }, option)
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.padding(vertical = 8.dp))

            HorizontalDivider()

            Spacer(modifier = Modifier.padding(vertical = 8.dp))

            /*
             * Organisation row: which organisation and collections the item lives in, and
             * sharing personal items into one
             */
            if (l_org != null) {
                val l_names = l_org.collections.filter { it.id in collectionIds }.joinToString { it.name }
                Row(verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(MaterialTheme.colorScheme.surfaceContainerHigh)
                        .padding(12.dp)) {
                    Icon(Lucide.Building2, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(l_org.name)
                        if (l_names.isNotEmpty()) {
                            Text(l_names, style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                    if (canEdit && !deleted && id.isNotEmpty()) {
                        TextButton(onClick = { c_expanded = true }) { Text("Collections") }
                    }
                }

                Spacer(modifier = Modifier.padding(vertical = 8.dp))
            } else if (id.isNotEmpty() && !deleted && !editable &&
                NavScreen.organizations.any { it.enabled && it.keyAvailable }) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                    TextButton(onClick = { cb_duplicate?.invoke() }) {
                        Text("Duplicate")
                    }
                    TextButton(onClick = { s_expanded = true }) {
                        Icon(Lucide.Share2, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Move to organisation")
                    }
                }

                Spacer(modifier = Modifier.padding(vertical = 4.dp))
            } else if (id.isNotEmpty() && !deleted && !editable) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                    TextButton(onClick = { cb_duplicate?.invoke() }) {
                        Text("Duplicate")
                    }
                }
            }

            for (genericItem in genericItems) {
                /*
                 * Empty fields only clutter the view (identities have 18 of them)
                 */
                if (!editable && genericItem.value.isEmpty()) {
                    continue
                }

                key(System.identityHashCode(genericItem)) {
                    AnimatedContent(
                        targetState = editable,
                        transitionSpec = {
                            fadeIn(tween(200, delayMillis = 80)) togetherWith fadeOut(tween(80))
                        },
                        label = "genericItemEditable"
                    ) { i_editable ->
                        GenericItem(genericItem, i_editable && genericItem.key.isNotEmpty()).view()
                    }
                }

                Spacer(modifier = Modifier.padding(vertical = 8.dp))
            }

            if (editable || notesData.value.isNotEmpty()) {
                AnimatedContent(
                    targetState = editable,
                    transitionSpec = {
                        fadeIn(tween(200, delayMillis = 80)) togetherWith fadeOut(tween(80))
                    },
                    label = "genericItemNotesEditable"
                ) { i_editable ->
                    GenericItem(notesData, i_editable).view()
                }

                Spacer(modifier = Modifier.padding(vertical = 8.dp))
            }

            if (editable) {
                Row(verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(MaterialTheme.colorScheme.surfaceContainerHigh)
                        .padding(horizontal = 12.dp)) {
                    Text("Master password re-prompt", modifier = Modifier.weight(1f))
                    Switch(checked = reprompt, onCheckedChange = { reprompt = it },
                        modifier = Modifier.scale(0.75f))
                }

                Spacer(modifier = Modifier.padding(vertical = 8.dp))
            }

            HorizontalDivider()

            Spacer(modifier = Modifier.padding(vertical = 8.dp))

            for (fieldItem in fieldItems) {
                key(System.identityHashCode(fieldItem)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(modifier = Modifier.weight(1f)) {
                            AnimatedContent(
                                targetState = editable,
                                transitionSpec = {
                                    fadeIn(tween(200, delayMillis = 80)) togetherWith fadeOut(tween(80))
                                },
                                label = "fieldItemEditable"
                            ) { i_editable ->
                                FieldItem(fieldItem, i_editable).view()
                            }
                        }

                        if (editable) {
                            IconButton(onClick = { fieldItems.removeAll { it === fieldItem } }) {
                                Icon(Lucide.X, contentDescription = "Remove field",
                                    modifier = Modifier.size(18.dp))
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.padding(vertical = 8.dp))
            }

            if (editable) {
                Row {
                    for ((l_type, l_label) in listOf(FieldItemType.Text to "Text", FieldItemType.Hidden to "Hidden",
                        FieldItemType.Checkbox to "Checkbox", FieldItemType.Linked to "Linked")) {
                        if (l_type == FieldItemType.Linked &&
                            type != ItemType.Login && type != ItemType.Card && type != ItemType.Identity) {
                            continue
                        }
                        TextButton(onClick = {
                            fieldItems.add(FieldItemData(if (l_type == FieldItemType.Checkbox) "New field" else "",
                                if (l_type == FieldItemType.Checkbox) "false" else "", l_type, type))
                        }) {
                            Text("+ $l_label")
                        }
                    }
                }

                Spacer(modifier = Modifier.padding(vertical = 8.dp))
            }

            if (fieldItems.isNotEmpty() || editable) {
                HorizontalDivider()

                Spacer(modifier = Modifier.padding(vertical = 8.dp))
            }

            for (attachmentItems in attachmentItems) {
                AnimatedContent(
                    targetState = editable,
                    transitionSpec = {
                        fadeIn(tween(200, delayMillis = 80)) togetherWith fadeOut(tween(80))
                    },
                    label = "attachmentItemEditable"
                ) { i_editable ->
                    AttachmentItem(attachmentItems, i_editable).view()
                }

                Spacer(modifier = Modifier.padding(vertical = 8.dp))
            }

            if (id.isNotEmpty() && !editable && !deleted && canEdit) {
                TextButton(onClick = { cb_addAttachment?.invoke() }) {
                    Icon(Lucide.Paperclip, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Add attachment")
                }

                Spacer(modifier = Modifier.padding(vertical = 4.dp))
            }

            if (attachmentItems.isNotEmpty()) {
                HorizontalDivider()

                Spacer(modifier = Modifier.padding(vertical = 8.dp))
            }

            for (item in itemHistory) {
                Text(item, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant)
            }

            if (passwordHistory.isNotEmpty()) {
                Text("View Password History", style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(top = 4.dp).clickable {
                        pw_expanded = true
                    }
                )
            }
        }

        if (pw_expanded) {
            AlertDialog(
                onDismissRequest = { pw_expanded = false }, title = { Text("Password History") },
                text = {
                    Column(
                        modifier = Modifier
                            .heightIn(max = 400.dp)
                            .verticalScroll(rememberScrollState())
                    ) {
                        for (pwHist in passwordHistory) {
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(12.dp))
                                    .background(MaterialTheme.colorScheme.surfaceContainerHighest)
                                    .padding(12.dp)
                            ) {
                                /*
                                 * Date Text
                                 */
                                Text(
                                    pwHist.date,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    style = MaterialTheme.typography.bodySmall
                                )

                                HorizontalDivider(
                                    modifier = Modifier.padding(
                                        0.dp,
                                        4.dp,
                                        0.dp,
                                        8.dp
                                    )
                                )

                                /*
                                 * Password
                                 */
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text(
                                        pwHist.password,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                        style = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                                        modifier = Modifier.weight(1f)
                                    )
                                    IconButton(
                                        onClick = { GenericItem.cb_copy?.invoke(pwHist.password, true) },
                                        modifier = Modifier.size(18.dp)
                                    ) {
                                        Icon(Lucide.Copy, contentDescription = "Copy")
                                    }
                                }
                            }

                            Spacer(modifier = Modifier.padding(vertical = 8.dp))
                        }
                    }
                },
                confirmButton = {
                    TextButton(onClick = { pw_expanded = false }) {
                        Text("Done")
                    }
                }
            )
        }

        if (s_expanded) {
            CollectionPicker(
                title = "Move to organisation",
                organizations = NavScreen.organizations.filter { it.enabled && it.keyAvailable },
                initialOrganization = null,
                initialCollections = emptyList(),
                onDismiss = { s_expanded = false },
                onConfirm = { org, collections ->
                    s_expanded = false
                    cb_share?.invoke(org, collections)
                }
            )
        }

        if (c_expanded && l_org != null) {
            CollectionPicker(
                title = "Collections",
                organizations = listOf(l_org),
                initialOrganization = l_org.id,
                initialCollections = collectionIds.toList(),
                onDismiss = { c_expanded = false },
                onConfirm = { _, collections ->
                    c_expanded = false
                    cb_setCollections?.invoke(collections)
                }
            )
        }
    }

    /*
     * Picks an organisation (if there's more than one) and the writable collections in it.
     * Organisation items must be in at least one collection.
     */
    @Composable
    fun CollectionPicker(title: String, organizations: List<VaultOrganization>, initialOrganization: String?,
                         initialCollections: List<String>, onDismiss: () -> Unit,
                         onConfirm: (String, List<String>) -> Unit) {
        var l_org by remember { mutableStateOf(initialOrganization ?: organizations.firstOrNull()?.id ?: "") }
        val l_selected = remember { mutableStateListOf<String>().apply { addAll(initialCollections) } }

        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(title) },
            text = {
                Column(modifier = Modifier.heightIn(max = 400.dp).verticalScroll(rememberScrollState())) {
                    if (organizations.size > 1) {
                        for (org in organizations) {
                            Row(verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.fillMaxWidth().clickable {
                                    l_org = org.id
                                    l_selected.clear()
                                }) {
                                RadioButton(selected = l_org == org.id, onClick = {
                                    l_org = org.id
                                    l_selected.clear()
                                })
                                Text(org.name)
                            }
                        }

                        HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
                    }

                    val l_collections = organizations.firstOrNull { it.id == l_org }?.collections
                        ?.filter { !it.readOnly } ?: emptyList()
                    if (l_collections.isEmpty()) {
                        Text("You can't add items to any collection in this organisation.",
                            style = MaterialTheme.typography.bodySmall)
                    }
                    for (collection in l_collections) {
                        Row(verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier.fillMaxWidth().clickable {
                                if (collection.id in l_selected) l_selected.remove(collection.id)
                                else l_selected.add(collection.id)
                            }) {
                            Checkbox(checked = collection.id in l_selected, onCheckedChange = {
                                if (it) l_selected.add(collection.id) else l_selected.remove(collection.id)
                            })
                            Text(collection.name)
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(enabled = l_org.isNotEmpty() && l_selected.isNotEmpty(),
                    onClick = { onConfirm(l_org, l_selected.toList()) }) {
                    Text("Save")
                }
            },
            dismissButton = {
                TextButton(onClick = onDismiss) { Text("Cancel") }
            }
        )
    }
}

@Preview(
    showBackground = true,
    showSystemUi = true,
    device = Devices.PIXEL_9,
    uiMode = Configuration.UI_MODE_NIGHT_YES
)
@Composable
fun PreviewDetails() {
    VaultUI()
}