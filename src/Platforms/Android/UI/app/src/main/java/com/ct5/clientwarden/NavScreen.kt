package com.ct5.clientwarden

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.OutlinedTextField
import androidx.compose.runtime.mutableStateListOf
import com.composables.icons.lucide.Building2
import com.composables.icons.lucide.User

import android.content.res.Configuration
import android.graphics.fonts.Font
import androidx.compose.animation.core.MutableTransitionState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.IntrinsicSize
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Devices
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.Popup
import com.composables.icons.lucide.Archive
import com.composables.icons.lucide.ArrowRight
import com.composables.icons.lucide.CreditCard
import com.composables.icons.lucide.EllipsisVertical
import com.composables.icons.lucide.Folder
import com.composables.icons.lucide.House
import com.composables.icons.lucide.IdCard
import com.composables.icons.lucide.KeyRound
import com.composables.icons.lucide.Lucide
import com.composables.icons.lucide.Plus
import com.composables.icons.lucide.SquareAsterisk
import com.composables.icons.lucide.Star
import com.composables.icons.lucide.StickyNote
import com.composables.icons.lucide.Trash2
import com.composables.icons.lucide.X
import java.util.UUID

sealed interface NavItem {
    data object AllItems : NavItem
    data object Favorites : NavItem
    data object Trash : NavItem
    data object Archived : NavItem
    data object Login : NavItem
    data object Card : NavItem
    data object Identity : NavItem
    data object Note : NavItem
    data object SshKey : NavItem
    data object BankAccount : NavItem
    data object DriversLicense : NavItem
    data object Passport : NavItem
    data class Folder(val id: String) : NavItem
    data object Personal : NavItem
    data class Organization(val id: String) : NavItem
    data class Collection(val id: String, val organizationId: String) : NavItem
    data object None : NavItem
}

object NavScreen {
    var folders = mutableStateListOf<ClientwardenFolder>()
    var organizations = mutableStateListOf<VaultOrganization>()
    var c_item by mutableStateOf<NavItem>(NavItem.AllItems)

    /*
     * cb_open shows the items for a nav entry
     */
    var cb_open: ((NavItem) -> Unit)? = null
    var cb_NewFolder: ((name: String) -> Unit)? = null
    var cb_RenameFolder: ((id: String, name: String) -> Unit)? = null
    var cb_DeleteFolder: ((id: String) -> Unit)? = null

    /*
     * Collections, for organisation members allowed to manage them
     */
    var cb_NewCollection: ((organizationId: String, name: String) -> Unit)? = null
    var cb_RenameCollection: ((id: String, name: String) -> Unit)? = null
    var cb_DeleteCollection: ((id: String) -> Unit)? = null

    @Composable
    fun NavButton(text: String, icon: ImageVector, item: NavItem,
                  onClick: () -> Unit = {}, start: Boolean = false,
                  end: Boolean = false, addEllipses: Boolean = false,
                  kind: String = "Folder", onRename: ((String) -> Unit)? = null,
                  onDelete: (() -> Unit)? = null) {
        var m_expanded by remember { mutableStateOf(false) }
        var m_renameExpanded by remember { mutableStateOf(false) }
        var m_deleteExpanded by remember { mutableStateOf(false) }
        /*
         * A Mat You Button with a custom BG Color
         */
        FilledTonalButton(onClick = {
            if (item != NavItem.None) {
                c_item = item
            }
            onClick()
        },
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
                 * Nav Item Icon
                 */
                Icon(icon,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSecondaryContainer,
                    modifier = Modifier.size(20.dp))

                Spacer(Modifier.width(8.dp))

                /*
                 * Nav Item Name
                 */
                Text(text,
                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                    overflow = TextOverflow.Ellipsis,
                    maxLines = 1)

                Spacer(Modifier.weight(1f).fillMaxWidth())

                /*
                 * Ellipses Box
                 * Stores the Ellipses Button and Dropdown
                 */
                if (addEllipses) {
                    Box {
                        /*
                         * Ellipses Button
                         */
                        IconButton(
                            onClick = { m_expanded = true }
                        ) {
                            Icon(
                                Lucide.EllipsisVertical,
                                contentDescription = "More",
                                tint = MaterialTheme.colorScheme.onSecondaryContainer,
                                modifier = Modifier.size(20.dp)
                            )
                        }

                        val transitionState = remember { MutableTransitionState(false) }
                        transitionState.targetState = m_expanded

                        /*
                         * Thanks to Claude for the Animated Visibility,
                         * although the Popup stuff was mine
                         */
                        if (transitionState.currentState || transitionState.targetState) {
                            Popup(
                                alignment = Alignment.TopEnd,
                                onDismissRequest = { m_expanded = false }
                            ) {
                                androidx.compose.animation.AnimatedVisibility(
                                    visibleState = transitionState,
                                    enter = fadeIn(tween(120)) + scaleIn(
                                        initialScale = 0.85f,
                                        animationSpec = tween(120),
                                        transformOrigin = androidx.compose.ui.graphics.TransformOrigin(
                                            1f,
                                            0f
                                        )
                                    ),
                                    exit = fadeOut(tween(100)) + scaleOut(
                                        targetScale = 0.85f,
                                        animationSpec = tween(280),
                                        transformOrigin = androidx.compose.ui.graphics.TransformOrigin(
                                            1f,
                                            0f
                                        )
                                    )
                                ) {
                                    Surface(
                                        shape = RoundedCornerShape(8.dp),
                                        color = MaterialTheme.colorScheme.surfaceContainerHighest,
                                        tonalElevation = 3.dp,
                                        modifier = Modifier.padding(
                                            horizontal = 8.dp,
                                            vertical = 0.dp
                                        )
                                    ) {
                                        Column(
                                            modifier = Modifier.padding(
                                                horizontal = 0.dp,
                                                vertical = 0.dp
                                            )
                                        ) {
                                            /*
                                             * Rename Folder Button
                                             */
                                            TextButton(
                                                onClick = {
                                                    m_expanded = false
                                                    m_renameExpanded = true
                                                },
                                                shape = RoundedCornerShape(
                                                    topStart = 8.dp,
                                                    topEnd = 8.dp,
                                                    bottomStart = 0.dp,
                                                    bottomEnd = 0.dp
                                                ),
                                                modifier = Modifier.width(100.dp)
                                            ) {
                                                Text(
                                                    "Rename",
                                                    textAlign = TextAlign.Left,
                                                    modifier = Modifier.fillMaxWidth()
                                                )
                                            }

                                            /*
                                             * Delete Folder Button
                                             */
                                            TextButton(
                                                onClick = {
                                                    m_expanded = false
                                                    m_deleteExpanded = true
                                                },
                                                shape = RoundedCornerShape(
                                                    topStart = 8.dp,
                                                    topEnd = 8.dp,
                                                    bottomStart = 0.dp,
                                                    bottomEnd = 0.dp
                                                ),
                                                modifier = Modifier.width(100.dp)
                                            ) {
                                                Text(
                                                    "Delete",
                                                    textAlign = TextAlign.Left,
                                                    modifier = Modifier.fillMaxWidth()
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        var s_folderName by remember(m_renameExpanded) { mutableStateOf(text) }

        /*
         * Prompt to ask for New Folder Name
         */
        if (m_renameExpanded) {
            Dialog(
                onDismissRequest = {
                    m_renameExpanded = false
                },
                properties = DialogProperties(
                    usePlatformDefaultWidth = false
                ),
            ) {
                Surface(color = MaterialTheme.colorScheme.surfaceContainer, shape = RoundedCornerShape(32.dp)) {
                    Column(
                        modifier = Modifier
                            .padding(24.dp)
                            .width(300.dp),
                        verticalArrangement = Arrangement.Center
                    ) {
                        Text(
                            text = "Rename $kind",
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold
                        )

                        Spacer(Modifier.height(24.dp))

                        Row(verticalAlignment = Alignment.CenterVertically) {
                            /*
                             * Custom Text Field
                             * We are using a custom text field here
                             * bc the mat you one has to be thicc, but
                             * I need it to be thin
                             */
                            BasicTextField(
                                value = s_folderName,
                                onValueChange = {
                                    s_folderName = it
                                },
                                modifier = Modifier.weight(1f)
                                    .height(34.dp)
                                    .background(
                                        color = MaterialTheme.colorScheme.surfaceContainerHighest,
                                        shape = RoundedCornerShape(32.dp)
                                    )
                                    .padding(horizontal = 14.dp, vertical = 8.dp),
                                singleLine = true,
                                textStyle = MaterialTheme.typography.bodyMedium.copy(
                                    color = MaterialTheme.colorScheme.onSurface
                                ),
                                cursorBrush = SolidColor(
                                    MaterialTheme.colorScheme.primary
                                )
                            )

                            Spacer(Modifier.width(12.dp))

                            FilledIconButton(
                                onClick = {
                                    m_renameExpanded = false
                                    onRename?.invoke(s_folderName)
                                },
                                modifier = Modifier.size(32.dp)
                            ) {
                                Icon(
                                    Lucide.ArrowRight,
                                    contentDescription = "Rename",
                                    modifier = Modifier.size(18.dp)
                                )
                            }
                        }
                    }
                }
            }
        }

        /*
         * Prompt to Ask for Folder Deletion
         * Confirmation
         */
        if (m_deleteExpanded) {
            Dialog(
                onDismissRequest = {
                    m_deleteExpanded = false
                },
                properties = DialogProperties(
                    usePlatformDefaultWidth = false
                ),
            ) {
                Surface(color = MaterialTheme.colorScheme.surfaceContainer, shape = RoundedCornerShape(32.dp)) {
                    Column(
                        modifier = Modifier
                            .padding(24.dp)
                            .width(300.dp),
                        verticalArrangement = Arrangement.Center
                    ) {
                        Text(
                            text = "Delete $kind",
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold
                        )

                        Spacer(Modifier.height(8.dp))

                        Text(
                            text = "Are you sure you would like to delete this ${kind.lowercase()}? This is an irreversible action!",
                            style = MaterialTheme.typography.bodyMedium
                        )

                        Spacer(Modifier.height(8.dp))

                        TextButton(
                            onClick = {
                                m_deleteExpanded = false
                                onDelete?.invoke()
                            },
                            colors = ButtonDefaults.textButtonColors(
                                containerColor = MaterialTheme.colorScheme.primary,
                                contentColor = MaterialTheme.colorScheme.onPrimary
                            )
                        ) {
                            Text("Continue")
                        }
                    }
                }
            }
        }
    }

    @Composable
    fun view() {
        var addFolder_expanded by remember { mutableStateOf(false) }
        var addCollection_org by remember { mutableStateOf<String?>(null) }
        var s_folderName by remember { mutableStateOf("New Folder") }
        Column(
            modifier = Modifier.fillMaxSize()
                               .verticalScroll(rememberScrollState())
                               .padding(16.dp, 0.dp, 16.dp, 16.dp)
        ) {
            /*
             * Main Nav Items
             */
            NavButton("All Items", Lucide.House, NavItem.AllItems,
                start = true, onClick = { cb_open?.invoke(NavItem.AllItems) })
            NavButton("Favorites", Lucide.Star, NavItem.Favorites,
                onClick = { cb_open?.invoke(NavItem.Favorites) })
            NavButton("Trash", Lucide.Trash2, NavItem.Trash,
                onClick = { cb_open?.invoke(NavItem.Trash) })
            NavButton("Archived", Lucide.Archive, NavItem.Archived,
                end = true, onClick = { cb_open?.invoke(NavItem.Archived) })

            Spacer(modifier = Modifier.height(16.dp))

            /*
             * Item Type Nav Items
             */
            NavButton("Login", Lucide.SquareAsterisk, NavItem.Login,
                start = true, onClick = { cb_open?.invoke(NavItem.Login) })
            NavButton("Card", Lucide.CreditCard, NavItem.Card,
                onClick = { cb_open?.invoke(NavItem.Card) })
            NavButton("Identity", Lucide.IdCard, NavItem.Identity,
                onClick = { cb_open?.invoke(NavItem.Identity) })
            NavButton("Note", Lucide.StickyNote, NavItem.Note,
                onClick = { cb_open?.invoke(NavItem.Note) })
            NavButton("SSH Key", Lucide.KeyRound, NavItem.SshKey, end = !TopBar.extendedTypes,
                onClick = { cb_open?.invoke(NavItem.SshKey) })
            if (TopBar.extendedTypes) {
                NavButton(ItemType.BankAccount.desc, ItemType.BankAccount.icon, NavItem.BankAccount,
                    onClick = { cb_open?.invoke(NavItem.BankAccount) })
                NavButton(ItemType.DriversLicense.desc, ItemType.DriversLicense.icon, NavItem.DriversLicense,
                    onClick = { cb_open?.invoke(NavItem.DriversLicense) })
                NavButton(ItemType.Passport.desc, ItemType.Passport.icon, NavItem.Passport, end = true,
                    onClick = { cb_open?.invoke(NavItem.Passport) })
            }

            Spacer(modifier = Modifier.height(16.dp))

            /*
             * Organisations and their collections
             */
            if (organizations.isNotEmpty()) {
                NavButton("My Vault", Lucide.User, NavItem.Personal, start = true,
                    onClick = { cb_open?.invoke(NavItem.Personal) })

                for ((i, org) in organizations.withIndex()) {
                    val l_last = i == organizations.lastIndex
                    NavButton(if (org.keyAvailable) org.name else "${org.name} (unavailable)",
                        Lucide.Building2, NavItem.Organization(org.id),
                        end = l_last && org.collections.isEmpty() && !org.canManageCollections,
                        onClick = { cb_open?.invoke(NavItem.Organization(org.id)) })

                    for ((j, collection) in org.collections.withIndex()) {
                        NavButton("    " + collection.name, Lucide.Folder,
                            NavItem.Collection(collection.id, org.id),
                            end = l_last && j == org.collections.lastIndex && !org.canManageCollections,
                            onClick = { cb_open?.invoke(NavItem.Collection(collection.id, org.id)) },
                            addEllipses = org.canManageCollections || collection.manage,
                            kind = "Collection",
                            onRename = { cb_RenameCollection?.invoke(collection.id, it) },
                            onDelete = { cb_DeleteCollection?.invoke(collection.id) })
                    }

                    if (org.canManageCollections && org.keyAvailable) {
                        NavButton("    Add Collection", Lucide.Plus, NavItem.None, end = l_last,
                            onClick = { addCollection_org = org.id })
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))
            }

            /*
             * Folder Nav Items
             */
            for ((i, folder) in folders.withIndex()) {
                NavButton(folder.name, Lucide.Folder,
                    NavItem.Folder(folder.id), start = i == 0,
                    onClick = {
                        cb_open?.invoke(NavItem.Folder(folder.id))
                    }, addEllipses = true,
                    onRename = { cb_RenameFolder?.invoke(folder.id, it) },
                    onDelete = { cb_DeleteFolder?.invoke(folder.id) }
                )
            }

            /*
             * Add Folder Button
             */
            NavButton("Add Folder", Lucide.Plus, NavItem.None,
                start = if (folders.size == 0) true else false, end = true,
                onClick = {
                    addFolder_expanded = true
                }
            )
        }

        val l_collectionOrg = addCollection_org
        if (l_collectionOrg != null) {
            var l_name by remember { mutableStateOf("") }
            AlertDialog(
                onDismissRequest = { addCollection_org = null },
                title = { Text("Create Collection") },
                text = {
                    OutlinedTextField(value = l_name, onValueChange = { l_name = it },
                        singleLine = true, label = { Text("Name") })
                },
                confirmButton = {
                    TextButton(enabled = l_name.isNotBlank(), onClick = {
                        addCollection_org = null
                        cb_NewCollection?.invoke(l_collectionOrg, l_name)
                    }) { Text("Create") }
                },
                dismissButton = {
                    TextButton(onClick = { addCollection_org = null }) { Text("Cancel") }
                }
            )
        }

        /*
         * Prompt to ask for New Folder Name
         */
        if (addFolder_expanded) {
            Dialog(
                onDismissRequest = {
                    addFolder_expanded = false
                },
                properties = DialogProperties(
                    usePlatformDefaultWidth = false
                ),
            ) {
                Surface(color = MaterialTheme.colorScheme.surfaceContainer, shape = RoundedCornerShape(32.dp)) {
                    Column(
                        modifier = Modifier
                            .padding(24.dp)
                            .width(300.dp),
                        verticalArrangement = Arrangement.Center
                    ) {
                        Text(
                            text = "Create Folder",
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold
                        )

                        Spacer(Modifier.height(24.dp))

                        Row(verticalAlignment = Alignment.CenterVertically) {
                            /*
                             * Custom Text Field
                             * We are using a custom text field here
                             * bc the mat you one has to be thicc, but
                             * I need it to be thin
                             */
                            BasicTextField(
                                value = s_folderName,
                                onValueChange = {
                                    s_folderName = it
                                },
                                modifier = Modifier.weight(1f)
                                    .height(34.dp)
                                    .background(
                                        color = MaterialTheme.colorScheme.surfaceContainerHighest,
                                        shape = RoundedCornerShape(32.dp)
                                    )
                                    .padding(horizontal = 14.dp, vertical = 6.dp),
                                singleLine = true,
                                textStyle = MaterialTheme.typography.bodyMedium.copy(
                                    color = MaterialTheme.colorScheme.onSurface
                                ),
                                cursorBrush = SolidColor(
                                    MaterialTheme.colorScheme.primary
                                )
                            )

                            Spacer(Modifier.width(12.dp))

                            FilledIconButton(
                                onClick = {
                                    addFolder_expanded = false
                                    cb_NewFolder?.invoke(s_folderName)
                                },
                                modifier = Modifier.size(32.dp)
                            ) {
                                Icon(
                                    Lucide.ArrowRight,
                                    contentDescription = "Create",
                                    modifier = Modifier.size(18.dp)
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
fun PreviewNav() {
    VaultUI()
}