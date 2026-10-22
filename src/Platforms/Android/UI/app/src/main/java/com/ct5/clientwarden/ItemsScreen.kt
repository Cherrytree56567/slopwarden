package com.ct5.clientwarden

import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.OutlinedTextField
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import coil.compose.AsyncImage
import java.io.File

import android.content.res.Configuration
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.MutableTransitionState
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
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
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.tooling.preview.Devices
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.DpOffset
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Popup
import com.composables.icons.lucide.Archive
import com.composables.icons.lucide.CreditCard
import com.composables.icons.lucide.EllipsisVertical
import com.composables.icons.lucide.Expand
import com.composables.icons.lucide.Folder
import com.composables.icons.lucide.FunnelPlus
import com.composables.icons.lucide.Globe
import com.composables.icons.lucide.House
import com.composables.icons.lucide.IdCard
import com.composables.icons.lucide.KeyRound
import com.composables.icons.lucide.Lucide
import com.composables.icons.lucide.SquareAsterisk
import com.composables.icons.lucide.Star
import com.composables.icons.lucide.StickyNote
import com.composables.icons.lucide.Trash2
import com.ct5.clientwarden.DetailsScreen.passwordHistory
import com.ct5.clientwarden.NavScreen.NavButton
import com.ct5.clientwarden.NavScreen.folders
import java.util.UUID
import kotlin.math.floor

/*
 * f_items = Filtered Items
 */
object ItemsScreen {
    var f_items = mutableStateListOf<ItemElement>()
    var loading by mutableStateOf(false)

    /*
     * cb_view opens an item (asking for the master password first if it needs re-prompt),
     * cb_repromptView(id, password) checks the password and opens it
     */
    var cb_repromptView: ((String, String) -> Unit)? = null
    var cb_view: ((ItemElement) -> Unit)? = null

    /*
     * The item waiting for its master password re-prompt, if any
     */
    var rp_item by mutableStateOf<String?>(null)
    var rp_failure by mutableStateOf("")

    fun SetItems(l_items: List<ItemElement>) {
        f_items.clear()
        f_items.addAll(l_items)
    }

    @Composable
    fun Item(item: ItemElement, start: Boolean = false, end: Boolean = false) {
        var m_expanded by remember { mutableStateOf(false) }
        /*
         * A filled Button that has the top corners rounded, if its the start
         * or the bottom corners rouded, if its the end.
         */
        FilledTonalButton(onClick = { cb_view?.invoke(item) },
            modifier = Modifier.fillMaxWidth()
                .height(64.dp),
            shape = RoundedCornerShape(
                topStart = if (start) 12.dp else 0.dp,
                topEnd = if (start) 12.dp else 0.dp,
                bottomStart = if (end) 12.dp else 0.dp,
                bottomEnd = if (end) 12.dp else 0.dp
            ),
            contentPadding = PaddingValues(start = 16.dp, end = 4.dp),
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
                 * Item Icon
                 * Login's will have the website icon,
                 * while everything else will have its own default
                 * material you icon
                 */
                if (item.iconPath != null) {
                    AsyncImage(
                        model = File(item.iconPath!!),
                        contentDescription = null,
                        modifier = Modifier.size(20.dp).clip(RoundedCornerShape(4.dp))
                    )
                } else {
                    Icon(item.icon,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSecondaryContainer,
                        modifier = Modifier.size(20.dp)
                    )
                }

                Spacer(Modifier.width(8.dp))

                /*
                 * Text Column
                 * Stores the Item Name and Item Type
                 */
                Column(modifier = Modifier.padding(horizontal = 4.dp)) {
                    /*
                     * Item Name
                     * Displays the Item Name
                     */
                    Text(item.name,
                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                        lineHeight = 16.sp,
                        modifier = Modifier.padding(top = 2.dp),
                        overflow = TextOverflow.Ellipsis,
                        maxLines = 1
                    )
                    /*
                     * Item Type
                     * Displays the Item Type
                     */
                    Text(if (item.subtitle.isNotEmpty()) item.subtitle else item.type.desc,
                        color = MaterialTheme.colorScheme.onSecondaryContainer,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        lineHeight = 16.sp
                    )
                }

                Spacer(Modifier.weight(1f).fillMaxWidth())

                /*
                 * Ellipses Box
                 * Stores the Ellipses Button and Dropdown
                 */
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
                     * the Popup stuff was mine
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
                                    transformOrigin = androidx.compose.ui.graphics.TransformOrigin(1f, 0f) // top-end anchor
                                ),
                                exit = fadeOut(tween(100)) + scaleOut(
                                    targetScale = 0.85f,
                                    animationSpec = tween(280),
                                    transformOrigin = androidx.compose.ui.graphics.TransformOrigin(1f, 0f)
                                )
                            ) {
                                Surface(
                                    shape = RoundedCornerShape(8.dp),
                                    color = MaterialTheme.colorScheme.surfaceContainerHighest,
                                    tonalElevation = 3.dp,
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 0.dp)
                                ) {
                                    /*
                                     * Use NavScreen.c_item to show or hide restore/delete
                                     */
                                    Column(
                                        modifier = Modifier.padding(
                                            horizontal = 0.dp,
                                            vertical = 0.dp
                                        )
                                    ) {
                                        if (NavScreen.c_item == NavItem.Trash) {
                                            /*
                                             * Restore Icon
                                             */
                                            TextButton(
                                                onClick = {
                                                    m_expanded = false
                                                    TopBar.cb_restore?.invoke(item.id)
                                                },
                                                shape = RoundedCornerShape(
                                                    topStart = 8.dp,
                                                    topEnd = 8.dp,
                                                    bottomStart = 8.dp,
                                                    bottomEnd = 8.dp
                                                ),
                                                modifier = Modifier.width(100.dp)
                                            ) {
                                                Text(
                                                    "Restore",
                                                    textAlign = TextAlign.Left,
                                                    modifier = Modifier.fillMaxWidth()
                                                )
                                            }

                                            /*
                                             * Permenently Delete Button
                                             */
                                            TextButton(
                                                onClick = {
                                                    m_expanded = false
                                                    TopBar.cb_delete?.invoke(item.id)
                                                },
                                                shape = RoundedCornerShape(
                                                    topStart = 8.dp,
                                                    topEnd = 8.dp,
                                                    bottomStart = 8.dp,
                                                    bottomEnd = 8.dp
                                                ),
                                                modifier = Modifier.width(100.dp)
                                            ) {
                                                Text(
                                                    "Permanently Delete",
                                                    textAlign = TextAlign.Left,
                                                    modifier = Modifier.fillMaxWidth()
                                                )
                                            }
                                        } else if (NavScreen.c_item == NavItem.Archived) {
                                            /*
                                             * Un Archive Button
                                             */
                                            TextButton(
                                                onClick = {
                                                    m_expanded = false
                                                    TopBar.cb_unarchive?.invoke(item.id)
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
                                                    "Unarchive",
                                                    textAlign = TextAlign.Left,
                                                    modifier = Modifier.fillMaxWidth()
                                                )
                                            }

                                            /*
                                             * Bin Button
                                             */
                                            TextButton(
                                                onClick = {
                                                    m_expanded = false
                                                    TopBar.cb_bin?.invoke(item.id)
                                                },
                                                shape = RoundedCornerShape(
                                                    topStart = 0.dp,
                                                    topEnd = 0.dp,
                                                    bottomStart = 8.dp,
                                                    bottomEnd = 8.dp
                                                ),
                                                modifier = Modifier.width(100.dp)
                                            ) {
                                                Text(
                                                    "Bin",
                                                    textAlign = TextAlign.Left,
                                                    modifier = Modifier.fillMaxWidth()
                                                )
                                            }
                                        } else {
                                            /*
                                             * Bin Button
                                             * again
                                             */
                                            TextButton(
                                                onClick = {
                                                    m_expanded = false
                                                    TopBar.cb_bin?.invoke(item.id)
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
                                                    "Bin",
                                                    textAlign = TextAlign.Left,
                                                    modifier = Modifier.fillMaxWidth()
                                                )
                                            }

                                            /*
                                             * Archive Button
                                             */
                                            TextButton(
                                                onClick = {
                                                    m_expanded = false
                                                    TopBar.cb_archive?.invoke(item.id)
                                                },
                                                shape = RoundedCornerShape(
                                                    topStart = 0.dp,
                                                    topEnd = 0.dp,
                                                    bottomStart = 8.dp,
                                                    bottomEnd = 8.dp
                                                ),
                                                modifier = Modifier.width(100.dp)
                                            ) {
                                                Text(
                                                    "Archive",
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

        /*
         * Add a horizontal Divider to allow the user
         * to see the end of each button and to differentiate
         * each button separately
         */
        if (!end) {
            Column(modifier = Modifier.fillMaxWidth()
                                      .background(color = MaterialTheme.colorScheme.surfaceContainerHigh)) {
                HorizontalDivider(modifier = Modifier.padding(horizontal = 12.dp))
            }
        }
    }

    @Composable
    fun view() {
        Column(
            modifier = Modifier.fillMaxWidth()
                               .padding(16.dp)
                               .clip(RoundedCornerShape(16.dp))
                               .verticalScroll(rememberScrollState())
        ) {
            if (f_items.isEmpty()) {
                Text(
                    if (loading) "Loading…" else "No items",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.fillMaxWidth().padding(24.dp),
                    textAlign = TextAlign.Center
                )
            }

            /*
             * Display all items and set Start if the
             * index is 0 and set End if it is the last Index
             */
            for ((i, item) in f_items.withIndex()) {
                key(item.id) {
                    Item(item, start = i == 0, end = i == f_items.lastIndex)
                }
            }
        }

        val pending = rp_item
        if (pending != null) {
            var password by remember { mutableStateOf("") }
            AlertDialog(
                onDismissRequest = {
                    rp_item = null
                    rp_failure = ""
                },
                title = { Text("Master Password") },
                text = {
                    Column {
                        Text("This item is protected. Enter your master password to view it.",
                            style = MaterialTheme.typography.bodySmall)
                        Spacer(modifier = Modifier.height(8.dp))
                        OutlinedTextField(
                            value = password,
                            onValueChange = { password = it },
                            visualTransformation = PasswordVisualTransformation(),
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                        AnimatedVisibility(
                            visible = rp_failure != "",
                            enter = expandVertically() + fadeIn(),
                            exit = shrinkVertically() + fadeOut()
                        ) {
                            Column {
                                Spacer(modifier = Modifier.height(4.dp))
                                Text(rp_failure, color = MaterialTheme.colorScheme.error)
                            }
                        }
                    }
                },
                confirmButton = {
                    TextButton(onClick = {
                        cb_repromptView?.invoke(pending, password)
                        password = ""
                    }) {
                        Text("Done")
                    }
                },
                dismissButton = {
                    TextButton(onClick = {
                        rp_item = null
                        rp_failure = ""
                    }) {
                        Text("Cancel")
                    }
                }
            )
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
fun PreviewItems() {
    VaultUI()
}