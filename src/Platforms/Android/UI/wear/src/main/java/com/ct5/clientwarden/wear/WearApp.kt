package com.ct5.clientwarden.wear

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

class WearActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { WearApp() }
    }
}

/*
 * The whole watch app is one screen at a time, chosen from the vault's state, with two
 * pieces of local navigation inside the unlocked vault (an item, and settings). There is no
 * nav library: on a watch a back stack is more machinery than the UI needs.
 */
@Composable
fun WearApp() {
    val context = LocalContext.current
    LaunchedEffect(Unit) { WearCore.init(context) }

    val state = WearCore.state
    var selected by remember { mutableStateOf<WearItem?>(null) }
    var settings by remember { mutableStateOf(false) }

    LaunchedEffect(state) {
        if (state != "Unlocked") {
            selected = null
            settings = false
        }
    }

    Box(Modifier.fillMaxSize().background(Palette.Bg)) {
        when {
            state == "Unlocked" && settings -> SettingsScreen(onBack = { settings = false })
            state == "Unlocked" && selected != null -> ItemDetail(selected!!, onBack = { selected = null })
            state == "Unlocked" -> VaultScreen(onOpen = { selected = it }, onSettings = { settings = true })
            state == "Unlockable" -> UnlockScreen()
            state == "Unknown" -> LoadingScreen("Starting")
            else -> LoginScreen()
        }

        WearCore.message?.let { text ->
            Box(
                Modifier
                    .fillMaxWidth()
                    .align(Alignment.BottomCenter)
                    .padding(8.dp)
                    .clip(RoundedCornerShape(16.dp))
                    .background(Palette.PanelHigh)
                    .clickable { WearCore.clearMessage() }
                    .padding(horizontal = 12.dp, vertical = 8.dp),
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Label(text, size = 12.sp, maxLines = 3)
                    Label("tap to dismiss", size = 9.sp, color = Palette.Muted)
                }
            }
        }
    }
}
