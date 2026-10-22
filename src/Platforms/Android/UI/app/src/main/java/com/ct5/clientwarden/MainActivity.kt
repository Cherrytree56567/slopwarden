package com.ct5.clientwarden

import android.annotation.SuppressLint
import android.content.res.Configuration
import android.os.Bundle
import android.view.WindowManager
import androidx.fragment.app.FragmentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.calculateEndPadding
import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.PointerEventType
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInWindow
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.tooling.preview.Devices
import androidx.compose.ui.tooling.preview.Preview
import androidx.navigation.compose.rememberNavController
import com.ct5.clientwarden.HomeScreen.c_panel
import com.ct5.clientwarden.ui.theme.ClientwardenTheme

enum class MainViews {
    LoginUI,
    UnlockUI,
    VaultUI
}

object MainActivityObject {
    var c_view = mutableStateOf(MainViews.LoginUI)

    fun setUIType(ordinal: Int) {
        c_view.value = MainViews.entries[ordinal]
    }
}

class MainActivity : FragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        /*
         * Secure by default; the user's "allow screenshots" setting lifts this once the
         * vault's settings are known.
         */
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        setRecentsScreenshotEnabled(false)
        Files.register(this)
        LocalNetwork.register(this)
        enableEdgeToEdge()
        VaultBridge.attach(this)
        setContent {
            ClientwardenTheme {
                if (MainActivityObject.c_view.value == MainViews.VaultUI) {
                    VaultUI()
                } else if (MainActivityObject.c_view.value == MainViews.LoginUI) {
                    LoginScreen.view()
                } else if (MainActivityObject.c_view.value == MainViews.UnlockUI) {
                    UnlockScreen.view()
                }

                VaultBridge.ConfirmHost()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        VaultBridge.onForeground(this)
    }

    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) {
            VaultBridge.onBackground()
        }
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        VaultBridge.noteActivity()
    }
}

@SuppressLint("UnusedMaterial3ScaffoldPaddingParameter")
@Composable
fun VaultUI() {
    val navController = rememberNavController()

    Scaffold(
        bottomBar = {
            NavBar(navController = navController)
        }
    ) { innerPadding ->
        /*
         * A tap outside the open Add pill closes it without also pressing whatever is under
         * it. Watched here before the children see it, so taps on the pill itself still work.
         */
        var l_origin by remember { mutableStateOf(Offset.Zero) }
        Column(modifier = Modifier.fillMaxSize()
            .padding(innerPadding)
            .onGloballyPositioned { l_origin = it.positionInWindow() }
            .pointerInput(Unit) {
                awaitPointerEventScope {
                    while (true) {
                        val event = awaitPointerEvent(PointerEventPass.Initial)
                        if (!TopBar.m_expanded || event.type != PointerEventType.Press) {
                            continue
                        }
                        val position = event.changes.first().position + l_origin
                        if (TopBar.pillBounds?.contains(position) != true) {
                            event.changes.forEach { it.consume() }
                            TopBar.m_expanded = false
                        }
                    }
                }
            }
        ) {
            AppNavHost(
                navController = navController,
                startDestination = NavTabs.HOME,
                modifier = Modifier.weight(1f)
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
fun Preview() {
    ClientwardenTheme {
        VaultUI()
    }
}