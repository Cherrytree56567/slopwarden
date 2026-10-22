package com.ct5.clientwarden

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine

/*
 * Android 17 drops connections to private addresses (a self-hosted server on the home
 * network, or the emulator's 10.0.2.2) unless the app holds ACCESS_LOCAL_NETWORK, and the
 * connection just times out. Asked for only when the server is actually local.
 */
object LocalNetwork {
    private const val c_permission = "android.permission.ACCESS_LOCAL_NETWORK"

    private var launcher: ActivityResultLauncher<String>? = null
    private var pending: ((Boolean) -> Unit)? = null

    /*
     * The permission dialog is showing; the activity stopping for it isn't the user leaving
     */
    var prompting = false
        private set

    fun register(activity: ComponentActivity) {
        launcher = activity.registerForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            prompting = false
            pending?.invoke(granted)
            pending = null
        }
    }

    /*
     * True when the server can be reached: it isn't local, the permission is already held, or
     * the user grants it now.
     */
    suspend fun ensure(context: Context, url: String): Boolean {
        if (Build.VERSION.SDK_INT < 37 || !isLocal(url)) {
            return true
        }
        if (context.checkSelfPermission(c_permission) == PackageManager.PERMISSION_GRANTED) {
            return true
        }
        val l_launcher = launcher ?: return false
        return suspendCancellableCoroutine { continuation ->
            pending = { granted -> if (continuation.isActive) continuation.resume(granted) }
            prompting = true
            l_launcher.launch(c_permission)
        }
    }

    /*
     * Literal private, link-local and loopback addresses, and .local / single-label names.
     * Doesn't resolve names, so it never blocks.
     */
    private fun isLocal(url: String): Boolean {
        val host = try {
            URI(url.trim()).host?.trim('[', ']')?.lowercase()
        } catch (e: Exception) {
            null
        } ?: return false
        if (host.endsWith(".local") || host.endsWith(".lan") || host.endsWith(".home.arpa") || !host.contains('.') && !host.contains(':')) {
            return true
        }
        val literal = host.all { it.isDigit() || it == '.' } || host.contains(':')
        if (!literal) {
            return false
        }
        val address = try {
            InetAddress.getByName(host)
        } catch (e: Exception) {
            return false
        }
        val unique_local = address is Inet6Address && (address.address[0].toInt() and 0xFE) == 0xFC
        return address.isSiteLocalAddress || address.isLinkLocalAddress || address.isLoopbackAddress || unique_local
    }
}
