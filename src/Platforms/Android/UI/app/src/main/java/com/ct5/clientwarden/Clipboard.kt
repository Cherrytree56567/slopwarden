package com.ct5.clientwarden

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle

/*
 * Copies vault values. Secrets are flagged sensitive (so the system hides them in the
 * clipboard preview) and every copy is cleared again after the user's clipboard timeout,
 * unless something else has been copied since.
 */
object Clipboard {
    private const val c_label = "Clientwarden"

    private var manager: ClipboardManager? = null
    private val handler = Handler(Looper.getMainLooper())
    private var ours = false
    private val clear = Runnable { clearIfOurs() }

    var clearSeconds = 30

    fun init(context: Context) {
        if (manager != null) {
            return
        }
        manager = (context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager).also {
            it.addPrimaryClipChangedListener {
                /*
                 * Only delivered while we're in the foreground; a change we didn't make means
                 * the clip isn't ours to clear any more.
                 */
                val label = it.primaryClipDescription?.label
                if (label != null && label != c_label) {
                    ours = false
                }
            }
        }
    }

    fun copy(text: String, sensitive: Boolean = true) {
        val clipboard = manager ?: return
        val clip = ClipData.newPlainText(c_label, text)
        if (sensitive) {
            clip.description.extras = PersistableBundle().apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
                } else {
                    putBoolean("android.content.extra.IS_SENSITIVE", true)
                }
            }
        }
        clipboard.setPrimaryClip(clip)
        ours = true

        handler.removeCallbacks(clear)
        if (clearSeconds > 0) {
            handler.postDelayed(clear, clearSeconds * 1000L)
        }
    }

    fun clearIfOurs() {
        handler.removeCallbacks(clear)
        val clipboard = manager ?: return
        if (!ours) {
            return
        }
        /*
         * In the background we can't read the clipboard to check; clearing then is the safe
         * side of the trade-off.
         */
        val label = clipboard.primaryClipDescription?.label
        if (label == null || label == c_label) {
            clipboard.clearPrimaryClip()
        }
        ours = false
    }
}
