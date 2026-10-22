package com.ct5.clientwarden

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/*
 * The core reads and writes plain file paths, while Android hands out content URIs. Files
 * are staged in a private cache folder for the shortest time possible and deleted after.
 */
object Files {
    private var openLauncher: ActivityResultLauncher<Array<String>>? = null
    private var createLauncher: ActivityResultLauncher<String>? = null
    private var pendingOpen: ((Uri?) -> Unit)? = null
    private var pendingCreate: ((Uri?) -> Unit)? = null

    /*
     * A system file picker is showing; the activity being stopped for it isn't the user
     * leaving the app
     */
    var picking = false
        private set

    /*
     * Must be called from the activity's onCreate.
     */
    fun register(activity: ComponentActivity) {
        openLauncher = activity.registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            picking = false
            pendingOpen?.invoke(uri)
            pendingOpen = null
        }
        createLauncher = activity.registerForActivityResult(
            ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
            picking = false
            pendingCreate?.invoke(uri)
            pendingCreate = null
        }
    }

    fun pick(onPicked: (Uri) -> Unit) {
        pendingOpen = { uri -> if (uri != null) onPicked(uri) }
        picking = true
        openLauncher?.launch(arrayOf("*/*"))
    }

    fun saveAs(name: String, onChosen: (Uri) -> Unit) {
        pendingCreate = { uri -> if (uri != null) onChosen(uri) }
        picking = true
        createLauncher?.launch(name)
    }

    private fun stagingDir(context: Context): File {
        return File(context.cacheDir, "transfer").apply { mkdirs() }
    }

    /*
     * Removes anything left over from a crash mid-transfer.
     */
    fun wipeStaging(context: Context) {
        stagingDir(context).listFiles()?.forEach { it.delete() }
    }

    fun displayName(context: Context, uri: Uri): String {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
            if (it.moveToFirst()) {
                return it.getString(0) ?: "file"
            }
        }
        return uri.lastPathSegment ?: "file"
    }

    /*
     * Copies a picked document into a staging file named like the original (the core uses
     * the file name), runs the block, and deletes it again.
     */
    suspend fun <T> withImported(context: Context, uri: Uri, block: suspend (File, String) -> T): T {
        val name = displayName(context, uri)
        val dir = withContext(Dispatchers.IO) {
            File(stagingDir(context), System.nanoTime().toString()).apply { mkdirs() }
        }
        val file = File(dir, name.replace('/', '_'))
        try {
            withContext(Dispatchers.IO) {
                context.contentResolver.openInputStream(uri)?.use { input ->
                    file.outputStream().use { input.copyTo(it) }
                } ?: throw BridgeError("Couldn't read the file")
            }
            return block(file, name)
        } finally {
            withContext(Dispatchers.IO) { dir.deleteRecursively() }
        }
    }

    /*
     * Gives the block a staging path to write to, then copies the result to the chosen URI.
     */
    suspend fun withExport(context: Context, uri: Uri, block: suspend (File) -> Boolean): Boolean {
        val file = withContext(Dispatchers.IO) { File.createTempFile("cw", null, stagingDir(context)) }
        try {
            if (!block(file)) {
                return false
            }
            withContext(Dispatchers.IO) {
                context.contentResolver.openOutputStream(uri)?.use { output ->
                    file.inputStream().use { it.copyTo(output) }
                } ?: throw BridgeError("Couldn't write the file")
            }
            return true
        } finally {
            withContext(Dispatchers.IO) { file.delete() }
        }
    }
}
