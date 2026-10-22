package com.ct5.clientwarden

import android.app.assist.AssistStructure
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import kotlinx.coroutines.Job
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject

/*
 * Offers matching logins to other apps and browsers. Only works while the vault is unlocked
 * (the master password never leaves the app); locked vaults simply offer nothing.
 *
 * Pages match on the browser's web domain, apps on "androidapp://<package>" URIs, using the
 * core's matching rules (equivalent domains, match detection). Items that need the master
 * password re-prompt are never offered.
 */
class ClientwardenAutofillService : AutofillService() {
    private val scope = MainScope()

    private class Fields {
        var username: AutofillId? = null
        var password: AutofillId? = null
        var webDomain: String? = null
    }

    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure
        if (structure == null || !VaultBridge.init(applicationContext)) {
            callback.onSuccess(null)
            return
        }

        val fields = Fields()
        for (i in 0 until structure.windowNodeCount) {
            walk(structure.getWindowNodeAt(i).rootViewNode, fields)
        }
        if (fields.username == null && fields.password == null) {
            callback.onSuccess(null)
            return
        }

        val packageName = structure.activityComponent.packageName
        if (packageName == this.packageName) {
            callback.onSuccess(null)
            return
        }
        val url = fields.webDomain?.let { "https://$it" } ?: "androidapp://$packageName"

        val job: Job = scope.launch {
            try {
                callback.onSuccess(respond(url, fields))
            } catch (e: Exception) {
                callback.onSuccess(null)
            }
        }
        cancellationSignal.setOnCancelListener { job.cancel() }
    }

    private suspend fun respond(url: String, fields: Fields): FillResponse? {
        VaultBridge.refreshState()
        if (!VaultBridge.unlocked) {
            return null
        }

        val ids = VaultBridge.call("autofill.match", VaultBridge.json("url" to url)) as? JSONArray ?: return null
        val response = FillResponse.Builder()
        var count = 0
        for (i in 0 until minOf(ids.length(), 10)) {
            val item = VaultBridge.call("items.get", VaultBridge.json("id" to ids.getString(i))) as? JSONObject ?: continue
            if (item.optBoolean("reprompt")) {
                continue
            }
            val values = item.optJSONArray("fields") ?: continue
            var username = ""
            var password: String? = null
            for (j in 0 until values.length()) {
                val field = values.getJSONObject(j)
                if (field.isNull("value")) {
                    continue
                }
                when (field.getString("key")) {
                    "username" -> username = field.getString("value")
                    "password" -> password = field.getString("value")
                }
            }

            val label = RemoteViews(packageName, android.R.layout.simple_list_item_2).apply {
                setTextViewText(android.R.id.text1, item.optString("name"))
                setTextViewText(android.R.id.text2, username)
            }
            @Suppress("DEPRECATION")
            val dataset = Dataset.Builder(label).apply {
                fields.username?.let { setValue(it, AutofillValue.forText(username)) }
                if (password != null) {
                    fields.password?.let { setValue(it, AutofillValue.forText(password)) }
                }
            }
            try {
                response.addDataset(dataset.build())
                count++
            } catch (e: IllegalStateException) {
                // nothing to fill for this item (e.g. password-only form, hidden password)
            }
        }
        return if (count == 0) null else response.build()
    }

    private fun walk(node: AssistStructure.ViewNode, fields: Fields) {
        if (fields.webDomain == null && !node.webDomain.isNullOrEmpty()) {
            fields.webDomain = node.webDomain
        }

        val id = node.autofillId
        if (id != null && node.autofillType == View.AUTOFILL_TYPE_TEXT) {
            when (classify(node)) {
                "password" -> if (fields.password == null) fields.password = id
                "username" -> if (fields.username == null) fields.username = id
            }
        }

        for (i in 0 until node.childCount) {
            walk(node.getChildAt(i), fields)
        }
    }

    private fun classify(node: AssistStructure.ViewNode): String? {
        node.autofillHints?.forEach { hint ->
            val h = hint.lowercase()
            when {
                h.contains("password") -> return "password"
                h.contains("username") || h.contains("email") -> return "username"
            }
        }

        val variation = node.inputType and InputType.TYPE_MASK_VARIATION
        val textClass = node.inputType and InputType.TYPE_MASK_CLASS
        if (textClass == InputType.TYPE_CLASS_TEXT && (variation == InputType.TYPE_TEXT_VARIATION_PASSWORD ||
                variation == InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD ||
                variation == InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD)) {
            return "password"
        }
        if (textClass == InputType.TYPE_CLASS_TEXT && (variation == InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS ||
                variation == InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS)) {
            return "username"
        }

        node.htmlInfo?.attributes?.forEach { attribute ->
            if (attribute.first == "type" && attribute.second == "password") {
                return "password"
            }
            if (attribute.first == "type" && attribute.second == "email") {
                return "username"
            }
        }

        val hint = listOfNotNull(node.idEntry, node.hint).joinToString(" ").lowercase()
        return when {
            hint.contains("pass") -> "password"
            hint.contains("user") || hint.contains("email") || hint.contains("login") -> "username"
            else -> null
        }
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        /*
         * Saving new logins from other apps isn't offered (no SaveInfo is ever requested)
         */
        callback.onSuccess()
    }
}
