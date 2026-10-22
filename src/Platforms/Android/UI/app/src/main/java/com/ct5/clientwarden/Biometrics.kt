package com.ct5.clientwarden

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

/*
 * Shows the system biometric (or device PIN/pattern) prompt. A success opens the 10 second
 * window in which SecretVault's auth-bound key works, so the core call that reads or writes
 * the biometric secret must follow straight away.
 */
object Biometrics {
    private const val c_authenticators = BIOMETRIC_STRONG or DEVICE_CREDENTIAL

    /*
     * A prompt is showing; the device-credential screen stops the activity, which isn't the
     * user leaving the app
     */
    var prompting = false
        private set

    fun available(activity: FragmentActivity): Boolean {
        return BiometricManager.from(activity).canAuthenticate(c_authenticators) ==
            BiometricManager.BIOMETRIC_SUCCESS
    }

    fun authenticate(activity: FragmentActivity, title: String, subtitle: String,
                     onSuccess: () -> Unit, onFailure: (String?) -> Unit = {}) {
        val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    prompting = false
                    onSuccess()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    prompting = false
                    /*
                     * Cancelling isn't worth a toast.
                     */
                    val cancelled = errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                        errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                        errorCode == BiometricPrompt.ERROR_CANCELED
                    onFailure(if (cancelled) null else errString.toString())
                }
            })

        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(c_authenticators)
            .setConfirmationRequired(false)
            .build()
        prompting = true
        prompt.authenticate(info)
    }
}
