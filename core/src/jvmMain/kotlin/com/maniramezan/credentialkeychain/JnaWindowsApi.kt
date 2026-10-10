@file:Suppress("FunctionName", "ktlint:standard:function-naming")

package com.maniramezan.credentialkeychain

import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.Structure
import com.sun.jna.WString
import com.sun.jna.ptr.IntByReference
import com.sun.jna.ptr.PointerByReference
import com.sun.jna.win32.StdCallLibrary

/**
 * [WindowsApi] through in-process calls into `crypt32`, `advapi32`, and `ncrypt` using JNA, so no
 * helper process or script host is involved. Secrets are copied into native buffers this class
 * owns and those buffers, and the ones Windows returns, are zeroed before they are released.
 */
internal class JnaWindowsApi(
    /** Test seam: runs just before an imported identity is added to `My`, so tests can fail an import there. */
    private val beforeStoreAdd: ((KeyLocation) -> Unit)? = null,
) : WindowsApi {
    private val crypt32 = Native.load("crypt32", Crypt32::class.java)
    private val advapi32 = Native.load("advapi32", Advapi32::class.java)
    private val ncrypt = Native.load("ncrypt", NCrypt::class.java)
    private val kernel32 = Native.load("kernel32", Kernel32::class.java)

    override fun protect(plaintext: ByteArray): ByteArray =
        dpapi(plaintext, "CryptProtectData") { input, output ->
            crypt32.CryptProtectData(input, null, null, null, null, CRYPTPROTECT_UI_FORBIDDEN, output)
        }

    override fun unprotect(ciphertext: ByteArray): ByteArray =
        dpapi(ciphertext, "CryptUnprotectData") { input, output ->
            crypt32.CryptUnprotectData(input, null, null, null, null, CRYPTPROTECT_UI_FORBIDDEN, output)
        }

    private inline fun dpapi(
        data: ByteArray,
        function: String,
        call: (DataBlob, DataBlob) -> Boolean,
    ): ByteArray {
        val input = DataBlob(data)
        val output = DataBlob()
        try {
            if (!call(input, output)) throw win32Failure(function)
            return output.pbData?.getByteArray(0, output.cbData) ?: ByteArray(0)
        } finally {
            input.wipe()
            output.pbData?.let {
                it.clear(output.cbData.toLong())
                kernel32.LocalFree(it)
            }
        }
    }

    override fun writeCredential(
        target: String,
        userName: String,
        secret: ByteArray,
    ) {
        val blob = nativeCopy(secret)
        val credential =
            Credential().apply {
                type = CRED_TYPE_GENERIC
                persist = CRED_PERSIST_LOCAL_MACHINE
                targetName = wideString(target)
                this.userName = wideString(userName)
                credentialBlobSize = secret.size
                credentialBlob = blob
            }
        try {
            if (!advapi32.CredWriteW(credential, 0)) throw win32Failure("CredWriteW")
        } finally {
            blob.clear()
        }
    }

    override fun readCredential(target: String): WindowsCredential? {
        val result = PointerByReference()
        if (!advapi32.CredReadW(WString(target), CRED_TYPE_GENERIC, 0, result)) {
            if (Native.getLastError() == ERROR_NOT_FOUND) return null
            throw win32Failure("CredReadW")
        }
        try {
            return describe(result.value)
        } finally {
            advapi32.CredFree(result.value)
        }
    }

    override fun enumerateCredentials(filter: String): List<WindowsCredential> {
        val count = IntByReference()
        val result = PointerByReference()
        if (!advapi32.CredEnumerateW(WString(filter), 0, count, result)) {
            if (Native.getLastError() == ERROR_NOT_FOUND) return emptyList()
            throw win32Failure("CredEnumerateW")
        }
        try {
            return result.value.getPointerArray(0, count.value).mapNotNull(::describe)
        } finally {
            advapi32.CredFree(result.value)
        }
    }

    override fun deleteCredential(target: String) {
        if (!advapi32.CredDeleteW(WString(target), CRED_TYPE_GENERIC, 0) && Native.getLastError() != ERROR_NOT_FOUND) {
            throw win32Failure("CredDeleteW")
        }
    }

    /** Copies a generic credential out of Windows memory, zeroing the secret left behind. */
    private fun describe(pointer: Pointer): WindowsCredential? {
        val credential = Credential(pointer).apply { read() }
        if (credential.type != CRED_TYPE_GENERIC) return null
        val size = credential.credentialBlobSize
        val secret = credential.credentialBlob?.let { blob -> blob.getByteArray(0, size).also { blob.clear(size.toLong()) } }
        return WindowsCredential(
            credential.targetName?.getWideString(0).orEmpty(),
            credential.userName?.getWideString(0).orEmpty(),
            secret ?: ByteArray(0),
        )
    }

    override fun importIdentity(
        friendlyName: String,
        pkcs12: ByteArray,
        passphrase: CharArray,
    ) {
        val imported = importPfx(pkcs12, passphrase)
        try {
            // PFXImportCertStore has already persisted the key, so a failed import must delete it.
            val identity = keyedCertificate(imported)
            try {
                setFriendlyName(identity, friendlyName)
                withPersonalStore { store ->
                    removeIdentities(store, friendlyName)
                    beforeStoreAdd?.invoke(checkNotNull(keyLocation(identity)))
                    if (!crypt32.CertAddCertificateContextToStore(store, identity, CERT_STORE_ADD_REPLACE_EXISTING, null)) {
                        throw win32Failure("CertAddCertificateContextToStore")
                    }
                }
            } catch (error: Throwable) {
                deleteKey(identity)
                throw error
            } finally {
                crypt32.CertFreeCertificateContext(identity)
            }
        } finally {
            crypt32.CertCloseStore(imported, 0)
        }
    }

    override fun deleteIdentities(friendlyName: String) = withPersonalStore { removeIdentities(it, friendlyName) }

    /** The key containers of the current-user `My` certificates named [friendlyName]. */
    internal fun keyLocations(friendlyName: String): List<KeyLocation> =
        withPersonalStore { store ->
            val locations = mutableListOf<KeyLocation>()
            forEachCertificate(store) { context ->
                if (stringProperty(context, CERT_FRIENDLY_NAME_PROP_ID) == friendlyName) keyLocation(context)?.let(locations::add)
            }
            locations
        }

    /** Imports into a temporary store; keys go to the user's key set and are not exportable. */
    private fun importPfx(
        pkcs12: ByteArray,
        passphrase: CharArray,
    ): Pointer {
        val bundle = DataBlob(pkcs12)
        val password =
            Memory((passphrase.size + 1) * 2L).apply {
                write(0, passphrase, 0, passphrase.size)
                setChar(passphrase.size * 2L, '\u0000')
            }
        try {
            // An empty PKCS#12 password may have been encoded as either "" or NULL.
            return crypt32.PFXImportCertStore(bundle, password, CRYPT_USER_KEYSET)
                ?: passphrase.takeIf { it.isEmpty() }?.let { crypt32.PFXImportCertStore(bundle, null, CRYPT_USER_KEYSET) }
                ?: throw win32Failure("PFXImportCertStore")
        } finally {
            bundle.wipe()
            password.clear()
        }
    }

    /** Returns a reference the caller frees to the one certificate in [store] that has a private key. */
    private fun keyedCertificate(store: Pointer): Pointer {
        var identity: Pointer? = null
        forEachCertificate(store) { context ->
            if (identity == null && keyLocation(context) != null) identity = crypt32.CertDuplicateCertificateContext(context)
        }
        return identity ?: throw IllegalStateException("PKCS#12 bundle has no private key")
    }

    private fun setFriendlyName(
        context: Pointer,
        name: String,
    ) {
        val value = DataBlob((name + '\u0000').toByteArray(Charsets.UTF_16LE))
        if (!crypt32.CertSetCertificateContextProperty(context, CERT_FRIENDLY_NAME_PROP_ID, 0, value)) {
            throw win32Failure("CertSetCertificateContextProperty")
        }
    }

    private inline fun <T> withPersonalStore(block: (Pointer) -> T): T {
        val store =
            crypt32.CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, null, CERT_SYSTEM_STORE_CURRENT_USER, WString("My"))
                ?: throw win32Failure("CertOpenStore")
        try {
            return block(store)
        } finally {
            crypt32.CertCloseStore(store, 0)
        }
    }

    private fun removeIdentities(
        store: Pointer,
        friendlyName: String,
    ) {
        val matches = mutableListOf<Pointer>()
        forEachCertificate(store) { context ->
            if (stringProperty(context, CERT_FRIENDLY_NAME_PROP_ID) == friendlyName) {
                crypt32.CertDuplicateCertificateContext(context)?.let(matches::add)
            }
        }
        var failed = false
        for (match in matches) {
            if (failed) {
                crypt32.CertFreeCertificateContext(match)
                continue
            }
            deleteKey(match)
            // Frees the context even when it fails.
            failed = !crypt32.CertDeleteCertificateFromStore(match)
        }
        if (failed) throw IllegalStateException("CertDeleteCertificateFromStore failed")
    }

    /** Visits each certificate; [action] must duplicate a context it keeps, because enumeration frees it. */
    private inline fun forEachCertificate(
        store: Pointer,
        action: (Pointer) -> Unit,
    ) {
        var context = crypt32.CertEnumCertificatesInStore(store, null)
        while (context != null) {
            try {
                action(context)
            } catch (error: Throwable) {
                crypt32.CertFreeCertificateContext(context)
                throw error
            }
            context = crypt32.CertEnumCertificatesInStore(store, context)
        }
    }

    /**
     * Deletes the certificate's key container, whether CNG or CryptoAPI. Best effort, like
     * `X509Certificate2` key deletion: the certificate is still removed if its key is already gone.
     */
    private fun deleteKey(context: Pointer) {
        val key = keyLocation(context) ?: return
        val machine = key.flags and CRYPT_MACHINE_KEYSET
        if (key.providerType == 0) {
            val provider = PointerByReference()
            if (ncrypt.NCryptOpenStorageProvider(provider, key.provider?.let(::WString), 0) != 0) return
            try {
                val handle = PointerByReference()
                val opened = ncrypt.NCryptOpenKey(provider.value, handle, WString(key.container), 0, machine or NCRYPT_SILENT_FLAG) == 0
                // NCryptDeleteKey releases the handle only when it succeeds.
                if (opened && ncrypt.NCryptDeleteKey(handle.value, NCRYPT_SILENT_FLAG) != 0) ncrypt.NCryptFreeObject(handle.value)
            } finally {
                ncrypt.NCryptFreeObject(provider.value)
            }
        } else {
            advapi32.CryptAcquireContextW(
                PointerByReference(),
                WString(key.container),
                key.provider?.let(::WString),
                key.providerType,
                machine or CRYPT_DELETEKEYSET or CRYPT_SILENT,
            )
        }
    }

    /** Where a certificate's private key lives: a CNG key when [providerType] is 0, otherwise a CryptoAPI container. */
    internal class KeyLocation(
        val container: String,
        val provider: String?,
        val providerType: Int,
        val flags: Int,
    )

    private fun keyLocation(context: Pointer): KeyLocation? {
        val buffer = property(context, CERT_KEY_PROV_INFO_PROP_ID) ?: return null
        val info = KeyProviderInfo(buffer).apply { read() }
        val container = info.containerName?.getWideString(0) ?: return null
        return KeyLocation(container, info.providerName?.getWideString(0), info.providerType, info.flags)
    }

    private fun stringProperty(
        context: Pointer,
        propertyId: Int,
    ): String? = property(context, propertyId)?.getWideString(0)

    /** Returns a copy of a certificate context property, or `null` if the certificate does not have it. */
    private fun property(
        context: Pointer,
        propertyId: Int,
    ): Memory? {
        val size = IntByReference()
        if (!crypt32.CertGetCertificateContextProperty(context, propertyId, null, size) || size.value <= 0) return null
        val buffer = Memory(size.value.toLong())
        return buffer.takeIf { crypt32.CertGetCertificateContextProperty(context, propertyId, buffer, size) }
    }

    /** Only the function name and Win32 code; the caller discards even these. */
    private fun win32Failure(function: String) = IllegalStateException("$function failed with error ${Native.getLastError()}")

    private fun nativeCopy(bytes: ByteArray): Memory = Memory(maxOf(bytes.size, 1).toLong()).apply { write(0, bytes, 0, bytes.size) }

    private fun wideString(value: String): Memory = Memory((value.length + 1) * 2L).apply { setWideString(0, value) }

    /** `CRYPT_INTEGER_BLOB`, owning a native copy of its bytes when built from an array. */
    @Structure.FieldOrder("cbData", "pbData")
    internal class DataBlob() : Structure() {
        @JvmField var cbData: Int = 0

        @JvmField var pbData: Pointer? = null
        private var owned: Memory? = null

        constructor(bytes: ByteArray) : this() {
            owned = Memory(maxOf(bytes.size, 1).toLong()).apply { write(0, bytes, 0, bytes.size) }
            cbData = bytes.size
            pbData = owned
        }

        /** Zeroes the owned copy. */
        fun wipe() {
            owned?.clear()
        }
    }

    /** `CREDENTIALW`; `LastWritten` is a `FILETIME`, two 32-bit halves. */
    @Structure.FieldOrder(
        "flags",
        "type",
        "targetName",
        "comment",
        "lastWrittenLow",
        "lastWrittenHigh",
        "credentialBlobSize",
        "credentialBlob",
        "persist",
        "attributeCount",
        "attributes",
        "targetAlias",
        "userName",
    )
    internal class Credential : Structure {
        constructor() : super()
        constructor(pointer: Pointer) : super(pointer)

        @JvmField var flags: Int = 0

        @JvmField var type: Int = 0

        @JvmField var targetName: Pointer? = null

        @JvmField var comment: Pointer? = null

        @JvmField var lastWrittenLow: Int = 0

        @JvmField var lastWrittenHigh: Int = 0

        @JvmField var credentialBlobSize: Int = 0

        @JvmField var credentialBlob: Pointer? = null

        @JvmField var persist: Int = 0

        @JvmField var attributeCount: Int = 0

        @JvmField var attributes: Pointer? = null

        @JvmField var targetAlias: Pointer? = null

        @JvmField var userName: Pointer? = null
    }

    /** `CRYPT_KEY_PROV_INFO`. */
    @Structure.FieldOrder("containerName", "providerName", "providerType", "flags", "parameterCount", "parameters", "keySpec")
    internal class KeyProviderInfo(
        pointer: Pointer,
    ) : Structure(pointer) {
        @JvmField var containerName: Pointer? = null

        @JvmField var providerName: Pointer? = null

        @JvmField var providerType: Int = 0

        @JvmField var flags: Int = 0

        @JvmField var parameterCount: Int = 0

        @JvmField var parameters: Pointer? = null

        @JvmField var keySpec: Int = 0
    }

    internal interface Crypt32 : StdCallLibrary {
        fun CryptProtectData(
            dataIn: DataBlob,
            description: WString?,
            entropy: DataBlob?,
            reserved: Pointer?,
            prompt: Pointer?,
            flags: Int,
            dataOut: DataBlob,
        ): Boolean

        fun CryptUnprotectData(
            dataIn: DataBlob,
            description: Pointer?,
            entropy: DataBlob?,
            reserved: Pointer?,
            prompt: Pointer?,
            flags: Int,
            dataOut: DataBlob,
        ): Boolean

        fun PFXImportCertStore(
            pfx: DataBlob,
            password: Pointer?,
            flags: Int,
        ): Pointer?

        fun CertOpenStore(
            provider: Pointer,
            encodingType: Int,
            cryptProvider: Pointer?,
            flags: Int,
            parameter: WString,
        ): Pointer?

        fun CertCloseStore(
            store: Pointer,
            flags: Int,
        ): Boolean

        fun CertEnumCertificatesInStore(
            store: Pointer,
            previous: Pointer?,
        ): Pointer?

        fun CertDuplicateCertificateContext(context: Pointer): Pointer?

        fun CertFreeCertificateContext(context: Pointer): Boolean

        fun CertDeleteCertificateFromStore(context: Pointer): Boolean

        fun CertGetCertificateContextProperty(
            context: Pointer,
            propertyId: Int,
            data: Pointer?,
            size: IntByReference,
        ): Boolean

        fun CertSetCertificateContextProperty(
            context: Pointer,
            propertyId: Int,
            flags: Int,
            data: DataBlob,
        ): Boolean

        fun CertAddCertificateContextToStore(
            store: Pointer,
            context: Pointer,
            disposition: Int,
            storeContext: Pointer?,
        ): Boolean
    }

    internal interface Advapi32 : StdCallLibrary {
        fun CredWriteW(
            credential: Credential,
            flags: Int,
        ): Boolean

        fun CredReadW(
            target: WString,
            type: Int,
            flags: Int,
            credential: PointerByReference,
        ): Boolean

        fun CredEnumerateW(
            filter: WString,
            flags: Int,
            count: IntByReference,
            credentials: PointerByReference,
        ): Boolean

        fun CredDeleteW(
            target: WString,
            type: Int,
            flags: Int,
        ): Boolean

        fun CredFree(buffer: Pointer)

        fun CryptAcquireContextW(
            provider: PointerByReference,
            container: WString,
            providerName: WString?,
            providerType: Int,
            flags: Int,
        ): Boolean
    }

    /** Functions return `SECURITY_STATUS`, which is zero on success. */
    internal interface NCrypt : StdCallLibrary {
        fun NCryptOpenStorageProvider(
            provider: PointerByReference,
            providerName: WString?,
            flags: Int,
        ): Int

        fun NCryptOpenKey(
            provider: Pointer,
            key: PointerByReference,
            keyName: WString,
            legacyKeySpec: Int,
            flags: Int,
        ): Int

        fun NCryptDeleteKey(
            key: Pointer,
            flags: Int,
        ): Int

        fun NCryptFreeObject(handle: Pointer): Int
    }

    internal interface Kernel32 : StdCallLibrary {
        fun LocalFree(memory: Pointer): Pointer?
    }

    private companion object {
        const val CRYPTPROTECT_UI_FORBIDDEN = 0x1
        const val CRED_TYPE_GENERIC = 1
        const val CRED_PERSIST_LOCAL_MACHINE = 2
        const val ERROR_NOT_FOUND = 1168
        const val CRYPT_USER_KEYSET = 0x1000
        const val CRYPT_MACHINE_KEYSET = 0x20
        const val CRYPT_DELETEKEYSET = 0x10
        const val CRYPT_SILENT = 0x40
        const val NCRYPT_SILENT_FLAG = 0x40
        const val CERT_KEY_PROV_INFO_PROP_ID = 2
        const val CERT_FRIENDLY_NAME_PROP_ID = 11
        const val CERT_STORE_ADD_REPLACE_EXISTING = 3
        const val CERT_SYSTEM_STORE_CURRENT_USER = 1 shl 16
        val CERT_STORE_PROV_SYSTEM_W: Pointer = Pointer.createConstant(10)
    }
}
