@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.maniramezan.credentialkeychain

import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Security.*

internal actual fun platformKeychain(
    serviceName: String,
    accountName: String,
    options: KeychainOptions,
): CredentialKeychain = AppleKeychain(serviceName, accountName, options.appleAccessibility)

/**
 * Generic-password items whose service attribute is the length-prefixed service/account
 * namespace and whose account attribute is the entry key, so [clear] can match the whole
 * namespace with a single query.
 */
internal class AppleKeychain(
    service: String,
    account: String,
    accessibility: AppleAccessibility,
) : CredentialKeychain {
    private val namespace = credentialNamespace(service, account)
    private val accessible = accessibleAttribute(accessibility)

    override fun read(key: String): String? = query(key) { secItemCopyString(it) }

    override fun write(
        key: String,
        value: String,
    ) = withCFData(value.encodeToByteArray()) { data -> query(key) { secItemUpsert(it, data, accessible) } }

    override fun delete(key: String) = query(key) { secItemDelete(it) }

    override fun clear() = query(key = null) { secItemDeleteAll(it) }

    /** Builds a query for one entry, or for the whole namespace when [key] is `null`. */
    private fun <T> query(
        key: String?,
        block: (CFMutableDictionaryRef) -> T,
    ): T = withSecQuery(kSecClassGenericPassword, listOf(kSecAttrService to namespace, kSecAttrAccount to key), block)
}
