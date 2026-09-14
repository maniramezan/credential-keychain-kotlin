@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package com.maniramezan.credentialkeychain

import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Security.*

internal actual fun platformPasswordStore(
    serviceName: String,
    accountName: String,
    options: KeychainOptions,
): PasswordStore = ApplePasswordStore(serviceName, accountName, options.appleAccessibility)

/**
 * Internet-password items whose security-domain attribute is the length-prefixed service/account
 * namespace, with the server and account attributes holding the credential's server and
 * username. Generic-password entries of [AppleKeychain] are a different item class, so the two
 * stores never match each other's items.
 */
internal class ApplePasswordStore(
    service: String,
    account: String,
    accessibility: AppleAccessibility,
) : PasswordStore {
    private val namespace = credentialNamespace(service, account)
    private val accessible = accessibleAttribute(accessibility)

    override fun save(credential: PasswordCredential) =
        withCFData(credential.password.encodeToByteArray()) { data ->
            query(credential.server, credential.username) { secItemUpsert(it, data, accessible) }
        }

    override fun find(
        server: String,
        username: String,
    ): PasswordCredential? = query(server, username) { secItemCopyString(it) }?.let { PasswordCredential(server, username, it) }

    override fun findAll(server: String): List<PasswordCredential> =
        query(server, username = null) { secItemCopyAccounts(it) }.distinct().mapNotNull { find(server, it) }

    override fun delete(
        server: String,
        username: String,
    ) = query(server, username) { secItemDelete(it) }

    override fun clear() = query(server = null, username = null) { secItemDeleteAll(it) }

    private fun <T> query(
        server: String?,
        username: String?,
        block: (CFMutableDictionaryRef) -> T,
    ): T =
        withSecQuery(
            kSecClassInternetPassword,
            listOf(kSecAttrSecurityDomain to namespace, kSecAttrServer to server, kSecAttrAccount to username),
            block,
        )
}
