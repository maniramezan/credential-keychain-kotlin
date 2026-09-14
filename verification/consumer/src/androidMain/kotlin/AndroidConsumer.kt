package consumer

import android.content.Context
import dev.amoo.credentialkeychain.CredentialKeychain
import dev.amoo.credentialkeychain.forCurrentPlatform

fun createRepository(context: Context): CredentialRepository =
    CredentialRepository(CredentialKeychain.forCurrentPlatform(context, "consumer", "account"))
