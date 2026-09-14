package consumer

import android.content.Context
import com.maniramezan.credentialkeychain.CredentialKeychain
import com.maniramezan.credentialkeychain.forCurrentPlatform

fun createRepository(context: Context): CredentialRepository =
    CredentialRepository(CredentialKeychain.forCurrentPlatform(context, "consumer", "account"))
