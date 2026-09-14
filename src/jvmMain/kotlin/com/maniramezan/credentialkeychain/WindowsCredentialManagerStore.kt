package com.maniramezan.credentialkeychain

import com.maniramezan.credentialkeychain.KeychainUnavailableException.Reason
import java.io.File
import java.util.Base64

/**
 * Backs [PasswordStore] with Windows Credential Manager generic credentials for the current
 * user. Target names are `credential-keychain-kotlin:password:<namespace>:<server>:<username>`
 * with each component SHA-256 hashed; the username is stored in the credential's user-name
 * field and the password as a UTF-8 blob. A small C# shim calls `CredWriteW`, `CredReadW`,
 * `CredEnumerateW`, and `CredDeleteW`. Secrets and scripts travel only through stdin.
 */
internal class WindowsCredentialManagerStore(
    serviceName: String,
    accountName: String = serviceName,
    powershell: File? = findExecutable("powershell.exe"),
    runner: CommandRunner = systemCommandRunner,
) : PasswordStore {
    private val shell = PowerShell(powershell, runner)
    private val prefix = "credential-keychain-kotlin:password:${digest(credentialNamespace(serviceName, accountName))}:"

    override fun save(credential: PasswordCredential) {
        val target = PowerShell.literal(targetFor(credential.server, credential.username))
        run(
            "[CkkCredentials]::Write($target, [System.Text.Encoding]::UTF8.GetString(" +
                "[System.Convert]::FromBase64String(${base64Literal(credential.username)})), " +
                "[System.Convert]::FromBase64String(${base64Literal(credential.password)}))",
        )
    }

    override fun find(
        server: String,
        username: String,
    ): PasswordCredential? {
        val result = run(printLines("[CkkCredentials]::Read(${PowerShell.literal(targetFor(server, username))})"))
        val credentials = parse(result.stdout, server)
        if (credentials.size > 1 || credentials.any { it.username != username }) throw corrupted()
        return credentials.singleOrNull()
    }

    override fun findAll(server: String): List<PasswordCredential> {
        val result = run(printLines("[CkkCredentials]::Enumerate(${PowerShell.literal("$prefix${digest(server)}:*")})"))
        return parse(result.stdout, server)
    }

    override fun delete(
        server: String,
        username: String,
    ) {
        run("[CkkCredentials]::Delete(${PowerShell.literal(targetFor(server, username))})")
    }

    override fun clear() {
        run("[CkkCredentials]::DeleteAll(${PowerShell.literal("$prefix*")})")
    }

    internal fun targetFor(
        server: String,
        username: String,
    ): String = "$prefix${digest(server)}:${digest(username)}"

    /** Each line is `base64(username) TAB base64(password) TAB target`; the target must match the username. */
    private fun parse(
        output: String,
        server: String,
    ): List<PasswordCredential> =
        output.lines().map { it.trim() }.filter { it.isNotEmpty() }.map { line ->
            val fields = line.split('\t')
            if (fields.size != 3) throw corrupted()
            val username = decodeBase64(fields[0])
            val password = decodeBase64(fields[1])
            if (fields[2] != targetFor(server, username)) throw corrupted()
            PasswordCredential(server, username, password)
        }

    private fun decodeBase64(value: String): String =
        try {
            Base64.getDecoder().decode(value).decodeStrictUtf8() ?: throw corrupted()
        } catch (_: IllegalArgumentException) {
            throw corrupted()
        }

    private fun corrupted() = KeychainUnavailableException(Reason.Corrupted, "Windows Credential Manager returned invalid data")

    private fun base64Literal(value: String) = PowerShell.literal(Base64.getEncoder().encodeToString(value.toByteArray(Charsets.UTF_8)))

    private fun printLines(expression: String) = "foreach (${'$'}line in $expression) { [Console]::Out.WriteLine(${'$'}line) }"

    private fun run(statement: String): CommandResult =
        shell.run(
            "Add-Type -TypeDefinition ${PowerShell.literal(CREDENTIAL_API)}\n$statement",
            "Windows Credential Manager operation failed",
        )

    private companion object {
        const val CREDENTIAL_API = """
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class CkkCredentials {
    [StructLayout(LayoutKind.Sequential)]
    private struct Credential {
        public int Flags;
        public int Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public int LastWrittenLow;
        public int LastWrittenHigh;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CredWriteW(ref Credential credential, int flags);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredReadW(string target, int type, int flags, out IntPtr credential);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredDeleteW(string target, int type, int flags);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CredEnumerateW(string filter, int flags, out int count, out IntPtr credentials);

    [DllImport("advapi32.dll")]
    private static extern void CredFree(IntPtr buffer);

    private const int GenericType = 1;
    private const int PersistLocalMachine = 2;
    private const int NotFound = 1168;

    public static void Write(string target, string userName, byte[] secret) {
        Credential credential = new Credential();
        credential.Type = GenericType;
        credential.Persist = PersistLocalMachine;
        credential.CredentialBlobSize = secret.Length;
        credential.TargetName = Marshal.StringToCoTaskMemUni(target);
        credential.UserName = Marshal.StringToCoTaskMemUni(userName);
        credential.CredentialBlob = Marshal.AllocCoTaskMem(secret.Length);
        try {
            Marshal.Copy(secret, 0, credential.CredentialBlob, secret.Length);
            if (!CredWriteW(ref credential, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
        } finally {
            Marshal.FreeCoTaskMem(credential.TargetName);
            Marshal.FreeCoTaskMem(credential.UserName);
            Marshal.FreeCoTaskMem(credential.CredentialBlob);
        }
    }

    public static string[] Read(string target) {
        IntPtr pointer;
        if (!CredReadW(target, GenericType, 0, out pointer)) {
            int error = Marshal.GetLastWin32Error();
            if (error == NotFound) return new string[0];
            throw new Win32Exception(error);
        }
        try {
            return new string[] { Describe(pointer) };
        } finally {
            CredFree(pointer);
        }
    }

    public static string[] Enumerate(string filter) {
        List<string> lines = new List<string>();
        Collect(filter, lines);
        return lines.ToArray();
    }

    public static void Delete(string target) {
        if (!CredDeleteW(target, GenericType, 0)) {
            int error = Marshal.GetLastWin32Error();
            if (error != NotFound) throw new Win32Exception(error);
        }
    }

    public static void DeleteAll(string filter) {
        List<string> lines = new List<string>();
        Collect(filter, lines);
        foreach (string line in lines) Delete(line.Substring(line.LastIndexOf('\t') + 1));
    }

    private static void Collect(string filter, List<string> lines) {
        int count;
        IntPtr pointers;
        if (!CredEnumerateW(filter, 0, out count, out pointers)) {
            int error = Marshal.GetLastWin32Error();
            if (error == NotFound) return;
            throw new Win32Exception(error);
        }
        try {
            for (int i = 0; i < count; i++) {
                IntPtr pointer = Marshal.ReadIntPtr(pointers, i * IntPtr.Size);
                Credential credential = (Credential)Marshal.PtrToStructure(pointer, typeof(Credential));
                if (credential.Type == GenericType) lines.Add(Describe(pointer));
            }
        } finally {
            CredFree(pointers);
        }
    }

    private static string Describe(IntPtr pointer) {
        Credential credential = (Credential)Marshal.PtrToStructure(pointer, typeof(Credential));
        byte[] secret = new byte[credential.CredentialBlobSize];
        if (credential.CredentialBlobSize > 0) Marshal.Copy(credential.CredentialBlob, secret, 0, credential.CredentialBlobSize);
        string userName = credential.UserName == IntPtr.Zero ? "" : Marshal.PtrToStringUni(credential.UserName);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(userName)) + "\t" +
            Convert.ToBase64String(secret) + "\t" + Marshal.PtrToStringUni(credential.TargetName);
    }
}
"""
    }
}
