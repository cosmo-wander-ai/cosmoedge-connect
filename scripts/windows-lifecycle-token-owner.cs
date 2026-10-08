// Test harness only. Windows hosted runners can use Administrators as the
// default owner even though the installer is intended for an ordinary user.
// Change only this process token's default for newly created objects, retain
// production file-owner validation, and restore the original value on exit.
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace CosmoEdgeConnectLifecycle
{
    public sealed class TokenOwnerScope : IDisposable
    {
        private IntPtr token;
        private IntPtr user;
        private IntPtr originalOwner;
        private bool changed;
        public bool OriginalOwnerMatchesUser { get; private set; }
        public bool OriginalOwnerIsAdministrators { get; private set; }
        public bool Restored { get; private set; }

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr handle);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr handle, int kind, IntPtr data, int length, out int needed);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetTokenInformation(IntPtr handle, int kind, IntPtr data, int length);
        [DllImport("advapi32.dll")]
        private static extern bool EqualSid(IntPtr first, IntPtr second);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern uint GetLongPathNameW(string path, StringBuilder result, uint capacity);

        public static string CanonicalTemporaryBase(string path)
        {
            if (!Directory.Exists(path))
                throw new DirectoryNotFoundException("The test temporary base must already exist.");
            // .NET Framework and Core can preserve/expand 8.3 names differently.
            // Canonicalize the existing base once, before deriving any test paths.
            uint capacity = GetLongPathNameW(path, null, 0);
            if (capacity == 0) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
            for (int attempt = 0; attempt < 3; attempt++)
            {
                if (capacity > 32768) { throw new PathTooLongException("The test temporary base is too long."); }
                StringBuilder result = new StringBuilder((int)capacity);
                uint length = GetLongPathNameW(path, result, capacity);
                if (length == 0) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
                if (length < capacity) { return result.ToString(); }
                capacity = length;
            }
            throw new IOException("The test temporary base changed during path normalization.");
        }

        private IntPtr Read(int kind)
        {
            int needed;
            GetTokenInformation(token, kind, IntPtr.Zero, 0, out needed);
            if (needed <= 0) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
            IntPtr data = Marshal.AllocHGlobal(needed);
            if (!GetTokenInformation(token, kind, data, needed, out needed))
            {
                int error = Marshal.GetLastWin32Error();
                Marshal.FreeHGlobal(data);
                throw new Win32Exception(error);
            }
            return data;
        }

        public TokenOwnerScope()
        {
            // TOKEN_QUERY | TOKEN_ADJUST_DEFAULT. No ownership privilege is enabled.
            if (!OpenProcessToken(GetCurrentProcess(), 0x0088, out token))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                user = Read(1); // TOKEN_USER starts with SID_AND_ATTRIBUTES.Sid.
                originalOwner = Read(4); // TOKEN_OWNER contains one SID pointer.
                OriginalOwnerMatchesUser = EqualSid(Marshal.ReadIntPtr(user), Marshal.ReadIntPtr(originalOwner));
                OriginalOwnerIsAdministrators = new SecurityIdentifier(Marshal.ReadIntPtr(originalOwner))
                    .IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid);
            }
            catch { Release(); throw; }
        }

        public void UseCurrentUser()
        {
            if (token == IntPtr.Zero) { throw new ObjectDisposedException("TokenOwnerScope"); }
            if (!OriginalOwnerMatchesUser && !changed)
            {
                // TOKEN_USER's leading SID pointer is also a TOKEN_OWNER value.
                if (!SetTokenInformation(token, 4, user, IntPtr.Size))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                changed = true;
            }
            IntPtr actual = Read(4);
            try
            {
                if (!EqualSid(Marshal.ReadIntPtr(actual), Marshal.ReadIntPtr(user)))
                    throw new InvalidOperationException("Test process default owner did not become the current user.");
            }
            finally { Marshal.FreeHGlobal(actual); }
        }

        public void Dispose()
        {
            if (token == IntPtr.Zero) { return; }
            try
            {
                if (changed && !SetTokenInformation(token, 4, originalOwner, IntPtr.Size))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                IntPtr actual = Read(4);
                try
                {
                    Restored = EqualSid(Marshal.ReadIntPtr(actual), Marshal.ReadIntPtr(originalOwner));
                    if (!Restored) { throw new InvalidOperationException("Test process default owner restoration failed."); }
                }
                finally { Marshal.FreeHGlobal(actual); }
            }
            finally { Release(); }
        }

        private void Release()
        {
            if (originalOwner != IntPtr.Zero) { Marshal.FreeHGlobal(originalOwner); originalOwner = IntPtr.Zero; }
            if (user != IntPtr.Zero) { Marshal.FreeHGlobal(user); user = IntPtr.Zero; }
            if (token != IntPtr.Zero) { CloseHandle(token); token = IntPtr.Zero; }
        }
    }
}
