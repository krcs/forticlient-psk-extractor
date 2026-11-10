using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace ForticlientPskExtractor;

/// <summary>
/// Decrypts FortiClient <c>EncX ...</c> values by calling FortiClient's own
/// native <c>utilsdll.dll!decrypt_buffer</c> export, rather than reimplementing
/// the (FIPS-wrapped) key derivation.
///
/// The <c>EncX</c> ciphertext layout is: [salt 8B][marker 2B][AES-128-CTR body][HMAC-SHA1 10B].
/// The AES key is derived from a context string + the salt. For values that were
/// re-exported with <c>FCConfig ... -o export -p &lt;password&gt;</c>, the context is
/// that password, so pass the same password here.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class NativeDecryptor
{
    // int decrypt_buffer(const void* in, int inlen, void* out, int* outlen, const wchar_t* context)
    [DllImport("utilsdll.dll", CallingConvention = CallingConvention.Cdecl,
               CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int decrypt_buffer(
        byte[] input, int inLen, byte[] output, ref int outLen,
        [MarshalAs(UnmanagedType.LPWStr)] string context);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetDllDirectory(string lpPathName);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibrary(string lpFileName);

    private readonly string _context;

    private NativeDecryptor(string context) => _context = context;

    /// <summary>
    /// Points the loader at the FortiClient install directory (so <c>utilsdll.dll</c>
    /// and its dependencies resolve) and verifies the DLL + export are usable.
    /// </summary>
    public static NativeDecryptor Create(string fortiClientDir, string context)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException(
                "Decryption requires Windows: it loads FortiClient's native DLLs.");

        var dll = Path.Combine(fortiClientDir, "utilsdll.dll");
        if (!File.Exists(dll))
            throw new FileNotFoundException(
                $"utilsdll.dll not found in \"{fortiClientDir}\". " +
                "Point --fcdir at your FortiClient install directory.", dll);

        if (!SetDllDirectory(fortiClientDir))
            throw new InvalidOperationException(
                $"SetDllDirectory failed (error {Marshal.GetLastWin32Error()}).");

        if (LoadLibrary(dll) == IntPtr.Zero)
            throw new DllNotFoundException(
                $"Failed to load utilsdll.dll (error {Marshal.GetLastWin32Error()}). " +
                "Make sure its dependencies (FCCryptDLL.dll, libcrypto-3-x64.dll, " +
                "libssl-3-x64.dll, libcurl.dll, nanomsg.dll, VC++ runtimes) are present " +
                "in the FortiClient directory, and that this build is x64.");

        return new NativeDecryptor(context);
    }

    /// <summary>
    /// Decrypts one <c>EncX ...</c> value. Returns the plaintext on success, or null
    /// with <paramref name="error"/> set (e.g. "wrong password/context (rc=-4)").
    /// </summary>
    public string? Decrypt(string? encxValue, out string? error)
    {
        error = null;
        if (string.IsNullOrWhiteSpace(encxValue))
            return null;

        var hex = encxValue.Trim();
        if (hex.StartsWith("EncX ", StringComparison.Ordinal))
            hex = hex.Substring(5).Trim();

        byte[] input;
        try { input = Convert.FromHexString(hex); }
        catch { error = "not a valid EncX hex value"; return null; }

        var output = new byte[4096];
        int outLen = output.Length;
        int rc = decrypt_buffer(input, input.Length, output, ref outLen, _context);

        if (rc != 0)
        {
            error = rc switch
            {
                -4 => "wrong password/context (marker mismatch, rc=-4)",
                -5 => "integrity check failed (rc=-5)",
                -6 => "context too short/empty (rc=-6)",
                _  => $"decrypt_buffer failed (rc={rc})",
            };
            return null;
        }

        if (outLen < 0 || outLen > output.Length)
            outLen = 0;

        // Plaintext is raw bytes; FortiClient stores credentials as UTF-8 text.
        return Encoding.UTF8.GetString(output, 0, outLen);
    }
}
