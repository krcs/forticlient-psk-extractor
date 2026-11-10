namespace ForticlientPskExtractor;

public sealed class CliOptions
{
    public string ConfigPath { get; private set; } = "vpn_pw.conf";
    public string? Password { get; private set; }
    public string FcDir { get; private set; } = @"C:\Program Files\Fortinet\FortiClient";
    public bool ShowHex { get; private set; }
    public bool ShowHelp { get; private set; }

    /// <summary>Returns null on a parse error (unknown/invalid option).</summary>
    public static CliOptions? Parse(string[] args)
    {
        var o = new CliOptions();
        var positional = new List<string>();

        for (int i = 0; i < args.Length; i++)
        {
            var a = args[i];
            switch (a)
            {
                case "-h" or "--help":
                    o.ShowHelp = true;
                    return o;
                case "-p" or "--password":
                    if (++i >= args.Length) return null;
                    o.Password = args[i];
                    break;
                case "--fcdir":
                    if (++i >= args.Length) return null;
                    o.FcDir = args[i];
                    break;
                case "--show-hex":
                    o.ShowHex = true;
                    break;
                default:
                    if (a.StartsWith('-')) return null;
                    positional.Add(a);
                    break;
            }
        }

        if (positional.Count > 1) return null;
        if (positional.Count == 1) o.ConfigPath = positional[0];
        return o;
    }

    public static void PrintUsage()
    {
        Console.WriteLine(
"""
fcpsk - FortiClient VPN preshared-key / username extractor

USAGE:
  fcpsk [<config.conf>] [-p <password>] [--fcdir <dir>] [--show-hex]

ARGUMENTS:
  <config.conf>     Path to the FortiClient config to read.
                    Default: vpn_pw.conf (in the current directory).

OPTIONS:
  -p, --password    Context/password the EncX values are protected with.
                    For a config made by `FCConfig ... -o export -p <pass>`,
                    this is that <pass>. Prompted for if omitted.
  --fcdir <dir>     FortiClient install directory containing utilsdll.dll.
                    Default: C:\Program Files\Fortinet\FortiClient
  --show-hex        Also print the plaintext as hex (for verification).
  -h, --help        Show this help.

WORKFLOW:
  1) On the target PC, in an elevated Command Prompt, re-export the VPN config
     under a password you choose:

       "C:\Program Files\Fortinet\FortiClient\FCConfig.exe" ^
           -f "%CD%\vpn_pw.conf" -m vpn -o export -p MyPass12345

  2) Run this tool with that same password:

       fcpsk vpn_pw.conf -p MyPass12345

NOTE:
  Only preshared keys and usernames are recoverable. FortiClient does not
  export saved account login passwords.
""");
    }
}
