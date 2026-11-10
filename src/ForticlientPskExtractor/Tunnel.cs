namespace ForticlientPskExtractor;

/// <summary>A single VPN tunnel parsed from a FortiClient configuration file.</summary>
public sealed class Tunnel
{
    public required string Name { get; init; }

    /// <summary>"IPsec" or "SSL".</summary>
    public required string Type { get; init; }

    public string? Server { get; init; }

    /// <summary>Raw <c>EncX ...</c> value of the saved username, if any.</summary>
    public string? UsernameEnc { get; init; }

    /// <summary>Raw <c>EncX ...</c> value of the preshared key (IPsec only), if any.</summary>
    public string? PresharedKeyEnc { get; init; }

    // Filled in by the decryptor.
    public string? Username { get; set; }
    public string? PresharedKey { get; set; }

    /// <summary>Non-null when decryption of a present value failed (holds the reason).</summary>
    public string? Note { get; set; }
}
