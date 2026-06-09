using System.Security.Cryptography;

public class LegacyCrypto
{
    // Quantum-vulnerable: RSA key generation
    public RSA MakeKey() => RSA.Create(2048);

    // Quantum-vulnerable: elliptic-curve signature
    public ECDsa Sign() => ECDsa.Create(ECCurve.NamedCurves.nistP256);

    // Broken: MD5 + SHA-1
    public byte[] Hash(byte[] d) => MD5.Create().ComputeHash(d);
    public byte[] LegacyHash(byte[] d) => SHA1.Create().ComputeHash(d);

    // Already good: AES-256
    public Aes Strong() => Aes.Create(); // AES-256 keying elsewhere
}
