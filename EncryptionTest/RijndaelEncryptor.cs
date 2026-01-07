using System;
using System.IO;
using System.Security.Cryptography;

namespace EncryptionTest
{
    public class RijndaelEncryptor
    {
        private readonly byte[] _key;
        private readonly byte[] _iv;

        // 固定パスワード/ソルト（テスト用）
        private const string Password = "P@ssw0rd-Fixed-ForTest";
        private static readonly byte[] Salt = new byte[] { 0x21, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

        // PBKDF2 iterations
        private const int Iterations = 1000;

        public RijndaelEncryptor()
        {
            using (var pdb = new Rfc2898DeriveBytes(Password, Salt, Iterations))
            {
                using (var temp = new RijndaelManaged())
                {
                    int keyBytes = temp.KeySize / 8;
                    int ivBytes = temp.BlockSize / 8;

                    // Key と IV を PBKDF2 から取得（IVもここから取得する仕様）
                    _key = pdb.GetBytes(keyBytes);
                    _iv = pdb.GetBytes(ivBytes);
                }
            }
        }

        // バイト配列を暗号化してバイト配列で返す
        public byte[] Encrypt(byte[] plainBytes)
        {
            if (plainBytes == null || plainBytes.Length == 0) throw new ArgumentException("plainBytes is null or empty");

            using (var rij = new RijndaelManaged())
            {
                rij.Mode = CipherMode.CBC;
                rij.Padding = PaddingMode.PKCS7;
                rij.Key = _key;
                rij.IV = _iv;

                using (var ms = new MemoryStream())
                using (var crypto = rij.CreateEncryptor())
                using (var cs = new CryptoStream(ms, crypto, CryptoStreamMode.Write))
                {
                    cs.Write(plainBytes, 0, plainBytes.Length);
                    cs.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }

        // 文字列版（UTF8）
        public byte[] EncryptString(string plainText)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return Encrypt(bytes);
        }

        // バイト配列を復号してバイト配列で返す
        public byte[] Decrypt(byte[] cipherBytes)
        {
            if (cipherBytes == null || cipherBytes.Length == 0) throw new ArgumentException("cipherBytes is null or empty");

            using (var rij = new RijndaelManaged())
            {
                rij.Mode = CipherMode.CBC;
                rij.Padding = PaddingMode.PKCS7;
                rij.Key = _key;
                rij.IV = _iv;

                using (var ms = new MemoryStream())
                using (var crypto = rij.CreateDecryptor())
                using (var cs = new CryptoStream(ms, crypto, CryptoStreamMode.Write))
                {
                    cs.Write(cipherBytes, 0, cipherBytes.Length);
                    cs.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }

        // 復号して文字列で返す（UTF8）
        public string DecryptToString(byte[] cipherBytes)
        {
            var plain = Decrypt(cipherBytes);
            return System.Text.Encoding.UTF8.GetString(plain);
        }
    }
}