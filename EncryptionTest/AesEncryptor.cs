using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;

namespace EncryptionTest
{
    // RijndaelEncryptor と同じ公開インターフェースに合わせた AES 実装
    // メタデータは MetadataTlv に委譲して TLV（バイナリ）形式でファイル先頭に格納する。
    public class AesEncryptor
    {
        // 互換用の固定パスワード/ソルト（テスト用） - 既存コード互換を保つため残す
        private const string Password = "P@ssw0rd-Fixed-ForTest";
        private static readonly byte[] FixedSalt = new byte[] { 0x21, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };

        // 仕様: 反復回数 100,000（コード内定数として管理、ファイルには通常書き込まない）
        private const int Iterations = 100000;

        // 既定のソルト長 (バイト)
        private const int SaltLength = 16;

        // AES 用キー（互換用：コンストラクタで固定パスワードから導出）
        private readonly byte[] _key;

        public AesEncryptor()
        {
            // 既存互換のため、固定パスワード + 固定ソルトからの鍵も保持しておく
            _key = DeriveKey(Password, FixedSalt, Iterations, 32);
        }

        // 互換性のための既存シグネチャ（固定パスワードを使用）
        public byte[] Encrypt(byte[] plainBytes)
        {
            return Encrypt(plainBytes, Password);
        }

        // 新: 外部からパスワードを指定して暗号化するメソッド
        // フォーマット: [Magic(4)] [Version(1)] [HeaderLen(4 BE)] [TLVヘッダ (HeaderLen bytes)] [ciphertext bytes]
        public byte[] Encrypt(byte[] plainBytes, string password)
        {
            if (plainBytes == null || plainBytes.Length == 0) throw new ArgumentException("plainBytes is null or empty");
            if (password == null) throw new ArgumentNullException(nameof(password));

            // ランダムソルトを生成
            var salt = new byte[SaltLength];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            // パスワード + ソルトから鍵を導出（AES-256）
            var key = DeriveKey(password, salt, Iterations, 32);

            byte[] ciphertext;
            byte[] iv;

            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.KeySize = 256;
                aes.Key = key;
                aes.GenerateIV(); // ランダム IV を生成（毎回）
                iv = aes.IV;

                using (var msCipher = new MemoryStream())
                using (var crypto = aes.CreateEncryptor(aes.Key, aes.IV))
                using (var cs = new CryptoStream(msCipher, crypto, CryptoStreamMode.Write))
                {
                    cs.Write(plainBytes, 0, plainBytes.Length);
                    cs.FlushFinalBlock();
                    ciphertext = msCipher.ToArray();
                }
            }

            // TLV ヘッダを MetadataTlv に構築させる
            var headerBytes = MetadataTlv.BuildStandardHeader(salt, iv);

            // 最終出力を組み立てる
            using (var msOut = new MemoryStream())
            {
                // Magic
                msOut.Write(MetadataTlv.Magic, 0, MetadataTlv.Magic.Length);

                // Version
                msOut.WriteByte(MetadataTlv.FormatVersion);

                // Header length (4 bytes big-endian)
                msOut.Write(MetadataTlv.UInt32ToBigEndianBytes((uint)headerBytes.Length), 0, 4);

                // Header (TLV bytes)
                msOut.Write(headerBytes, 0, headerBytes.Length);

                // Ciphertext
                msOut.Write(ciphertext, 0, ciphertext.Length);

                return msOut.ToArray();
            }
        }

        // 文字列版（UTF8） - 互換版（固定パスワード）
        public byte[] EncryptString(string plainText)
        {
            return EncryptString(plainText, Password);
        }

        // 文字列版（UTF8） - パスワード指定版
        public byte[] EncryptString(string plainText, string password)
        {
            var bytes = Encoding.UTF8.GetBytes(plainText);
            return Encrypt(bytes, password);
        }

        // 互換版：デフォルト Decrypt は既存互換のため固定振る舞いを維持
        // ここでは入力が新フォーマット（Magic がある）なら固定パスワードで復号を試みる
        // それ以外は従来互換復号（未サポート）へフォールバックする
        public byte[] Decrypt(byte[] cipherBytes)
        {
            if (cipherBytes == null || cipherBytes.Length == 0) throw new ArgumentException("cipherBytes is null or empty");

            // 新フォーマット判定: 先頭に Magic があるか
            if (cipherBytes.Length >= MetadataTlv.Magic.Length + 1)
            {
                bool hasMagic = true;
                for (int i = 0; i < MetadataTlv.Magic.Length; i++)
                {
                    if (cipherBytes[i] != MetadataTlv.Magic[i])
                    {
                        hasMagic = false;
                        break;
                    }
                }

                if (hasMagic)
                {
                    // 新フォーマットなら既定の固定パスワードで復号を試みる
                    return Decrypt(cipherBytes, Password);
                }
            }

            // 既存旧形式の互換復号（固定ソルト等の既往の形式）をサポートしない
            return DecryptWithFixedSalt(cipherBytes);
        }

        // 新: パスワード指定版の復号（期待入力形式: Magic + ver + headerLen + TLV + ciphertext）
        public byte[] Decrypt(byte[] fileBytes, string password)
        {
            if (fileBytes == null || fileBytes.Length == 0) throw new ArgumentException("fileBytes is null or empty");
            if (password == null) throw new ArgumentNullException(nameof(password));

            // ヘッダ領域を抽出
            MetadataTlv.ReadHeaderRegion(fileBytes, out var headerBytes, out var headerLen, out var payloadOffset);

            // TLV をパースして salt/iv を取得
            var fields = MetadataTlv.ParseHeader(headerBytes);

            if (!fields.TryGetValue(MetadataTlv.TagSalt, out var salt) || salt == null)
                throw new ArgumentException("salt not found in header");
            if (!fields.TryGetValue(MetadataTlv.TagIv, out var iv) || iv == null)
                throw new ArgumentException("iv not found in header");

            // 残りが ciphertext
            var cipherLen = fileBytes.Length - payloadOffset;
            if (cipherLen <= 0) throw new ArgumentException("ciphertext missing");

            var actualCipher = new byte[cipherLen];
            Array.Copy(fileBytes, payloadOffset, actualCipher, 0, cipherLen);

            // 鍵を導出
            var key = DeriveKey(password, salt, Iterations, 32);

            using (var aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.KeySize = 256;
                aes.Key = key;

                using (var ms = new MemoryStream())
                using (var crypto = aes.CreateDecryptor(aes.Key, iv))
                using (var cs = new CryptoStream(ms, crypto, CryptoStreamMode.Write))
                {
                    cs.Write(actualCipher, 0, actualCipher.Length);
                    cs.FlushFinalBlock();
                    return ms.ToArray();
                }
            }
        }

        // 互換用固定ソルト復号（既存の固定派生鍵で暗号化されたデータを扱う場合）
        private byte[] DecryptWithFixedSalt(byte[] cipherBytes)
        {
            // 既存 RijndaelEncryptor と同様に固定 IV を使っていた場合の復号は難しいため
            throw new NotSupportedException("固定ソルト/固定IV 形式の互換復号はサポートしていません。パスワード指定版の Decrypt(fileBytes, password) を使用してください。");
        }

        // 復号して文字列で返す（UTF8） - 互換版（固定パスワード）
        public string DecryptToString(byte[] cipherBytes)
        {
            var plain = Decrypt(cipherBytes);
            return Encoding.UTF8.GetString(plain);
        }

        // 復号して文字列で返す（UTF8） - パスワード指定版
        public string DecryptToString(byte[] cipherBytes, string password)
        {
            var plain = Decrypt(cipherBytes, password);
            return Encoding.UTF8.GetString(plain);
        }

        // PBKDF2-HMAC-SHA256 を手実装（.NET Framework 4.7 環境で SHA-256 指定が使えない場合に備えて）
        private static byte[] DeriveKey(string password, byte[] salt, int iterations, int dkLen)
        {
            if (password == null) throw new ArgumentNullException(nameof(password));
            if (salt == null) throw new ArgumentNullException(nameof(salt));
            if (iterations <= 0) throw new ArgumentOutOfRangeException(nameof(iterations));
            if (dkLen <= 0) throw new ArgumentOutOfRangeException(nameof(dkLen));

            var passwordBytes = Encoding.UTF8.GetBytes(password);
            using (var hmac = new HMACSHA256(passwordBytes))
            {
                int hashLen = hmac.HashSize / 8;
                int blocks = (int)Math.Ceiling((double)dkLen / hashLen);
                var derived = new byte[dkLen];
                for (int i = 1; i <= blocks; i++)
                {
                    // U_1 = HMAC(password, salt || INT(i))
                    hmac.Initialize();
                    hmac.TransformBlock(salt, 0, salt.Length, null, 0);
                    var intBlock = GetBigEndianBytes(i);
                    hmac.TransformFinalBlock(intBlock, 0, intBlock.Length);
                    var u = hmac.Hash; // U_1

                    var t = (byte[])u.Clone();

                    for (int j = 2; j <= iterations; j++)
                    {
                        u = hmac.ComputeHash(u); // U_j
                        for (int k = 0; k < hashLen; k++)
                        {
                            t[k] ^= u[k];
                        }
                    }

                    int destOffset = (i - 1) * hashLen;
                    int remaining = dkLen - destOffset;
                    int toCopy = Math.Min(hashLen, remaining);
                    Array.Copy(t, 0, derived, destOffset, toCopy);
                }

                return derived;
            }
        }

        private static byte[] GetBigEndianBytes(int i)
        {
            var b = BitConverter.GetBytes(i);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(b);
            }
            return b;
        }
    }
}