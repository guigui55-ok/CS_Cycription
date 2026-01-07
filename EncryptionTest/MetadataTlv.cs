using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace EncryptionTest
{
    // TLV メタデータを構築 / 解析するユーティリティ
    public static class MetadataTlv
    {
        public static readonly byte[] Magic = Encoding.ASCII.GetBytes("AES1"); // 4 bytes
        public const byte FormatVersion = 0x01;

        // Tag 定義
        public const byte TagSalt = 0x01;
        public const byte TagIv = 0x02;
        public const byte TagKeyLen = 0x03;
        public const byte TagMode = 0x04;
        public const byte TagPadding = 0x05;
        public const byte TagKdf = 0x06;
        public const byte TagKdfHash = 0x07;
        public const byte TagAuth = 0x08;
        public const byte TagItor = 0x09;
        public const byte TagAlg = 0x0A;
        public const byte TagCustom = 0xFF;

        // TLV を組み立てる。fields の順序で出力される。
        public static byte[] BuildHeader(Dictionary<byte, byte[]> fields)
        {
            if (fields == null) throw new ArgumentNullException(nameof(fields));
            using (var ms = new MemoryStream())
            {
                foreach (var kv in fields)
                {
                    WriteTlv(ms, kv.Key, kv.Value);
                }
                return ms.ToArray();
            }
        }

        // よく使う標準ヘッダを構築するヘルパー
        public static byte[] BuildStandardHeader(byte[] salt, byte[] iv)
        {
            if (salt == null) throw new ArgumentNullException(nameof(salt));
            if (iv == null) throw new ArgumentNullException(nameof(iv));

            var fields = new Dictionary<byte, byte[]>
            {
                { TagSalt, salt },
                { TagIv, iv },
                { TagKeyLen, UInt16ToBigEndianBytes(256) },
                { TagMode, Encoding.UTF8.GetBytes("CBC") },
                { TagPadding, Encoding.UTF8.GetBytes("PKCS7") },
                { TagKdf, Encoding.UTF8.GetBytes("PBKDF2") },
                { TagKdfHash, Encoding.UTF8.GetBytes("SHA-256") },
                { TagAuth, Array.Empty<byte>() } // 将来用（空）
            };

            return BuildHeader(fields);
        }

        // TLV ヘッダ領域をパースしてタグ->値マップを返す
        public static Dictionary<byte, byte[]> ParseHeader(byte[] headerBytes)
        {
            if (headerBytes == null) throw new ArgumentNullException(nameof(headerBytes));
            var fields = new Dictionary<byte, byte[]>();
            int offset = 0;
            while (offset < headerBytes.Length)
            {
                if (offset + 1 + 2 > headerBytes.Length) throw new ArgumentException("TLV header truncated");
                byte tag = headerBytes[offset++];
                ushort len = ReadUInt16BigEndian(headerBytes, offset);
                offset += 2;
                if (offset + len > headerBytes.Length) throw new ArgumentException("TLV length invalid");
                var value = new byte[len];
                if (len > 0) Array.Copy(headerBytes, offset, value, 0, len);
                offset += len;
                fields[tag] = value;
            }
            return fields;
        }

        // ヘッダ先頭から Magic/Version/HeaderLen を検査してヘッダ領域を抽出するユーティリティ
        // 戻り: headerBytes（TLV 部分）、headerLen、payloadOffset（暗号文開始オフセット）
        public static void ReadHeaderRegion(byte[] fileBytes, out byte[] headerBytes, out uint headerLen, out int payloadOffset)
        {
            if (fileBytes == null) throw new ArgumentNullException(nameof(fileBytes));
            if (fileBytes.Length < Magic.Length + 1 + 4) throw new ArgumentException("fileBytes is too short to contain header");

            int offset = 0;
            // Magic
            for (int i = 0; i < Magic.Length; i++)
            {
                if (fileBytes[offset + i] != Magic[i]) throw new ArgumentException("Unknown file format (magic mismatch)");
            }
            offset += Magic.Length;

            // Version
            byte ver = fileBytes[offset++];
            if (ver != FormatVersion) throw new NotSupportedException("Unsupported format version");

            // HeaderLen (4 bytes big-endian)
            headerLen = ReadUInt32BigEndian(fileBytes, offset);
            offset += 4;

            if (fileBytes.Length < offset + headerLen) throw new ArgumentException("Invalid header length");

            headerBytes = new byte[headerLen];
            Array.Copy(fileBytes, offset, headerBytes, 0, headerBytes.Length);

            payloadOffset = offset + (int)headerLen;
        }

        // --- TLV ヘルパー ---
        private static void WriteTlv(MemoryStream ms, byte tag, byte[] value)
        {
            if (ms == null) throw new ArgumentNullException(nameof(ms));
            if (value == null) value = Array.Empty<byte>();

            ms.WriteByte(tag);
            var lenBytes = UInt16ToBigEndianBytes((ushort)value.Length);
            ms.Write(lenBytes, 0, 2);
            if (value.Length > 0) ms.Write(value, 0, value.Length);
        }

        public static byte[] UInt16ToBigEndianBytes(ushort v)
        {
            var b = BitConverter.GetBytes(v);
            if (BitConverter.IsLittleEndian) Array.Reverse(b);
            return b;
        }

        public static byte[] UInt32ToBigEndianBytes(uint v)
        {
            var b = BitConverter.GetBytes(v);
            if (BitConverter.IsLittleEndian) Array.Reverse(b);
            return b;
        }

        public static ushort ReadUInt16BigEndian(byte[] src, int offset)
        {
            if (src == null) throw new ArgumentNullException(nameof(src));
            if (offset + 2 > src.Length) throw new ArgumentOutOfRangeException(nameof(offset));
            return (ushort)((src[offset] << 8) | src[offset + 1]);
        }

        public static uint ReadUInt32BigEndian(byte[] src, int offset)
        {
            if (src == null) throw new ArgumentNullException(nameof(src));
            if (offset + 4 > src.Length) throw new ArgumentOutOfRangeException(nameof(offset));
            return (uint)((src[offset] << 24) | (src[offset + 1] << 16) | (src[offset + 2] << 8) | src[offset + 3]);
        }
    }
}