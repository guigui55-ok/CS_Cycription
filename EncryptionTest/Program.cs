using System;
using System.IO;

namespace EncryptionTest
{
    internal class Program
    {
        static void Main(string[] args)
        {
            // 手動で切り替えてください（コメントアウト/解除）
            EncryptionTestMain();
            // DecryptionTestMain();

            Console.WriteLine("処理が終了しました。Enterキーで終了します...");
            Console.ReadLine();
        }

        // 既存の暗号化フローを呼び出すメソッド（現在の実装を移動）
        private static void EncryptionTestMain()
        {
            var executor = new EncryptionExecutor();
            executor.Run();
        }

        // 複合化のサンプル処理（暗号化と同じパラメータで復号します）
        private static void DecryptionTestMain()
        {
            var logger = new AppLogger();
            logger.Mode = 1 | 2 | 4;

            try
            {
                logger.Info("複合化サンプル開始: 初期設定");

                // 入出力パス（EncryptionExecutor と同じ場所・ファイル名を使用）
                var baseDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "EncryptionTestData");
                var encryptedPath = Path.Combine(baseDir, "test.txt.enc");
                var decryptedPath = Path.Combine(baseDir, "test.txt.dec.txt");

                if (!File.Exists(encryptedPath))
                {
                    logger.Error($"暗号化ファイルが存在しません: {encryptedPath}");
                    return;
                }

                logger.Info($"暗号化ファイル読み取り: {encryptedPath}");
                var cipher = File.ReadAllBytes(encryptedPath);
                logger.Info($"読み取り完了: {cipher.Length} バイト");

                var decryptor = new RijndaelEncryptor();
                logger.Info("複合化実行");
                var plain = decryptor.Decrypt(cipher);
                logger.Info($"複合化完了: {plain.Length} バイト");

                File.WriteAllBytes(decryptedPath, plain);
                logger.Info($"複合化出力完了: {decryptedPath}");
            }
            catch (Exception ex)
            {
                logger.Error("複合化中に例外が発生しました。", ex);
            }
        }
    }
}
