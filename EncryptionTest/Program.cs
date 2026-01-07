using System;
using System.IO;

namespace EncryptionTest
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("実行選択:");
            Console.WriteLine("1: 既存の暗号化フロー (RijndaelEncryptor を使用する既存の EncryptionExecutor)");
            Console.WriteLine("2: 新規 AES 暗号化フロー (AesEncryptor を使用)");
            Console.WriteLine("3: 複合化サンプル (既存の DecryptionTestMain)");
            Console.Write("番号を入力してください (1/2/3) : ");
            var key = Console.ReadKey();
            Console.WriteLine();

            switch (key.KeyChar)
            {
                case '1':
                    EncryptionTestMain();
                    break;
                case '2':
                    AesEncryptionTestMain();
                    break;
                case '3':
                    DecryptionTestMain();
                    break;
                default:
                    Console.WriteLine("不正な選択です。既定で既存フローを実行します。");
                    EncryptionTestMain();
                    break;
            }

            Console.WriteLine("処理が終了しました。Enterキーで終了します...");
            Console.ReadLine();
        }

        // 既存の暗号化フローを呼び出すメソッド（変更なし）
        private static void EncryptionTestMain()
        {
            var executor = new EncryptionExecutor();
            executor.Run();
        }

        // 新規: AesEncryptor を用いた暗号化サンプル（EncryptionExecutor と同様の動作）
        private static void AesEncryptionTestMain()
        {
            var logger = new AppLogger();
            logger.Mode = 1 | 2 | 4;

            try
            {
                logger.Info("Aes 暗号化サンプル開始: 初期設定");

                var baseDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "EncryptionTestData");
                Directory.CreateDirectory(baseDir);

                var inputPath = Path.Combine(baseDir, "test.txt");
                var outputPath = Path.Combine(baseDir, "test.txt.enc");

                if (!File.Exists(inputPath))
                {
                    logger.Info("入力ファイルが存在しないためサンプルを作成します。");
                    var sample = "テストファイル (AES フロー) のサンプルテキストです。\r\n行2 のテキスト。";
                    File.WriteAllText(inputPath, sample, System.Text.Encoding.UTF8);
                }

                logger.Info($"入力ファイルを読み込み: {inputPath}");
                var plain = File.ReadAllBytes(inputPath);
                logger.Info($"読み取り完了: {plain.Length} バイト");

                var aes = new AesEncryptor();
                logger.Info("暗号化実行 (AES)");
                var cipher = aes.Encrypt(plain);
                logger.Info($"暗号化完了: {cipher.Length} バイト");

                File.WriteAllBytes(outputPath, cipher);
                logger.Info($"暗号化出力完了: {outputPath}");
            }
            catch (Exception ex)
            {
                logger.Error("AES 暗号化中に例外が発生しました。", ex);
            }
        }

        // 複合化のサンプル処理（既存の実装を維持）
        private static void DecryptionTestMain()
        {
            var logger = new AppLogger();
            logger.Mode = 1 | 2 | 4;

            try
            {
                logger.Info("複合化サンプル開始: 初期設定");

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
