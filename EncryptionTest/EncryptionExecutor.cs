using System;
using System.IO;

namespace EncryptionTest
{
    public class EncryptionExecutor
    {
        private readonly AppLogger _logger;
        private readonly RijndaelEncryptor _encryptor;

        private const string DataFolderName = "EncryptionTestData";
        private const string InputFileName = "test.txt";
        private const string OutputFileName = "test.txt.enc";

        public EncryptionExecutor()
        {
            _logger = new AppLogger();
            // ログをファイル・コンソール・Debug出力（必要に応じて変更）
            _logger.Mode = 1 | 2 | 4;
            _encryptor = new RijndaelEncryptor();
        }

        // メイン実行メソッド
        public void Run()
        {
            try
            {
                _logger.Info("開始: 初期設定");
                var inputPath = PrepareInputFile();
                _logger.Info($"入力ファイルパス: {inputPath}");

                _logger.Info("ファイル読み取り開始");
                var plain = ReadInputFile(inputPath);
                _logger.Info($"読み取り完了: {plain.Length} バイト");

                _logger.Info("暗号化実行");
                var cipher = _encryptor.Encrypt(plain);
                _logger.Info($"暗号化完了: {cipher.Length} バイト");

                var outputPath = Path.Combine(Path.GetDirectoryName(inputPath), OutputFileName);
                _logger.Info($"ファイル出力開始: {outputPath}");
                WriteOutputFile(outputPath, cipher);
                _logger.Info("ファイル出力完了");
            }
            catch (Exception ex)
            {
                _logger.Error("実行中に例外が発生しました。", ex);
            }
        }

        private string PrepareInputFile()
        {
            var baseDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), DataFolderName);
            Directory.CreateDirectory(baseDir);
            var inputPath = Path.Combine(baseDir, InputFileName);

            if (!File.Exists(inputPath))
            {
                _logger.Info("テスト用入力ファイルが存在しないため作成します。");
                var sample = "これはテストファイルです。暗号化対象のサンプル文字列。\r\n行2のテキスト。";
                File.WriteAllText(inputPath, sample, System.Text.Encoding.UTF8);
                _logger.Info("テスト用入力ファイル作成完了");
            }
            else
            {
                _logger.Info("テスト用入力ファイルが存在します。");
            }

            return inputPath;
        }

        private byte[] ReadInputFile(string path)
        {
            return File.ReadAllBytes(path);
        }

        private void WriteOutputFile(string path, byte[] data)
        {
            File.WriteAllBytes(path, data);
        }
    }
}