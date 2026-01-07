using System;
using System.IO;
using System.Diagnostics;

namespace EncryptionTest
{
    public class AppLogger
    {
        // 公開メンバで任意設定可能
        public string DirectoryPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "EncryptionTestLogs");
        public string FileName = "app.log";

        // モードはビットフラグ: 1 = ファイル出力, 2 = コンソール出力, 4 = Debug出力
        public int Mode = 1 | 2;

        private string LogFilePath => Path.Combine(DirectoryPath, FileName);

        public void Info(string value)
        {
            Write("INFO", value, null);
        }

        public void Error(string value)
        {
            Write("ERROR", value, null);
        }

        public void Error(string value, Exception ex)
        {
            Write("ERROR", value, ex);
        }

        private void Write(string level, string message, Exception ex)
        {
            string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
            string text = $"[{timestamp}] {level}: {message}";
            if (ex != null)
            {
                text += Environment.NewLine + ex.ToString();
            }

            if ((Mode & 1) != 0)
            {
                try
                {
                    Directory.CreateDirectory(DirectoryPath);
                    File.AppendAllText(LogFilePath, text + Environment.NewLine);
                }
                catch
                {
                    // テスト用簡易実装なので失敗は無視
                }
            }

            if ((Mode & 2) != 0)
            {
                Console.WriteLine(text);
            }

            if ((Mode & 4) != 0)
            {
                Debug.WriteLine(text);
            }
        }
    }
}