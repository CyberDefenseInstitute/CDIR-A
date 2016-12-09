using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Registry;
using Registry.Abstractions;
using Registry.Other;

namespace RECmd
{
    internal class Program
    {

        private static bool CheckForDotnet46()
        {
            using (var ndpKey = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry32).OpenSubKey("SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full\\"))
            {
                int releaseKey = Convert.ToInt32(ndpKey.GetValue("Release"));

                return (releaseKey >= 393295);
            }
        }

        private static void Help()
        {
            Console.WriteLine(@"regruns.exe version " + Assembly.GetExecutingAssembly().GetName().Version + "\r\n"
                +"Cyber Defense Institute, Inc. A modified version of RECmd\r\n"
                + "Usage: regruns.exe -o|--output OUTPUTFOLDER INPUTFOLDER");
            Environment.Exit(0);
        }

        private static void Main(string[] args)
        {

            if (!CheckForDotnet46())
            {
                Console.Error.WriteLine("Please install .NET Framework 4.6.");
                return;
            }

            string inDir = "", outDir = "";
            string outFileBase = $"regruns_output.csv";

            // option handling
            string[] cmds = Environment.GetCommandLineArgs();

            if (args.Length == 3 || args.Length == 4) // -o output input [--noheader]
            {
                if (args[0] == "-o" || args[0] == "--output")
                {
                    outDir = args[1];
                    inDir = args[2];
                }
                else
                    Help();
            }
//          TODO: implement standard output
//          else if (args.Length == 1) // only input
//              inDir = args[0];
            else
                Help();

            if (Directory.Exists(outDir) == false)
                Directory.CreateDirectory(outDir);

            var systemHives = new List<string>();
            var softwareHives = new List<string>();
            var ntuserHives = new List<string>();

            // Search SYSTEM/SOFTWARE/NTUSER.DAT Hive
            foreach (string fileName in Directory.GetFiles(inDir, "*", SearchOption.AllDirectories))
            {
                Stream st = File.OpenRead(fileName);
                if (st.Length < 4)
                    continue;

                BinaryReader br = new BinaryReader(st);
                if (br.ReadInt32() != 1718052210) // means not "regf"
                    continue;

                if (Path.GetFileName(fileName).ToUpper().Contains("SYSTEM"))
                    systemHives.Add(fileName);
                else if (Path.GetFileName(fileName).ToUpper().Contains("SOFTWARE"))
                    softwareHives.Add(fileName);
                else if (Path.GetFileName(fileName).ToUpper().Contains("NTUSER.DAT"))
                    ntuserHives.Add(fileName);
            }

            var outFileName = Path.Combine(outDir, outFileBase);
            var sw = new StreamWriter(outFileName, true, System.Text.Encoding.UTF8);
            sw.AutoFlush = true;
            if (args.Length == 4)
                if (args[3] == "--noheader")
                {
                    // no header
                }
                else
                    sw.WriteLine("ComputerName\tHiveName\tKey\tName\tValue\tLastModified\tTimeZone");
            else
                sw.WriteLine("ComputerName\tHiveName\tKey\tName\tValue\tLastModified\tTimeZone");

            // SYSTEM
            foreach (var systemHive in systemHives)
            {

                var reg = new RegistryHive(systemHive);

                try
                {
                    reg.ParseHive();
                }
                catch
                {
                    Console.Error.WriteLine($"Error: {systemHive}");
                    continue;
                }

                var subKey = reg.GetKey("Select");
                if (subKey == null)
                    continue;

                var currentCtlSet = int.Parse(subKey.Values.Single(c => c.ValueName == "Current").ValueData);

                StreamReader cReader = new StreamReader(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + @"\system.txt", System.Text.Encoding.Default);

                // read key per line
                while (cReader.Peek() >= 0)
                {
                    string keyName = cReader.ReadLine();
                    var key = reg.GetKey($@"ControlSet00{currentCtlSet}\{keyName}");

                    if (key == null)
                        continue;

                    WriteSpecificKeyInfo(key, sw, systemHive);
                }

                Console.WriteLine($"Finished: '{systemHive}'");
                cReader.Close();
            }

            // SOFTWARE
            foreach (var softwareHive in softwareHives)
            {
                var reg = new RegistryHive(softwareHive);

                try
                {
                    reg.ParseHive();
                }
                catch
                {
                    Console.Error.WriteLine($"Error: {softwareHive}");
                    continue;
                }

                StreamReader cReader = new StreamReader(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + @"\software.txt", System.Text.Encoding.Default);

                // read key per line
                while (cReader.Peek() >= 0)
                {
                    string keyName = cReader.ReadLine();
                    var key = reg.GetKey(keyName);

                    if (key == null)
                        continue;

                    WriteSpecificKeyInfo(key, sw, softwareHive);
                }

                Console.WriteLine($"Finished: '{softwareHive}'");
                cReader.Close();

            }

            // NTUSER.dat
            foreach (var ntuserHive in ntuserHives)
            {
                var reg = new RegistryHive(ntuserHive);

                try
                {
                    reg.ParseHive();
                }
                catch
                {
                    Console.Error.WriteLine($"Error: {ntuserHive}");
                    continue;
                }

                StreamReader cReader = new StreamReader(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location) + @"\ntuser.txt", System.Text.Encoding.Default);

                // read key by line
                while (cReader.Peek() >= 0)
                {
                    string keyName = cReader.ReadLine();
                    var key = reg.GetKey(keyName);

                    if (key == null)
                        continue;

                    WriteSpecificKeyInfo(key, sw, ntuserHive);
                }

                Console.WriteLine($"Finished: '{ntuserHive}'");
                cReader.Close();

            }

            Console.WriteLine($"Saved: '{outFileName}'");
            sw.Close();
            return;

        }

        // write entries information recursively under specified key
        private static void WriteSpecificKeyInfo(RegistryKey key, StreamWriter sw, string filepath)
        {

            string computerName = ExtractComputerName(filepath);
            string hiveName = Path.GetFileName(filepath);

            // processing if entries exist under specified key
            if (key.Values.Count > 0)
                WriteValueData(key, sw, computerName, hiveName);
            // loop processing if entries exist under specified key
            if (key.SubKeys.Count > 0)
            {
                foreach (var sk in key.SubKeys)
                    WriteSubKeyData(sk, sw, computerName, hiveName);
            }
        }

        // extract computername from filepath info
        private static string ExtractComputerName(string filepath)
        {
            DirectoryInfo parentFolder = Directory.GetParent(filepath);
            string targetFolder = parentFolder.Parent.ToString();
            return targetFolder.Substring(0, targetFolder.LastIndexOf('_'));
        }

        // write entries information under specified key
        private static void WriteValueData(RegistryKey key, StreamWriter sw, string computerName, string hiveName)
        {
            string timestampStr = key.LastWriteTime.Value.LocalDateTime.ToString("yyyy/MM/dd HH:mm:ss.fff");
            string tzStr = key.LastWriteTime.Value.LocalDateTime.ToString("zzz");

            foreach (var keyValue in key.Values)
            {
                if (keyValue.ValueData.Length > 256)
                    sw.WriteLine("{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}", 
                        computerName, hiveName, Helpers.StripRootKeyNameFromKeyPath(key.KeyPath), keyValue.ValueName, $"(Large Data: {keyValue.ValueDataRaw.Length} bytes", timestampStr, tzStr);
                else
                    sw.WriteLine("{0}\t{1}\t{2}\t{3}\t{4}\t{5}\t{6}", 
                        computerName, hiveName, Helpers.StripRootKeyNameFromKeyPath(key.KeyPath), keyValue.ValueName, keyValue.ValueData, timestampStr, tzStr);
            }
        }

        // write entries information under subkey of specified key
        private static void WriteSubKeyData(RegistryKey key, StreamWriter sw, string computerName, string hiveName)
        {

            if (key.SubKeys.Count > 0)
            {
                foreach (var sk in key.SubKeys)
                {
                    if (sk.Values.Count > 0)
                        WriteValueData(sk, sw, computerName, hiveName);
                    else // wirte only key and timestamp if no entries exist
                    {
                        string timestampStr = key.LastWriteTime.Value.LocalDateTime.ToString("yyyy/MM/dd HH:mm:ss.fff");
                        string tzStr = key.LastWriteTime.Value.LocalDateTime.ToString("zzz");
                        sw.WriteLine("{0}\t{1}\t{2}\t\t\t{3}\t{4}", 
                            computerName, hiveName, Helpers.StripRootKeyNameFromKeyPath(key.KeyPath), timestampStr, tzStr);
                    }
                }
            }
        }
    }

    internal class ApplicationArguments
    {
        public string HiveFile { get; set; } = string.Empty;
        public string Directory { get; set; } = string.Empty;
        public bool RecoverDeleted { get; set; } = false;
        public string KeyName { get; set; } = string.Empty;
        public string SaveTo { get; set; } = string.Empty;
        public bool NoHeader { get; set; } = false;
        public string ValueName { get; set; } = string.Empty;
        public string SaveToName { get; set; } = string.Empty;
        public bool Recursive { get; set; } = false;
        public string SimpleSearchKey { get; set; } = string.Empty;
        public string DumpKey { get; set; } = string.Empty;
        public string DumpDir { get; set; } = string.Empty;
        public string SimpleSearchValue { get; set; } = string.Empty;
        public string SimpleSearchValueData { get; set; } = string.Empty;
        public string SimpleSearchValueSlack { get; set; } = string.Empty;
        public int MinimumSize { get; set; }
        public string StartDate { get; set; }
        public string EndDate { get; set; }
        public bool Sort { get; set; }
        public bool RegEx { get; set; }
        public bool Literal { get; set; }
        public bool SuppressData { get; set; }
    }
}