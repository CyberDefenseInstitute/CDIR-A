using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Microsoft.Win32;
using Registry.Abstractions;
using Registry.Other;
using CsvHelper;
using CsvHelper.Configuration;
using RegistryHive = Registry.RegistryHive;
using RegistryKey = Registry.Abstractions.RegistryKey;
namespace RECmd
{
    internal class Program
    {

        private static bool CheckForDotnet46()
        {
            using (var ndpKey = Microsoft.Win32.RegistryKey
                .OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry32)
                .OpenSubKey("SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full\\"))
            {
                var releaseKey = Convert.ToInt32(ndpKey.GetValue("Release"));

                return releaseKey >= 393295;
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
            bool hiveFlag = false;
            // Search SYSTEM/SOFTWARE/NTUSER.DAT Hive
            foreach (string fileName in Directory.GetFiles(inDir, "*", SearchOption.AllDirectories))
            {
                DirectoryInfo parentFolder = Directory.GetParent(fileName);
                if (outDir.Contains(parentFolder.ToString()))
                    continue;
                try
                {
                    Stream st = File.OpenRead(fileName);
                    if (st.Length < 4)
                        continue;

                    BinaryReader br = new BinaryReader(st);
                    if (br.ReadInt32() != 1718052210) // means not "regf"
                        continue;

                    if (Path.GetFileName(fileName).ToUpper().EndsWith("SYSTEM"))
                    {
                        systemHives.Add(fileName);
                        hiveFlag = true;
                    }
                    else if (Path.GetFileName(fileName).ToUpper().EndsWith("SOFTWARE"))
                    {
                        softwareHives.Add(fileName);
                        hiveFlag = true;
                    }
                    else if (Path.GetFileName(fileName).ToUpper().EndsWith("NTUSER.DAT"))
                    {
                        ntuserHives.Add(fileName);
                        hiveFlag = true;
                    }
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Skip: " + fileName);
                    //Console.Error.WriteLine($"Skip: {ex.Message}");
                }
            }

            var outFileName = Path.Combine(outDir, outFileBase);
            var sw = new StreamWriter(outFileName, true, new System.Text.UTF8Encoding(false));
            sw.AutoFlush = true;
            var csv = new CsvWriter(sw);
            csv.Configuration.RegisterClassMap<CacheOutputMap>();
            csv.Configuration.Delimiter = "\t";
            csv.Configuration.Encoding = new System.Text.UTF8Encoding(false);
            csv.Configuration.IgnoreQuotes = false;
            csv.Configuration.Quote = '"';
            csv.Configuration.QuoteAllFields = true;


            if (args.Length == 4)
                if (args[3] == "--noheader")
                    csv.Configuration.HasHeaderRecord = false;
                else
                    csv.WriteHeader<CacheEntry>();
            else
                csv.WriteHeader<CacheEntry>();

            // SYSTEM
            foreach (var systemHive in systemHives)
            {

                var reg = new RegistryHive(systemHive);
//                var reg = new RegistryHiveOnDemand(systemHive);

                if (reg.Header.PrimarySequenceNumber != reg.Header.SecondarySequenceNumber)
                {
                    var logFiles = Directory.GetFiles(Path.GetDirectoryName(systemHive), Path.GetFileName(systemHive)+".LOG*");

                    if (logFiles.Length == 0)
                    {
                        Console.WriteLine("Registry hive is dirty and no transaction logs were found in the same directory! Skip!!");
                        continue;
                    }

                    reg.ProcessTransactionLogs(logFiles.ToList(), true);
                }

                reg.ParseHive();

                var subKey = reg.GetKey("Select");
                if (subKey == null)
                    continue;

                var currentCtlSet = int.Parse(subKey.Values.Single(c => c.ValueName == "Current").ValueData);

                StreamReader cReader = new StreamReader(Path.Combine(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), "system.txt"), System.Text.Encoding.Default);

                // read key per line
                while (cReader.Peek() >= 0)
                {
                    string keyName = cReader.ReadLine();
                    try
                    {
                        var key = reg.GetKey($@"ControlSet00{currentCtlSet}\{keyName}");

                        if (key == null)
                            continue;

                        WriteSpecificKeyInfo(key, csv, systemHive);
                    }
                    catch
                    {
                        Console.Error.WriteLine($"Error: {systemHive},{keyName}");
                        continue;
                    }
                }

                Console.WriteLine($"Finished: '{systemHive}'");
                cReader.Close();
            }

            // SOFTWARE
            foreach (var softwareHive in softwareHives)
            {
                var reg = new RegistryHive(softwareHive);
//                var reg = new RegistryHiveOnDemand(softwareHive);

                if (reg.Header.PrimarySequenceNumber != reg.Header.SecondarySequenceNumber)
                {
                    var logFiles = Directory.GetFiles(Path.GetDirectoryName(softwareHive), Path.GetFileName(softwareHive)+".LOG*");

                    if (logFiles.Length == 0)
                    {
                        Console.WriteLine("Registry hive is dirty and no transaction logs were found in the same directory! Skip!!");
                        continue;
                    }

                    reg.ProcessTransactionLogs(logFiles.ToList(), true);
                }

                reg.ParseHive();

                StreamReader cReader = new StreamReader(Path.Combine(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), "software.txt"), System.Text.Encoding.Default);

                // read key per line
                while (cReader.Peek() >= 0)
                {
                    string keyName = cReader.ReadLine();
                    try
                    {
                        var key = reg.GetKey(keyName);

                        if (key == null)
                            continue;
                        WriteSpecificKeyInfo(key, csv, softwareHive);
                    }
                    catch
                    {
                        Console.Error.WriteLine($"Error: {softwareHive}, {keyName}");
                        continue;
                    }
                }

                Console.WriteLine($"Finished: '{softwareHive}'");
                cReader.Close();

            }

            // NTUSER.dat
            foreach (var ntuserHive in ntuserHives)
            {
                var reg = new RegistryHive(ntuserHive);
//                var reg = new RegistryHiveOnDemand(ntuserHive);

                if (reg.Header.PrimarySequenceNumber != reg.Header.SecondarySequenceNumber)
                {
                    var logFiles = Directory.GetFiles(Path.GetDirectoryName(ntuserHive), Path.GetFileName(ntuserHive) +".LOG*");

                    if (logFiles.Length == 0)
                    {
                        Console.WriteLine("Registry hive is dirty and no transaction logs were found in the same directory! Skip!!");
                        continue;
                    }

                    reg.ProcessTransactionLogs(logFiles.ToList(), true);
                }

                reg.ParseHive();
                StreamReader cReader = new StreamReader(Path.Combine(Path.GetDirectoryName(Assembly.GetEntryAssembly().Location), "ntuser.txt"), System.Text.Encoding.Default);

                // read key by line
                while (cReader.Peek() >= 0)
                {
                    string keyName = cReader.ReadLine();
                    try
                    {
                        var key = reg.GetKey(keyName);

                        if (key == null)
                            continue;

                        WriteSpecificKeyInfo(key, csv, ntuserHive);
                    }
                    catch
                    {                    
                        Console.Error.WriteLine($"Error: {ntuserHive}, {keyName}");
                        continue;
                    }

                }

                Console.WriteLine($"Finished: '{ntuserHive}'");
                cReader.Close();

            }

            sw.Close();
            if (hiveFlag == true)
                Console.WriteLine($"Saved: '{outFileName}'");
            else
                Console.WriteLine($"Found 0 entries..");
            return;

        }

        // write entries information recursively under specified key
        private static void WriteSpecificKeyInfo(RegistryKey key, CsvWriter csv, string filepath)
        {

            string computerName = ExtractComputerName(filepath);
            string hiveName = Path.GetFileName(filepath);

            // processing if entries exist under specified key
            if (key.Values.Count > 0)
                WriteValueData(key, csv, computerName, hiveName);
            // loop processing if entries exist under specified key
            if (key.SubKeys.Count > 0)
            {
                foreach (var sk in key.SubKeys)
                    WriteSubKeyData(sk, csv, computerName, hiveName);
            }
        }

        // write entries information under subkey of specified key
        private static void WriteSubKeyData(RegistryKey key, CsvWriter csv, string computerName, string hiveName)
        {

            if (key.SubKeys.Count > 0)
            {
                foreach (var sk in key.SubKeys)
                {
                    if (sk.Values.Count > 0)
                        WriteValueData(sk, csv, computerName, hiveName);
                    else // wirte only key and timestamp if no entries exist
                    {
                        var ce = new CacheEntry();

                        ce.ComputerName = computerName;
                        ce.HiveName = hiveName;
                        ce.Key = Helpers.StripRootKeyNameFromKeyPath(key.KeyPath);
                        ce.Name = "";
                        ce.Value = "";
                        ce.LastModified = key.LastWriteTime.Value.LocalDateTime.ToString("yyyy/MM/dd HH:mm:ss.fff");
                        ce.TimeZone = key.LastWriteTime.Value.LocalDateTime.ToString("zzz");

                        csv.WriteRecord(ce);

                    }
                }
            }
        }

        // write entries information under specified key
        private static void WriteValueData(RegistryKey key, CsvWriter csv, string computerName, string hiveName)
        {

            foreach (var keyValue in key.Values)
            {

                var ce = new CacheEntry();

                ce.ComputerName = computerName;
                ce.HiveName = hiveName;
                ce.Key = Helpers.StripRootKeyNameFromKeyPath(key.KeyPath);
                ce.Name = keyValue.ValueName;
                if (keyValue.ValueData.Length > 256)
                    ce.Value = $"(Large Data: {keyValue.ValueDataRaw.Length} bytes";
                else
                    ce.Value = keyValue.ValueData;
                ce.LastModified = key.LastWriteTime.Value.LocalDateTime.ToString("yyyy/MM/dd HH:mm:ss.fff");
                ce.TimeZone = key.LastWriteTime.Value.LocalDateTime.ToString("zzz");

                csv.WriteRecord(ce);
            }
        }

        // extract computername from filepath info
        private static string ExtractComputerName(string filepath)
        {
            DirectoryInfo parentFolder = Directory.GetParent(filepath);
            string targetFolder = parentFolder.Parent.ToString();
            return targetFolder.Substring(0, targetFolder.LastIndexOf('_'));
        }

    }

    public class CacheEntry
    {
        public string ComputerName { get; set; }
        public string HiveName { get; set; }
        public string Key { get; set; }
        public string Name { get; set; }
        public string Value { get; set; }
        public string LastModified { get; set; }
        public string TimeZone { get; set; }
    }

    public sealed class CacheOutputMap : CsvClassMap<CacheEntry>
    {
        public CacheOutputMap()
        {
            Map(m => m.ComputerName);
            Map(m => m.HiveName);
            Map(m => m.Key);
            Map(m => m.Name);
            Map(m => m.Value);
            Map(m => m.LastModified);
            Map(m => m.TimeZone);
        }
    }


    public interface IRegrunsCache
    {
        List<CacheEntry> Entries { get; }
    }

}
