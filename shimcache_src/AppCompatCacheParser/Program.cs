using System;
using System.IO;
using System.Reflection;
using AppCompatCache;
using CsvHelper;
using CsvHelper.Configuration;

namespace AppCompatCacheParser
{
    internal class Program
    {

        private static bool CheckForDotnet46()
        {
            using (
                var ndpKey =
                    Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry32)
                        .OpenSubKey("SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full\\"))
            {
                var releaseKey = Convert.ToInt32(ndpKey.GetValue("Release"));

                return (releaseKey >= 393295);
            }
        }
        private static void Help()
        {
            Console.WriteLine(@"shimcache.exe version " + Assembly.GetExecutingAssembly().GetName().Version + "\r\n"
                + "Cyber Defense Institute, Inc. A modified version of AppCompatCacheParser\r\n"
                + "Usage: shimcache.exe -o|--output OUTPUTFOLDER INPUTFOLDER");
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
            string outFileBase = $"shimcache_output.csv";

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

            var outFilename = Path.Combine(outDir, outFileBase);
            var sw = new StreamWriter(outFilename, true, System.Text.Encoding.UTF8);
            sw.AutoFlush = true;
            var csv = new CsvWriter(sw);
            csv.Configuration.RegisterClassMap<CacheOutputMap>();
            csv.Configuration.Delimiter = "\t";
            csv.Configuration.Encoding = System.Text.Encoding.UTF8;

            if (args.Length == 4)
                if (args[3] == "--noheader")
                    csv.Configuration.HasHeaderRecord = false;
                else
                    csv.WriteHeader<CacheEntry>();
            else
                csv.WriteHeader<CacheEntry>();

            if (Directory.Exists(outDir) == false)
                Directory.CreateDirectory(outDir);

            foreach (string fileName in Directory.GetFiles(inDir, "*", SearchOption.AllDirectories))
            {

                Stream st = File.OpenRead(fileName);
                if (st.Length < 4)
                    continue;

                BinaryReader br = new BinaryReader(st);
                if (br.ReadInt32() != 1718052210) // means not "regf"
                    continue;

                br.BaseStream.Seek(48, SeekOrigin.Begin);
                if (br.ReadUInt16() != 'S') // means not SYSTEM hive 
                    continue;

                br.Close();
                st.Close();

                try
                {
                    var appCompat = new AppCompatCache.AppCompatCache(fileName);

                    if ((appCompat.Cache != null))
                    {
                        Console.WriteLine($"Found: {appCompat.Cache.Entries.Count:N0} entries, '{fileName}'");                    
                        csv.WriteRecords(appCompat.Cache.Entries);
                    }

                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"Skip: {ex.Message}");
                }
            }
            Console.WriteLine($"Saved: '{outFilename}'");
            sw.Close();
            return;
        }
    }

    public sealed class CacheOutputMap : CsvClassMap<CacheEntry>
    {
        public CacheOutputMap()
        {
            Map(m => m.ComputerName);
            Map(m => m.Path);
            Map(m => m.LastModified).TypeConverterOption("yyyy/MM/dd HH:mm:ss.fff");
            Map(m => m.TimeZone);
            Map(m => m.Flag);
            Map(m => m.EntryPosition);
        }
    }

}