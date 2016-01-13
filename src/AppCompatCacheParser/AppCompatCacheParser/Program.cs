using System;
using System.IO;
using System.Linq;
using System.Reflection;
using AppCompatCache;
using CsvHelper;
using CsvHelper.Configuration;
using Fclp;
using NLog;

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
        private static void Main(string[] args)
        {
            var logger = LogManager.GetCurrentClassLogger();

            if (!CheckForDotnet46())
            {
                logger.Warn(".net 4.6 not detected. Please install .net 4.6 and try again.");
                return;
            }

            var p = new FluentCommandLineParser<ApplicationArguments>();
            
            p.Setup(arg => arg.SaveTo)
                .As('s', "SaveTo")
                .WithDescription("Parsed data will be written to AppCompatCacheParser_Output.csv in this Directory")
                .Required();

//            p.Setup(arg => arg.HiveFile)
//                .As('h', "HiveFile")
//                .WithDescription(
//                    "Full path to SYSTEM hive file to process")
//                .SetDefault(string.Empty);

            // added -r option by CDI
            p.Setup(arg => arg.Dir)
                .As('d', "Dir")
                .WithDescription(
                    "Folder containing SYSTEM hive files to process")
                .SetDefault(string.Empty);

//            p.Setup(arg => arg.SortTimestamps)
//                 .As('t', "SortDates")
//                 .WithDescription("If true, sorts timestamps in descending order. If -r option is specified, this option will be ignored")
//                 .SetDefault(false);

            var header =
                $"AppCompatCache Parser version {Assembly.GetExecutingAssembly().GetName().Version}" +
                $" modified by CDI, Inc." +
                $"\r\n(Original Author: Eric Zimmerman)" +
                $"\r\n\r\nAppCompatCacheParser.exe --Dir C:\\data\\ --SaveTo C:\\output\\";

            p.SetupHelp("?", "help").WithHeader(header).Callback(text => logger.Info(text));

            var result = p.Parse(args);
            
            if (result.HelpCalled)
                return;

            if (result.HasErrors)
            {
                
                p.HelpOption.ShowHelp(p.Options);

                logger.Info("Either the short name or long name can be used for the command line switches. For example, either -d or --Dir");
                logger.Info("--Dir option is not specified, the live Registry will be used");
                return;
            }

            logger.Info(header);
            logger.Info("");

            // handling -s option
            if (Directory.Exists(p.Object.SaveTo) == false)
                Directory.CreateDirectory(p.Object.SaveTo);

            // -h option
            /*
            if (p.Object.HiveFile?.Length > 0)
            {
                var hiveToProcess = p.Object.HiveFile;
                logger.Info($"Processing hive '{hiveToProcess}'");
                logger.Info("");
                try
                {
                    var appCompat = new AppCompatCache.AppCompatCache(p.Object.HiveFile);

                    if ((appCompat.Cache != null))
                    {
                        logger.Info($"Found {appCompat.Cache.Entries.Count:N0} cache entries for {appCompat.OperatingSystem}");

                        var outFileBase = string.Empty;
                        outFileBase = $"{appCompat.OperatingSystem}_{Path.GetFileNameWithoutExtension(p.Object.HiveFile)}_AppCompatCache.csv";
                        var outFilename = Path.Combine(p.Object.SaveTo, outFileBase);

                        logger.Info($"\r\nSaving results to '{outFilename}'");

                        var sw = new StreamWriter(outFilename, true, System.Text.Encoding.Unicode);
                        sw.AutoFlush = true;
                        var csv = new CsvWriter(sw);

                        csv.Configuration.RegisterClassMap<CacheOutputMap>();
                        csv.Configuration.Delimiter = "\t";
                        csv.Configuration.Encoding = System.Text.Encoding.Unicode;
                        //csv.Configuration.AllowComments = true;

                        csv.WriteHeader<CacheEntry>();

                        if (p.Object.SortTimestamps)
                            csv.WriteRecords(appCompat.Cache.Entries.OrderByDescending(t => t.LastModifiedTimeUTC));
                        else
                            csv.WriteRecords(appCompat.Cache.Entries);
                        sw.Close();
                    }
                }
                catch (Exception ex)
                {
                    logger.Error($"There was an error: Error message: {ex.Message}");
                }
                return;
            }*/

            // -r option
            if (p.Object.Dir?.Length > 0)
            {
                string outFileBase = $"AppCompatCacheParser_Output.csv";
                var outFilename = Path.Combine(p.Object.SaveTo, outFileBase);
                var sw = new StreamWriter(outFilename, true, System.Text.Encoding.Unicode);
                sw.AutoFlush = true;
                var csv = new CsvWriter(sw);
                csv.Configuration.RegisterClassMap<CacheOutputMap>();
                csv.Configuration.Delimiter = "\t";
                csv.Configuration.Encoding = System.Text.Encoding.Unicode;
                csv.WriteHeader<CacheEntry>();

                foreach (string fileName in Directory.GetFiles(p.Object.Dir, "*", SearchOption.AllDirectories))
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
                            logger.Info($"Processing hive '{fileName}'");
                            logger.Info($"Found {appCompat.Cache.Entries.Count:N0} cache entries for {appCompat.OperatingSystem}");

                            csv.WriteRecords(appCompat.Cache.Entries);
                        }

                    }
                    catch (Exception ex)
                    {
                        logger.Error($"Skip: {ex.Message}");
                    }
                }
                logger.Info($"\r\nSaving results to '{outFilename}'");
                sw.Close();
                return;
            }

            // Live Registry
            logger.Info($"Processing Live Registry");
            logger.Info("");
            try
            {
                var appCompat = new AppCompatCache.AppCompatCache(p.Object.HiveFile);

                if ((appCompat.Cache != null))
                {
                    logger.Info($"Found {appCompat.Cache.Entries.Count:N0} cache entries for {appCompat.OperatingSystem}");

                    var outFileBase = string.Empty;
                    outFileBase = $"{appCompat.OperatingSystem}_{Environment.MachineName}_AppCompatCache.csv";
                    var outFilename = Path.Combine(p.Object.SaveTo, outFileBase);

                    logger.Info($"\r\nSaving results to '{outFilename}'");

                    var sw = new StreamWriter(outFilename, true, System.Text.Encoding.Unicode);
                    sw.AutoFlush = true;
                    var csv = new CsvWriter(sw);

                    csv.Configuration.RegisterClassMap<CacheOutputMap>();
                    csv.Configuration.Delimiter = "\t";
                    csv.Configuration.Encoding = System.Text.Encoding.Unicode;
                    csv.WriteHeader<CacheEntry>();
                    csv.WriteRecords(appCompat.Cache.Entries);

//                    if (p.Object.SortTimestamps)
//                        csv.WriteRecords(appCompat.Cache.Entries.OrderByDescending(t => t.LastModifiedTimeUTC));
//                    else
//                        csv.WriteRecords(appCompat.Cache.Entries);
                    sw.Close();
                }
            }
            catch (Exception ex)
            {
                logger.Error($"There was an error: Error message: {ex.Message}");
            }
            return;

#if DEBUG
            logger.Info("");
            logger.Info("Press a key to exit");
            Console.ReadKey();
#endif
        }
    }

    public class ApplicationArguments
    {
        public string HiveFile { get; set; }
        public string Dir { get; set; }
//       public bool FindEvidence { get; set; }
//       public bool SortTimestamps { get; set; }
        public string SaveTo { get; set; }
    }

    public sealed class CacheOutputMap : CsvClassMap<CacheEntry>
    {
        public CacheOutputMap()
        {
            Map(m => m.ComputerName);
            Map(m => m.CacheEntryPosition);
            Map(m => m.Path);
            Map(m => m.LastModifiedTimeLocal).TypeConverterOption("yyyy/MM/dd HH:mm:ss"); // added
            Map(m => m.LastModifiedTimeUTC).TypeConverterOption("yyyy/MM/dd HH:mm:ss");   // changed format
            Map(m => m.Flag);
        }
    }
}