using System;
using System.CodeDom;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Registry;
using Registry.Abstractions;

namespace AppCompatCache
{
    public class AppCompatCache
    {

        public enum Execute
        {
            Executed,
            Unknown,
            NA
        }

        [Flags]
        public enum InsertFlag
        {
            Unknown1 = 0x00000001,
            Executed = 0x00000002,
            Unknown4 = 0x00000004,
            Unknown8 = 0x00000008,
            Unknown10 = 0x00000010,
            Unknown20 = 0x00000020,
            Unknown40 = 0x00000040,
            Unknown80 = 0x00000080,
            Unknown10000 = 0x00010000,
            Unknown20000 = 0x00020000,
            Unknown30000 = 0x00030000,
            Unknown40000 = 0x00040000,
            Unknown100000 = 0x00100000,
            Unknown200000 = 0x00200000,
            Unknown400000 = 0x00400000,
            Unknown800000 = 0x00800000
        }

        public enum OperatingSystemVersion
        {
            WindowsVistaWin2k3Win2k8,
            Windows7x86,
            Windows7x64_Windows2008R2,
            Windows80_Windows2012,
            Windows81_Windows2012R2,
            Windows10,
            Windows10Creators,
            Unknown
        }

        public AppCompatCache(byte[] rawBytes, int controlSet, string computerName)
        {
            Caches = new List<IAppCompatCache>();
            var cache = Init(rawBytes, false, controlSet, computerName);
            Caches.Add(cache);
        }

        public AppCompatCache(string filename, int controlSet)
        {
            byte[] rawBytes = null;
            Caches = new List<IAppCompatCache>();

            if (File.Exists(filename) == false)
                throw new FileNotFoundException($"File not found ({filename})!");

            var controlSetIds = new List<int>();

//            var hive = new RegistryHiveOnDemand(filename);
            var hive = new RegistryHive(filename);

            if (hive.Header.PrimarySequenceNumber != hive.Header.SecondarySequenceNumber)
            {
                var logFiles = Directory.GetFiles(Path.GetDirectoryName(filename), Path.GetFileName(filename) + ".LOG*");

                if (logFiles.Length == 0)
                {
                    Console.WriteLine("Registry hive is dirty and no transaction logs were found in the same directory! Skip!!");
                    return;
                }

                hive.ProcessTransactionLogs(logFiles.ToList(), true);
            }

            hive.ParseHive();


            RegistryKey subKey = hive.GetKey("Select");
            var ControlSet = int.Parse(subKey.Values.Single(c => c.ValueName == "Current").ValueData);
//            ControlSet = controlSet;

            if (controlSet == -1)
            {
                for (var i = 0; i < 10; i++)
                {
                    subKey = hive.GetKey($@"ControlSet00{i}\Control\Session Manager\AppCompatCache");

                    if (subKey == null)
                        subKey = hive.GetKey($@"ControlSet00{i}\Control\Session Manager\AppCompatibility");

                    if (subKey != null)
                        controlSetIds.Add(i);
                }

                if (controlSetIds.Count > 1)
                    Console.WriteLine($"***The following ControlSet00x keys will be exported: {string.Join(",", controlSetIds)}.\r\n");
            }
            else
            {
                //a control set was passed in
                subKey = hive.GetKey($@"ControlSet00{ControlSet}\Control\Session Manager\AppCompatCache");

                if (subKey == null)
                    subKey = hive.GetKey($@"ControlSet00{ControlSet}\Control\Session Manager\AppCompatibility");

                if (subKey == null)
                    throw new Exception($"Could not find ControlSet00{ControlSet}. Exiting");

                controlSetIds.Add(ControlSet);
            }

            var is32 = Is32Bit(filename);
            string computerName = ComputerName(filename);

            foreach (var id in controlSetIds)
            {
                var hive2 = new RegistryHiveOnDemand(filename);
                subKey = hive2.GetKey($@"ControlSet00{id}\Control\Session Manager\AppCompatCache");

                if (subKey == null)
                    subKey = hive2.GetKey($@"ControlSet00{id}\Control\Session Manager\AppCompatibility");

                var val = subKey?.Values.SingleOrDefault(c => c.ValueName == "AppCompatCache");

                if (val != null)
                    rawBytes = val.ValueDataRaw;

                if (rawBytes == null)
                    throw new Exception($@"'AppCompatCache' value not found for 'ControlSet00{id}'! Exiting");

                var cache = Init(rawBytes, is32, id, computerName);

                Caches.Add(cache);
            }
        }

        public int ControlSet { get; }

        public List<IAppCompatCache> Caches { get; }
        public OperatingSystemVersion OperatingSystem { get; private set; }

        // added computerName argument
        private IAppCompatCache Init(byte[] rawBytes, bool is32, int controlSet, string computerName)
        {
            IAppCompatCache appCache = null;
            OperatingSystem = OperatingSystemVersion.Unknown;

            string signature;

            var sigNum = BitConverter.ToUInt32(rawBytes, 0);

            //TODO check minimum length of rawBytes and throw exception if not enough data

            signature = Encoding.ASCII.GetString(rawBytes, 128, 4);

            if (sigNum == 0xbadc0ffe) // Vista
            {
                OperatingSystem = OperatingSystemVersion.WindowsVistaWin2k3Win2k8;
                appCache = new VistaWin2k3Win2k8(rawBytes, is32, controlSet, computerName);
            }
            else if (sigNum == 0xbadc0fee) // Win7
            {
                if (is32)
                    OperatingSystem = OperatingSystemVersion.Windows7x86;
                else
                    OperatingSystem = OperatingSystemVersion.Windows7x64_Windows2008R2;

                appCache = new Windows7(rawBytes, is32, controlSet, computerName);

            }
            else if ((signature == "00ts"))
            {
                OperatingSystem = OperatingSystemVersion.Windows80_Windows2012;
                appCache = new Windows8x(rawBytes, OperatingSystem, controlSet, computerName);
            }
            else if (signature == "10ts")
            {
                OperatingSystem = OperatingSystemVersion.Windows81_Windows2012R2;
                appCache = new Windows8x(rawBytes, OperatingSystem, controlSet, computerName);
            }
            else
            {
                //is it windows 10?

                var offsetToEntries = BitConverter.ToInt32(rawBytes, 0);

                OperatingSystem = OperatingSystemVersion.Windows10;

                if (offsetToEntries == 0x34)
                    OperatingSystem = OperatingSystemVersion.Windows10Creators;

                signature = Encoding.ASCII.GetString(rawBytes, offsetToEntries, 4);
                if ((signature == "10ts"))
                    appCache = new Windows10(rawBytes, controlSet, computerName);
            }

            if (appCache == null)
                throw new Exception("Unable to determine operating system...");

            return appCache;
        }

        // added to retrieve ComputerName in SYSTEM hive
        public static string ComputerName(string fileName)
        {
            var hive = new RegistryHiveOnDemand(fileName);
            var subKey = hive.GetKey("Select");
            var currentCtlSet = int.Parse(subKey.Values.Single(c => c.ValueName == "Current").ValueData);
            subKey = hive.GetKey($"ControlSet00{currentCtlSet}\\Control\\ComputerName\\ComputerName");
            string computerName = subKey.Values.Single(c => c.ValueName == "ComputerName").ValueData;

            return computerName;
        }

        public static bool Is32Bit(string fileName)
        {
            var hive = new RegistryHiveOnDemand(fileName);
            var subKey = hive.GetKey("Select");
            var currentCtlSet = int.Parse(subKey.Values.Single(c => c.ValueName == "Current").ValueData);

            subKey = hive.GetKey($"ControlSet00{currentCtlSet}\\Control\\Session Manager\\Environment");

            var val = subKey?.Values.SingleOrDefault(c => c.ValueName == "PROCESSOR_ARCHITECTURE");

            if (val != null)
                return val.ValueData.Equals("x86");

            throw new NullReferenceException("Unable to determine CPU architecture...");
        }
    }
}