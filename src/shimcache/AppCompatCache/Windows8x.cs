using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AppCompatCache
{
    public class Windows8x : IAppCompatCache
    {
        public Windows8x(byte[] rawBytes, AppCompatCache.OperatingSystemVersion os, int controlSet, string computerName)
        {
            Entries = new List<CacheEntry>();

            var index = 128;

            var signature = "00ts";

            ControlSet = controlSet;

            EntryCount = -1;

            if (os == AppCompatCache.OperatingSystemVersion.Windows81_Windows2012R2)
                signature = "10ts";

            var position = 0;

            while (index < rawBytes.Length)
            {
                try
                {
                    var ce = new CacheEntry
                    {
                        Signature = Encoding.ASCII.GetString(rawBytes, index, 4)
                    };

                    if (ce.Signature != signature)
                        break;

                    ce.ComputerName = computerName;

                    index += 4;

                    // skip 4 unknown
                    index += 4;

                    var ceDataSize = BitConverter.ToUInt32(rawBytes, index);
                    index += 4;

                    ce.PathSize = BitConverter.ToUInt16(rawBytes, index);
                    index += 2;

                    ce.Path = Encoding.Unicode.GetString(rawBytes, index, ce.PathSize).Replace(@"\??\", "");
                    index += ce.PathSize;

                    var packageLen = BitConverter.ToUInt16(rawBytes, index);
                    index += 2;
                    //skip package data
                    index += packageLen;

                    // skip 4 unknown (insertion flags?)
                    ce.InsertFlags = (AppCompatCache.InsertFlag)BitConverter.ToInt32(rawBytes, index);
                    index += 4;

                    // skip 4 unknown (shim flags?)
                    index += 4;

                    ce.LastModified =
                        DateTimeOffset.FromFileTime(BitConverter.ToInt64(rawBytes, index));

                    ce.TimeZone = ce.LastModified.ToString("zzz");

                    index += 8;

                    ce.DataSize = BitConverter.ToInt32(rawBytes, index);
                    index += 4;

                    ce.Data = rawBytes.Skip(index).Take(ce.DataSize).ToArray();
                    index += ce.DataSize;

                    if ((ce.InsertFlags & AppCompatCache.InsertFlag.Executed) == AppCompatCache.InsertFlag.Executed)
                        ce.Flag = AppCompatCache.Execute.Executed;
                    else
                        ce.Flag = AppCompatCache.Execute.Unknown;

                    ce.ControlSet = controlSet;
                    ce.EntryPosition = position;
                    Entries.Add(ce);
                    position += 1;

                }
                catch (Exception ex)
                {
                    //TODO report this
                    //take what we can get
                    Console.Error.WriteLine($"Error parsing cache entry. Position: {position} Index: {index}, Error: {ex.Message} ");
                    break;
                }
            }
        }

        public List<CacheEntry> Entries { get; }
        public int EntryCount { get; }
        public int ControlSet { get; }
    }
}