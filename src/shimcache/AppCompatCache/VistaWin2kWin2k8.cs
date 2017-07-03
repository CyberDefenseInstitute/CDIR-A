using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace AppCompatCache
{
    public class VistaWin2k3Win2k8 : IAppCompatCache
    {
        public VistaWin2k3Win2k8(byte[] rawBytes, bool is32Bit, string computerName)
        {
            Entries = new List<CacheEntry>();

            var index = 4;

            EntryCount = BitConverter.ToInt32(rawBytes, index);

            index = 8;

            var position = 0;

            if (EntryCount == 0)
            {
                return; ;
            }

            if (is32Bit)
            {
                while (index < rawBytes.Length)
                {
                    try
                    {
                        var ce = new CacheEntry();

                        ce.ComputerName = computerName;

                        ce.PathSize = BitConverter.ToUInt16(rawBytes, index);
                        index += 2;

                        var maxPathSize = BitConverter.ToUInt16(rawBytes, index);
                        index += 2;


                        var pathOffset = BitConverter.ToInt32(rawBytes, index);
                        index += 4;

                        ce.LastModified = DateTimeOffset.FromFileTime(BitConverter.ToInt64(rawBytes, index));

                        ce.TimeZone = ce.LastModified.ToString("zzz");

                        index += 8;

                        // skip 4 unknown (insertion flags?)
                        index += 4;

                        // skip 4 unknown (shim flags?)
                        index += 4;

                        ce.Path = Encoding.Unicode.GetString(rawBytes, pathOffset, ce.PathSize).Replace(@"\??\", "");

                        //                        if ((ce.InsertFlags & AppCompatCache.InsertFlag.Executed) == AppCompatCache.InsertFlag.Executed)
                        //                        {
                        //                            ce.Executed = AppCompatCache.Execute.Yes;
                        //                        }
                        //                        else
                        //                        {
                        //                            ce.Executed = AppCompatCache.Execute.No;
                        //                        }

                        // Unknown Executed Flag
                        ce.Flag = "N/A";

                        ce.EntryPosition = position;
                        Entries.Add(ce);
                        position += 1;

                        if (Entries.Count == EntryCount)
                        {
                            break;
                        }
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine(ex.Message);
                        //take what we can get
                        break;
                    }
                }
            }
            else
            {
                while (index < rawBytes.Length)
                {
                    try
                    {
                        var ce1 = new CacheEntry();

                        ce1.ComputerName = computerName;

                        ce1.PathSize = BitConverter.ToUInt16(rawBytes, index);
                        index += 2;

                        var maxPathSize = BitConverter.ToUInt16(rawBytes, index);
                        index += 2;

                        // skip 4 unknown (padding)
                        index += 4;

                        var pathOffset = BitConverter.ToInt64(rawBytes, index);
                        index += 8;

                        ce1.LastModified = DateTimeOffset.FromFileTime(BitConverter.ToInt64(rawBytes, index));

                        ce1.TimeZone = ce1.LastModified.ToString("zzz");
                        index += 8;

                        // skip 4 unknown (insertion flags?)
                        index += 4;

                        // skip 4 unknown (shim flags?)
                        index += 4;

                        ce1.Path = Encoding.Unicode.GetString(rawBytes, (int)pathOffset, ce1.PathSize).Replace(@"\??\", "");

                        // set N/A until structure is known
                        ce1.Flag = "N/A";

                        ce1.EntryPosition = position;
                        Entries.Add(ce1);
                        position += 1;

                        if (Entries.Count == EntryCount)
                        {
                            break;
                        }
                    }
                    catch (Exception ex)
                    {
                        if (Entries.Count < EntryCount)
                        {
                            throw;
                        }
                        //take what we can get
                        break;
                    }
                }
            }
        }

        public List<CacheEntry> Entries { get; }
        public int EntryCount { get; }
        public int ControlSet { get; }
    }
}
