using System;

namespace AppCompatCache
{
    public class CacheEntry
    {
        public string ComputerName { get; set; }
        public int EntryPosition { get; set; }
        public byte[] Data { get; set; }
        public int DataSize { get; set; }
        public DateTimeOffset LastModified { get; set; }
        public string TimeZone { get; set; }
        public string Flag { get; set; }
        public string Path { get; set; }
        public int PathSize { get; set; }
        public string Signature { get; set; }

        public override string ToString()
        {
            return $"#{EntryPosition} (Path size: {PathSize}), Path: {Path}, Last modified (Local):{LastModified}";
        }
    }
}