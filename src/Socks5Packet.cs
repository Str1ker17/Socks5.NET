using System.Diagnostics.CodeAnalysis;

namespace A2S.Socks5 {
    [SuppressMessage("ReSharper", "UnusedMember.Global")]
    public abstract class Socks5Packet {
        public static readonly byte SocksVersion = 0x05;
        public static readonly int MessageMaxLength = 262;

        //protected byte socks_version = 0x05;

        public abstract byte[] GetBytes();
    }
}