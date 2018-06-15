using System.Diagnostics.CodeAnalysis;

namespace A2S.Socks5 {
    [SuppressMessage("ReSharper", "UnusedMember.Global")]
    public enum Socks5Command {
          TCPConnect = 0x01 // 1
        , TCPBind = 0x02 // 2
        , UDPMap = 0x03 // 3
    }
}
