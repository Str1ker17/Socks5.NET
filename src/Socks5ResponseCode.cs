using System.Diagnostics.CodeAnalysis;

namespace A2S.Socks5 {
    [SuppressMessage("ReSharper", "UnusedMember.Global")]
    public enum Socks5ResponseCode {
          OK // 0
        , InternalServerError // 1
        , ConnectionDeniedACL // 2
        , NetworkUnreachable // 3
        , HostUnreachable // 4
        , ConnectionRefused // 5
        , TTLExpire // 6
        , ProtocolError // 7
        , AddresNotSupported // 8
    }
}
