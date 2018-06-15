using System.Diagnostics.CodeAnalysis;

namespace A2S.Socks5 {
    [SuppressMessage("ReSharper", "UnusedMember.Global")]
    public enum Socks5AuthMethod {
          None // 0
        , GSSAPI // 1
        , LoginPassword // 2
    }
}
