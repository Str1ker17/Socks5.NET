using System;
using System.Diagnostics.CodeAnalysis;

namespace A2S.Socks5 {
    [SuppressMessage("ReSharper", "UnusedMember.Global")]
    public class Socks5Exception : Exception {
        public Socks5Exception(String message) : base(message) { }

        public Socks5Exception(String message, Exception inner) : base(message, inner) { }
    }
}
