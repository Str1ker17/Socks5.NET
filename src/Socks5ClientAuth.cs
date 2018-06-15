using System.Net.Sockets;

namespace A2S.Socks5 {
    abstract class Socks5ClientAuth {
        public abstract void Authenticate(Socket proxyConnection, params object[] args);
    }
}
