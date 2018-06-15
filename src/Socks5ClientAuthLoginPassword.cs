using System;
using System.Net.Sockets;
using System.Text;

namespace A2S.Socks5 {
    class Socks5ClientAuthLoginPassword : Socks5ClientAuth {
        public override void Authenticate(Socket proxyConnection, params object[] args) {
            if(args.Length != 2)
                throw new ArgumentException("first arg is username, second is password");

            String username = (String) (args[0]);
            String password = (String) (args[1]);

            byte[] auth = new byte[1 + 1 + username.Length + 1 + password.Length];
            int indexer = 1;
            auth[0] = 0x01;
            auth[indexer] = (byte)username.Length;
            Array.Copy(Encoding.ASCII.GetBytes(username), 0, auth, indexer + 1, auth[indexer]);
            indexer += 1 + auth[indexer];
            auth[indexer] = (byte)password.Length;
            Array.Copy(Encoding.ASCII.GetBytes(password), 0, auth, indexer + 1, auth[indexer]);
            proxyConnection.Send(auth);

            byte[] auth_reply = new byte[2];
            proxyConnection.Receive(auth_reply);

            if(auth_reply[0] != 0x01 || auth_reply[1] != 0x00)
                throw new Socks5Exception("Invalid authentication");
        }
    }
}
