using System;
using System.Collections.Generic;

namespace A2S.Socks5 {
    class Socks5AuthHello : Socks5Packet {
        private readonly List<byte> auth_methods = new List<byte>();

        public void AddMethod(byte method) {
            if(method == 0xFF)
                throw new ArgumentOutOfRangeException("method"
                    , "0xFF is a special value by SOCKS5 specification");
            if (!auth_methods.Contains(method)) {
                auth_methods.Add(method);
            }
        }

        public void AddMethod(Socks5AuthMethod method) {
            AddMethod((byte)method);
        }

        public void RemoveMethod(byte method) {
            auth_methods.Remove(method);
        }

        public override byte[] GetBytes() {
            byte count = (byte) auth_methods.Count;
            byte[] data = new byte[1 + 1 + count];
            
            data[0] = SocksVersion;
            data[1] = count;
            auth_methods.CopyTo(data, 2);

            return data;
        }
    }
}
