using System;

namespace A2S.Socks5 {
    class Socks5AuthHelloReply : Socks5Packet {
        protected byte chosen_method;

        public byte ChosenMethod {
            get { return chosen_method; }
        }

        public Socks5AuthHelloReply(byte[] data) {
            if (data.Length < 2)
                throw new ArgumentException("Reply should be 2 bytes length");
            if (data[0] != SocksVersion)
                throw new Socks5Exception("Invalid SOCKS5 header");
            if (data[1] == 0xFF)
                throw new Socks5Exception("None of the offered auth methods are supported by server");

            //this.socks_version = data[0];
            this.chosen_method = data[1];
        }

        public override byte[] GetBytes() {
            return new[] { SocksVersion, chosen_method };
        }
    }
}