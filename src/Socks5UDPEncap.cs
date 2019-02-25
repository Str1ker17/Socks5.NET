using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace A2S.Socks5 {
    public class Socks5UDPEncap {
        private UInt16 reserved = 0x0000;

        private byte fragment = 0x00;

        public Socks5AddressType AddressType { get; set; }

        public String DestinationAddress { get; set; }

        public ushort DestinationPort { get; set; }

        public byte[] GetBytes() {
            int len, position;
            byte[] buf = null;
            switch (AddressType) {
                case Socks5AddressType.IPv4:
                    len = 4;
                    break;
                case Socks5AddressType.IPv6:
                    len = 16;
                    break;
                case Socks5AddressType.Hostname:
                    buf = Encoding.ASCII.GetBytes(this.DestinationAddress);
                    if (buf.Length > Byte.MaxValue)
                        throw new Socks5Exception("Hostname is too long; max. 255 chars");
                    len = buf.Length + 1;
                    break;
                default: throw new ArgumentOutOfRangeException();
            }

            len += 1 + 1 + 1 + 1 + 2;
            byte[] data = new byte[len];

            data[0] = 0x00;
            data[1] = 0x00;
            data[2] = 0x00;
            data[3] = (byte) this.AddressType;

            switch (AddressType) {
                case Socks5AddressType.IPv4:
                case Socks5AddressType.IPv6:
                    byte[] addr = IPAddress.Parse(DestinationAddress).GetAddressBytes();
                    Array.Copy(addr, 0, data, 4, addr.Length);
                    position = 4 + addr.Length;
                    break;
                case Socks5AddressType.Hostname:
                    // ReSharper disable once PossibleNullReferenceException
                    data[4] = (byte) (buf.Length);
                    Array.Copy(buf, 0, data, 5, buf.Length);
                    position = 5 + buf.Length;
                    break;
                default: throw new ArgumentOutOfRangeException();
            }

            Array.Copy(BitConverter.GetBytes(IPAddress.HostToNetworkOrder((short) this.DestinationPort))
                , 0, data, position, 2);

            return data;
        }
    }
}
