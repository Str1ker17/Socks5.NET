using System;
using System.Net;
using System.Text;

namespace A2S.Socks5 {
    public class Socks5ClientRequestReply : Socks5Packet {
        public Socks5ResponseCode ResponseCode { get; set; }

        private byte reserved = 0x00;

        public Socks5AddressType AddressType { get; set; }

        public String RemoteLocalAddress { get; set; }

        public UInt16 RemoteLocalPort { get; set; }

        public Socks5ClientRequestReply(byte[] data) {
            if (data.Length < 10)
                throw new ArgumentException("Reply should be at least 10 bytes length");
            if (data[0] != SocksVersion)
                throw new Socks5Exception("Invalid SOCKS5 header");
            if (data[2] != 0x00)
                throw new ApplicationException("Invalid SOCKS5 reserved byte");

            this.ResponseCode = (Socks5ResponseCode) data[1];
            this.AddressType = (Socks5AddressType) data[3];

            int addr_len;
            switch (this.AddressType) {
                case Socks5AddressType.IPv4:
                    addr_len = 4;
                    byte[] addr4 = new byte[addr_len];
                    Array.Copy(data, 4, addr4, 0, addr4.Length);
                    RemoteLocalAddress = new IPAddress(addr4).ToString();
                    break;
                case Socks5AddressType.IPv6:
                    addr_len = 16;
                    byte[] addr6 = new byte[addr_len];
                    Array.Copy(data, 4, addr6, 0, addr6.Length);
                    RemoteLocalAddress = new IPAddress(addr6).ToString();
                    break;
                case Socks5AddressType.Hostname:
                    addr_len = data[4] + 1;
                    byte[] hostname = new byte[data[4]];
                    Array.Copy(data, 5, hostname, 0, hostname.Length);
                    RemoteLocalAddress = Encoding.ASCII.GetString(hostname);
                    break;

                default:
                    throw new ArgumentOutOfRangeException();
            }

            this.RemoteLocalPort = (ushort)IPAddress.NetworkToHostOrder(
                (short)(BitConverter.ToUInt16(data, 4 + addr_len)));
        }

        public override byte[] GetBytes() {
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
                    buf = Encoding.ASCII.GetBytes(this.RemoteLocalAddress);
                    if (buf.Length > Byte.MaxValue)
                        throw new Socks5Exception("Hostname is too long; max. 255 chars");
                    len = buf.Length + 1;
                    break;
                default: throw new ArgumentOutOfRangeException();
            }

            len += 1 + 1 + 1 + 1 + 2;
            byte[] data = new byte[len];

            data[0] = SocksVersion;
            data[1] = (byte) this.ResponseCode;
            data[2] = this.reserved;
            data[3] = (byte) this.AddressType;

            switch (AddressType) {
                case Socks5AddressType.IPv4:
                case Socks5AddressType.IPv6:
                    var addr = IPAddress.Parse(RemoteLocalAddress).GetAddressBytes();
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

            Array.Copy(BitConverter.GetBytes(IPAddress.HostToNetworkOrder(this.RemoteLocalPort))
                , 0, data, position, 2);

            return data;
        }

        public override string ToString() {
            return String.Format("{0}:{1} - {2}", RemoteLocalAddress, RemoteLocalPort, ResponseCode);
        }
    }
}