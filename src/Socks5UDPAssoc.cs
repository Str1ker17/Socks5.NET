using System;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;

namespace A2S.Socks5 {
    [SuppressMessage("ReSharper", "UnusedMember.Global")]
    public class Socks5UDPAssoc : UdpClient {
        public static int MaxDgramLength { get { return 65000; /* dirty value */ } }
        //protected new Socket Client { get; set; }
        protected TcpClient _socks_control;
        protected EndPoint _socks_rcv_endpoint = new IPEndPoint(0, 0);
        protected byte[] _socks_buffer = new byte[MaxDgramLength];
        protected IPAddress _socks_addr;
        protected ushort _socks_port;
        protected String _socks_username = String.Empty;
        protected String _socks_password = String.Empty;
        protected Socks5AuthMethod _socks_auth_method = Socks5AuthMethod.None;

        protected IPAddress _origin_addr;
        protected ushort _origin_port;
        protected bool _established; // = false

        protected IPEndPoint _socks_endpoint;

        public IPAddress SocksAddr {
            get { return this._socks_addr; }
            set { this._socks_addr = value; }
        }

        public ushort SocksPort {
            get { return this._socks_port; }
            set { this._socks_port = value; }
        }

        public Socks5AuthMethod SocksAuthMethod {
            get { return this._socks_auth_method; }
            set { this._socks_auth_method = value; }
        }

        public String SocksUsername {
            get { return this._socks_username; }
            set { 
                this._socks_username = value;
                this._socks_auth_method = Socks5AuthMethod.LoginPassword;
            }
        }
        
        public String SocksPassword {
            get { return this._socks_password; }
            set {
                this._socks_password = value;
                this._socks_auth_method = Socks5AuthMethod.LoginPassword;
            }
        }

        public bool Established { get { return _established; } }

        // PRIVATE METHODS //
        protected void Hello() {
            Socks5AuthHello auth_hello = new Socks5AuthHello();
            if(_socks_auth_method != Socks5AuthMethod.None)
                auth_hello.AddMethod(Socks5AuthMethod.None);
            auth_hello.AddMethod(_socks_auth_method);
            _socks_control.Client.Send(auth_hello.GetBytes());

            byte[] auth_methods_reply = new byte[2];
            _socks_control.Client.Receive(auth_methods_reply);
            Socks5AuthHelloReply auth_hello_reply = new Socks5AuthHelloReply(auth_methods_reply);

            if(auth_hello_reply.ChosenMethod != (byte)_socks_auth_method)
                throw new Socks5Exception("SOCKS5 server does not support selected auth method");

        }

        protected void Authenticate() {
            // ReSharper disable once TooWideLocalVariableScope
            Socks5ClientAuth authorizer;
            switch(this._socks_auth_method) {
                case Socks5AuthMethod.None:
                    // do nothing
                    break;

                case Socks5AuthMethod.LoginPassword:
                    authorizer = new Socks5ClientAuthLoginPassword();
                    authorizer.Authenticate(_socks_control.Client, _socks_username, _socks_password);
                    break;

                default:
                    throw new Socks5Exception("This method of authentication is not supported");
            }
        }

        protected void ConnectCore() {
            this._established = false;
            // соединяемся с прокси
            _socks_control = new TcpClient();
            _socks_control.Connect(_socks_addr, _socks_port);

            Hello();
            Authenticate();
        }
        // PRIVATE METHODS //

        public new void Connect(IPAddress addr, int port) {
            throw new NotImplementedException();
        }

        public new void Connect(IPEndPoint endpoint) {
            throw new NotImplementedException();
        }

        public new void Connect(String hostname, int port) {
            throw new NotImplementedException();
        }

        public void Connect() {
            ConnectCore();
        }

        public Socks5ClientRequestReply Assoc(IPAddress addr, int port) {
            if(!_established)
                ConnectCore();
            return AssocCore(addr, port);
        }

        private Socks5ClientRequestReply AssocCore(IPAddress addr, int port) {
            Socks5ClientRequest request = new Socks5ClientRequest {
                Command = Socks5Command.UDPMap,
                AddressType = Socks5AddressType.IPv4,
                DestinationAddress = addr.ToString(),
                DestinationPort = (ushort)port
            };
            _socks_control.Client.Send(request.GetBytes());

            byte[] connect_request_reply = new byte[Socks5Packet.MessageMaxLength]; // for everything
            _socks_control.Client.Receive(connect_request_reply);

            Socks5ClientRequestReply request_reply = new Socks5ClientRequestReply(connect_request_reply);

            if(request_reply.ResponseCode != Socks5ResponseCode.OK)
                throw new Socks5Exception("SOCKS5 server reports: " 
                                               + request_reply.ResponseCode);

            this._established = true;
            this._socks_endpoint = new IPEndPoint(_socks_addr, request_reply.RemoteLocalPort);
            this.Client.ReceiveTimeout = 1000;
            return request_reply;
        }

        public int SendTo(IPEndPoint endpoint, byte[] data) {
/*
      +----+------+------+----------+----------+----------+
      |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
      +----+------+------+----------+----------+----------+
      | 2  |  1   |  1   | Variable |    2     | Variable |
      +----+------+------+----------+----------+----------+
 */

            Socks5UDPEncap encap = new Socks5UDPEncap {
                AddressType = Socks5AddressType.IPv4,
                DestinationAddress = endpoint.Address.ToString(),
                DestinationPort = (ushort) endpoint.Port
            };

            byte[] encap_hdr = encap.GetBytes();
            byte[] out_data = new byte[encap_hdr.Length + data.Length];
            Array.Copy(encap_hdr, out_data, encap_hdr.Length);
            Array.Copy(data, 0, out_data, encap_hdr.Length, data.Length);

            return this.Client.SendTo(out_data, _socks_endpoint);
        }

        public int ReceiveFrom(ref byte[] data, ref IPEndPoint endpoint) {
            int got = this.Client.ReceiveFrom(_socks_buffer, ref _socks_rcv_endpoint);
            // 
            //endpoint.Address = new IPAddress()
            Array.Copy(_socks_buffer, 10, data, 0, _socks_buffer.Length - 10);
            return got;
        }

        public new void Close() {
            this._established = false;
            if (_socks_control.Client != null) {
                this._socks_control.Close();
            }
        }
    }
}
