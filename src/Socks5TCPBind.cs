using System;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;

namespace A2S.Socks5 {
    [SuppressMessage("ReSharper", "UnusedMember.Global")]
    public class Socks5TCPBind : TcpClient {
        protected IPAddress _socks_addr;
        protected ushort _socks_port;
        protected String _socks_username = String.Empty;
        protected String _socks_password = String.Empty;
        protected Socks5AuthMethod _socks_auth_method = Socks5AuthMethod.None;

        protected IPAddress _origin_addr;
        protected ushort _origin_port;
        protected bool _established; // = false

        protected String _remote_hostname;

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
            this.Client.Send(auth_hello.GetBytes());

            byte[] auth_methods_reply = new byte[2];
            this.Client.Receive(auth_methods_reply);
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
                    authorizer.Authenticate(this.Client, _socks_username, _socks_password);
                    break;

                default:
                    throw new Socks5Exception("This method of authentication is not supported");
            }
        }

        protected Socks5ClientRequestReply RemoteBindCore(Socks5ClientRequest request) {
            this.Client.Send(request.GetBytes());

            byte[] connect_request_reply = new byte[Socks5Packet.MessageMaxLength]; // for everything
            this.Client.Receive(connect_request_reply);

            Socks5ClientRequestReply request_reply = new Socks5ClientRequestReply(connect_request_reply);

            if(request_reply.ResponseCode != Socks5ResponseCode.OK)
                throw new Socks5Exception("SOCKS5 server reports: " 
                                               + request_reply.ResponseCode);

            this._established = true;
            return request_reply;
        }

        protected Socks5ClientRequestReply RemoteAcceptCore() {
            byte[] connect_request_reply = new byte[Socks5Packet.MessageMaxLength]; // for everything
            this.Client.Receive(connect_request_reply);

            Socks5ClientRequestReply request_reply = new Socks5ClientRequestReply(connect_request_reply);

            if(request_reply.ResponseCode != Socks5ResponseCode.OK)
                throw new Socks5Exception("SOCKS5 server reports: " 
                                          + request_reply.ResponseCode);

            return request_reply;
        }

        protected Socks5ClientRequestReply RemoteBind(Socks5AddressType addressType, ushort preferPort) {
            if (addressType != Socks5AddressType.IPv4 && addressType != Socks5AddressType.IPv6) {
                throw new Socks5Exception("You can request only IPv4/IPv6 binding, not hostname");
            }
            Socks5ClientRequest request = new Socks5ClientRequest {
                Command = Socks5Command.TCPBind,
                AddressType = addressType,
                DestinationPort = preferPort
            };
            if (addressType == Socks5AddressType.IPv4) 
                request.DestinationAddress = "0.0.0.0";
            else if (addressType == Socks5AddressType.IPv6)
                request.DestinationAddress = "::";

            return RemoteBindCore(request);
        }

        protected void ConnectCore() {
            this._established = false;
            // соединяемся с прокси
            base.Connect(_socks_addr, _socks_port);

            Hello();
            Authenticate();
        }
        // PRIVATE METHODS //

        private new void Connect(IPEndPoint endPoint) {
            throw new NotImplementedException();
        }

        private new void Connect(IPAddress[] addrs, int port) {
            throw new NotImplementedException();
        }

        private new void Connect(String hostname, int port) {
            throw new NotImplementedException();
        }

        private new void Connect(IPAddress addr, int port) {
            throw new NotImplementedException();
        }

        public void Connect() {
            ConnectCore();
        }

        public Socks5ClientRequestReply Bind(Socks5AddressType addressType, ushort preferPort = 0) {
            if (addressType != Socks5AddressType.IPv4 && addressType != Socks5AddressType.IPv6) {
                throw new Socks5Exception("You can request only IPv4/IPv6 binding, not hostname");
            }
            if(!_established)
                ConnectCore();
            return RemoteBind(addressType, preferPort);
        }

        public Socks5ClientRequestReply Accept() {
            this.ReceiveTimeout = 0;
            return RemoteAcceptCore();
        }

        public new void Close() {
            this._established = false;
            if (this.Client != null) {
                this.Client.Close();
            }

            base.Close();
        }
    }
}
