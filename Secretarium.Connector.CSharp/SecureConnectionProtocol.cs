using Secretarium.Helpers;
using System;
using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Threading;
using WebSocketSharp;

namespace Secretarium
{
    public class SecureConnectionProtocol : IDisposable
    {
        public const byte MaxAllowedPoWDifficilty = 18;

        [Flags]
        public enum ConnectionState : uint
        {
            None = 0,
            Connecting = 1,
            Open = 2,
            SecureConnectionInProgress = Open | 4,
            SecureConnectionEstablished = Open | 8,
            Closed = 16
        }
        
        internal static readonly byte[] _hop = new byte[] { 0, 0, 0, 1 };

        internal ScpConfig _config;
        internal WebSocket _webSocket;
        internal ECDsaCng _clientECDsa;

        public byte[] SymmetricKey { get; internal set; }
        public ConnectionState State { get; private set; }
        public string PublicKey { get { return _clientECDsa?.PublicKey().ToBase64String(); } }

        public event Action<byte[]> OnMessage;
        public event Action<ConnectionState> OnStateChange;

        static SecureConnectionProtocol()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
        }

        private void UpdateState(ConnectionState state)
        {
            if (state == State) return;

            State = state;
            OnStateChange?.Invoke(state);
        }

        public bool Init(ScpConfig config)
        {
            if (config == null)
                return false;

            // TODO checks

            _config = config;

            return true;
        }

        public bool Set(ECDsaCng key)
        {
            if (key == null || key.HashAlgorithm != CngAlgorithm.Sha256 || key.KeySize != 256)
                return false;

            _clientECDsa = key;

            return true;
        }

        public bool Connect(int timeout = 3000)
        {
            if (_webSocket != null)
                _webSocket.Close();
            
            // -1- Open Websocket
            UpdateState(ConnectionState.Connecting);
            var signal = new AutoResetEvent(false);
            var canContinue = true;
            void onOpenHandler(object sender, EventArgs e)
            {
                UpdateState(ConnectionState.Open);
                signal.Set();
            }
            void onCloseHandler(object sender, CloseEventArgs e)
            {
                UpdateState(ConnectionState.Closed);
                canContinue = false;
                //signal.Set(); Force wait until timeout to avoid quick reconnection loops
            }
            void onErrorHandler(object sender, ErrorEventArgs e)
            {
                UpdateState(ConnectionState.Closed);
                canContinue = false;
                //signal.Set(); Force wait until timeout to avoid quick reconnection loops
            }
            EventHandler<MessageEventArgs> onMessageHandler;
            _webSocket = new WebSocket(_config.secretarium.endPoint, "pair1.sp.nanomsg.org");
            _webSocket.SslConfiguration.EnabledSslProtocols = SslProtocols.Tls12;
            _webSocket.Compression = CompressionMethod.None;
            _webSocket.OnOpen += onOpenHandler;
            _webSocket.OnClose += onCloseHandler;
            _webSocket.OnError += onErrorHandler;
            _webSocket.Connect();

            if (!signal.WaitOne(timeout) || !canContinue)
            {
                _webSocket.Close();
                return false;
            }

            _webSocket.OnOpen -= onOpenHandler;

            // -2- Send Client Hello  
            UpdateState(ConnectionState.SecureConnectionInProgress);
            var clientEphCngKey = ECDHHelper.CreateCngKey();
            var clientEphCng = ECDHHelper.CreateECDiffieHellmanCngSha256(clientEphCngKey);
            var clientEphPub = clientEphCngKey.PublicKey();
            var clientHello = ByteHelper.Combine(_hop, clientEphPub);
            ServerHello serverHello = null;
            onMessageHandler = (sender, e) =>
            {
                if (!ServerHello.Parse(e.RawData.Extract(4), MaxAllowedPoWDifficilty, out serverHello))
                    canContinue = false;
                signal.Set();
            };
            _webSocket.OnMessage += onMessageHandler;
            _webSocket.Send(clientHello);
            
            if (!signal.WaitOne(timeout) || !canContinue)
            {
                _webSocket.Close();
                return false;
            }
            
            _webSocket.OnMessage -= onMessageHandler;

            // -3- Send Client Proof Of Work
            if (!DiffieHellmanHelper.ComputeProofOfWork(serverHello.proofOfWorkDetails, out byte[] proofOfWork))
                return false;
            var knownPubKey = _config.secretarium.knownPubKey.FromBase64String();
            var clientProofOfWork = ByteHelper.Combine(_hop, proofOfWork.ExtendTo(32), knownPubKey);
            ServerIdentity serverIdentity = null;
            onMessageHandler = (sender, e) =>
            {
                if (!ServerIdentity.Parse(e.RawData.Extract(4), out serverIdentity))
                    canContinue = false;
                signal.Set();
            };
            _webSocket.OnMessage += onMessageHandler;
            _webSocket.Send(clientProofOfWork);
            
            if (!signal.WaitOne(timeout) || !canContinue)
            {
                _webSocket.Close();
                return false;
            }

            _webSocket.OnMessage -= onMessageHandler;

            // -4- Check Server Identity
            if (!DiffieHellmanHelper.CheckKnownPubKeyPath(knownPubKey, serverIdentity.publicKeyPath))
            {
                _webSocket.Close();
                return false;
            }

            // -5- Compute Symmetric Key
            SymmetricKey = DiffieHellmanHelper.GetSymmetricKey(
                clientEphCng, serverIdentity.ephDHKey, serverIdentity.preMasterSecret);

            // -6- Send Client Proof Of Identity
            var clientPub = _clientECDsa.Key.PublicKey();
            var nonce = ByteHelper.GetRandom(32);
            var nonceSigned = _clientECDsa.SignData(nonce);
            var clientProofOfIdentity = ByteHelper.Combine(nonce, clientEphPub, clientPub, nonceSigned);
            var ivOffset = ByteHelper.GetRandom(16);
            var encryptedClientProofOfIdentity = clientProofOfIdentity.AesCtrEncrypt(SymmetricKey, ivOffset);
            var encryptedClientProofOfIdentityWithIvOffset = ByteHelper.Combine(_hop, ivOffset, encryptedClientProofOfIdentity);
            ServerProofOfIdentityEncrypted serverProofOfIdentityEncrypted = null;
            onMessageHandler = (sender, e) =>
            {
                if (!ServerProofOfIdentityEncrypted.Parse(e.RawData.Extract(4), out serverProofOfIdentityEncrypted))
                    canContinue = false;
                signal.Set();
            };
            _webSocket.OnMessage += onMessageHandler;
            _webSocket.Send(encryptedClientProofOfIdentityWithIvOffset);
            
            if (!signal.WaitOne(timeout) || !canContinue)
            {
                _webSocket.Close();
                return false;
            }

            _webSocket.OnMessage -= onMessageHandler;
            _webSocket.OnClose -= onCloseHandler;
            _webSocket.OnError -= onErrorHandler;

            // -7- Decrypt Server Proof Of Identity
            var serverProofOfIdentityDecrypted = serverProofOfIdentityEncrypted.encryptedPayload
                .AesCtrDecrypt(SymmetricKey, serverProofOfIdentityEncrypted.ivOffset);
            if (!ServerProofOfIdentity.Parse(serverProofOfIdentityDecrypted, out ServerProofOfIdentity serverProofOfIdentity))
            {
                _webSocket.Close();
                return false;
            }

            // -8- Check Server Proof Of Identity
            var msg = "Hey you! Welcome to Secretarium!".ToBytes();
            var toVerify = ByteHelper.Combine(serverProofOfIdentity.nonce, msg);
            var secretariumECDsaCng = serverIdentity.publicKey.ToECDsaCngKey();
            if (!secretariumECDsaCng.VerifyData(toVerify, serverProofOfIdentity.welcomeSigned))
            {
                _webSocket.Close();
                return false;
            }

            _webSocket.OnClose += (sender, e) => {
                UpdateState(ConnectionState.Closed);
            };
            _webSocket.OnError += (sender, e) => {
                UpdateState(ConnectionState.Closed);
            };
            _webSocket.OnMessage += (sender, e) =>
            {
                var offset = e.RawData.Extract(4, 16);
                var decrypted = e.RawData.Extract(20).AesCtrDecrypt(SymmetricKey, offset);
                try
                {
                    OnMessage?.Invoke(decrypted);
                }
                catch (Exception) { }
            };

            UpdateState(ConnectionState.SecureConnectionEstablished);

            return true;
        }

        public void Disconnect()
        {
            if (_webSocket != null)
                _webSocket.Close();
        }

        public string Send<T>(string dcapp, string function, T args) where T : class
        {
            var command = new Request<T>(dcapp, function, args);
            return Send(command);
        }
        public string Send<T>(Request<T> command) where T : class
        {
            var encrypted = command.Encrypt(SymmetricKey);
            Send(encrypted);
            return command.requestId;
        }
        public void Send(string request)
        {
            var ivOffset = ByteHelper.GetRandom(16);
            var encryptedCmd = request.ToBytes().AesCtrEncrypt(SymmetricKey, ivOffset);
            Send(ByteHelper.Combine(ivOffset, encryptedCmd));
        }
        public void Send(byte[] encrypted)
        {
            var encryptedWithHop = ByteHelper.Combine(_hop, encrypted);
            _webSocket.Send(encryptedWithHop);
        }

        public bool Ping()
        {
            if (_webSocket == null) return false;
            return _webSocket.Ping();
        }

        public void Dispose()
        {
            Disconnect();
        }
    }
}
