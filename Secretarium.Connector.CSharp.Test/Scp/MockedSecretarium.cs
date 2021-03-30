using Newtonsoft.Json;
using Secretarium.Helpers;
using System;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;

namespace Secretarium.Test
{
    public class Session
    {
        public enum DHSteps
        {
            ClientHello,
            ClientChallenge,
            ClientProofOfIdentity,
            Secured
        };

        public DHSteps Step;
        public byte[] ClientEphDHPubKey;
        public byte[] ClientPubKey;
        public byte[] ProofOfWorkDetails;
        public byte[] SymmetricKey;
    }

    public class MockedSecretarium
    {
        public const string SecretariumPrivateKeyBase64 = "KSO+hOFs1q5SkEnx8bvp67Om2zyHDD6ZJF4NHAa3R94=";
        public const string SecretariumPublicKeyBase64 = "f7Bvp9DCsplG9z5AK6O8v/ga3GHWpmAe8agSIvyDWK4K8n/zGq0kSEF6MK+yJunvicXRXvvhqo96tblq2spUjg==";
        
        public static ECDsaCng SecretariumKey;
        public static byte[] GenesisPubKey;

        public Session Session { get; }
        public ScpConfig.EncryptionMode EncryptionMode { get; }

        static MockedSecretarium()
        {
            GenesisPubKey = SecretariumPublicKeyBase64.FromBase64String().ReverseEndianness();
            var privateKey = SecretariumPrivateKeyBase64.FromBase64String().ReverseEndianness();
            SecretariumKey = ECDsaHelper.ImportPrivateKey(GenesisPubKey, privateKey);
        }

        public MockedSecretarium(ScpConfig.EncryptionMode encryptionMode)
        {
            Session = new Session();
            EncryptionMode = encryptionMode;
        }

        public bool GetServerHello(byte[] clientHello, out byte[] serverHello)
        {
            serverHello = null;
            
            if (!ClientHello.Parse(clientHello, out ClientHello ch))
                return false;

            var nonce = ByteHelper.GetRandom(32);

            var proofOfWorkDetails = ByteHelper.GetRandom(32);
            proofOfWorkDetails[0] = 15;

            serverHello = ByteHelper.Combine(nonce, proofOfWorkDetails);

            Session.ClientEphDHPubKey = ch.ephDHKey;

            return true;
        }

        public bool GetServerIdentity(byte[] clientProofOfWork, out byte[] serverIdentity)
        {
            serverIdentity = null;

            if (!ClientProofOfWork.Parse(clientProofOfWork, out ClientProofOfWork cpow))
                return false;

            if(!cpow.knownSecretariumPubKey.SequenceEqual(GenesisPubKey))
                return false;

            // Create ephemereal DH keys
            var eph = ECDHHelper.CreateCngKey();
            var ephCng = ECDHHelper.CreateECDiffieHellmanCngSha256(eph);
            var ephPubKey = ephCng.PublicKey();

            // Get CommonKey from DH
            var clientPublicCngKey = Session.ClientEphDHPubKey.ToECDHCngKey();
            var commonKey = ephCng.DeriveKeyMaterial(clientPublicCngKey);

            // Generate a random SymmetricKey
            var symmetricKey = ByteHelper.GetRandom(commonKey.Length);

            // XOR CommonKey and SymmetricKey to produce a PreMasterSecret
            var preMasterSecret = commonKey.Xor(symmetricKey);

            serverIdentity = ByteHelper.Combine(preMasterSecret, ephPubKey, GenesisPubKey);

            Session.SymmetricKey = symmetricKey;

            return true;
        }

        public bool GetServerProofOfIdentity(byte[] encryptedClientProofOfIdentity, out byte[] serverProofOfIdentity)
        {
            serverProofOfIdentity = null;

            // Decrypt Client Finished message signed with symmetric key
            var ivOffset = encryptedClientProofOfIdentity.Extract(0, 16);
            var clientProofOfIdentity = EncryptionMode == ScpConfig.EncryptionMode.AESCTR
                ? encryptedClientProofOfIdentity.Extract(16).AesCtrDecrypt(Session.SymmetricKey, ivOffset)
                : encryptedClientProofOfIdentity.Extract(16).AesGcmDecryptWithOffset(Session.SymmetricKey, ivOffset);

            if (!ClientProofOfIdentity.Parse(clientProofOfIdentity, out ClientProofOfIdentity cpoi))
                return false;

            // Verify eph pub key
            if (!cpoi.ephDHKey.SequenceEqual(Session.ClientEphDHPubKey))
                return false;

            // Verify signature
            var clientsECDsaCng = ECDsaHelper.ImportPublicKey(cpoi.publicKey);
            if (!clientsECDsaCng.VerifyData(cpoi.nonce, cpoi.nonceSigned))
                return false;

            Session.ClientPubKey = cpoi.publicKey;

            // Prepare answer
            var nonce = ByteHelper.GetRandom(32);
            var msg = "Hey you! Welcome to Secretarium!".ToBytes();
            var signed = SecretariumKey.SignData(ByteHelper.Combine(nonce, msg));

            // Generate a random IV offset
            ivOffset = ByteHelper.GetRandom(16);

            // Encrypt
            var combined = ByteHelper.Combine(nonce, signed);
            var encrypted = EncryptionMode == ScpConfig.EncryptionMode.AESCTR
                ? combined.AesCtrEncrypt(Session.SymmetricKey, ivOffset)
                : combined.AesGcmEncryptWithOffset(Session.SymmetricKey, ivOffset);

            serverProofOfIdentity = ByteHelper.Combine(ivOffset, encrypted);

            return true;
        }

        public byte[] RunCommand(byte[] data)
        {
            var ivOffset = data.Extract(0, 16);
            var command = data.Extract(16);

            // Decrypt the command
            var decrypted = EncryptionMode == ScpConfig.EncryptionMode.AESCTR
                ? command.AesCtrDecrypt(Session.SymmetricKey, ivOffset)
                : command.AesGcmDecryptWithOffset(Session.SymmetricKey, ivOffset);
            var commandJson = decrypted.DeserializeJsonAs<Request>();
            if (commandJson == null || string.IsNullOrEmpty(commandJson.function))
                return null;

            // Find Command method            
            var methodInfo = Type.GetType(commandJson.dcapp).GetMethod(commandJson.function, BindingFlags.Public | BindingFlags.Static | BindingFlags.IgnoreCase);
            if (methodInfo == null)
                return null;

            // Look for args
            object[] parameters = null;
            var methodParams = methodInfo.GetParameters();
            if (methodParams.Length == 1)
            {                
                var commandText = decrypted.GetUtf8String();
                var commandOption = JsonConvert.DeserializeObject(commandText, 
                    typeof(Request<>).MakeGenericType(methodParams[0].ParameterType));
                parameters = new[] { commandOption.GetType().GetProperty("args").GetValue(commandOption) };
            }

            try
            {
                // Run
                var result = methodInfo.Invoke(null, parameters);
                if (result == null)
                    return null;

                // Prepare
                if(methodInfo.ReturnType != typeof(byte[]))
                {
                    var m = typeof(Result<>).MakeGenericType(methodInfo.ReturnType).GetMethod("GetBytes", BindingFlags.Public | BindingFlags.Static);
                    result = m.Invoke(null, new[] { commandJson.requestId, result });
                }
                
                // Encrypt
                ivOffset = ByteHelper.GetRandom(16);
                var encryptedResult = EncryptionMode == ScpConfig.EncryptionMode.AESCTR
                    ? ((byte[])result).AesCtrEncrypt(Session.SymmetricKey, ivOffset)
                    : ((byte[])result).AesGcmEncryptWithOffset(Session.SymmetricKey, ivOffset);

                // Return result dataInputId
                return ByteHelper.Combine(ivOffset, encryptedResult);
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}