using System;
using Org.BouncyCastle.Crypto.Generators;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.OpenSsl;
using System.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.X9;
using RestSharp;
using Newtonsoft.Json;
using System.Security.Cryptography;
using System.Collections;

namespace ECDSATest
{
    class Program
    {
        
        static AsymmetricCipherKeyPair SignatureKeys;

        static async Task Main(string[] args)
        {
            Console.WriteLine("working!");
            Console.WriteLine($"{StringToByteArray("b25e24d54ef799f8").Length} bytes");

            Console.ReadKey();

            //var serverPubKey = CreateHandshake("claudio");
            await Login("claudio", "admin");


            Console.ReadKey();
        }

        static async Task<byte[]> CreateHandshake(string user)
        {
            Console.WriteLine("Creating handshake...");

            //Get the newly created keys and store them locally
            SignatureKeys = GenerateKeyPair();

            var publicKey = SignatureKeys.Public as ECPublicKeyParameters;

            var client = new RestClient($"http://54.38.182.228:4000");

            //Create a body for the handshake
            Dictionary<string, string> body = new Dictionary<string, string>()
            {
                { "username", user },
                { "pubkey", ToHex(publicKey.Q.GetEncoded()) }
            };

            var request = new RestRequest("auth/handshake", Method.POST);
            request.AddHeader("Content-Type", "application/json");

            string jsonBody = JsonConvert.SerializeObject(body);

            Console.WriteLine($"Body Content {jsonBody}");

            request.AddJsonBody(jsonBody);

            Console.WriteLine("Requesting for server pub key...");

            var response = await client.ExecutePostTaskAsync(request);

            byte[] serverPubKey = StringToByteArray(response.Content);

            Console.WriteLine($"Server public key: {ToHex(serverPubKey)}");

            Console.WriteLine("Done requesting for server pub key!");

            return serverPubKey;
        }

        static async Task<byte[]> Login(string username, string password)
        {
            // HANDSHAKE
            var serverPubKey = await CreateHandshake(username);

            //Client to use on the login
            var client = new RestClient($"http://54.38.182.228:4000");

            // ENCRYPT DATA TO SEND

            var toEncryptData = JsonConvert.SerializeObject(new Dictionary<string, string>()
            {
                { "username", username },
                { "password", password }
            });

            //Stored encrypted data
            byte[] dataEncrypted;
            //Generated IV
            byte[] IV;

            byte[] signature;

            //Get the shared key
            var fullKey = GetSharedKey((ECPrivateKeyParameters)SignatureKeys.Private, serverPubKey);

            //16 bytes of key
            Console.WriteLine("slicing key...");

            byte[] slicedKey = fullKey.Take(16).ToArray();

            Console.WriteLine("Key sliced!");

            Console.WriteLine($"{slicedKey.Length} bytes Test Slice: {ToHex(slicedKey)}");

            // Encrypt the string to an array of bytes. 
            var encrypted = EncryptStringToBytes_Aes(toEncryptData, slicedKey);

            //Retrieve the encyption and the IV
            dataEncrypted = encrypted.Item1;
            IV = encrypted.Item2;

            Console.WriteLine($"{dataEncrypted.Length} bytes ENCRYPTED DATA ({ToHex(dataEncrypted)})");
            Console.WriteLine($"{IV.Length} bytes IV ({ToHex(IV)})");

            signature = GetSignature(SignatureKeys.Private, dataEncrypted);

            Dictionary<string, string> body = new Dictionary<string, string>()
            {
                { "username", username },
                { "encryptedData", ToHex(dataEncrypted) },
                { "signature", ToHex(signature) },
                { "iv", ToHex(IV) }
            };

            var request = new RestRequest("auth/login", Method.POST);
            request.AddHeader("Content-Type", "application/json");

            var jsonBody = JsonConvert.SerializeObject(body);
            request.AddJsonBody(jsonBody);
            Console.WriteLine($"JSON BODY: {jsonBody}");

            var response = await client.ExecutePostTaskAsync(request);

            Console.WriteLine($"RESPONDE CODE: {response.StatusCode} RESPONSE: {response.Content}");

            return new byte[0];
        }

        static AsymmetricCipherKeyPair GenerateKeyPair()
        {
            Console.WriteLine("Generating signature keys...");
            var curve = ECNamedCurveTable.GetByName("secp256k1");
            var domainParams = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

            var secureRandom = new SecureRandom();
            var keyParams = new ECKeyGenerationParameters(domainParams, secureRandom);

            var generator = new ECKeyPairGenerator("ECDSA");
            generator.Init(keyParams);
            var keyPair = generator.GenerateKeyPair();

            var privateKey = keyPair.Private as ECPrivateKeyParameters;
            var publicKey = keyPair.Public as ECPublicKeyParameters;

            var strPrivKey = ToHex(privateKey.D.ToByteArrayUnsigned());
            var strPubKey = ToHex(publicKey.Q.GetEncoded());

            Console.WriteLine($"{strPrivKey.Length} bytes Private key: {strPrivKey}");
            Console.WriteLine($"{strPubKey.Length} bytes Public key: {strPubKey}");

            Console.WriteLine("Done generating signature keys!");

            return keyPair;
        }

        static byte[] GetSharedKey(ECPrivateKeyParameters sigPrivKey, byte[] serverPubKey)
        {
            Console.WriteLine("Generating shared key!");

            var ecP = ECNamedCurveTable.GetByName("secp256k1");

            var domainParams = new ECDomainParameters(ecP.Curve, ecP.G, ecP.N, ecP.H, ecP.GetSeed());

            Org.BouncyCastle.Math.EC.ECPoint point = domainParams.Curve.DecodePoint(serverPubKey);

            ECPublicKeyParameters oEcPublicKeyParameters = new ECPublicKeyParameters(point, domainParams);

            IBasicAgreement aKeyAgree = AgreementUtilities.GetBasicAgreement("ECDH");

            aKeyAgree.Init(sigPrivKey);

            var sharedKey = aKeyAgree.CalculateAgreement(oEcPublicKeyParameters).ToByteArray();

            Console.WriteLine($"{sharedKey.Length} bytes Created shared key ({ToHex(sharedKey)})");

            return sharedKey;
        }

        static string ToHex(byte[] data) => String.Concat(data.Select(x => x.ToString("x2")));

        static byte[] GetSignature(AsymmetricKeyParameter key, byte[] data)
        {
            Console.WriteLine("Signing data...");
            //var signerAlgorithm = "ECDSA";
            var signerAlgorithm = "SHA256withECDSA";
            ISigner signer = SignerUtilities.GetSigner(signerAlgorithm);
            signer.Init(true, key);
            signer.BlockUpdate(data, 0, data.Length);
            byte[] signature = signer.GenerateSignature();
            Console.WriteLine($"{signature.Length} bytes Signature generated: {ToHex(signature)}");
            return signature;
        }

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        public static AsymmetricCipherKeyPair GenerateKeys(int keySize)
        {
            //using ECDSA algorithm for the key generation
            var gen = new ECKeyPairGenerator();
            //Creating Random
            var secureRandom = new SecureRandom();
            //Parameters creation using the random and keysize
            var keyGenParam = new KeyGenerationParameters(secureRandom, keySize);
            //Initializing generation algorithm with the Parameters--This method Init i modified
            gen.Init(keyGenParam);
            //Generation of Key Pair
            return gen.GenerateKeyPair();
        }

        public static void GeneratePKeys(int intSize)
        {
            //Generating p-128 keys 128 specifies strength
            var keyPair = GenerateKeys(intSize);

            TextWriter textWriter = new StringWriter();
            PemWriter pemWriter = new PemWriter(textWriter);

            pemWriter.WriteObject(keyPair.Private);
            pemWriter.Writer.Flush();

            string privateKey = textWriter.ToString();

            pemWriter.WriteObject(keyPair.Public);
            pemWriter.Writer.Flush();

            string publicKey = textWriter.ToString();

            Console.WriteLine(privateKey);
            Console.WriteLine(publicKey);
        }

        internal static Tuple<byte[], byte[]> EncryptStringToBytes_Aes(string plainText, byte[] Key)
        {
            byte[] encrypted;
            byte[] IV;

            Console.WriteLine("AES encryption...");

            RijndaelManaged rj = new RijndaelManaged();
            rj.KeySize = 128;
            rj.BlockSize = 128;
            rj.Key = Key;
            rj.GenerateIV();
            IV = rj.IV;
            rj.Mode = CipherMode.CBC;
            //rj.Padding = PaddingMode.PKCS7;

            try
            {
                MemoryStream ms = new MemoryStream();

                using (CryptoStream cs = new CryptoStream(ms, rj.CreateEncryptor(Key, IV), CryptoStreamMode.Write))
                {
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(plainText);
                        sw.Close();
                    }
                    cs.Close();
                }
                encrypted = ms.ToArray();

                ms.Close();
            }
            catch (CryptographicException e)
            {
                Console.WriteLine("A Cryptographic error occurred: {0}", e.Message);
                return null;
            }
            /*
            using (Aes aesAlg = Aes.Create())
            {
                //aesAlg.KeySize = 128;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.BlockSize = 128;
                aesAlg.Key = Key;

                //aesAlg.GenerateIV();
                IV = aesAlg.IV = StringToByteArray("b25e24d54ef799f8");

                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption. 
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            */
            Console.WriteLine($"{IV.Length} bytes TEST IV: {ToHex(IV)}");
            Console.WriteLine("AES encryption done!");
            // Return the encrypted bytes from the memory stream. 
            return new Tuple<byte[], byte[]>(encrypted, IV);
        }

        internal static string DecryptStringFromBytes_Aes(byte[] cipherTextCombined, byte[] Key)
        {
            // Declare the string used to hold 
            // the decrypted text. 
            string plaintext = null;

            // Create an Aes object 
            // with the specified key and IV. 
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;

                byte[] IV = new byte[aesAlg.BlockSize / 8];
                byte[] cipherText = new byte[cipherTextCombined.Length - IV.Length];

                Array.Copy(cipherTextCombined, IV, IV.Length);
                Array.Copy(cipherTextCombined, IV.Length, cipherText, 0, cipherText.Length);

                aesAlg.IV = IV;

                aesAlg.Mode = CipherMode.CBC;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption. 
                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return plaintext;
        }
    }
}
