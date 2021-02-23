using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Numerics;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Linq;


using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.OpenSsl;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Digests;

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

namespace verifier
{
    class Program
    {

        public static RsaKeyParameters Pv;
        public static RsaKeyParameters Sv;
        static void gen_keys()
        {
            var key_variable = Encoding.ASCII.GetBytes("test_ver");

            RsaKeyPairGenerator rsaKeyPairGnr_s = new RsaKeyPairGenerator();
            rsaKeyPairGnr_s.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(key_variable), 512));
            Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair_s = rsaKeyPairGnr_s.GenerateKeyPair();

            Pv = (RsaKeyParameters)keyPair_s.Public;
            Sv = (RsaKeyParameters)keyPair_s.Private;
        }

        public static byte[] EncryptByteArray(byte[] key, byte[] secret)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                using (AesManaged cryptor = new AesManaged())
                {
                    cryptor.Mode = CipherMode.CBC;
                    cryptor.Padding = PaddingMode.Zeros;
                    cryptor.KeySize = 128;
                    cryptor.BlockSize = 128;
                    key = key.Concat(key).ToArray();

                    //We use the random generated iv created by AesManaged
                    byte[] iv = cryptor.IV;

                    using (CryptoStream cs = new CryptoStream(ms, cryptor.CreateEncryptor(key, iv), CryptoStreamMode.Write))
                    {
                        cs.Write(secret, 0, secret.Length);
                    }
                    byte[] encryptedContent = ms.ToArray();

                    //Create new byte array that should contain both unencrypted iv and encrypted data
                    byte[] result = new byte[iv.Length + encryptedContent.Length];

                    //copy our 2 array into one
                    System.Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                    System.Buffer.BlockCopy(encryptedContent, 0, result, iv.Length, encryptedContent.Length);

                    return result;
                }
            }
        }

        public static byte[] DecryptByteArray(byte[] key, byte[] secret)
        {
            byte[] iv = new byte[16]; //initial vector is 16 bytes
            byte[] encryptedContent = new byte[secret.Length - 16]; //the rest should be encryptedcontent

            //Copy data to byte array
            System.Buffer.BlockCopy(secret, 0, iv, 0, iv.Length);
            System.Buffer.BlockCopy(secret, iv.Length, encryptedContent, 0, encryptedContent.Length);

            using (MemoryStream ms = new MemoryStream())
            {
                using (AesManaged cryptor = new AesManaged())
                {
                    cryptor.Mode = CipherMode.CBC;
                    cryptor.Padding = PaddingMode.Zeros;
                    cryptor.KeySize = 128;
                    cryptor.BlockSize = 128;
                    key = key.Concat(key).ToArray();

                    using (CryptoStream cs = new CryptoStream(ms, cryptor.CreateDecryptor(key, iv), CryptoStreamMode.Write))
                    {
                        cs.Write(encryptedContent, 0, encryptedContent.Length);

                    }
                    return ms.ToArray();
                }
            }
        }




        static void Main(string[] args)
        {
            int n = Int32.Parse(args[0]);
            gen_keys();

            TcpListener server = null;
            Int32 port = 13000;
            IPAddress localAddr = IPAddress.Parse("127.0.0.1");

            // TcpListener server = new TcpListener(port);
            server = new TcpListener(localAddr, port);

            // Start listening for client requests.
            server.Start();

            // Buffer for reading data
            Byte[] bytes;


            TcpClient client = server.AcceptTcpClient();
            NetworkStream stream = client.GetStream();

            bytes = new Byte[204800];
            stream.Read(bytes, 0, bytes.Length);
            string P_str = System.Text.Encoding.ASCII.GetString(bytes, 0, bytes.Length);

            string[] temp_split;

            temp_split = P_str.Split("|");

            Org.BouncyCastle.Math.BigInteger[] X = new Org.BouncyCastle.Math.BigInteger[n + 1];

            for (int i = 0; i < n + 1; ++i)
            {
                X[i] = new Org.BouncyCastle.Math.BigInteger(temp_split[i]);
            }

            Org.BouncyCastle.Math.BigInteger[] M = new Org.BouncyCastle.Math.BigInteger[n + 1];

            for (int i = 0; i < n + 1; ++i)
            {
                M[i] = new Org.BouncyCastle.Math.BigInteger(temp_split[i + n + 1]);
            }

            RsaKeyParameters[] P = new RsaKeyParameters[n + 1];

            for (int i = 0; i < n + 1; ++i)
            {
                P[i] = new RsaKeyParameters(false, M[i], X[i]);
            }

            //const int DefaultPrimeProbability = 30;

            /*DHParametersGenerator generator = new DHParametersGenerator();
            var key_variable = Encoding.ASCII.GetBytes("test");
            generator.Init(256, DefaultPrimeProbability, new SecureRandom(key_variable));
            DHParameters parameters = generator.GenerateParameters();

            Org.BouncyCastle.Math.BigInteger g = parameters.G;*/

            Random random = new Random();
            int g = 31;
            int x0 = 5;


            //Org.BouncyCastle.Math.BigInteger X0 = g.Pow(x);
            BigInteger X0 = (BigInteger)Math.Pow(g, x0);

            //byte[] X0_byte = X0.ToByteArray();
            byte[] X0_byte = Encoding.Default.GetBytes(X0.ToString());
            IAsymmetricBlockCipher cipher = new RsaEngine();

            byte[][] y = new byte[n + 1][];

            for (int i = 0; i < n + 1; ++i)
            {
                cipher.Init(true, P[i]);
                y[i] = cipher.ProcessBlock(X0_byte, 0, X0_byte.Length);

                stream.Write(y[i]);

                stream.Flush();
            }


            bytes = new byte[64];
            stream.Read(bytes, 0, bytes.Length);

            cipher.Init(false, Sv);
            byte[] Y0_byte = cipher.ProcessBlock(bytes, 0, bytes.Length);

            int Y0 = Int32.Parse(Encoding.Default.GetString(Y0_byte));
            //Org.BouncyCastle.Math.BigInteger X0 = new Org.BouncyCastle.Math.BigInteger(X0_byte);

            BigInteger K = BigInteger.Pow(Y0, x0);
            byte[] k_byte = Encoding.Default.GetBytes(X0.ToString());


            int R = random.Next();
            byte[] R_byte = Encoding.Default.GetBytes(R.ToString());

            byte[] R_cipher = EncryptByteArray(k_byte, R_byte);

            stream.Write(R_cipher);

            stream.Flush();

            bytes = new byte[32];
            stream.Read(bytes, 0, bytes.Length);

            string R_str = Encoding.Default.GetString(bytes);

            int R1 = Int32.Parse(R_str);


            if (R == R1)
            {
                Console.WriteLine("SUCCESS");
            }
            else
            {
                Console.WriteLine("FAIL");
            }







        }
    }
}
