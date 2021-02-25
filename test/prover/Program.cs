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

namespace prover
{
    class Program
    {

        public static RsaKeyParameters Pp;
        public static RsaKeyParameters Sp;
        static void gen_keys()
        {
            var key_variable = Encoding.ASCII.GetBytes("test_pro");

            RsaKeyPairGenerator rsaKeyPairGnr_s = new RsaKeyPairGenerator();
            rsaKeyPairGnr_s.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(key_variable), 512));
            Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair_s = rsaKeyPairGnr_s.GenerateKeyPair();

            Pp = (RsaKeyParameters)keyPair_s.Public;
            Sp = (RsaKeyParameters)keyPair_s.Private;
        }

        public static RsaKeyParameters[] req_keys(int n)
        {
            RsaKeyParameters[] keys = new RsaKeyParameters[n];
            for (int i = 0; i < n; ++i)
            {
                RsaKeyPairGenerator rsaKeyPairGnr_s = new RsaKeyPairGenerator();
                rsaKeyPairGnr_s.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 512));
                Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair_s = rsaKeyPairGnr_s.GenerateKeyPair();

                keys[i] = (RsaKeyParameters)keyPair_s.Public;
            }
            return keys;
        }

        public static RsaKeyParameters req_ver_key()
        {
            var key_variable = Encoding.ASCII.GetBytes("test_ver");

            RsaKeyPairGenerator rsaKeyPairGnr_s = new RsaKeyPairGenerator();
            rsaKeyPairGnr_s.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(key_variable), 512));
            Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair_s = rsaKeyPairGnr_s.GenerateKeyPair();

            RsaKeyParameters key = (RsaKeyParameters)keyPair_s.Public;
            return key;
        }

        public static byte[] EncryptByteArray(byte[] key, byte[] secret)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                using (AesManaged cryptor = new AesManaged())
                {
                    cryptor.Mode = CipherMode.CBC;
                    cryptor.Padding = PaddingMode.PKCS7;
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

            string server = "127.0.0.1";
            Int32 port = 13000;
            TcpClient client = new TcpClient(server, port);
            NetworkStream stream = client.GetStream();

            gen_keys();
            RsaKeyParameters[] P = req_keys(n);

            RsaKeyParameters Pv = req_ver_key();
            
<<<<<<< HEAD

            //Time start
			DateTime now = DateTime.Now;
			Console.WriteLine("Strat Second: {0}", now.Second);
=======
       

            //Time start
            DateTime now = DateTime.Now;
	    Console.WriteLine("Strat Second: {0}", now.Second);
>>>>>>> e87d7bd6763c0e2c9302616faed3c846a8178038
            
            string X = Pp.Exponent + "|";
            for (int i = 0; i < n; ++i)
            {
                X += P[i].Exponent + "|";
            }

            string M = Pp.Modulus + "|";
            for (int i = 0; i < n; ++i)
            {
                M += P[i].Modulus + "|";
            }

            string P_str = X + M;

            byte[] data;

            data = new byte[2048];

            data = Encoding.UTF8.GetBytes(X + M);
            stream.Write(data);



            /*const int DefaultPrimeProbability = 30;

            DHParametersGenerator generator = new DHParametersGenerator();
            var key_variable = Encoding.ASCII.GetBytes("test");
            generator.Init(512, DefaultPrimeProbability, new SecureRandom(key_variable));
            DHParameters parameters = generator.GenerateParameters();

            Org.BouncyCastle.Math.BigInteger g = parameters.G;*/

            byte[] bytes;
            byte[][] y = new byte[n + 1][];
            for (int i = 0; i < n + 1; ++i)
            {
                bytes = new byte[64];
                stream.Read(bytes, 0, bytes.Length);
                y[i] = bytes;
            }

            IAsymmetricBlockCipher cipher = new RsaEngine();
            cipher.Init(false, Sp);
            byte[] X0_byte = cipher.ProcessBlock(y[0], 0, y[0].Length);

            int X0 = Int32.Parse(Encoding.Default.GetString(X0_byte));
            //Org.BouncyCastle.Math.BigInteger X0 = new Org.BouncyCastle.Math.BigInteger(X0_byte);

            int g = 31;
            int y0 = 3;

            BigInteger Y0 = (BigInteger)Math.Pow(g, y0);

            BigInteger K = BigInteger.Pow(X0, y0);
            byte[] k_byte = Encoding.Default.GetBytes(X0.ToString());


            byte[] Y0_byte = Encoding.Default.GetBytes(Y0.ToString());

            cipher.Init(true, Pv);
            byte[] Y0_cipher = cipher.ProcessBlock(Y0_byte, 0, Y0_byte.Length);

            stream.Write(Y0_cipher);

            stream.Flush();

            bytes = new byte[32];
            stream.Read(bytes, 0, bytes.Length);

            byte[] R_plain = DecryptByteArray(k_byte, bytes);


            stream.Write(R_plain);

            stream.Flush();

<<<<<<< HEAD
            

=======
>>>>>>> e87d7bd6763c0e2c9302616faed3c846a8178038

        }
    }
}
