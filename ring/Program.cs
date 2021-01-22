using System;
using System.Text;
using System.Security.Cryptography;
using System.Collections;
using System.Collections.Generic;

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

namespace ring
{
    class Program
    {


        static void Main(string[] args)
        {
            /*byte[][] y = new byte[10][];
            byte[][] x = new byte[10][];

            string message = "Hello!!";

            Console.WriteLine("Ring signature generation");

            byte[] k1 = Encoding.UTF8.GetBytes(message);

            byte[] k = new byte[64];

            for (int i = 0; i < k1.Length; ++i)
            {
                k[i] = (byte)(k[i] + k1[i]);
            }

            Dictionary<int, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair> keys = new Dictionary<int, Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair>();

            Random rnd = new Random();

            RsaKeyParameters[] P = new RsaKeyParameters[11];

            for (int i = 0; i < 10; ++i)
            {
                UTF8Encoding utf8enc = new UTF8Encoding();
                x[i] = utf8enc.GetBytes(rnd.Next().ToString());

                RsaKeyPairGenerator rsaKeyPairGnr = new RsaKeyPairGenerator();
                rsaKeyPairGnr.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 512));
                Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair = rsaKeyPairGnr.GenerateKeyPair();

                RsaKeyParameters publicKey = (RsaKeyParameters)keyPair.Public;
                IAsymmetricBlockCipher cipher = new RsaEngine();

                keys[i] = keyPair;
                P[i + 1] = publicKey;

                cipher.Init(true, publicKey);

                y[i] = cipher.ProcessBlock(x[i], 0, x[i].Length);
            }

            byte[] ring = y[0];
            for (int i = 1; i < 10; ++i)
            {
                ring = exclusiveOR(ring, k);
                ring = exclusiveOR(ring, y[i]);
            }


            RsaKeyPairGenerator rsaKeyPairGnr_s = new RsaKeyPairGenerator();
            rsaKeyPairGnr_s.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 512));
            Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair_s = rsaKeyPairGnr_s.GenerateKeyPair();

            RsaKeyParameters Ps = (RsaKeyParameters)keyPair_s.Public;
            RsaKeyParameters Ks = (RsaKeyParameters)keyPair_s.Private;

            IAsymmetricBlockCipher cipher_s = new RsaEngine();

            UTF8Encoding utf8enc_s = new UTF8Encoding();
            byte[] xs = utf8enc_s.GetBytes(rnd.Next().ToString());

            P[0] = Ps;

            cipher_s.Init(true, Ps);

            byte[] ys = cipher_s.ProcessBlock(xs, 0, xs.Length);

            ring = exclusiveOR(ring, k);
            byte[] v = exclusiveOR(ring, ys);

            byte[][] X = new byte[11][];

            X[0] = xs;

            for (int i = 1; i < 11; ++i)
            {
                X[i] = x[i - 1];
            }*/

            byte[][] X = new byte[11][];
            Random rnd = new Random();

            for (int i = 0; i < 11; ++i)
            {
                UTF8Encoding utf8enc = new UTF8Encoding();
                X[i] = utf8enc.GetBytes(rnd.Next().ToString());
            }

            RsaKeyParameters[] P = new RsaKeyParameters[11];

            for (int i = 0; i < 10; ++i)
            {

                RsaKeyPairGenerator rsaKeyPairGnr = new RsaKeyPairGenerator();
                rsaKeyPairGnr.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 512));
                Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair = rsaKeyPairGnr.GenerateKeyPair();

                RsaKeyParameters publicKey = (RsaKeyParameters)keyPair.Public;
                IAsymmetricBlockCipher cipher = new RsaEngine();

                P[i + 1] = publicKey;
            }

            RsaKeyPairGenerator rsaKeyPairGnr_s = new RsaKeyPairGenerator();
            rsaKeyPairGnr_s.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 512));
            Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair_s = rsaKeyPairGnr_s.GenerateKeyPair();

            P[0] = (RsaKeyParameters)keyPair_s.Public;
            RsaKeyParameters Ks = (RsaKeyParameters)keyPair_s.Private;

            string m = "Hello!!";

            byte[] v = ring_sign(P, m, Ks, X);

            ring_verify(P, v, X, m);
            Console.WriteLine();



        }

        public static byte[] ring_sign(RsaKeyParameters[] P, string m, RsaKeyParameters Ks, byte[][] X)
        {
            byte[] v = new byte[256];

            byte[][] y = new byte[11][];

            for (int i = 0; i < 11; ++i)
            {
                IAsymmetricBlockCipher cipher = new RsaEngine();
                cipher.Init(true, P[i]);

                y[i] = cipher.ProcessBlock(X[i], 0, X[i].Length);
            }

            return v;
        }

        public static void ring_verify(RsaKeyParameters[] P, byte[] v, byte[][] X, string m)
        {
            Console.WriteLine("Ring signature verification");

            byte[][] y = new byte[11][];

            for (int i = 0; i < 11; ++i)
            {
                IAsymmetricBlockCipher cipher = new RsaEngine();
                cipher.Init(true, P[i]);

                y[i] = cipher.ProcessBlock(X[i], 0, X[i].Length);
            }

            byte[] k1 = Encoding.UTF8.GetBytes(m);

            byte[] k = new byte[64];

            for (int i = 0; i < k1.Length; ++i)
            {
                k[i] = (byte)(k[i] + k1[i]);
            }


            byte[] ring = y[0];
            for (int i = 1; i < 11; ++i)
            {
                ring = exclusiveOR(ring, k);
                ring = exclusiveOR(ring, y[i]);
            }

            Console.WriteLine("ring: " + ByteArrayToString(ring));

        }

        public static byte[] exclusiveOR(byte[] arr1, byte[] arr2)
        {
            if (arr1.Length != arr2.Length)
                throw new ArgumentException("arr1 and arr2 are not the same length");

            byte[] result = new byte[arr1.Length];

            for (int i = 0; i < arr1.Length; ++i)
                result[i] = (byte)(arr1[i] ^ arr2[i]);

            return result;
        }

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        static byte[] Encrypt(byte[] input, RSAParameters publicKey)
        {
            byte[] encrypted;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(publicKey);

                //get public key from file
                //rsa.ImportParameters(StringToKey(File.ReadAllText(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + @"\pubKey.xml")));
                try
                {
                    encrypted = rsa.Encrypt(input, true);
                    return encrypted;
                }
                catch (System.Exception e)
                {
                    System.Console.WriteLine(e);
                    byte[] empty = { };
                    return empty;
                }
            }
        }

        static byte[] Decrypt(byte[] input, RSAParameters privateKey)
        {
            Console.WriteLine(input.Length);
            byte[] decrypted;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(privateKey);

                //get private key from file
                //rsa.ImportParameters(StringToKey(File.ReadAllText(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + @"\priKey.xml")));

                try
                {
                    decrypted = rsa.Decrypt(input, true);
                    return decrypted;
                }
                catch (System.Exception e)
                {
                    System.Console.WriteLine(e);
                    byte[] empty = { };
                    return empty;
                }
            }
        }
    }
}
