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


namespace client
{
    class Program
    {
        //public static System.Numerics.BigInteger;
        static int n;

        static void Main(string[] args)
        {
            n = Int32.Parse(args[0]);
            try
            {

                byte[][] X = new byte[n + 1][];
                string[] X0 = new string[n + 1];
                Random rnd = new Random();

                for (int i = 0; i < n + 1; ++i)
                {
                    UTF8Encoding utf8enc = new UTF8Encoding();
                    X0[i] = rnd.Next().ToString();
                    X[i] = utf8enc.GetBytes(X0[i]);
                }

                RsaKeyParameters[] P = new RsaKeyParameters[n + 1];

                for (int i = 0; i < n; ++i)
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


                string server = "127.0.0.1";

                Int32 port = 13000;
                TcpClient client = new TcpClient(server, port);


                //Time start
                var watch = new System.Diagnostics.Stopwatch();
            
                watch.Start();
                
                NetworkStream stream = client.GetStream();

                byte[] bytes;
                string response;

                bytes = new byte[64];
                stream.Read(bytes, 0, bytes.Length);
                response = System.Text.Encoding.ASCII.GetString(bytes, 0, bytes.Length);
                string N = response;

                string m = N;

                byte[] v = ring_sign(P, m, Ks, X);

                stream.Write(v);
                Console.WriteLine(v.Length);

                string x = "";
                for (int i = 0; i < n + 1; ++i)
                {
                    x += P[i].Exponent + "|";
                }

                string M = "";
                for (int i = 0; i < n + 1; ++i)
                {
                    M += P[i].Modulus + "|";
                }

                string X0_str = "";
                for (int i = 0; i < n + 1; ++i)
                {
                    X0_str += X0[i] + "|";
                }


                bytes = Encoding.UTF8.GetBytes(x + M + X0_str);
                stream.Write(bytes);

                stream.Flush();





                // Close everything.
                stream.Close();
                client.Close();
            }
            catch (ArgumentNullException e)
            {
                Console.WriteLine("ArgumentNullException: {0}", e);
            }
            catch (SocketException e)
            {
                Console.WriteLine("SocketException: {0}", e);
            }
            
            watch.Stop();

            Console.WriteLine($"Execution Time: {watch.ElapsedMilliseconds} ms");

        }

        public static byte[] ring_sign(RsaKeyParameters[] P, string m, RsaKeyParameters Ks, byte[][] X)
        {
            byte[] k1 = Encoding.UTF8.GetBytes(m);

            byte[] k = new byte[64];

            for (int i = 0; i < k1.Length; ++i)
            {
                k[i] = (byte)(k[i] + k1[i]);
            }


            byte[][] y = new byte[n + 1][];

            for (int i = 0; i < n + 1; ++i)
            {
                IAsymmetricBlockCipher cipher = new RsaEngine();
                cipher.Init(true, P[i]);

                y[i] = cipher.ProcessBlock(X[i], 0, X[i].Length);
            }

            byte[] ring = y[0];
            for (int i = 1; i < n + 1; ++i)
            {
                ring = exclusiveOR(ring, k);
                ring = exclusiveOR(ring, y[i]);
            }

            byte[] v = ring;
            return v;
        }

        public static void ring_verify(RsaKeyParameters[] P, byte[] v, byte[][] X, string m)
        {

            byte[][] y = new byte[n + 1][];

            for (int i = 0; i < n + 1; ++i)
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
            for (int i = 1; i < n + 1; ++i)
            {
                ring = exclusiveOR(ring, k);
                ring = exclusiveOR(ring, y[i]);
            }

            Console.WriteLine("v: " + ByteArrayToString(v));
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
