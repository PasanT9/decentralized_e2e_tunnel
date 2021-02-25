using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Numerics;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using Newtonsoft.Json;

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


namespace server
{
    class Program
    {
        static int n;
        static void Main(string[] args)
        {
            var watch = new System.Diagnostics.Stopwatch();
            
            watch.Start();

            n = Int32.Parse(args[0]);
            TcpListener server = null;
            Int32 port = 13000;
            IPAddress localAddr = IPAddress.Parse("127.0.0.1");

            server = new TcpListener(localAddr, port);
            server.Start();

            TcpClient client = server.AcceptTcpClient();
            NetworkStream stream = client.GetStream();

            Console.WriteLine("Connected!");
            byte[] bytes;
            string response;

            Random random = new Random();
            int N = random.Next();


            bytes = System.Text.Encoding.ASCII.GetBytes(N.ToString());
            stream.Write(bytes, 0, bytes.Length);

            bytes = new byte[64];
            stream.Read(bytes, 0, bytes.Length);

            byte[] v = bytes;
            Console.WriteLine(v.Length);



            bytes = new byte[20480];
            stream.Read(bytes, 0, bytes.Length);
            string P_str = System.Text.Encoding.ASCII.GetString(bytes, 0, bytes.Length);

            string[] temp_split;

            temp_split = P_str.Split("|");

            Org.BouncyCastle.Math.BigInteger[] x = new Org.BouncyCastle.Math.BigInteger[n + 1];

            for (int i = 0; i < n + 1; ++i)
            {
                x[i] = new Org.BouncyCastle.Math.BigInteger(temp_split[i]);
            }

            Org.BouncyCastle.Math.BigInteger[] M = new Org.BouncyCastle.Math.BigInteger[n + 1];

            for (int i = 0; i < n + 1; ++i)
            {
                M[i] = new Org.BouncyCastle.Math.BigInteger(temp_split[i + n + 1]);
            }

            RsaKeyParameters[] P = new RsaKeyParameters[n + 1];

            for (int i = 0; i < n + 1; ++i)
            {
                P[i] = new RsaKeyParameters(false, M[i], x[i]);
            }

            string[] X0 = new string[n + 1];

            for (int i = 0; i < n + 1; ++i)
            {
                X0[i] = temp_split[i + n + n + 2];
            }

            byte[][] X = new byte[n + 1][];

            for (int i = 0; i < n + 1; ++i)
            {
                UTF8Encoding utf8enc = new UTF8Encoding();
                X[i] = utf8enc.GetBytes(X0[i]);
            }

            ring_verify(P, v, X, N.ToString());

            //End time
            
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
