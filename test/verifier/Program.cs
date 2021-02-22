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

        static void Main(string[] args)
        {
            int n = Int32.Parse(args[0]);

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
            Console.WriteLine("Connected!");


            bytes = new Byte[2048];
            stream.Read(bytes, 0, bytes.Length);
            string X_str = System.Text.Encoding.ASCII.GetString(bytes, 0, bytes.Length);


            bytes = new Byte[2048];
            stream.Read(bytes, 0, bytes.Length);
            string M_str = System.Text.Encoding.ASCII.GetString(bytes, 0, bytes.Length);

            string[] temp_split;

            temp_split = X_str.Split("|");

            Org.BouncyCastle.Math.BigInteger[] X = new Org.BouncyCastle.Math.BigInteger[n + 1];

            for (int i = 0; i < n + 1; ++i)
            {
                X[i] = new Org.BouncyCastle.Math.BigInteger(temp_split[i]);
            }


            temp_split = M_str.Split("|");

            Org.BouncyCastle.Math.BigInteger[] M = new Org.BouncyCastle.Math.BigInteger[n + 1];

            for (int i = 0; i < n + 1; ++i)
            {
                M[i] = new Org.BouncyCastle.Math.BigInteger(temp_split[i]);
            }

            RsaKeyParameters[] P = new RsaKeyParameters[n + 1];


            for (int i = 0; i < n + 1; ++i)
            {
                P[i] = new RsaKeyParameters(false, M[i], X[i]);
            }



        }
    }
}
