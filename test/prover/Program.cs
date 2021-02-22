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

            byte[] data;

            data = new byte[2048];

            data = Encoding.UTF8.GetBytes(X);
            stream.Write(data);

            stream.Flush();


            data = new byte[2048];
            data = Encoding.UTF8.GetBytes(M);
            stream.Write(data);

            stream.Flush();

            const int DefaultPrimeProbability = 30;

            DHParametersGenerator generator = new DHParametersGenerator();
            var key_variable = Encoding.ASCII.GetBytes("test_g");
            generator.Init(512, DefaultPrimeProbability, new SecureRandom(key_variable));
            DHParameters parameters = generator.GenerateParameters();

            Org.BouncyCastle.Math.BigInteger g = parameters.G;




        }
    }
}
