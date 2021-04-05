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
        public static Org.BouncyCastle.Math.BigInteger g;
        static void gen_keys()
        {
            var key_variable = Encoding.ASCII.GetBytes("test_ver");

            RsaKeyPairGenerator rsaKeyPairGnr_s = new RsaKeyPairGenerator();
            rsaKeyPairGnr_s.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(key_variable), 512));
            Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair_s = rsaKeyPairGnr_s.GenerateKeyPair();

            Pv = (RsaKeyParameters)keyPair_s.Public;
            Sv = (RsaKeyParameters)keyPair_s.Private;
        }

        public static Org.BouncyCastle.Math.BigInteger p;
        public static Org.BouncyCastle.Math.BigInteger q;




        static void Main(string[] args)
        {


            int n = Int32.Parse(args[0]);
            g = new Org.BouncyCastle.Math.BigInteger(2.ToString());
            p = new Org.BouncyCastle.Math.BigInteger(31.ToString());
            q = new Org.BouncyCastle.Math.BigInteger(5.ToString());

            TcpListener server = null;
            Int32 port = 13000;
            IPAddress localAddr = IPAddress.Parse("127.0.0.1");

            // TcpListener server = new TcpListener(port);
            server = new TcpListener(localAddr, port);

            // Start listening for client requests.
            server.Start();

            // Buffer for reading data


            TcpClient client = server.AcceptTcpClient();
            NetworkStream stream = client.GetStream();

            byte[] bytes;

            bytes = new byte[204800];
            stream.Read(bytes, 0, bytes.Length);

            string U = Encoding.UTF8.GetString(bytes);


            Random random = new Random();
            int c = random.Next(1, 4);

            bytes = new byte[64];
            bytes = Encoding.UTF8.GetBytes(c.ToString());
            stream.Write(bytes);

            stream.Flush();


            bytes = new byte[204800];
            stream.Read(bytes, 0, bytes.Length);

            string msg = Encoding.UTF8.GetString(bytes);

            string[] temp_split = msg.Split("|");

            int[] V = new int[n];
            int c0 = 0;
            for (int i = 0; i < n; ++i)
            {
                V[i] = Int32.Parse(temp_split[i]);
                c0 = c0 ^ V[i];
            }


            Org.BouncyCastle.Math.BigInteger[] P = new Org.BouncyCastle.Math.BigInteger[n];
            for (int i = 0; i < n; ++i)
            {
                P[i] = new Org.BouncyCastle.Math.BigInteger(temp_split[n + i]);
            }

            int r = Int32.Parse(temp_split[2 * n]);
            if (c0 == c)
            {
                Console.WriteLine("1st verification PASS");
            }
            else
            {
                Console.WriteLine("1st verification FAIL");
            }

            Org.BouncyCastle.Math.BigInteger U0 = (g.Pow(r)).Mod(p);
            for (int i = 0; i < n; ++i)
            {
                U0 = U0.Multiply((P[i].Pow(V[i])).Mod(p)).Mod(p);
            }
            Console.WriteLine(U);
            Console.WriteLine(U0);

            string U1 = U0.ToString();
            bool flag = true;
            for (int i = 0; i < U1.Length; ++i)
            {
                if (U1[i] != U[i])
                {
                    Console.WriteLine("2nd verification FAIL");
                    flag = false;
                    break;
                }
            }
            if (flag)
            {
                Console.WriteLine("2nd verification PASS");
            }
            //End time

            DateTime now = DateTime.Now;
            Console.WriteLine("Strat Second: {0}", now.Millisecond);



        }
        static void PrintByteArray(byte[] bytes)
        {
            var sb = new StringBuilder("new byte[] { ");
            foreach (var b in bytes)
            {
                sb.Append(b + ", ");
            }
            sb.Append("}");
            Console.WriteLine(sb.ToString());
        }
    }

}


/*bytes = new Byte[204800];
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
*/
//const int DefaultPrimeProbability = 30;

/*DHParametersGenerator generator = new DHParametersGenerator();
var key_variable = Encoding.ASCII.GetBytes("test");
generator.Init(256, DefaultPrimeProbability, new SecureRandom(key_variable));
DHParameters parameters = generator.GenerateParameters();

Org.BouncyCastle.Math.BigInteger g = parameters.G;*/

/*Random random = new Random();
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
//Time start
*/
