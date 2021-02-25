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

        public static int a_p;
        public static Org.BouncyCastle.Math.BigInteger A_p;

        public static Org.BouncyCastle.Math.BigInteger g;

        public static Org.BouncyCastle.Math.BigInteger p;
        public static Org.BouncyCastle.Math.BigInteger q;
        static void gen_keys()
        {
            Random random = new Random();
            a_p = 2;

            A_p = g.Pow(a_p).Mod(q);
        }

        public static Org.BouncyCastle.Math.BigInteger[] req_keys(int n)
        {
            Org.BouncyCastle.Math.BigInteger[] P = new Org.BouncyCastle.Math.BigInteger[n];
            for (int i = 0; i < n; ++i)
            {
                Random random = new Random();
                int a_i = random.Next(1, 4);

                P[i] = g.Pow(a_i).Mod(q);
            }
            return P;
        }


        public static int[] gen_v(int n)
        {
            int[] V = new int[n];
            for (int i = 0; i < n; ++i)
            {
                Random random = new Random();
                V[i] = random.Next(1, 4);
            }
            return V;
        }



        static void Main(string[] args)
        {

            string server = "127.0.0.1";

            Int32 port = 13000;
            TcpClient client = new TcpClient(server, port);
            NetworkStream stream = client.GetStream();

            g = new Org.BouncyCastle.Math.BigInteger(2.ToString());
            p = new Org.BouncyCastle.Math.BigInteger(31.ToString());
            q = new Org.BouncyCastle.Math.BigInteger(5.ToString());
            int n = Int32.Parse(args[0]);
            gen_keys();

            Org.BouncyCastle.Math.BigInteger[] P = req_keys(n - 1);

            int[] V = gen_v(n - 1);
            
           

            //Start time
			DateTime now = DateTime.Now;
			Console.WriteLine("Strat Second: {0}", now.Second);
		
		
            Random random = new Random();
            int s = 4;
            //int s = 29;
            Org.BouncyCastle.Math.BigInteger U = (g.Pow(s)).Mod(p);
            for (int i = 0; i < n - 1; ++i)
            {
                U = U.Multiply((P[i].Pow(V[i])).Mod(p)).Mod(p);
            }

            byte[] bytes;

            bytes = new byte[204800];
            bytes = Encoding.UTF8.GetBytes(U.ToString());
            stream.Write(bytes);

            stream.Flush();

            bytes = new byte[64];
            stream.Read(bytes, 0, bytes.Length);

            int c = Int32.Parse(Encoding.UTF8.GetString(bytes));


            int v_p = c;
            for (int i = 0; i < n - 1; ++i)
            {
                v_p = v_p ^ V[i];
            }


            string V_str = v_p + "|";

            for (int i = 0; i < n - 1; ++i)
            {
                V_str += V[i] + "|";
            }

            string P_str = A_p.ToString() + "|";
            for (int i = 0; i < n - 1; ++i)
            {
                P_str += P[i] + "|";
            }

            Org.BouncyCastle.Math.BigInteger a_p_big = new Org.BouncyCastle.Math.BigInteger(a_p.ToString());
            Org.BouncyCastle.Math.BigInteger v_p_big = new Org.BouncyCastle.Math.BigInteger(v_p.ToString());

            Org.BouncyCastle.Math.BigInteger s_big = new Org.BouncyCastle.Math.BigInteger(s.ToString());

            Org.BouncyCastle.Math.BigInteger r_big = (s_big.Add((a_p_big.Multiply(v_p_big)).Negate())).Mod(q);
            //int r = (s - ((a_p * v_p) % 31));
            //int r = Int32.Parse(r_big.ToString());

            string r_str = r_big.ToString();

            string msg = V_str + P_str + r_str;

            bytes = new byte[204800];
            bytes = Encoding.UTF8.GetBytes(msg);
            stream.Write(bytes);

            stream.Flush(); 
            
         

        }
    }
}
 
