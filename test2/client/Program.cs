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

using LSAG;


namespace client
{
    class Program
    {
        //public static System.Numerics.BigInteger;

        static BigInteger gcd(BigInteger n1, BigInteger n2)
        {
            if (n2.Equals(0))
            {
                return n1;
            }
            else
            {
                return gcd(n2, BigInteger.Remainder(n1, n2));
            }
        }

        static List<BigInteger> multiGroup(BigInteger n)
        {
            List<BigInteger> group = new List<BigInteger>();
            for (BigInteger i = 0; i < n; ++i)
            {
                if (gcd(n, i) == 1)
                {
                    group.Add(i);
                }
            }
            return group;
        }

        static void Main(string[] args)
        {
            try
            {
                string server = "127.0.0.1";
                string message = "Hello!!!";
                Int32 port = 13000;
                TcpClient client = new TcpClient(server, port);
                NetworkStream stream = client.GetStream();

                byte[] bytes;
                string response;

                bytes = new byte[64];
                stream.Read(bytes, 0, bytes.Length);
                response = System.Text.Encoding.ASCII.GetString(bytes, 0, bytes.Length);
                Console.WriteLine(response);
                string N = response;


                //TcpClient client = null;

                /*BigInteger P = BigInteger.Parse("149");
                BigInteger Q = BigInteger.Parse("257");
                BigInteger N = BigInteger.Multiply(P,Q);
                Console.WriteLine(N);

                List<BigInteger> group = new List<BigInteger>(multiGroup(N));
                Console.WriteLine(group[10]);

                SHA1 sha = new SHA1CryptoServiceProvider();
                string id = "pasan96tennakoon@gmail.com";


                byte[] seed_bytes = System.Text.Encoding.UTF8.GetBytes(P.ToString() + Q.ToString() + id);
                byte [] seed = sha.ComputeHash(seed_bytes);

                StringBuilder sb = new StringBuilder();
                foreach (byte b in seed)
                    sb.Append(b.ToString("X2"));

                string seed_string = sb.ToString();

                byte[] PI_bytes = System.Text.Encoding.UTF8.GetBytes(seed_string+N.ToString());
                byte [] PI = sha.ComputeHash(PI_bytes);

                sb = new StringBuilder();
                foreach (byte b in PI)
                    sb.Append(b.ToString("X2"));

                string PI_string = sb.ToString(); 


                byte[] MAC_bytes = System.Text.Encoding.UTF8.GetBytes(PI_string+N.ToString()+seed_string);
                byte [] MAC = sha.ComputeHash(MAC_bytes);

                sb = new StringBuilder();
                foreach (byte b in PI)
                    sb.Append(b.ToString("X2"));

                string MAC_string = sb.ToString();



                string[] PIC = {PI_string, N.ToString(), seed_string, MAC_string};

                Console.WriteLine("PI:\t" + PIC[0]);
                Console.WriteLine("N:\t" + PIC[1]);
                Console.WriteLine("Seed:\t" + PIC[2]);
                Console.WriteLine("MAC:\t" + PIC[3]);
                Console.WriteLine();

                int length = 20;
                BigInteger[] S = new BigInteger[length];
                BigInteger[] V = new BigInteger[length];
                BigInteger[] J = new BigInteger[length];

                var random = new Random();
                Console.Write("S: ");
                
                for(int i=0;i<length;++i)
                {
                    J[i] = random.Next(group.Count);
                    byte[] temp_bytes = System.Text.Encoding.UTF8.GetBytes(PIC[0] + J[i].ToString());
                    byte [] temp_h = sha.ComputeHash(temp_bytes);
                    int index = 1;
                    foreach(byte b in temp_h)
                    {
                        //Console.WriteLine(b);
                        index = (index * b) % group.Count;
                    }
                    S[i] = group[index];
                    Console.Write(S[i]+" ");
                }
                Console.WriteLine();

                Console.Write("V: ");
                for(int i=0;i<length;++i)
                {
                    V[i] = BigInteger.Remainder(BigInteger.Pow(S[i], 2),N);
                    Console.Write(V[i]+" ");
                }
                Console.WriteLine();

                string msg = "";
                for(int i=0;i<length;++i)
                {
                    msg += V[i] + "|";
                }

                BigInteger a = 4;
                BigInteger Ga = BigInteger.Remainder(a,N);

                BigInteger r =group[random.Next(group.Count)];
                BigInteger X = BigInteger.Remainder(BigInteger.Multiply(r,r),N);
                Console.WriteLine("X: "+X);
                Console.WriteLine();
                
                msg += X + "|";
                msg += N;*/


                var liu2005 = new Liu2005();
                int participants = 10;
                string msg = N;


                Console.WriteLine("{0} participants", participants);
                liu2005.GroupParameters = KnownGroupParameters.RFC5114_2_1_160;

                var messageBytes = Encoding.UTF8.GetBytes(msg);

                var keys = Enumerable.Range(0, participants).Select(i => liu2005.GenerateKeyPair()).ToArray();
                var publicKeys = keys.Select(k => k[1]).ToArray();

                var signature = liu2005.GenerateSignature(messageBytes, publicKeys, keys[0][0], 0);
                string pub_keys_string = JsonConvert.SerializeObject(publicKeys);
                string liu2005_string = JsonConvert.SerializeObject(liu2005);
                string signature_string = JsonConvert.SerializeObject(signature);

                msg = msg + "/" + pub_keys_string + "/" + liu2005_string + "/" + signature_string;

                Console.WriteLine(msg);

                bytes = System.Text.Encoding.ASCII.GetBytes(msg);
                stream.Write(bytes, 0, bytes.Length);

                bytes = new Byte[256];

                // String to store the response ASCII representation.
                String responseData = String.Empty;

                stream.Read(bytes, 0, bytes.Length);
                responseData = System.Text.Encoding.ASCII.GetString(bytes);
                Console.WriteLine("Received: {0}", responseData);

                /*string[] temp_split = responseData.Split('|');
                int[] B = new int[length];
                for (int i = 0; i < length; ++i)
                {
                    B[i] = Int32.Parse(temp_split[i]);
                }

                BigInteger Y1 = 1;
                for (int i = 0; i < S.Length; ++i)
                {
                    Y1 = BigInteger.Remainder(Y1, N);
                    Y1 = BigInteger.Multiply(Y1, BigInteger.Remainder(BigInteger.Pow(S[i], B[i]), N));
                    //Y1 *= (Math.Pow(S[i], (B[i]))%N);
                    //Y2 *= Math.Pow(S[i], (1-B[i]))%N;
                }
                Y1 = BigInteger.Remainder(BigInteger.Multiply(r, Y1), N);
                //Y1 = (r*Y1)%N;
                msg = Y1.ToString();
                //Y2 = (r*Y2);
                data = System.Text.Encoding.ASCII.GetBytes(msg);
                stream.Write(data, 0, data.Length);

                data = new Byte[256];
                stream.Read(data, 0, data.Length);
                responseData = System.Text.Encoding.ASCII.GetString(data, 0, bytes);
                Console.WriteLine("Received: {0}", responseData);*/





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

            Console.WriteLine("\n Press Enter to continue...");
            Console.Read();
        }
    }
}
