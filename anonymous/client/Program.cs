using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;


namespace client
{
    class Program
    {
                static long gcd(long n1, long n2)
        {
            if (n2 == 0)
            {
                return n1;
            }
            else
            {
                return gcd(n2, n1 % n2);
            }
        }

        static List<long> multiGroup(long n)
        {
            List<long> group = new List<long>();
            for(int i=0;i<n;++i)
            {
                if(gcd(n,i) == 1)
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
                // Create a TcpClient.
                // Note, for this client to work you need to have a TcpServer
                // connected to the same address as specified by the server, port
                // combination.
                string server = "127.0.0.1";
                string message = "Hello!!!";
                Int32 port = 13000;
                TcpClient client = new TcpClient(server, port);

                

                int P = 149;
                int Q = 257;
                int N = P*Q;
                List<long> group = new List<long>(multiGroup(N));

                SHA1 sha = new SHA1CryptoServiceProvider();
            string id = "pasan96tennakoon@gmail.com";


            byte[] seed_bytes = System.Text.Encoding.UTF8.GetBytes(P+Q+id);
            byte [] seed = sha.ComputeHash(seed_bytes);

            StringBuilder sb = new StringBuilder();
            foreach (byte b in seed)
                sb.Append(b.ToString("X2"));

            string seed_string = sb.ToString();

            byte[] PI_bytes = System.Text.Encoding.UTF8.GetBytes(seed_string+N);
            byte [] PI = sha.ComputeHash(PI_bytes);

            sb = new StringBuilder();
            foreach (byte b in PI)
                sb.Append(b.ToString("X2"));

            string PI_string = sb.ToString();

            string[] PIC = {PI_string, N.ToString(), seed_string};

            Console.WriteLine("PI:\t" + PIC[0]);
            Console.WriteLine("N:\t" + PIC[1]);
            Console.WriteLine("Seed:\t" + PIC[2]);
            Console.WriteLine();

                int length = 20;
                double[] S = new double[length];
                double[] V = new double[length];
                double[] J = new double[length];
                var random = new Random();
                Console.Write("S: ");
                
                for(int i=0;i<length;++i)
                {
                    J[i] = random.Next(group.Count);
                    byte[] temp_bytes = System.Text.Encoding.UTF8.GetBytes(PIC[0] + J[i]);
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
                    V[i] = Math.Pow(S[i], 2)%N;
                    Console.Write(V[i]+" ");
                }
                Console.WriteLine();

                string msg = "";
                for(int i=0;i<length;++i)
                {
                    msg += V[i] + "|";
                }

                int a = 4;
                int Ga = a%P;

                double r =group[random.Next(group.Count)];
                double X = (r*r)%N;
                Console.WriteLine("X: "+X);
                Console.WriteLine();
                
                msg += X + "|";
                msg += N;

                // Translate the passed message into ASCII and store it as a Byte array.
                Byte[] data = System.Text.Encoding.ASCII.GetBytes(msg);
                NetworkStream stream = client.GetStream();
                stream.Write(data, 0, data.Length);

                data = new Byte[256]; 

                // String to store the response ASCII representation.
                String responseData = String.Empty;

                Int32 bytes = stream.Read(data, 0, data.Length);
                responseData = System.Text.Encoding.ASCII.GetString(data, 0, bytes);
                Console.WriteLine("Received: {0}", responseData);

                string[] temp_split = responseData.Split('|');
                int[] B = new int[length];
                for(int i=0;i<length;++i)
                {
                    B[i] = Int32.Parse(temp_split[i]);
                }
                
                double Y1=1;
                for(int i=0;i<S.Length;++i)
                {
                    Y1 = Y1 % N;
                    Y1 *= (Math.Pow(S[i], (B[i]))%N);
                    //Y2 *= Math.Pow(S[i], (1-B[i]))%N;
                }
                Y1 = (r*Y1)%N;
                msg = Y1.ToString();
                //Y2 = (r*Y2);
                data = System.Text.Encoding.ASCII.GetBytes(msg);
                stream.Write(data, 0, data.Length);

                data = new Byte[256];
                stream.Read(data, 0, data.Length);
                responseData = System.Text.Encoding.ASCII.GetString(data, 0, bytes);
                Console.WriteLine("Received: {0}", responseData);



                

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
