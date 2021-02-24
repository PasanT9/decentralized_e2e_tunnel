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

using LSAG;

namespace server
{
    class Program
    {

        static void Main(string[] args)
        {


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


            /*int length = 20;

            // Get a stream object for reading and writing
            NetworkStream stream = client.GetStream();

            stream.Read(bytes, 0, bytes.Length);
            data = System.Text.Encoding.ASCII.GetString(bytes, 0, bytes.Length);
            Console.WriteLine("Received: {0}", data);
            Console.WriteLine();

            string[] temp_split = data.Split('|', '/');
            BigInteger[] V = new BigInteger[length];
            for (int i = 0; i < length; ++i)
            {
                V[i] = BigInteger.Parse(temp_split[i]);
            }
            BigInteger X = BigInteger.Parse(temp_split[length]);
            BigInteger N = BigInteger.Parse(temp_split[length + 1]);

            Console.WriteLine();*/
            bytes = new byte[2048];
            stream.Read(bytes, 0, bytes.Length);
            response = System.Text.Encoding.ASCII.GetString(bytes, 0, bytes.Length);
            Console.WriteLine("Received: {0}", response);

            string[] temp_split = response.Split('/');
            string message = temp_split[0];
            var messageBytes = Encoding.UTF8.GetBytes(message);

            var pub_keys = JsonConvert.DeserializeObject<BigInteger[]>(temp_split[1]);
            var liu2005 = JsonConvert.DeserializeObject<Liu2005>(temp_split[2]);
            var signature = JsonConvert.DeserializeObject<LSAG.Liu2005.Signature>(temp_split[3]);

            var cache = new MultiExponentiation(liu2005.GroupParameters.Prime, pub_keys);

            bool res = liu2005.VerifySignature(messageBytes, signature, cache);
            if (res)
            {
                Console.WriteLine("PASS");
            }
            else
            {
                Console.WriteLine("FAIL");
            }


            /* int[] B = new int[length];
             var random = new Random();
             Console.Write("B: ");
             for (int i = 0; i < length; ++i)
             {
                 B[i] = random.Next(0, 2);
                 Console.Write(B[i] + " ");
             }
             Console.WriteLine();
             Console.WriteLine();

             string msg = "";
             for (int i = 0; i < length - 1; ++i)
             {
                 msg += B[i] + "|";
             }
             msg += B[19];

             bytes = System.Text.Encoding.ASCII.GetBytes(msg);

             stream.Write(bytes, 0, bytes.Length);

             bytes = new Byte[256];
             stream.Read(bytes, 0, bytes.Length);
             data = System.Text.Encoding.ASCII.GetString(bytes, 0, bytes.Length);
             Console.WriteLine("Received: {0}", data);
             Console.WriteLine();

             BigInteger Y1 = BigInteger.Parse(data);

             BigInteger X1 = 1;
             for (int i = 0; i < length; ++i)
             {
                 X1 = BigInteger.Remainder(X1, N);
                 X1 = BigInteger.Multiply(BigInteger.Remainder(BigInteger.Pow(V[i], B[i]), N), X1);
                 //X1 *= Math.Pow(V[i],B[i])%N;
                 //X2 *= Math.Pow(V[i], (1-B[i]));
             }
             //X1 = Y1*Y1*X1%N;
             X1 = BigInteger.Remainder(BigInteger.Multiply(X, X1), N);
             //X1 = (X*X1)%N;
             Y1 = BigInteger.Remainder(BigInteger.Multiply(Y1, Y1), N);
             //Y1 = (Y1*Y1)%N;
             if (X1.Equals(Y1))
             {
                 bytes = System.Text.Encoding.ASCII.GetBytes("ACCEPT");
                 stream.Write(bytes, 0, bytes.Length);
             }
             else
             {
                 bytes = System.Text.Encoding.ASCII.GetBytes("REJECT");
                 stream.Write(bytes, 0, bytes.Length);
             }*/

        }
    }
}