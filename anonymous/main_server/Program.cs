using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Numerics;

namespace main_server
{
    class Program
    {

        static void Main(string[] args)
        {
            TcpListener server=null;
            /*try
            {*/
            // Set the TcpListener on port 13000.
            Int32 port = 13000;
            IPAddress localAddr = IPAddress.Parse("127.0.0.1");

            // TcpListener server = new TcpListener(port);
            server = new TcpListener(localAddr, port);

            // Start listening for client requests.
            server.Start();

            // Buffer for reading data
            Byte[] bytes = new Byte[256];
            String data = null;

            TcpClient client = server.AcceptTcpClient();
            Console.WriteLine("Connected!");
            int length = 20;

            // Get a stream object for reading and writing
            NetworkStream stream = client.GetStream();

            stream.Read(bytes, 0, bytes.Length);
            data = System.Text.Encoding.ASCII.GetString(bytes, 0, bytes.Length);
            Console.WriteLine("Received: {0}", data);
            Console.WriteLine();

            string[] temp_split = data.Split('|');
            double[] V = new double[length]; 
            for(int i=0;i<length;++i)
            {
                V[i] = Int32.Parse(temp_split[i]);
            }
            double X = Int32.Parse(temp_split[length]);
            double N = Int32.Parse(temp_split[length+1]);

            Console.WriteLine();


            int[] B = new int[length];
            var random = new Random();
            Console.Write("B: ");
            for(int i=0;i<length;++i)
            {
                B[i] = random.Next(0, 2);
                Console.Write(B[i]+" ");
            }
            Console.WriteLine();
            Console.WriteLine();

            string msg = "";
            for(int i=0;i<length-1;++i)
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

            double Y1 = Int32.Parse(data);

            double X1=1;
            for(int i=0;i<length;++i)
            {
                X1 = X1%N;
                X1 *= Math.Pow(V[i],B[i])%N;
                //X2 *= Math.Pow(V[i], (1-B[i]));
            }
            //X1 = Y1*Y1*X1%N;
            X1 = (X*X1)%N;
            Y1 = (Y1*Y1)%N;
            if(X1 == Y1)
            {
                bytes = System.Text.Encoding.ASCII.GetBytes("ACCEPT");
                stream.Write(bytes, 0, bytes.Length);
            }
            else
            {
                bytes = System.Text.Encoding.ASCII.GetBytes("REJECT");
                stream.Write(bytes, 0, bytes.Length);
            }







            //Send to Client
            /*SHA1 sha = new SHA1CryptoServiceProvider();
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
            Console.WriteLine();*/
            
            
            // Enter the listening loop.
            /*while(true)
            {*/
                /*Console.Write("Waiting for a connection... ");

                // Perform a blocking call to accept requests.
                // You could also use server.AcceptSocket() here.


                int i;

                byte[] msg = System.Text.Encoding.ASCII.GetBytes("010");

                // Send back a response.
                stream.Write(msg, 0, msg.Length);
                Console.WriteLine("Sent: {0}", data);




                // Loop to receive all the data sent by the client.*/
                /*while((i = stream.Read(bytes, 0, bytes.Length))!=0)
                {
                    // Translate data bytes to a ASCII string.
                    data = System.Text.Encoding.ASCII.GetString(bytes, 0, i);
                    Console.WriteLine("Received: {0}", data);

                    // Process the data sent by the client.
                    data = data.ToUpper();

                    byte[] msg = System.Text.Encoding.ASCII.GetBytes(data);

                    // Send back a response.
                    stream.Write(msg, 0, msg.Length);
                    Console.WriteLine("Sent: {0}", data);
                }*/

                // Shutdown and end connection
                //client.Close();
            //}
            /*}
            catch(SocketException e)
            {
                Console.WriteLine("SocketException: {0}", e);
            }
            finally
            {
            // Stop listening for new clients.
                server.Stop();
            }*/

            /*Console.WriteLine("\nHit enter to continue...");
            Console.Read();*/
        }
    }
}
/*
            //Send to Client
            SHA1 sha = new SHA1CryptoServiceProvider();
            string id = "pasan96tennakoon@gmail.com";

            int P = 7;
            int Q = 11;
            int N = P*Q;

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


            //Client
            double[] S = {9, 43, 47, 53, 59, 3, 67, 71, 73, 11, 83, 89, 97};
            double[] V = new double[S.Length];

            for(int i=0;i<S.Length;++i)
            {
                V[i] = Math.Pow(S[i],-2)%N;
            }

            int a = 36;
            int Ga = a%P;

            int r = 63;
            int X = (r*r);
            Console.WriteLine("Ga: "+Ga+ "\nX: "+X);

            //Server
            int[] B = {0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0};

            //Client
            double Y1=1;
            double Y2=1;
            for(int i=0;i<S.Length;++i)
            {
                Y1 *= Math.Pow(S[i], (B[i]));
                Y2 *= Math.Pow(S[i], (1-B[i]));
            }
            Y1 = (r*Y1);
            Y2 = (r*Y2);
            Console.WriteLine("Y1: " + Y1 + "\nY2: " + Y2);


            //Server
            double X1=1;
            double X2=1;
            for(int i=0;i<S.Length;++i)
            {
                X1 *= Math.Pow(V[i],B[i]);
                X2 *= Math.Pow(V[i], (1-B[i]));
            }
            X1 = Y1*Y1*X1;
            X2 = Y2*Y2*X2;
            Console.WriteLine("X1: " + X1 + "\nX2: " + X2);*/





/*int P1 = 3;
            int P2 = 5;
            int N = P1*P2;
            Console.WriteLine("N: " + N);

            double[] Zn = {1, 2, 4, 7, 8, 11, 13, 14};


            double[] V = { 4, 6, 9, 10};
            double[] S = new double[V.Length];

            for(int i=0;i<V.Length;++i)
            {
                S[i] = Math.Sqrt(V[i]);
            }
            int c = 67;
            int X = (c*c);
            Console.WriteLine("c: "+c+ "\nX: "+X);

            //Server
            int[] U = {1, 0, 1, 0};
            int[] E = {0, 1, 1, 0};

            //Client
            double Y=1;
            double Y2=1;
            for(int i=0;i<S.Length;++i)
            {
                Y *= Math.Pow(S[i], (E[i]+U[i]));
                Y2 *= Math.Pow(V[i], (E[i]+U[i]));
            }
            Y = (c*Y);
            Y2 = (X*Y2);
            Console.WriteLine("Y^2: " + (Y*Y) + "\nY2: " + Y2);*/