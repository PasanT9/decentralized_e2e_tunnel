using System;
using System.Text;
using System.Net;
using Newtonsoft.Json;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Threading;
using System.Numerics;
#if !NETSTANDARD2_0
using System.Buffers;
#endif
using System.Runtime.InteropServices;

using TCP;
using dtls_server;
using dtls_client;
using PairStream;
using Cryptography;

namespace superpeer_peer
{

    class Program
    {
        static string server_ip = "127.0.0.1";
        static int server_port;

        static string local_ip = "127.0.0.1";
        static int local_port;

        static PublicKeyCoordinates pubKey;

        //static Aes myAes;
        static string dest_ip;
        static int dest_port;

        public static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None || sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors)
                return true;

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

            // Do not allow this client to communicate with unauthenticated servers.
            return false;
        }



        static void authenticate_server(SslStream sslStream)
        {
            try
            {
                sslStream.AuthenticateAsClient("test", null, SslProtocols.Tls13, true);
            }
            catch (AuthenticationException e)
            {
                Console.WriteLine("Exception: {0}", e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }
                Console.WriteLine("Authentication failed - closing the connection.");
                sslStream.Close();
                return;
            }
        }

        static void Main(string[] args)
        {

            //Get user input for server port
            Console.Write("Server port: ");
            server_port = Int32.Parse(Console.ReadLine());

            //Select a random port as local port
            Random random = new Random();
            local_port = random.Next(20000, 40000);

            //Create local endpoint for connection
            IPAddress ipAddress = IPAddress.Parse("127.0.0.1");
            IPEndPoint ipLocalEndPoint = new IPEndPoint(ipAddress, local_port);

            //Connect to server
            TcpClient client = new TcpClient(ipLocalEndPoint);
            client.Connect(server_ip, server_port);
            SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);


            init_connection(sslStream);

            sslStream.Close();
            client.Close();
            Console.Write("init connection: ");
            string input = Console.ReadLine();
            if (input == "y")
            {
                find_superpeer();
            }
            else
            {
                listen_superpeer();
            }


        }

        static void init_connection(SslStream sslStream)
        {

            //Authenticate certificate
            authenticate_server(sslStream);

            TCPCommunication.send_message_tcp(sslStream, "HELLO_P");
            string response = TCPCommunication.recieve_message_tcp(sslStream);
            Console.WriteLine(response);

            ECDiffieHellmanOpenSsl peer = new ECDiffieHellmanOpenSsl();
            ECParameters ep = peer.ExportParameters(false);

            pubKey = new PublicKeyCoordinates(ep.Q.X, ep.Q.Y);

            Console.WriteLine("My hash key: " + HashString.GetHashString(pubKey.ToString()));

            //Console.WriteLine(pubKey.ToString());

            TCPCommunication.send_message_tcp(sslStream, pubKey.ToString());

        }

        static void find_superpeer()
        {

            Console.Write("Destination: ");
            string dest_key = Console.ReadLine();
            IPAddress ipAddress = IPAddress.Parse("127.0.0.1");
            IPEndPoint ipLocalEndPoint = new IPEndPoint(ipAddress, local_port);

            //Connect to server
            TcpClient client = new TcpClient(ipLocalEndPoint);
            client.Connect(server_ip, server_port);
            SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
            authenticate_server(sslStream);

            TCPCommunication.send_message_tcp(sslStream, "FIND_P");
            //TCPCommunication.send_message_tcp(sslStream, pubKey.ToString());
            TCPCommunication.send_message_tcp(sslStream, dest_key);

            string response = TCPCommunication.recieve_message_tcp(sslStream);

            string[] temp_split = response.Split(':');
            dest_ip = temp_split[1];
            dest_port = Int32.Parse(temp_split[2]);

            Console.WriteLine($"destination peer in {dest_ip}:{dest_port}");

            TCPCommunication.send_message_tcp(sslStream, pubKey.ToString());
            response = TCPCommunication.recieve_message_tcp(sslStream);
            Console.WriteLine(response);
            sslStream.Close();
            client.Close();

            client = new TcpClient(ipLocalEndPoint);
            client.Connect(dest_ip, dest_port);
            sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
            authenticate_server(sslStream);

            req_connection(sslStream, client, dest_key);


            sslStream.Close();
            client.Close();


        }

        static void listen_superpeer()
        {
            IPAddress ipAddress = IPAddress.Parse("127.0.0.1");
            IPEndPoint ipLocalEndPoint = new IPEndPoint(ipAddress, local_port);
            TcpClient client = new TcpClient(ipLocalEndPoint);

            client.Connect(server_ip, server_port);
            SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
            authenticate_server(sslStream);

            listen_connection(sslStream, client);
            //req_connection(sslStream, client, dest_key);


            sslStream.Close();
            client.Close();
        }

        static void req_connection(SslStream sslStream, TcpClient client, string dest_key)
        {

            TCPCommunication.send_message_tcp(sslStream, "CONNECT_P");
            TCPCommunication.send_message_tcp(sslStream, dest_key);

            string response = TCPCommunication.recieve_message_tcp(sslStream);
            Console.WriteLine(response);
            sslStream.Close();

            if (String.Compare(response, "ACCEPT") == 0)
            {
                DTLSServer dtls = new DTLSServer(local_port.ToString(), new byte[] { 0xBA, 0xA0 });
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    dtls.Unbuffer = "winpty.exe";
                    dtls.Unbuffer_Args = "-Xplain -Xallow-non-tty";
                }
                else
                {
                    dtls.Unbuffer = "stdbuf";
                    dtls.Unbuffer_Args = "-i0 -o0";
                }
                dtls.Start();


                dtls.GetStream().Write(Encoding.Default.GetBytes("SUCCESS"));
                byte[] bytes;
                string message = "";
                while (String.Compare(message, "SUCCESS") != 0)
                {
                    bytes = new byte[128];
                    dtls.GetStream().Read(bytes, 0, bytes.Length);
                    message = Encoding.UTF8.GetString(bytes);
                    Console.Write(message);
                }

                Console.WriteLine();

                statpair IOStream = new statpair(new StreamReader(Console.OpenStandardInput()), new StreamWriter(Console.OpenStandardOutput()));

                new Thread(() => dtls.GetStream().CopyTo(IOStream, 16)).Start();
                new Thread(() => read_relay(dtls)).Start();

                while (true)
                {
                    string input = Console.ReadLine();
                    dtls.GetStream().Write(Encoding.Default.GetBytes(input + Environment.NewLine));
                }
                dtls.WaitForExit();
            }
            else if (String.Compare(response, "REJECT") == 0)
            {
                Console.WriteLine("Connection rejected");
            }



            /*}
            else
            {
                Console.WriteLine("Connection declined");
            }*/
        }

        static void listen_connection(SslStream sslStream, TcpClient client)
        {

            TCPCommunication.send_message_tcp(sslStream, "LISTEN_P");
            //TCPCommunication.send_message_tcp(sslStream, dest_key);

            string response = TCPCommunication.recieve_message_tcp(sslStream);
            Console.WriteLine(response);
            sslStream.Close();


            DTLSServer dtls = new DTLSServer(local_port.ToString(), new byte[] { 0xBA, 0xA0 });
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                dtls.Unbuffer = "winpty.exe";
                dtls.Unbuffer_Args = "-Xplain -Xallow-non-tty";
            }
            else
            {
                dtls.Unbuffer = "stdbuf";
                dtls.Unbuffer_Args = "-i0 -o0";
            }
            dtls.Start();


            dtls.GetStream().Write(Encoding.Default.GetBytes("SUCCESS"));
            byte[] bytes;
            string message = "";
            while (String.Compare(message, "SUCCESS") != 0)
            {
                bytes = new byte[128];
                dtls.GetStream().Read(bytes, 0, bytes.Length);
                message = Encoding.UTF8.GetString(bytes);
                Console.Write(message);
            }

            Console.WriteLine();

            statpair IOStream = new statpair(new StreamReader(Console.OpenStandardInput()), new StreamWriter(Console.OpenStandardOutput()));

            new Thread(() => dtls.GetStream().CopyTo(IOStream, 16)).Start();
            new Thread(() => read_relay(dtls)).Start();

            while (true)
            {
                string input = Console.ReadLine();
                dtls.GetStream().Write(Encoding.Default.GetBytes(input + Environment.NewLine));
            }
            dtls.WaitForExit();
        }

        static void send_message_tcp(SslStream sslStream, string message)
        {
            Request req = new Request(200, message);
            string jsonString = JsonConvert.SerializeObject(req);
            byte[] data = Encoding.UTF8.GetBytes(jsonString);
            sslStream.Write(data);
            sslStream.Flush();
        }

        static string recieve_message_tcp(SslStream sslStream)
        {
            Byte[] bytes = new Byte[256];
            sslStream.Read(bytes, 0, bytes.Length);
            string message = Encoding.UTF8.GetString(bytes);
            Request reply = JsonConvert.DeserializeObject<Request>(message);
            return reply.body;
        }

        static void read_relay(DTLSServer dtls)
        {
            byte[] bytes;
            while (true)
            {
                bytes = new byte[16];
                dtls.GetStream().Read(bytes, 0, bytes.Length);
                //string decryptedData = DecryptStringFromBytes_Aes(bytes, myAes.Key, myAes.IV);
                Console.WriteLine(bytes.ToString());
            }
        }

    }

}
