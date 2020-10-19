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

namespace superpeer_peer
{

    class Program
    {
        static string server_ip = "127.0.0.1";
        static int server_port;

        static string local_ip = "127.0.0.1";
        static int local_port;

        static PublicKeyCoordinates pubKey;

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

            Console.Write("server port: ");
            server_port = Int32.Parse(Console.ReadLine());

            find_superpeer();


        }

        static void init_connection(SslStream sslStream)
        {

            //Authenticate certificate
            authenticate_server(sslStream);

            send_message_tcp(sslStream, "HELLO_P");
            string response = recieve_message_tcp(sslStream);
            Console.WriteLine(response);

            ECDiffieHellmanOpenSsl peer = new ECDiffieHellmanOpenSsl();
            ECParameters ep = peer.ExportParameters(false);

            pubKey = new PublicKeyCoordinates(ep.Q.X, ep.Q.Y);

            //Console.WriteLine(pubKey.ToString());

            send_message_tcp(sslStream, pubKey.ToString());

        }

        static void find_superpeer()
        {
            IPAddress ipAddress = IPAddress.Parse("127.0.0.1");
            IPEndPoint ipLocalEndPoint = new IPEndPoint(ipAddress, local_port);

            //Connect to server
            TcpClient client = new TcpClient(ipLocalEndPoint);
            client.Connect(server_ip, server_port);
            SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
            authenticate_server(sslStream);

            send_message_tcp(sslStream, "FIND_P");
            send_message_tcp(sslStream, pubKey.ToString());

            string response = recieve_message_tcp(sslStream);
            Console.WriteLine(response);
            /*
            string[] temp_split = response.Split(':');
            string op_code = temp_split[0];
            string data0 = (temp_split.Length == 3) ? temp_split[1] : "";
            string data1 = (temp_split.Length == 3) ? temp_split[2] : "";

            if (String.Compare(op_code, "FOUND") == 0)
            {
                Console.Write("Enter destination: ");
                string dest_peer = Console.ReadLine();

                send_message_tcp(sslStream, "FIND_P");
                send_message_tcp(sslStream, dest_peer);

                response = recieve_message_tcp(sslStream);

                temp_split = response.Split(':');
                op_code = temp_split[0];
                data0 = (temp_split.Length == 3) ? temp_split[1] : "";
                data1 = (temp_split.Length == 3) ? temp_split[2] : "";


                if (String.Compare(op_code, "FOUND") == 0)
                {
                    Console.WriteLine("Destination peer exists");
                }
                else if (String.Compare(op_code, "NOTFOUND") == 0)
                {
                    Console.WriteLine("Destination peer does not exits");
                }
            }
            else if (String.Compare(op_code, "NOTFOUND") == 0)
            {
                Console.WriteLine("User is not registered");
            }*/


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
    }

}
