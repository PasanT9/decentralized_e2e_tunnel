using System;
using System.Text;
using Newtonsoft.Json;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace superpeer_network
{
    class Program
    {
        static Dictionary<string, IPEndPoint> peers;
        static List<IPEndPoint> superpeer_neighbours;

        static X509Certificate2 server_cert;
        static int local_port;
        static IPAddress local_ip;
        static string server_ip = "127.0.0.1";
        static int server_port = 28005;
        static int peers_count;

        public static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None || sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors)
                return true;

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

            // Do not allow this client to communicate with unauthenticated servers.
            return false;
        }

        public static void insert_peers(string[] new_peers)
        {
            for (int i = 0; i < new_peers.Length - 1; ++i)
            {
                peers[new_peers[i]] = null;
            }
            peers_count = new_peers.Length - 1;
        }

        static void Main(string[] args)
        {
            superpeer_neighbours = new List<IPEndPoint>();

            peers = new Dictionary<string, IPEndPoint>();

            Random random = new Random();
            local_port = random.Next(20000, 40000);

            server_cert = new X509Certificate2("/home/pasan/Documents/FYP_certificates/ssl-certificate.pfx", "password", X509KeyStorageFlags.PersistKeySet);
            X509Store store = new X509Store(StoreName.My);
            store.Open(OpenFlags.ReadWrite);
            store.Add(server_cert);

            local_ip = IPAddress.Parse("127.0.0.1");
            IPEndPoint ipLocalEndPoint = new IPEndPoint(local_ip, local_port);

            TcpClient client = new TcpClient(ipLocalEndPoint);
            client.Connect(server_ip, server_port);
            SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
            //sslStream.Flush();

            init_connection(sslStream);

        }

        static void init_connection(SslStream sslStream)
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

            send_message_tcp(sslStream, "HELLO");
            send_message_tcp(sslStream, (server_ip + ":" + server_port));


            string delimiter = "Y";
            string response;

            while (delimiter == "Y")
            {
                response = recieve_message_tcp(sslStream);
                string[] temp = response.Split('/');
                insert_peers(temp);
                delimiter = temp[temp.Length - 1];
            }
            Console.WriteLine("New peers");
            foreach (var pair in peers)
            {
                Console.WriteLine(pair.Key);
            }
            superpeer_neighbours.Add(new IPEndPoint(IPAddress.Parse(server_ip), server_port));

            response = recieve_message_tcp(sslStream);
            Console.WriteLine(response);

            string[] temp = response.Split(':');
            string neighbour_ip = temp[0];
            int neighbour_port = Int16.Parse(temp[1]);

            /*

            

            superpeer_neighbours.Add(new IPEndPoint(IPAddress.Parse(neighbour_ip), neighbour_port));

            for (int i = 0; i < 2; ++i)
            {
                Console.WriteLine(superpeer_neighbours[i]);
            }*/


            /*peer_address = Int16.Parse(response);
            Console.WriteLine("Recieved address: " + peer_address);*/
        }

        static void handle_connections(TcpListener server)
        {
            Console.WriteLine("Server is listening for clients to initialize a connection");
            Byte[] bytes = new Byte[256];
            string response;
            while (true)
            {
                TcpClient client = server.AcceptTcpClient();
                SslStream sslStream = new SslStream(client.GetStream(), false);
                sslStream.AuthenticateAsServer(server_cert, clientCertificateRequired: false, SslProtocols.Tls13, checkCertificateRevocation: true);

                sslStream.ReadTimeout = 20000;
                sslStream.WriteTimeout = 20000;
                // Read a message from the client.
                response = recieve_message_tcp(sslStream);
                if (String.Compare(response, "HELLO") == 0)
                {
                    Console.WriteLine(((IPEndPoint)client.Client.RemoteEndPoint) + " is requesting a connection");

                    Console.WriteLine((IPEndPoint)client.Client.RemoteEndPoint);
                    /*client_map[client_count] = (IPEndPoint)client.Client.RemoteEndPoint;
                    client_map_reverse[(IPEndPoint)client.Client.RemoteEndPoint] = client_count++;

                    Console.WriteLine("address " + (client_count - 1) + " is now reserved for client " + ((IPEndPoint)client.Client.RemoteEndPoint));

                    send_message_tcp(sslStream, (client_count - 1).ToString());
                    Thread request_t = new Thread(() => handle_relay_requests(sslStream, client));
                    request_t.Start();*/
                }
                else
                {
                    Console.WriteLine("unrecognized command");
                }
            }
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
