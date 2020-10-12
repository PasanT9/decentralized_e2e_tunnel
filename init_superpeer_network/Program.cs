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
        static int peers_count;
        public static string random_string()
        {
            string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            char[] rand_char_array = new char[32];
            Random random = new Random();
            for (int i = 0; i < rand_char_array.Length; ++i)
            {
                rand_char_array[i] = chars[random.Next(chars.Length)];
            }
            string rand_string = new String(rand_char_array);
            return rand_string;
        }

        public static void insert_peers()
        {
            for (int i = 0; i < 20; ++i)
            {
                string peer = random_string();
                peers[peer] = null;
            }
            peers_count = 20;
        }

        static void Main(string[] args)
        {
            superpeer_neighbours = new List<IPEndPoint>();

            peers = new Dictionary<string, IPEndPoint>();

            server_cert = new X509Certificate2("/home/pasan/Documents/FYP_certificates/ssl-certificate.pfx", "password", X509KeyStorageFlags.PersistKeySet);
            X509Store store = new X509Store(StoreName.My);
            store.Open(OpenFlags.ReadWrite);
            store.Add(server_cert);

            local_ip = IPAddress.Parse("127.0.0.1");

            TcpListener server;
            try
            {
                server = new TcpListener(local_ip, 27005);
                local_port = 27005;
                server.Start();
                superpeer_neighbours.Add(new IPEndPoint(local_ip, 28005));
            }
            catch (Exception)
            {
                server = new TcpListener(local_ip, 28005);
                local_port = 28005;
                server.Start();
                superpeer_neighbours.Add(new IPEndPoint(local_ip, 27005));
            }

            insert_peers();

            handle_connections(server);
        }

        public static void transfer_peers(SslStream sslStream)
        {
            string reply = "";
            int limit_count = 0;
            int count = 0;
            foreach (var pair in peers)
            {
                if (count > peers_count / 3)
                {
                    break;
                }
                if (limit_count > 5)
                {
                    send_message_tcp(sslStream, reply + "Y");
                    reply = "";
                    limit_count = 0;
                }
                reply += pair.Key + "/";
                count++;
                limit_count++;
            }
            send_message_tcp(sslStream, reply + "N");
        }

        static void handle_connections(TcpListener server)
        {
            Console.WriteLine("Server is starting on port: " + local_port);
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
                    Console.WriteLine(((IPEndPoint)client.Client.RemoteEndPoint) + " is requesting to join superpeer network");

                    response = recieve_message_tcp(sslStream);

                    string myIp = local_ip.ToString() + ":" + local_port;
                    Console.WriteLine("Requesting neighbour: " + response);
                    if (myIp == response)
                    {
                        Console.WriteLine("Sending 1/3 of Peers");
                        transfer_peers(sslStream);
                        send_message_tcp(sslStream, superpeer_neighbours[0].ToString());
                        superpeer_neighbours[0] = ((IPEndPoint)client.Client.RemoteEndPoint);
                        Console.WriteLine("new neighbour: " + superpeer_neighbours[0]);

                    }






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
