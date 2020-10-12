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

namespace main_server
{
    class Program
    {
        static string[] client_buffers;
        static Dictionary<int, IPEndPoint> client_map;
        static Dictionary<IPEndPoint, int> client_map_reverse;
        static Dictionary<int, IPEndPoint> relay_servers;

        static PublicKeyCoordinates[] client_pub_keys;
        static int client_count;
        static int server_count;
        static X509Certificate2 server_cert;

        static void Main(string[] args)
        {
            relay_servers = new Dictionary<int, IPEndPoint>();
            server_count = 0;
            relay_servers[server_count++] = IPEndPoint.Parse("127.0.0.1:27005");

            client_pub_keys = new PublicKeyCoordinates[10];
            client_buffers = new string[10];
            for (int i = 0; i < 10; ++i)
            {
                client_buffers[i] = null;
                client_pub_keys[i] = null;
            }

            client_map = new Dictionary<int, IPEndPoint>();
            client_map_reverse = new Dictionary<IPEndPoint, int>();
            client_count = 0;

            server_cert = new X509Certificate2("/home/pasan/Documents/FYP_certificates/ssl-certificate.pfx", "password", X509KeyStorageFlags.PersistKeySet);
            X509Store store = new X509Store(StoreName.My);
            store.Open(OpenFlags.ReadWrite);
            store.Add(server_cert);

            int port = 28005;
            IPAddress localAddr = IPAddress.Parse("127.0.0.1");
            TcpListener server = new TcpListener(localAddr, port);

            server.Start();
            Console.WriteLine("Server is starting");
            handle_connections(server);
            //handle_relay_requests();

        }

        public static void con_relay_listner(UdpClient client, IPEndPoint ip, int peer)
        {
            while (true)
            {
                string response = Encoding.UTF8.GetString(client.Receive(ref ip));
                Console.WriteLine("client" + peer + ": " + response);
                client_buffers[peer] = response;
            }

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
                    client_map[client_count] = (IPEndPoint)client.Client.RemoteEndPoint;
                    client_map_reverse[(IPEndPoint)client.Client.RemoteEndPoint] = client_count++;

                    Console.WriteLine("address " + (client_count - 1) + " is now reserved for client " + ((IPEndPoint)client.Client.RemoteEndPoint));

                    send_message_tcp(sslStream, (client_count - 1).ToString());
                    Thread request_t = new Thread(() => handle_relay_requests(sslStream, client));
                    request_t.Start();
                }
                else
                {
                    Console.WriteLine("unrecognized command");
                }
            }
        }

        static void handle_relay_requests(SslStream sslStream, TcpClient client)
        {
            string msg = recieve_message_tcp(sslStream);
            if (String.Compare(msg, "REQUEST") == 0)
            {
                send_message_tcp(sslStream, "ACCEPT");
                msg = recieve_message_tcp(sslStream);
                int peer0 = client_map_reverse[((IPEndPoint)client.Client.RemoteEndPoint)];
                int peer1 = Int32.Parse(msg);
                Console.WriteLine("Peer " + peer0 + " requesting a connection to Peer " + peer1);
                client_buffers[peer1] = peer0.ToString();

                while (client_buffers[peer0] == null) ;
                send_message_tcp(sslStream, "ACCEPT");
                int server_no = Int16.Parse(client_buffers[peer0]);
                IPEndPoint relay_server = relay_servers[server_no];
                Console.WriteLine(relay_servers.ToString() + " assigned to " + peer0 + " and " + peer1);
                send_message_tcp(sslStream, relay_server.ToString());

                while (client_pub_keys[peer0] == null) ;

                byte[] data = Encoding.UTF8.GetBytes(client_pub_keys[peer0].ToString());
                sslStream.Write(data);
                sslStream.Flush();

                client_pub_keys[peer0] = null;

                byte[] bytes = new Byte[256];
                sslStream.Read(bytes, 0, bytes.Length);
                string message = Encoding.UTF8.GetString(bytes);
                PublicKeyCoordinates destPubKey = JsonConvert.DeserializeObject<PublicKeyCoordinates>(message);
                //Console.WriteLine(destPubKey.ToString());
                client_pub_keys[peer1] = destPubKey;

                sslStream.Close();
                client.Close();
            }
            else if (String.Compare(msg, "LISTEN") == 0)
            {
                send_message_tcp(sslStream, "ACCEPT");
                int peer = client_map_reverse[((IPEndPoint)client.Client.RemoteEndPoint)];
                while (client_buffers[peer] == null) ;
                send_message_tcp(sslStream, client_buffers[peer]);
                msg = recieve_message_tcp(sslStream);
                if (String.Compare(msg, "ACCEPT") == 0)
                {
                    Random rnd = new Random();
                    int server_no = rnd.Next(0, server_count - 1);

                    client_buffers[Int32.Parse(client_buffers[peer])] = server_no.ToString();
                    IPEndPoint relay_server = relay_servers[server_no];
                    send_message_tcp(sslStream, relay_server.ToString());

                    byte[] bytes = new byte[256];
                    sslStream.Read(bytes, 0, bytes.Length);
                    string message = Encoding.UTF8.GetString(bytes);
                    PublicKeyCoordinates destPubKey = JsonConvert.DeserializeObject<PublicKeyCoordinates>(message);
                    client_pub_keys[Int32.Parse(client_buffers[peer])] = destPubKey;


                    //client_pub_keys[Int32.Parse(client_buffers[peer])] = msg;
                    while (client_pub_keys[peer] == null) ;

                    byte[] data = Encoding.UTF8.GetBytes(client_pub_keys[peer].ToString());
                    sslStream.Write(data);
                    sslStream.Flush();



                    sslStream.Close();
                    client.Close();
                }
                else if (String.Compare(msg, "REJECT") == 0)
                {
                    client_buffers[Int32.Parse(client_buffers[peer])] = "REJECT";
                    sslStream.Close();
                    client.Close();
                }
            }
            else
            {
                Console.WriteLine("unrecognized command");
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
