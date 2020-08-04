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
using dtls_client;


namespace relay_server
{
    class Program
    {
        static string[] client_buffers;
        static Dictionary<int, IPEndPoint> client_map;
        static int client_count;

        static List<string>  pending_connections;

        static X509Certificate2 server_cert;
        
        static void Main(string[] args)
        {
            client_buffers = new string[10];
            for(int i=0;i<10;++i)
            {
                client_buffers[i] = null;
            }
            pending_connections = new List<string>();

            client_map = new Dictionary<int, IPEndPoint>();
            client_count=0;

            server_cert = new X509Certificate2("/home/pasan/Documents/FYP_certificates/ssl-certificate.pfx", "password", X509KeyStorageFlags.PersistKeySet);
            X509Store store = new X509Store(StoreName.My);
            store.Open(OpenFlags.ReadWrite);
            store.Add(server_cert);

            int port = 27005;
            IPAddress localAddr = IPAddress.Parse("127.0.0.1");
            TcpListener server = new TcpListener(localAddr, port);

            server.Start();
            Console.WriteLine("Server is starting");
            handle_connections(server);
            //handle_relay_requests();

        }

        public static void con_relay_listner(UdpClient client, IPEndPoint ip, int peer)
        {
            while(true)
            {
                string response = Encoding.UTF8.GetString(client.Receive(ref ip));
                Console.WriteLine("client"+peer+": "+ response);
                client_buffers[peer] = response;
            }

        }

        static void handle_connections(TcpListener server)
        {
            Console.WriteLine("relay server is listening for clients to initialize a connection");
            Byte[] bytes = new Byte[256];
            string response;
            while(true)
            {
                TcpClient client = server.AcceptTcpClient();
                SslStream sslStream = new SslStream(client.GetStream(), false);
                sslStream.AuthenticateAsServer(server_cert, clientCertificateRequired: false,SslProtocols.Tls13, checkCertificateRevocation: true);

                sslStream.ReadTimeout = 20000;
                sslStream.WriteTimeout = 20000;
                // Read a message from the client.
                response = recieve_message_tcp(sslStream);
                Console.WriteLine(response);
                string[] temp = response.Split(":");
                client_map[Int16.Parse(temp[0])] = (IPEndPoint)client.Client.RemoteEndPoint;
                if(pending_connections.Contains(response)){
                    init_relay(Int16.Parse(temp[0]), Int16.Parse(temp[1]));
                }
                else{
                    string req_connection = temp[1] + ":" + temp[0];
                    pending_connections.Add(req_connection);
                    Console.WriteLine("Connection added");
                }
                    
            }
        }


        static void init_relay(int peer0, int peer1)
        {
            Console.WriteLine("Creating connection");
            string[] socket_peer0 = client_map[peer0].ToString().Split(':');
            string[] socket_peer1 = client_map[peer1].ToString().Split(':');

            
			DTLSClient dtls_client0 = new DTLSClient(socket_peer0[0], socket_peer0[1], new byte[] {0xBA,0xA0});
            DTLSClient dtls_client1 = new DTLSClient(socket_peer1[0], socket_peer1[1], new byte[] {0xBA,0xA0});
            
			dtls_client0.Start();
            dtls_client1.Start();

			new Thread(() => dtls_client0.GetStream().CopyTo(dtls_client1.GetStream(), 16)).Start();
            new Thread(() => dtls_client1.GetStream().CopyTo(dtls_client0.GetStream(), 16)).Start();

			dtls_client0.WaitForExit();
            dtls_client1.WaitForExit();

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
