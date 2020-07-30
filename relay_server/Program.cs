﻿using System;
using System.Text;
using Newtonsoft.Json;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Collections.Generic;  
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using dtls_client;
using System.Runtime.InteropServices;
using ProxyClient;
using PairStream;


namespace peer
{
    class Program
    {
        static string[] client_buffers;
        static Dictionary<int, IPEndPoint> client_map;
        static Dictionary<IPEndPoint, int> client_map_reverse;
        static int client_count;

        static X509Certificate2 server_cert;
        
        static void Main(string[] args)
        {
            client_buffers = new string[10];
            for(int i=0;i<10;++i)
            {
                client_buffers[i] = null;
            }

            client_map = new Dictionary<int, IPEndPoint>();
            client_map_reverse = new Dictionary<IPEndPoint, int>();
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
            Console.WriteLine("Server is listening for clients to initialize a connection");
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
                if(String.Compare(response,"HELLO") == 0){
                    Console.WriteLine(((IPEndPoint)client.Client.RemoteEndPoint)+" is requesting a connection");
                    client_map[client_count] = (IPEndPoint)client.Client.RemoteEndPoint;
                    client_map_reverse[(IPEndPoint)client.Client.RemoteEndPoint] = client_count++;

                    Console.WriteLine("address "+ (client_count-1)+" is now reserved for client " + ((IPEndPoint)client.Client.RemoteEndPoint));

                    send_message_tcp(sslStream, (client_count-1).ToString());
                    Thread request_t = new Thread(() => handle_relay_requests(sslStream,client));
                    request_t.Start();
                }
                else{
                    Console.WriteLine("unrecognized command");
                }
            }
        }

        static void handle_relay_requests(SslStream sslStream, TcpClient client)
        {
            string msg = recieve_message_tcp(sslStream);
            if(String.Compare(msg, "REQUEST") == 0){
                send_message_tcp(sslStream, "ACCEPT");
                msg = recieve_message_tcp(sslStream);
                int peer0 = client_map_reverse[((IPEndPoint)client.Client.RemoteEndPoint)];
                int peer1 = Int32.Parse(msg);
                Console.WriteLine("Peer "+ peer0 + " requesting a connection to Peer " + peer1);
                client_buffers[peer1] = peer0.ToString();
                while(client_buffers[peer0] == null);
                if(client_buffers[peer0] == "ACCEPT"){
                    send_message_tcp(sslStream, "ACCEPT");
                    client_buffers[peer0] = null;
                    client_buffers[peer1] = null;
                    sslStream.Close();
                    client.Close();
                    Thread p2p_connection_t = new Thread(() => init_relay(peer0, peer1));
                    p2p_connection_t.Start();
                }
                else if(client_buffers[peer0] == "REJECT"){
                    send_message_tcp(sslStream, "REJECT");
                }
            }
            else if(String.Compare(msg, "LISTEN") == 0){
                send_message_tcp(sslStream, "ACCEPT");
                int peer = client_map_reverse[((IPEndPoint)client.Client.RemoteEndPoint)];
                while(client_buffers[peer] == null);
                send_message_tcp(sslStream, peer.ToString());
                msg = recieve_message_tcp(sslStream);
                if(String.Compare(msg,"ACCEPT") == 0){
                    client_buffers[Int32.Parse(client_buffers[peer])] = "ACCEPT"; 
                    sslStream.Close();
                    client.Close();
                }
                else if(String.Compare(msg,"REJECT") == 0){
                    client_buffers[Int32.Parse(client_buffers[peer])] = "REJECT"; 
                }
            }
            else{
                Console.WriteLine("unrecognized command");
            }
        }

        static void init_relay(int peer0, int peer1)
        {
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
        static void send_message_udp(UdpClient client, IPEndPoint ip, String message)
        {
            byte[] data = Encoding.UTF8.GetBytes(message);
            client.Send(data, data.Length, ip);
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
