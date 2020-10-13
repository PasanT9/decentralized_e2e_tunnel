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

        static string neighbour_ip;
        static int neighbour_port;

        static TcpListener server;

        static IPEndPoint ipLocalEndPoint;

        static bool exit;

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
                ++peers_count;
            }
        }

        public static void redistribute_peers()
        {
            server.Server.Disconnect(true);
            server.Server.Close();

            TcpClient client = new TcpClient(ipLocalEndPoint);

            string neighbour_r = superpeer_neighbours[0].ToString();
            //superpeer_neighbours.RemoveAt(0);

            string[] temp_split = neighbour_r.Split(':');
            string neighbour_r_ip = temp_split[0];
            int neighbour_r_port = Int16.Parse(temp_split[1]);

            client.Connect(neighbour_r_ip, neighbour_r_port);

            SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);

            //sslStream.Flush();
            end_connection(sslStream);

            sslStream.Close();
            client.Close();
            superpeer_neighbours.Reverse();

            client = new TcpClient(ipLocalEndPoint);

            string neighbour_l = superpeer_neighbours[0].ToString();
            //superpeer_neighbours.RemoveAt(0);

            temp_split = neighbour_l.Split(':');
            string neighbour_l_ip = temp_split[0];
            int neighbour_l_port = Int16.Parse(temp_split[1]);

            client.Connect(neighbour_l_ip, neighbour_l_port);

            sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);

            //sslStream.Flush();
            end_connection(sslStream);

            sslStream.Close();
            client.Close();

            //client.Close();

            System.Environment.Exit(1);

        }
        static void end_connection(SslStream sslStream)
        {
            authenticate_client(sslStream);

            send_message_tcp(sslStream, "END");
            if (exit)
            {
                transfer_peers(sslStream, 1);
            }
            else
            {
                transfer_peers(sslStream, 2);
            }


            Console.WriteLine("My peers");
            foreach (var pair in peers)
            {
                Console.WriteLine(pair.Key);
            }
            string neighbour = superpeer_neighbours[1].ToString();
            //superpeer_neighbours.RemoveAt(0);

            send_message_tcp(sslStream, (neighbour));

            string response = recieve_message_tcp(sslStream);
            Console.WriteLine(response);
            exit = true;


            /*send_message_tcp(sslStream, (server_ip + ":" + server_port));


            string delimiter = "Y";
            string response;
            string[] temp_split;
            while (delimiter == "Y")
            {
                response = recieve_message_tcp(sslStream);
                temp_split = response.Split('/');
                insert_peers(temp_split);
                delimiter = temp_split[temp_split.Length - 1];
            }
            Console.WriteLine("My peers");
            foreach (var pair in peers)
            {
                Console.WriteLine(pair.Key);
            }

            response = recieve_message_tcp(sslStream);
            Console.WriteLine(response);

            if (response != "SUCCESS")
            {
                temp_split = response.Split(':');
                neighbour_ip = temp_split[0];
                neighbour_port = Int16.Parse(temp_split[1]);
            }



            Console.WriteLine("My neighbours: ");
            for (int i = 0; i < superpeer_neighbours.Count; ++i)
            {
                Console.WriteLine(superpeer_neighbours[i]);
            }*/

        }



        //Trap ctrl+c to distribute peers among neighbour upon exit
        private static void On_exit(object sender, ConsoleCancelEventArgs e)
        {
            e.Cancel = true;
            redistribute_peers();

        }


        static void Main(string[] args)
        {
            //To handle on exit function to distribute peers upon exit
            Console.CancelKeyPress += On_exit;
            peers_count = 0;
            exit = false;

            //Initiate database
            superpeer_neighbours = new List<IPEndPoint>();
            peers = new Dictionary<string, IPEndPoint>();

            //Select a random port number
            Random random = new Random();
            local_port = random.Next(20000, 40000);


            //Add ceritificate to the store
            server_cert = new X509Certificate2("/home/pasan/Documents/FYP_certificates/ssl-certificate.pfx", "password", X509KeyStorageFlags.PersistKeySet);
            X509Store store = new X509Store(StoreName.My);
            store.Open(OpenFlags.ReadWrite);
            store.Add(server_cert);

            //Create the local end point(ip+port)
            local_ip = IPAddress.Parse("127.0.0.1");
            ipLocalEndPoint = new IPEndPoint(local_ip, local_port);

            //Initiate connection with neighbour (Get 1/3 of neighbours peers)
            TcpClient client = new TcpClient(ipLocalEndPoint);
            client.Connect(server_ip, server_port);
            superpeer_neighbours.Add(new IPEndPoint(IPAddress.Parse(server_ip), server_port));
            SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
            //sslStream.Flush();
            init_connection(sslStream);
            sslStream.Close();
            client.Close();

            //Initiate connection with other neighbour (Get 1/3 of neighbour peers)
            client = new TcpClient(ipLocalEndPoint);
            client.Connect(neighbour_ip, neighbour_port);
            superpeer_neighbours.Add(new IPEndPoint(IPAddress.Parse(neighbour_ip), neighbour_port));
            sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
            init_connection(sslStream);
            sslStream.Close();
            client.Close();

            //Server start listening to requests
            local_ip = IPAddress.Parse("127.0.0.1");
            server = new TcpListener(local_ip, local_port);
            server.Start();
            handle_connections();


        }

        static void authenticate_client(SslStream sslStream)
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

        static void init_connection(SslStream sslStream)
        {
            authenticate_client(sslStream);

            send_message_tcp(sslStream, "HELLO");
            send_message_tcp(sslStream, (server_ip + ":" + server_port));


            string delimiter = "Y";
            string response;
            string[] temp_split;
            while (delimiter == "Y")
            {
                response = recieve_message_tcp(sslStream);
                temp_split = response.Split('/');
                insert_peers(temp_split);
                delimiter = temp_split[temp_split.Length - 1];
            }
            Console.WriteLine("My peers");
            foreach (var pair in peers)
            {
                Console.WriteLine(pair.Key);
            }

            response = recieve_message_tcp(sslStream);
            Console.WriteLine(response);

            if (response != "SUCCESS")
            {
                temp_split = response.Split(':');
                neighbour_ip = temp_split[0];
                neighbour_port = Int16.Parse(temp_split[1]);
            }



            Console.WriteLine("My neighbours: ");
            for (int i = 0; i < superpeer_neighbours.Count; ++i)
            {
                Console.WriteLine(superpeer_neighbours[i]);
            }

        }

        public static void transfer_peers(SslStream sslStream, int divident)
        {
            string reply = "";
            int limit_count = 0;
            int count = 0;

            foreach (var pair in peers)
            {
                if (count >= peers_count / divident)
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
                peers.Remove(pair.Key);
                count++;
                limit_count++;
            }
            send_message_tcp(sslStream, reply + "N");
        }


        static void handle_connections()
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
                    Console.WriteLine("Sending 1/3 of Peers");
                    transfer_peers(sslStream, 3);

                    if (myIp == response)
                    {
                        send_message_tcp(sslStream, superpeer_neighbours[0].ToString());
                        superpeer_neighbours[0] = ((IPEndPoint)client.Client.RemoteEndPoint);
                    }
                    else
                    {
                        string[] temp_split = response.Split(':');
                        string neighbour_ip = temp_split[0];
                        int neighbour_port = Int16.Parse(temp_split[1]);
                        IPEndPoint old_neighbour = new IPEndPoint(IPAddress.Parse(neighbour_ip), neighbour_port);
                        superpeer_neighbours.Remove(old_neighbour);
                        superpeer_neighbours.Add(((IPEndPoint)client.Client.RemoteEndPoint));
                        send_message_tcp(sslStream, "SUCCESS");
                    }


                    Console.WriteLine("My neighbours: ");
                    for (int i = 0; i < superpeer_neighbours.Count; ++i)
                    {
                        Console.WriteLine(superpeer_neighbours[i]);
                    }

                    Console.WriteLine("My peers");
                    foreach (var pair in peers)
                    {
                        Console.WriteLine(pair.Key);
                    }
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