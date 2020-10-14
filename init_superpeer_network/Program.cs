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
        static Dictionary<string, IPEndPoint> peers;    //Index of peers
        static List<IPEndPoint> superpeer_neighbours;   //Neighbours of the super peer network

        static X509Certificate2 server_cert;    //Server authentication certificate
        static int local_port;
        static IPAddress local_ip;
        static int peers_count; //Number of peers

        static SslStream[] neighbour_links;
        static int neighbour_count;

        static bool thread_change;
        static bool read = false;

        //Create random strings to imitate public keys
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

        //Insert a randomly created string as peers
        public static void insert_peers_random()
        {
            for (int i = 0; i < 20; ++i)
            {
                string peer = random_string();
                peers[peer] = null;
            }
            peers_count = 20;
        }

        public static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None || sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors)
                return true;

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

            // Do not allow this client to communicate with unauthenticated servers.
            return false;
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

        static void handle_neighbour(int index)
        {
            while (true)
            {
                //Console.WriteLine("index: " + index);
                if (!thread_change && index % 2 == 0)
                {
                    send_message_tcp(neighbour_links[0], "HELLO(" + index + ")");
                    string response = recieve_message_tcp(neighbour_links[0]);
                    Console.WriteLine(response);
                    if (String.Compare(response, "END") == 0)
                    {
                        neighbour_links[0].Close();
                        neighbour_links[0] = null;
                        break;
                    }
                    else if (String.Compare(response, "EXIT") == 0)
                    {
                        string delimiter = "Y";
                        string[] temp_split;
                        while (delimiter == "Y")
                        {
                            response = recieve_message_tcp(neighbour_links[0]);
                            temp_split = response.Split('/');
                            insert_peers(temp_split);
                            delimiter = temp_split[temp_split.Length - 1];
                        }
                        response = recieve_message_tcp(neighbour_links[0]);
                        neighbour_links[0].Close();
                        neighbour_links[0] = null;
                        --neighbour_count;
                        Console.WriteLine("Connect to: " + response);

                        Console.WriteLine("My peers");
                        foreach (var pair in peers)
                        {
                            Console.WriteLine(pair.Key);
                        }

                        temp_split = response.Split(':');
                        string neighbour_ip = temp_split[0];
                        int neighbour_port = Int16.Parse(temp_split[1]);
                        string init = temp_split[2];

                        if (String.Compare(init, "Y") == 0)
                        {
                            superpeer_neighbours[0] = new IPEndPoint(IPAddress.Parse(neighbour_ip), neighbour_port);
                            ++neighbour_count;
                            Console.WriteLine("Wait for connection");
                        }
                        else
                        {
                            Random random = new Random();

                            superpeer_neighbours[0] = new IPEndPoint(IPAddress.Parse(neighbour_ip), neighbour_port);
                            ++neighbour_count;
                            IPEndPoint ipLocalEndPoint = new IPEndPoint(local_ip, random.Next(20000, 40000));


                            //Initiate connection with neighbour (Get 1/3 of neighbours peers)
                            TcpClient client = new TcpClient(ipLocalEndPoint);
                            client.Connect(neighbour_ip, neighbour_port);

                            neighbour_links[0] = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
                            authenticate_client(neighbour_links[0]);
                            send_message_tcp(neighbour_links[0], "NEIGHBOUR");
                            response = recieve_message_tcp(neighbour_links[0]);
                            Console.WriteLine(response);
                            if (String.Compare(response, "SUCCESS") == 0)
                            {
                                new Thread(() => handle_neighbour(0)).Start();
                            }

                            Console.WriteLine("Create a connection");
                        }
                        break;
                    }
                    Thread.Sleep(2000);
                }
                else if (!thread_change && index % 2 == 1)
                {
                    string response = recieve_message_tcp(neighbour_links[0]);
                    Console.WriteLine(response);
                    if (String.Compare(response, "END") == 0)
                    {
                        neighbour_links[0].Close();
                        neighbour_links[0] = null;
                        break;
                    }
                    send_message_tcp(neighbour_links[0], "HELLO(" + index + ")");
                    Thread.Sleep(2000);
                }
                else if (thread_change && index % 2 == 1)
                {
                    string response = recieve_message_tcp(neighbour_links[0]);
                    Console.WriteLine(response);
                    send_message_tcp(neighbour_links[0], "END");


                    neighbour_links[0].Close();
                    neighbour_links[0] = null;

                    thread_change = false;
                    break;
                }
                else if (thread_change && index % 2 == 0)
                {
                    send_message_tcp(neighbour_links[0], "END");
                    neighbour_links[0].Close();
                    neighbour_links[0] = null;

                    thread_change = false;
                    break;
                }

            }
            Console.WriteLine("Tunnel Disconnected");
        }
        static void Main(string[] args)
        {
            superpeer_neighbours = new List<IPEndPoint>();

            peers = new Dictionary<string, IPEndPoint>();

            neighbour_links = new SslStream[2];
            neighbour_count = 0;
            thread_change = false;

            //Add certificate to the certificate store
            server_cert = new X509Certificate2("/home/pasan/Documents/FYP_certificates/ssl-certificate.pfx", "password", X509KeyStorageFlags.PersistKeySet);
            X509Store store = new X509Store(StoreName.My);
            store.Open(OpenFlags.ReadWrite);
            store.Add(server_cert);

            local_ip = IPAddress.Parse("127.0.0.1");

            //Initiate first and seconds servers of the super peer network
            TcpListener server;
            Random random = new Random();
            try
            {

                server = new TcpListener(local_ip, 27005);
                local_port = 27005;
                server.Start();
                superpeer_neighbours.Add(new IPEndPoint(local_ip, 28005));

                //TcpListener neighbour = new TcpListener(local_ip, 37005);
                //local_port = 27005;
                //server.Start();
                TcpClient client = server.AcceptTcpClient();
                neighbour_links[neighbour_count++] = new SslStream(client.GetStream(), false);
                neighbour_links[0].AuthenticateAsServer(server_cert, clientCertificateRequired: false, SslProtocols.Tls13, checkCertificateRevocation: true);

                neighbour_links[0].ReadTimeout = 20000;
                neighbour_links[0].WriteTimeout = 20000;

                string response = recieve_message_tcp(neighbour_links[0]);
                if (String.Compare(response, "SUCCESS") == 0)
                {
                    new Thread(() => handle_neighbour(0)).Start();
                }

            }
            catch (Exception)
            {

                server = new TcpListener(local_ip, 28005);
                local_port = 28005;
                server.Start();
                superpeer_neighbours.Add(new IPEndPoint(local_ip, 27005));

                IPEndPoint ipLocalEndPoint = new IPEndPoint(local_ip, random.Next(20000, 40000));

                //Initiate connection with neighbour (Get 1/3 of neighbours peers)
                TcpClient client = new TcpClient(ipLocalEndPoint);
                client.Connect("127.0.0.1", 27005);
                neighbour_links[neighbour_count++] = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
                authenticate_client(neighbour_links[0]);
                send_message_tcp(neighbour_links[0], "SUCCESS");
                new Thread(() => handle_neighbour(1)).Start();



            }

            insert_peers_random();

            //Connecet to neighbour


            //Handle requests from other super peers
            handle_connections(server);
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

        public static void insert_peers(string[] new_peers)
        {
            for (int i = 0; i < new_peers.Length - 1; ++i)
            {
                peers[new_peers[i]] = null;
                ++peers_count;
            }
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
                    Console.WriteLine("Sending 1/3 of Peers");
                    transfer_peers(sslStream, 3);

                    if (myIp == response)
                    {
                        thread_change = true;
                        Thread.Sleep(2000);

                        send_message_tcp(sslStream, superpeer_neighbours[0].ToString());
                        superpeer_neighbours[0] = ((IPEndPoint)client.Client.RemoteEndPoint);


                        neighbour_links[0] = sslStream;
                        new Thread(() => handle_neighbour(0)).Start();

                        //new Thread(() => handle_neighbour(2)).Start();
                    }
                    else
                    {
                        string[] temp_split = response.Split(':');
                        string neighbour_ip = temp_split[0];
                        int neighbour_port = Int16.Parse(temp_split[1]);
                        IPEndPoint old_neighbour = new IPEndPoint(IPAddress.Parse(neighbour_ip), neighbour_port);

                        int index = superpeer_neighbours.IndexOf(old_neighbour);
                        Console.WriteLine("index: " + index);


                        superpeer_neighbours.RemoveAt(index);
                        superpeer_neighbours.Add(((IPEndPoint)client.Client.RemoteEndPoint));

                        send_message_tcp(sslStream, "SUCCESS");

                        neighbour_links[index] = sslStream;
                        new Thread(() => handle_neighbour(0)).Start();
                        /*sslStream.Close();
                        client.Close();*/
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
                    //thread_change = true;
                    //Thread.Sleep(2000);
                    /*neighbour_links[0] = sslStream;
                    new Thread(() => handle_neighbour(1)).Start();*/
                    /*sslStream.Close();
                    client.Close();*/
                }
                else if (String.Compare(response, "NEIGHBOUR") == 0)
                {
                    send_message_tcp(sslStream, "SUCCESS");
                    neighbour_links[0] = sslStream;

                    new Thread(() => handle_neighbour(1)).Start();
                }

                /* else if (String.Compare(response, "END") == 0)
                 {
                     Console.WriteLine(((IPEndPoint)client.Client.RemoteEndPoint) + " is leaving the superpeer network");

                     string delimiter = "Y";
                     string[] temp_split;
                     while (delimiter == "Y")
                     {
                         response = recieve_message_tcp(sslStream);
                         temp_split = response.Split('/');
                         insert_peers(temp_split);
                         delimiter = temp_split[temp_split.Length - 1];
                     }
                     response = recieve_message_tcp(sslStream);
                     Console.WriteLine("My peers");
                     foreach (var pair in peers)
                     {
                         Console.WriteLine(pair.Key);
                     }

                     Console.WriteLine(response);

                     temp_split = response.Split(':');
                     string neighbour_ip = temp_split[0];
                     int neighbour_port = Int16.Parse(temp_split[1]);

                     IPEndPoint new_neighbour = new IPEndPoint(IPAddress.Parse(neighbour_ip), neighbour_port);
                     superpeer_neighbours.Remove(((IPEndPoint)client.Client.RemoteEndPoint));
                     superpeer_neighbours.Add(new_neighbour);

                     Console.WriteLine("My neighbours: ");
                     for (int i = 0; i < superpeer_neighbours.Count; ++i)
                     {
                         Console.WriteLine(superpeer_neighbours[i]);
                     }

                     send_message_tcp(sslStream, "SUCCESS");
                     sslStream.Close();
                     client.Close();

                 }*/
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
