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
        static Dictionary<IPEndPoint, SslStream> superpeer_neighbours;

        static X509Certificate2 server_cert;
        static IPAddress local_ip;
        static int local_port;
        static string server_ip = "127.0.0.1";
        static int server_port = 28005;
        static int peers_count;

        static string neighbour_ip;
        static int neighbour_port;

        static TcpListener server;

        static IPEndPoint ipLocalEndPoint;

        static bool exit;
        static bool change_neighbour;

        //static SslStream[] neighbour_links;
        static int neighbour_count;

        static List<IPEndPoint> exit_neighbours;
        static List<IPEndPoint> change_neighbours;

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
        static void listen_neighbours()
        {
            string response = "";
            IPEndPoint disconnect_neighbour = null;
            IPEndPoint connect_neighbour = null;
            string[] temp_split = null;
            while (true)
            {
                if (superpeer_neighbours.Count != 0)
                {
                    List<IPEndPoint> superpeer_neighbours_list = new List<IPEndPoint>(superpeer_neighbours.Keys);
                    foreach (var neighbour in superpeer_neighbours_list)
                    {
                        try
                        {
                            response = recieve_message_tcp(superpeer_neighbours[neighbour]);

                            Console.WriteLine(response);
                            if (String.Compare(response, "END") == 0)
                            {
                                send_message_tcp(superpeer_neighbours[neighbour], "ACCEPT_END");
                                disconnect_neighbour = neighbour;
                                break;
                            }

                            else if (String.Compare(response, "ACCEPT_END") == 0)
                            {
                                disconnect_neighbour = neighbour;
                                break;
                            }
                            else if (String.Compare(response, "EXIT") == 0)
                            {
                                recieve_peers(superpeer_neighbours[neighbour]);
                                response = recieve_message_tcp(superpeer_neighbours[neighbour]);

                                temp_split = response.Split(':');
                                string neighbour_ip = temp_split[0];
                                int neighbour_port = Int32.Parse(temp_split[1]);
                                string condition = temp_split[2];

                                Console.WriteLine(response);
                                send_message_tcp(superpeer_neighbours[neighbour], "ACCEPT_EXIT");
                                if (String.Compare(condition, "Y") == 0)
                                {
                                    //Thread.Sleep(2000);
                                    connect_neighbour = new IPEndPoint(IPAddress.Parse(neighbour_ip), neighbour_port);
                                }



                                disconnect_neighbour = neighbour;
                                break;
                            }

                            if (String.Compare(response, "ACCEPT_EXIT") == 0)
                            {
                                disconnect_neighbour = neighbour;
                                break;
                            }
                        }
                        catch (System.InvalidOperationException e)
                        {
                            Console.WriteLine(e);
                            break;
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e);
                            break;
                        }
                    }
                }
                if (disconnect_neighbour != null)
                {
                    Console.WriteLine("Disconnecting: " + disconnect_neighbour.ToString());
                    SslStream sslStream = superpeer_neighbours[disconnect_neighbour];
                    superpeer_neighbours.Remove(disconnect_neighbour);
                    sslStream.Close();
                    disconnect_neighbour = null;

                }
                if (connect_neighbour != null)
                {
                    Console.WriteLine("Connecting new neighbour");
                    server.Server.Shutdown(SocketShutdown.Both);
                    server.Stop();
                    IPEndPoint ipLocalEndPoint = new IPEndPoint(local_ip, local_port);

                    //Initiate connection with neighbour (Get 1/3 of neighbours peers)
                    TcpClient client = new TcpClient(ipLocalEndPoint);

                    client.Connect(temp_split[0], Int16.Parse(temp_split[1]));

                    SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
                    authenticate_client(sslStream);

                    send_message_tcp(sslStream, "NEIGHBOUR");
                    response = recieve_message_tcp(sslStream);
                    Console.WriteLine(response);
                    if (String.Compare(response, "SUCCESS") == 0)
                    {
                        superpeer_neighbours[connect_neighbour] = sslStream;
                    }
                    connect_neighbour = null;
                    server.Start();
                    new Thread(() => handle_connections()).Start();
                }
            }
        }
        static void handle_neighbour(int index)
        {
            new Thread(() => listen_neighbours()).Start();
            int count = 0;
            while (true)
            {
                if (exit_neighbours.Count != 0)
                {
                    int exit_neighbour_count = exit_neighbours.Count;
                    foreach (IPEndPoint neighbour in exit_neighbours)
                    {
                        Console.WriteLine("Disconnecting neighbour: " + neighbour.ToString());
                        send_message_tcp(superpeer_neighbours[neighbour], "EXIT");
                        if (exit_neighbour_count == 2)
                        {
                            transfer_peers(superpeer_neighbours[neighbour], 2);
                            send_message_tcp(superpeer_neighbours[neighbour], exit_neighbours[superpeer_neighbours.Count - 1].ToString() + ":Y");
                        }
                        else
                        {
                            transfer_peers(superpeer_neighbours[neighbour], 1);
                            send_message_tcp(superpeer_neighbours[neighbour], exit_neighbours[superpeer_neighbours.Count - 1].ToString() + ":N");

                        }
                        --exit_neighbour_count;

                    }
                    exit_neighbours.Clear();
                    if (exit_neighbour_count == 0)
                    {
                        break;
                    }
                }

                if (change_neighbours.Count != 0)
                {

                    foreach (var neighbour in change_neighbours)
                    {
                        Console.WriteLine("Disconnecting neighbour: " + neighbour.ToString());
                        send_message_tcp(superpeer_neighbours[neighbour], "END");
                    }
                    change_neighbours.Clear();
                }

                if (superpeer_neighbours.Count != 0)
                {
                    Console.WriteLine("Neighbours(Send): " + superpeer_neighbours.Count);
                    List<IPEndPoint> superpeer_neighbours_list = new List<IPEndPoint>(superpeer_neighbours.Keys);
                    foreach (var neighbour in superpeer_neighbours_list)
                    {
                        try
                        {
                            Console.WriteLine("sending: " + count);
                            send_message_tcp(superpeer_neighbours[neighbour], "HELLO(" + count++ + ")");
                        }
                        catch (System.InvalidOperationException e)
                        {
                            Console.WriteLine(e);
                            break;
                        }
                        catch (Exception e)
                        {
                            break;
                        }
                    }
                    Thread.Sleep(2000);
                }
            }
            Console.WriteLine("Thread Closed");
        }



        //Trap ctrl+c to distribute peers among neighbour upon exit
        private static void On_exit(object sender, ConsoleCancelEventArgs e)
        {
            Console.WriteLine("Exiting");
            e.Cancel = true;

            IPEndPoint neighbour;
            var neighbour_itr = superpeer_neighbours.GetEnumerator();
            neighbour_itr.MoveNext();
            neighbour = neighbour_itr.Current.Key;
            exit_neighbours.Add(neighbour);

            neighbour_itr.MoveNext();
            neighbour = neighbour_itr.Current.Key;
            exit_neighbours.Add(neighbour);

            Thread.Sleep(10000);

            server.Server.Disconnect(true);
            server.Server.Close();
            TcpClient client = new TcpClient(ipLocalEndPoint);

            System.Environment.Exit(1);

        }

        private static void init_connection(string ip, int port)
        {
            ipLocalEndPoint = new IPEndPoint(local_ip, local_port);

            //Initiate connection with neighbour (Get 1/3 of neighbours peers)
            TcpClient client = new TcpClient(ipLocalEndPoint);

            client.Connect(ip, port);
            SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
            establish_connection(sslStream);
            superpeer_neighbours[new IPEndPoint(IPAddress.Parse(ip), port)] = sslStream;
            neighbour_count++;

            /* sslStream.Close();
             client.Close();*/

        }


        static void Main(string[] args)
        {
            //To handle on exit function to distribute peers upon exit
            Console.CancelKeyPress += On_exit;
            peers_count = 0;
            exit = false;
            change_neighbour = false;

            //neighbour_links = new SslStream[2];
            neighbour_count = 0;

            neighbour_ip = null;
            neighbour_port = -1;

            Console.Write("Server port: ");
            server_port = Convert.ToInt32(Console.ReadLine());

            //Initiate database
            superpeer_neighbours = new Dictionary<IPEndPoint, SslStream>();
            peers = new Dictionary<string, IPEndPoint>();
            exit_neighbours = new List<IPEndPoint>();
            change_neighbours = new List<IPEndPoint>();

            //Select a random port number
            Random random = new Random();


            //Add ceritificate to the store
            server_cert = new X509Certificate2("/home/pasan/Documents/FYP_certificates/ssl-certificate.pfx", "password", X509KeyStorageFlags.PersistKeySet);
            X509Store store = new X509Store(StoreName.My);
            store.Open(OpenFlags.ReadWrite);
            store.Add(server_cert);

            //Create the local end point(ip+port)
            local_ip = IPAddress.Parse("127.0.0.1");
            local_port = random.Next(20000, 40000);

            init_connection(server_ip, server_port);

            init_connection(neighbour_ip, neighbour_port);

            new Thread(() => handle_neighbour(1)).Start();
            server = new TcpListener(local_ip, local_port);
            server.Start();

            //Listen to requests
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

        static void recieve_peers(SslStream sslStream)
        {
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

        }


        static void establish_connection(SslStream sslStream)
        {
            authenticate_client(sslStream);

            string response;
            string[] temp_split;

            send_message_tcp(sslStream, "HELLO");
            send_message_tcp(sslStream, (server_ip + ":" + server_port));

            recieve_peers(sslStream);

            response = recieve_message_tcp(sslStream);
            Console.WriteLine(response);

            if (response != "SUCCESS")
            {
                temp_split = response.Split(':');
                neighbour_ip = temp_split[0];
                neighbour_port = Int32.Parse(temp_split[1]);
            }

        }


        static void handle_connections()
        {
            Console.WriteLine("Server is starting on port: " + local_port);
            Byte[] bytes = new Byte[256];
            string response;

            while (true)
            {
                TcpClient client = null;
                try
                {
                    client = server.AcceptTcpClient();

                }
                catch
                {
                    Console.WriteLine("Exception");
                    break;
                }
                SslStream sslStream = new SslStream(client.GetStream(), false);
                sslStream.AuthenticateAsServer(server_cert, clientCertificateRequired: false, SslProtocols.Tls13, checkCertificateRevocation: true);
                sslStream.ReadTimeout = 10000;
                sslStream.WriteTimeout = 10000;
                // Read a message from the client.
                response = recieve_message_tcp(sslStream);
                Console.WriteLine(response);
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
                        //thread_change = true;

                        //Thread.Sleep(2000);
                        IPEndPoint neighbour;
                        var neighbour_itr = superpeer_neighbours.GetEnumerator();
                        neighbour_itr.MoveNext();

                        neighbour = neighbour_itr.Current.Key;
                        //exit_neighbours.Add(neighbour);

                        change_neighbours.Add(neighbour);

                        Thread.Sleep(2000);

                        send_message_tcp(sslStream, neighbour.ToString());
                        superpeer_neighbours[(IPEndPoint)client.Client.RemoteEndPoint] = sslStream;
                    }
                    else
                    {
                        string[] temp_split = response.Split(':');
                        string neighbour_ip = temp_split[0];
                        int neighbour_port = Int16.Parse(temp_split[1]);

                        IPEndPoint old_neighbour = new IPEndPoint(IPAddress.Parse(neighbour_ip), neighbour_port);


                        send_message_tcp(sslStream, "SUCCESS");
                        superpeer_neighbours[(IPEndPoint)client.Client.RemoteEndPoint] = sslStream;

                    }


                    Console.WriteLine("My neighbours: ");
                    foreach (var neighbour in superpeer_neighbours)
                    {
                        Console.WriteLine(neighbour.Key);
                    }
                    Console.WriteLine("My peers");
                    foreach (var pair in peers)
                    {
                        Console.WriteLine(pair.Key);
                    }
                }
                else if (String.Compare(response, "NEIGHBOUR") == 0)
                {
                    Console.WriteLine("Neighbour request received");
                    superpeer_neighbours[(IPEndPoint)client.Client.RemoteEndPoint] = sslStream;
                    send_message_tcp(sslStream, "SUCCESS");
                }
                else
                {
                    Console.WriteLine("unrecognized command");
                }
            }
        }
        private static readonly object balanceLock = new object();
        static void send_message_tcp(SslStream sslStream, string message)
        {
            Request req = new Request(200, message);
            string jsonString = JsonConvert.SerializeObject(req);
            byte[] data = Encoding.UTF8.GetBytes(jsonString);
            sslStream.Write(data);
            sslStream.Flush();
        }
        //private static readonly object balanceLock = new object();
        static string recieve_message_tcp(SslStream sslStream)
        {
            lock (balanceLock)
            {

                Byte[] bytes = new Byte[256];
                sslStream.Read(bytes, 0, bytes.Length);


                string message = Encoding.UTF8.GetString(bytes);
                Request reply = JsonConvert.DeserializeObject<Request>(message);
                return reply.body;
            }
        }
    }
}
