using System;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;

using System.Diagnostics;

using System.Runtime.InteropServices;

using Cryptography;
using Authentication;
using TCP;
using dtls_client;
using PairStream;
using dtls_server;


namespace superpeer_network
{
    class Program
    {
        static Dictionary<string, IPEndPoint> peers;
        static Dictionary<IPEndPoint, SslStream> superpeer_neighbours;

        static Dictionary<string, IPEndPoint> message_buffer;
        static Dictionary<IPEndPoint, IPEndPoint> message_tunnel;
        static Dictionary<IPEndPoint, int> pending_requests;

        static Dictionary<string, string> reply_buffer;
        static Dictionary <IPEndPoint, PublicKeyCoordinates> client_keys;

        static X509Certificate2 server_cert;
        static IPAddress local_ip;
        static int local_port;
        static string server_ip;
        static int server_port;

        static string neighbour_ip;
        static int neighbour_port;

        static TcpListener server;

        static IPEndPoint ipLocalEndPoint;

        static List<IPEndPoint> exit_neighbours;
        static List<IPEndPoint> change_neighbours;

        static int hop_count = 2;
        static int flood_phases = 2;

        public static void insert_peers(string[] new_peers)
        {
            for (int i = 0; i < new_peers.Length - 1; ++i)
            {
                peers[new_peers[i]] = null;
            }
        }

        static void connect_neighbour(IPEndPoint neighbour)
        {
            Console.WriteLine("Connecting new neighbour");
            server.Server.Shutdown(SocketShutdown.Both);
            server.Stop();

            server_ip = neighbour.Address.ToString();
            server_port = neighbour.Port;

            neighbour_ip = null;
            neighbour_port = -1;

            init_connection(server_ip, server_port);

            if(neighbour_ip != null)
            {
                init_connection(neighbour_ip, neighbour_port);
            }

            server.Start();
            new Thread(() => handle_connections()).Start();
        }

        static void disconnect_neighbour(IPEndPoint neighbour)
        {
            Console.WriteLine("Disconnecting: " + neighbour.ToString());

            SslStream sslStream = superpeer_neighbours[neighbour];
            superpeer_neighbours.Remove(neighbour);
            sslStream.Close();
        }

        static void listen_neighbours(KeyValuePair<IPEndPoint, SslStream> neighbour)
        {
            Console.WriteLine("A listen thread created");
            string response = "";
            string[] temp_split;
            IPEndPoint ip = neighbour.Key;
            SslStream sslStream = neighbour.Value;
            while (true)
            {
                try
                {
                    response = TCPCommunication.recieve_message_tcp(sslStream);
                    Console.Write($"Receive({ip}): ");
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine(response);
                    Console.ResetColor();
                    if (String.Compare(response, "END") == 0)
                    {
                        TCPCommunication.send_message_tcp(sslStream, "ACCEPT");
                        disconnect_neighbour(ip);

                        break;
                        /*disconnect_neighbour = neighbour;
                        break;*/
                    }

                    /*else if (String.Compare(response, "ACCEPT") == 0)
                    {
                        // TCPCommunication.send_message_tcp(sslStream, "ACCEPT_END");

                        disconnect_neighbour(ip);

                        break;
                        /*disconnect_neighbour = neighbour;
                        break;*//*
                    }*/
                    else if (String.Compare(response, "EXIT") == 0)
                    {

                        recieve_peers(sslStream);
                        response = TCPCommunication.recieve_message_tcp(sslStream);

                        Console.WriteLine(response);

                        temp_split = response.Split(':');
                        string neighbour_ip = temp_split[0];
                        int neighbour_port = Int32.Parse(temp_split[1]);
                        string condition = temp_split[2];

                        TCPCommunication.send_message_tcp(sslStream, "ACCEPT");
                        if (String.Compare(condition, "N") == 0)
                        {
                            Console.WriteLine("Here");
                            connect_neighbour(new IPEndPoint(IPAddress.Parse(neighbour_ip), neighbour_port));
                        }
                        disconnect_neighbour(ip);
                        break;
                    }
                    else if (String.Compare(response, "ACCEPT") == 0)
                    {
                        disconnect_neighbour(ip);
                        break;
                    }
                    else
                    {
                        temp_split = response.Split(':');

                        string op_code = temp_split[0];
                        string data0 = (temp_split.Length >= 2) ? temp_split[1] : "";
                        string data1 = (temp_split.Length >= 3) ? temp_split[2] : "";
                        string data2 = (temp_split.Length >= 4) ? temp_split[3] : "";

                        if (String.Compare(op_code, "SEARCH") == 0)
                        {
                            Console.WriteLine("search request recieved for: " + data0);
                            Console.WriteLine("Hop count: "+data2);
                            if (peers.ContainsKey(data0))
                            {
                                Console.WriteLine("Key is found");
                                //peers.Remove(data0);
                                if(!(String.Compare(data1, "NONE") == 0))
                                {
                                    peers[data1] = null;
                                    Console.WriteLine("add peer " + data1);
                                }
                                TCPCommunication.send_message_tcp(sslStream, "FOUND:" + data0 + ":" + local_ip.ToString() + ":" + local_port);
                                Console.WriteLine("Sent");
                            }
                            else
                            {
                                if(String.Compare(data2,"0") != 0)
                                {
                                    foreach (var dest in superpeer_neighbours)
                                    {
                                        if (!dest.Key.Equals(ip))
                                        {
                                            Console.WriteLine("Adding search to buffer for: " + dest.Key);
                                            message_tunnel[dest.Key] = ip;
                                            new Thread(() => remove_tunnel(dest.Key)).Start();
                                            message_buffer[-1 + ":SEARCH:" + data0 + ":" + data1+":"+data2] = dest.Key;
                                        }
                                    }
                                }
                            }
                        }
                        else if (String.Compare(op_code, "FOUND") == 0)
                        {
                            if (message_tunnel.ContainsKey(ip))
                            {
                                if (message_tunnel[ip] != null)
                                {
                                    Console.WriteLine("Tunnel exists for: " + neighbour + "->" + message_tunnel[ip]);
                                    TCPCommunication.send_message_tcp(superpeer_neighbours[message_tunnel[ip]], response);
                                    message_tunnel.Remove(ip);
                                }
                                else
                                {
                                    Console.WriteLine("key: " + data0);
                                    Console.WriteLine("Key exists in : " + data1 + ":" + data2);
                                    reply_buffer[data0] = "FOUND:" + data1 + ":" + data2;
                                    message_tunnel.Remove(ip);

                                }
                            }
                            else
                            {
                                Console.WriteLine("Tunnel does not exists");
                            }

                        }
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
            Console.WriteLine("Listen thread exit");
        }

        static void handle_neighbour(int index)
        {
            //new Thread(() => listen_neighbours()).Start();
            bool exit_neighbour = false;
            //bool break_loop = false;
            while (true)
            {
                if (exit_neighbours.Count != 0)
                {
                    Thread.Sleep(500);
                    foreach (IPEndPoint neighbour in exit_neighbours.ToArray())
                    {
                        Console.WriteLine("Disconnecting neighbour: " + neighbour.ToString());
                        TCPCommunication.send_message_tcp(superpeer_neighbours[neighbour], "EXIT");
                        if (!exit_neighbour)
                        {
                            transfer_peers(superpeer_neighbours[neighbour], (superpeer_neighbours.Count));
                            TCPCommunication.send_message_tcp(superpeer_neighbours[neighbour], exit_neighbours[0].ToString() + ":Y");
                            exit_neighbour = true;
                        }
                        else
                        {
                            transfer_peers(superpeer_neighbours[neighbour], (superpeer_neighbours.Count));
                            TCPCommunication.send_message_tcp(superpeer_neighbours[neighbour], exit_neighbours[0].ToString() + ":N");
                            //break_loop = true;
                        }
                    }
                    exit_neighbours.Clear();
                    break;
                }

                if (change_neighbours.Count != 0)
                {
                    foreach (var neighbour in change_neighbours)
                    {
                        //Console.WriteLine("Disconnecting neighbour: " + neighbour.ToString());
                        message_buffer[-1 + ":END"] = neighbour;
                        //TCPCommunication.send_message_tcp(superpeer_neighbours[neighbour], "END");
                    }
                    change_neighbours.Clear();
                }
                if (superpeer_neighbours.Count != 0)
                {
                    //Console.WriteLine("Neighbours(Send): " + superpeer_neighbours.Count);
                    List<IPEndPoint> superpeer_neighbours_list = null;
                    try
                    {
                        superpeer_neighbours_list = new List<IPEndPoint>(superpeer_neighbours.Keys);
                    }
                    catch (System.ArgumentException e)
                    {
                        Console.WriteLine("neighbours have changed");
                        Thread.Sleep(100);
                        continue;
                    }
                    catch (System.IndexOutOfRangeException)
                    {
                        Console.WriteLine("neighbours have changed");
                        Thread.Sleep(100);
                        continue;                
                    }
                    foreach (var neighbour in superpeer_neighbours_list)
                    {
                        if (message_buffer.Count != 0)
                        {
                            try
                            {

                                List<string> message_buffer_list = new List<string>(message_buffer.Keys);

                                //message_itr.MoveNext();
                                string message_full = message_buffer_list[0];
                                string[] temp_split = message_full.Split(':');

                                string message = (temp_split.Length >= 1) ? temp_split[1] : "";
                                //string message = message_full.Split(':')[1];
                                string data0 = (temp_split.Length > 2) ? temp_split[2] : "";
                                string data1 = (temp_split.Length > 2) ? temp_split[3] : "";
                                int hops = (Int32.Parse((temp_split.Length > 2) ? temp_split[4] : "0"))-1;

                                //Get corresponding destination of the message
                                IPEndPoint destination_ip = message_buffer[message_full];

                                if (destination_ip == neighbour)
                                {

                                    //message_tunnel[neighbour] = restrict_ip;
                                    //TCPCommunication.send_message_tcp(superpeer_neighbours[neighbour], "SEARCH:" + message);

                                    if (data0 != "")
                                    {
                                        Console.Write($"Sending({neighbour}): ");
                                        Console.ForegroundColor = ConsoleColor.Yellow;
                                        Console.WriteLine($"{message}: {data0}");
                                        Console.ResetColor();
                                        TCPCommunication.send_message_tcp(superpeer_neighbours[neighbour], message + ":" + data0 + ":" + data1 + ":"+hops);
                                    }
                                    else
                                    {
                                        Console.Write($"Sending({neighbour}): ");
                                        Console.ForegroundColor = ConsoleColor.Yellow;
                                        Console.WriteLine($"{message}");
                                        Console.ResetColor();
                                        TCPCommunication.send_message_tcp(superpeer_neighbours[neighbour], message);
                                    }
                                    message_buffer.Remove(message_full);
                                    //new Thread(() => remove_tunnel(neighbour)).Start();
                                }

                                /*else
                                {
                                    Console.WriteLine("sending: " + count);
                                    TCPCommunication.send_message_tcp(superpeer_neighbours[neighbour], "HELLO(" + count++ + ")");
                                }*/
                            }
                            catch (System.InvalidOperationException)
                            {
                                Console.WriteLine("neighbours have changed");
                                Thread.Sleep(100);
                                break;
                            }
                            catch (Exception)
                            {
                                Console.WriteLine("neighbours have changed");
                                Thread.Sleep(100);
                                break;
                            }
                        }
                    }

                    //Thread.Sleep(2000);
                }
            }
            Console.WriteLine("Send thread Closed");
        }

        static void remove_tunnel(IPEndPoint ip)
        {
            Thread.Sleep(5000);
            if (message_tunnel.ContainsKey(ip))
            {
                Console.WriteLine("tunnel " + ip.ToString() + " " + message_tunnel[ip] + " is removed");
                message_tunnel.Remove(ip);

            }
        }


        //Trap ctrl+c to distribute peers among neighbour upon exit
        private static void On_exit(object sender, ConsoleCancelEventArgs e)
        {
            Console.WriteLine("Exiting");
            e.Cancel = true;

            List<IPEndPoint> superpeer_neighbours_list = null;
            try
            {
                superpeer_neighbours_list = new List<IPEndPoint>(superpeer_neighbours.Keys);
            }
            catch (System.ArgumentException)
            {
                Console.WriteLine("neighbours have changed");
                Thread.Sleep(100);
            }
            foreach (IPEndPoint neighbour in superpeer_neighbours_list)
            {
                exit_neighbours.Add(neighbour);
            }


            /*IPEndPoint neighbour;
            var neighbour_itr = superpeer_neighbours.GetEnumerator();
            neighbour_itr.MoveNext();
            neighbour = neighbour_itr.Current.Key;
            exit_neighbours.Add(neighbour);
            //Thread.Sleep(1000);

            neighbour_itr.MoveNext();
            neighbour = neighbour_itr.Current.Key;
            exit_neighbours.Add(neighbour);*/

            Thread.Sleep(4000);

            server.Server.Disconnect(true);
            server.Server.Close();
            //TcpClient client = new TcpClient(ipLocalEndPoint);

            System.Environment.Exit(1);

        }

        private static void init_connection(string ip, int port)
        {
            ipLocalEndPoint = new IPEndPoint(local_ip, local_port);

            //Initiate connection with neighbour (Get 1/3 of neighbours peers)
            TcpClient client = new TcpClient(ipLocalEndPoint);

            client.Connect(ip, port);
            SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(SSLValidation.ValidateServerCertificate), null);
            establish_connection(sslStream);

            superpeer_neighbours[new IPEndPoint(IPAddress.Parse(ip), port)] = sslStream;

            KeyValuePair<IPEndPoint, SslStream> new_neighbour = new KeyValuePair<IPEndPoint, SslStream>(new IPEndPoint(IPAddress.Parse(ip), port), sslStream);
            new Thread(() => listen_neighbours(new_neighbour)).Start();

            /* sslStream.Close();
             client.Close();*/

        }

        static void establish_connection(SslStream sslStream)
        {
            SSLValidation.authenticate_client(sslStream);

            string response;
            string[] temp_split;

            TCPCommunication.send_message_tcp(sslStream, "HELLO_S");
            TCPCommunication.send_message_tcp(sslStream, (server_ip + ":" + server_port));

            response = TCPCommunication.recieve_message_tcp(sslStream);
            Console.WriteLine(response);
            if(String.Compare(response,"CONNECT_S") == 0)
            {
                recieve_peers(sslStream);
                response = TCPCommunication.recieve_message_tcp(sslStream);
                Console.WriteLine(response);
            }
            else if(String.Compare(response,"CHANGE_S") == 0)
            {
                recieve_peers(sslStream);
                response = TCPCommunication.recieve_message_tcp(sslStream);
                Console.WriteLine(response);

                temp_split = response.Split(':');
                neighbour_ip = temp_split[0];
                neighbour_port = Int32.Parse(temp_split[1]);

                //new IPEndPoint(IPAddress.Parse(neighbour_ip), neighbour_port);

                response = TCPCommunication.recieve_message_tcp(sslStream);
                Console.WriteLine(response);                

            }
            else
            {
                Console.WriteLine("Unrecognized message");
            }
        }

        static void hello_neighbour()
        {
            while (true)
            {
                int count = 0;
                List<IPEndPoint> superpeer_neighbours_list = null;
                try
                {
                    superpeer_neighbours_list = new List<IPEndPoint>(superpeer_neighbours.Keys);
                }
                catch (System.ArgumentException e)
                {
                    Console.WriteLine("neighbours have changed");
                    Thread.Sleep(100);
                    continue;
                }
                foreach (IPEndPoint neighbour in superpeer_neighbours_list)
                {
                    message_buffer[count + ":HELLO"] = neighbour;
                    count++;
                }
                Thread.Sleep(5000);
            }
            Console.WriteLine("Exit hello_neighbour thread");
        }

        static void Main(string[] args)
        {
            //To handle on exit function to distribute peers upon exit
            Console.CancelKeyPress += On_exit;


            neighbour_ip = null;
            neighbour_port = -1;

            Console.Write("Server ip: ");
            server_ip = Console.ReadLine();

            Console.Write("Server port: ");
            server_port = Convert.ToInt32(Console.ReadLine());


            //Initiate database
            superpeer_neighbours = new Dictionary<IPEndPoint, SslStream>();
            peers = new Dictionary<string, IPEndPoint>();
            message_buffer = new Dictionary<string, IPEndPoint>();
            message_tunnel = new Dictionary<IPEndPoint, IPEndPoint>();
            reply_buffer = new Dictionary<string, string>();
            pending_requests = new Dictionary<IPEndPoint, int>();

            exit_neighbours = new List<IPEndPoint>();
            change_neighbours = new List<IPEndPoint>();

            client_keys = new Dictionary<IPEndPoint, PublicKeyCoordinates>();

            //Select a random port number
            Random random = new Random();


            //Add ceritificate to the store
            server_cert = new X509Certificate2("../../FYP_certificates/ssl-certificate.pfx", "password", X509KeyStorageFlags.PersistKeySet);
            X509Store store = new X509Store(StoreName.My);
            store.Open(OpenFlags.ReadWrite);
            store.Add(server_cert);

            //Create the local end point(ip+port)
            local_ip = IPAddress.Parse("127.0.0.1");
            local_port = random.Next(20000, 40000);

            init_connection(server_ip, server_port);

            if(neighbour_ip != null)
            {
                init_connection(neighbour_ip, neighbour_port);
            }

            new Thread(() => handle_neighbour(1)).Start();
            new Thread(() => hello_neighbour()).Start();

            server = new TcpListener(local_ip, local_port);
            server.Start();

            //Listen to requests
            handle_connections();


        }

        public static void transfer_peers(SslStream sslStream, int divident)
        {
            string reply = "";
            int limit_count = 0;
            int count = 0;
            int peers_count = peers.Count;
            foreach (var pair in peers)
            {
                if (count >= peers_count / divident)
                {
                    break;
                }
                if (limit_count > 5)
                {
                    TCPCommunication.send_message_tcp(sslStream, reply + "Y");
                    reply = "";
                    limit_count = 0;
                }
                reply += pair.Key + "/";
                peers.Remove(pair.Key);
                count++;
                limit_count++;
            }
            TCPCommunication.send_message_tcp(sslStream, reply + "N");
        }

        static void recieve_peers(SslStream sslStream)
        {
            string delimiter = "Y";
            string response;
            string[] temp_split;
            while (delimiter == "Y")
            {
                response = TCPCommunication.recieve_message_tcp(sslStream);
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

        static void wait_reply(SslStream sslStream, string receiver_key, string sender_key)
        {
            Console.WriteLine("Thread");
            for(int i=0;i<flood_phases;++i)
            {
                Thread.Sleep(3000);
                if(!reply_buffer.ContainsKey(receiver_key))
                {
                    List<IPEndPoint> superpeer_neighbours_list = new List<IPEndPoint>(superpeer_neighbours.Keys);
                    int count = 0;
                    foreach (var neighbour in superpeer_neighbours_list)
                    {
                        message_tunnel[neighbour] = null;
                        message_buffer[(count++) + ":SEARCH:" + receiver_key + ":" + sender_key+":"+ (hop_count*2)] = neighbour;
                    }
                    //new Thread(() => wait_reply(sslStream, receiver_key, sender_key)).Start();
                }
                else
                {
                    break;
                }   
            }
            //Thread.Sleep(3000);
            if (reply_buffer.ContainsKey(receiver_key))
            {
                //peers[key] = null;
                TCPCommunication.send_message_tcp(sslStream, reply_buffer[receiver_key]);

                reply_buffer.Remove(receiver_key);
                //TCPCommunication.send_message_tcp(sslStream, "FOUND");

                //response = TCPCommunication.recieve_message_tcp(sslStream);
                if(!(String.Compare(sender_key, "NONE") == 0))
                {
                    peers.Remove(sender_key);
                    Console.WriteLine(sender_key + " is removed");
                }
                //TCPCommunication.send_message_tcp(sslStream, "SUCCESS");
                sslStream.Close();

            }
            else
            {
                TCPCommunication.send_message_tcp(sslStream, "NOTFOUND");
                sslStream.Close();
            }
                
            //sslStream.Close();
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
                sslStream.ReadTimeout = 40000;
                sslStream.WriteTimeout = 40000;
                // Read a message from the client.
                response = TCPCommunication.recieve_message_tcp(sslStream);
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(response);
                Console.ResetColor();
                if (String.Compare(response, "HELLO_S") == 0)
                {
                    Console.WriteLine(((IPEndPoint)client.Client.RemoteEndPoint) + " is requesting to join superpeer network");

                    response = TCPCommunication.recieve_message_tcp(sslStream);
 

                    string myIp = local_ip.ToString() + ":" + local_port;
                    Console.WriteLine("Requesting neighbour: " + response);

                    if (myIp == response)
                    {
                        if(superpeer_neighbours.Count < 2)
                        {
                            TCPCommunication.send_message_tcp(sslStream, "CONNECT_S"); 
                            Console.WriteLine("Sending 1/2 of Peers");
                            transfer_peers(sslStream, 2);

                            superpeer_neighbours[(IPEndPoint)client.Client.RemoteEndPoint] = sslStream;

                            KeyValuePair<IPEndPoint, SslStream> new_neighbour = new KeyValuePair<IPEndPoint, SslStream>((IPEndPoint)client.Client.RemoteEndPoint, sslStream);
                            new Thread(() => listen_neighbours(new_neighbour)).Start();

                            TCPCommunication.send_message_tcp(sslStream, "SUCCESS");

                        }
                        else
                        {
                            TCPCommunication.send_message_tcp(sslStream, "CHANGE_S");
                            Console.WriteLine("Sending 1/3 of Peers");
                            transfer_peers(sslStream, 3);

                            IPEndPoint neighbour;
                            var neighbour_itr = superpeer_neighbours.GetEnumerator();
                            neighbour_itr.MoveNext();

                            neighbour = neighbour_itr.Current.Key;

                            change_neighbours.Add(neighbour);
                            Thread.Sleep(500);

                            TCPCommunication.send_message_tcp(sslStream, neighbour.ToString());
                            superpeer_neighbours[(IPEndPoint)client.Client.RemoteEndPoint] = sslStream;

                            KeyValuePair<IPEndPoint, SslStream> new_neighbour = new KeyValuePair<IPEndPoint, SslStream>((IPEndPoint)client.Client.RemoteEndPoint, sslStream);
                            new Thread(() => listen_neighbours(new_neighbour)).Start();

                            TCPCommunication.send_message_tcp(sslStream, "SUCCESS");
                        }
                    }
                    else
                    {
                        TCPCommunication.send_message_tcp(sslStream, "CONNECT_S"); 
                        Console.WriteLine("Sending 1/3 of Peers");
                        transfer_peers(sslStream, 3);

                        superpeer_neighbours[(IPEndPoint)client.Client.RemoteEndPoint] = sslStream;

                        KeyValuePair<IPEndPoint, SslStream> new_neighbour = new KeyValuePair<IPEndPoint, SslStream>((IPEndPoint)client.Client.RemoteEndPoint, sslStream);
                        new Thread(() => listen_neighbours(new_neighbour)).Start();

                        TCPCommunication.send_message_tcp(sslStream, "SUCCESS");
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
                else if (String.Compare(response, "INIT_P") == 0)
                {
                    Console.WriteLine((IPEndPoint)client.Client.RemoteEndPoint + " peer is registering");
                    TCPCommunication.send_message_tcp(sslStream, "SUCCESS");
                    response = TCPCommunication.recieve_message_tcp(sslStream);
                    string hash = HashString.GetHashString(response);

                    peers[hash] = (IPEndPoint)client.Client.RemoteEndPoint;

                    Console.WriteLine(hash + " is added to peers");
                    sslStream.Close();
                    client.Close();
                }
                else if (String.Compare(response, "LOCATE_P") == 0)
                {
                    string sender_key = TCPCommunication.recieve_message_tcp(sslStream);
                    if (peers.ContainsKey(sender_key))
                    {
                        TCPCommunication.send_message_tcp(sslStream, "ACCEPT");

                        string key = TCPCommunication.recieve_message_tcp(sslStream);

                        if (peers.ContainsKey(key))
                        {
                            TCPCommunication.send_message_tcp(sslStream, "FOUND"+":"+local_ip+":"+local_port);
                        }
                        else
                        {
                            List<IPEndPoint> superpeer_neighbours_list = new List<IPEndPoint>(superpeer_neighbours.Keys);
                            int count = 0;
                            foreach (var neighbour in superpeer_neighbours_list)
                            {
                                message_tunnel[neighbour] = null;
                                message_buffer[(count++) + ":SEARCH:" + key + ":NONE" + ":" + hop_count] = neighbour;
                            }
                            new Thread(() => wait_reply(sslStream, key, "NONE")).Start();
                        }
                        
                    }
                    else
                    {
                        TCPCommunication.send_message_tcp(sslStream, "REJECT");
                        sslStream.Close();
                        client.Close();
                    }
                }
                else if (String.Compare(response, "ANONYM_P") == 0)
                {
                    string sender_key = TCPCommunication.recieve_message_tcp(sslStream);
                    if (peers.ContainsKey(sender_key))
                    {
                        TCPCommunication.send_message_tcp(sslStream, "ACCEPT");

                        string new_key = TCPCommunication.recieve_message_tcp(sslStream);

                        peers.Remove(sender_key);
                        peers[new_key] = (IPEndPoint)client.Client.RemoteEndPoint;
                        Console.WriteLine(sender_key+ " changed to "+ new_key);

                        TCPCommunication.send_message_tcp(sslStream, "SUCCESS");
                    }
                    else
                    {
                        TCPCommunication.send_message_tcp(sslStream, "REJECT");
                        sslStream.Close();
                        client.Close();
                    }
                }
                else if (String.Compare(response, "FIND_P") == 0)
                {
                    //sw = Stopwatch.StartNew();
                    string sender_key = TCPCommunication.recieve_message_tcp(sslStream);
                    if (peers.ContainsKey(sender_key))
                    {
                        TCPCommunication.send_message_tcp(sslStream, "ACCEPT");

                        string receiver_key = TCPCommunication.recieve_message_tcp(sslStream);

                        if (peers.ContainsKey(response))
                        {
                            TCPCommunication.send_message_tcp(sslStream, "FOUND");
                        }
                        else
                        {
                            List<IPEndPoint> superpeer_neighbours_list = new List<IPEndPoint>(superpeer_neighbours.Keys);
                            int count = 0;
                            foreach (var neighbour in superpeer_neighbours_list)
                            {
                                message_tunnel[neighbour] = null;
                                message_buffer[(count++) + ":SEARCH:" + receiver_key + ":" + sender_key+":"+hop_count] = neighbour;
                            }
                            new Thread(() => wait_reply(sslStream, receiver_key, sender_key)).Start();
                        }
                    }
                    else
                    {
                        TCPCommunication.send_message_tcp(sslStream, "REJECT");
                        sslStream.Close();
                        client.Close();
                    }
                }
                else if (String.Compare(response, "CONNECT_P") == 0)
                {
                    string sender_key = TCPCommunication.recieve_message_tcp(sslStream);
                    if (peers.ContainsKey(sender_key))
                    {
                        TCPCommunication.send_message_tcp(sslStream, "ACCEPT");

                        response = TCPCommunication.recieve_message_tcp(sslStream);
                        Console.WriteLine($"Connection request received for {response}");

                        IPEndPoint sender_ip = (IPEndPoint)client.Client.RemoteEndPoint;
                        IPEndPoint receiver_ip = peers[response];

                        if (pending_requests.ContainsKey(receiver_ip))
                        {
                            
                            TCPCommunication.send_message_tcp(sslStream, "ACCEPT");
                            TCPCommunication.send_message_tcp(sslStream, pending_requests[receiver_ip].ToString());

                            byte[] data = new Byte[256];
                            sslStream.Read(data, 0, data.Length);
                            response = Encoding.UTF8.GetString(data);

                            PublicKeyCoordinates request_key = JsonConvert.DeserializeObject<PublicKeyCoordinates>(response);

                            data = new Byte[256];
                            data = Encoding.UTF8.GetBytes(client_keys[receiver_ip].ToString());
                            sslStream.Write(data);
                            sslStream.Flush();

                            client_keys[receiver_ip] = request_key;

                            sslStream.Close();
                            client.Close();


                            /*Thread.Sleep(1000);
                            pending_requests.Remove(receiver_ip);

                            sslStream.Close();
                            client.Close();*/
                        }
                        else
                        {
                            TCPCommunication.send_message_tcp(sslStream, "REJECT");
                            sslStream.Close();
                            client.Close();
                        }
                    }
                    else
                    {
                        TCPCommunication.send_message_tcp(sslStream, "REJECT");
                        sslStream.Close();
                        client.Close();
                    }

                }
                else if (String.Compare(response, "LISTEN_P") == 0)
                {
                    string sender_key = TCPCommunication.recieve_message_tcp(sslStream);
                    if (peers.ContainsKey(sender_key))
                    {
                        //response = TCPCommunication.recieve_message_tcp(sslStream);
                        Console.WriteLine($"Listen request received for {response}");

                        Random random = new Random();
                        int dtls_port = random.Next(20000, 40000);

                        IPEndPoint listen_ip = (IPEndPoint)client.Client.RemoteEndPoint;

                        pending_requests[listen_ip] = dtls_port;
                        
                        new Thread(() => handle_relay(dtls_port, listen_ip, sslStream)).Start();
                        //Thread.Sleep(1000);

                        //TCPCommunication.send_message_tcp(sslStream, "ACCEPT");
                        
                        //TCPCommunication.send_message_tcp(sslStream, "ACCEPT");

                        //pending_requests.Add(listen_ip);

                        /*sslStream.Close();
                        client.Close();*/
                    }
                    else
                    {
                        TCPCommunication.send_message_tcp(sslStream, "REJECT");
                        sslStream.Close();
                        client.Close();
                    }


                    //new Thread(() => handle_relay(relay_ip)).Start();
                }
                else
                {
                    Console.WriteLine("unrecognized command");
                }
            }
        }

        static void handle_relay(int port, IPEndPoint listen_ip, SslStream listen_stream)
        {
            //pending_requests.Remove(client1);

            Console.WriteLine("start relay");

            DTLSServer dtls_server0 = new DTLSServer(local_port.ToString(), new byte[] { 0xBA, 0xA0 });
            DTLSServer dtls_server1 = new DTLSServer(port.ToString(), new byte[] { 0xBA, 0xA0 });


                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    dtls_server0.Unbuffer = "winpty.exe";
                    dtls_server0.Unbuffer_Args = "-Xplain -Xallow-non-tty";
                    dtls_server1.Unbuffer = "winpty.exe";
                    dtls_server1.Unbuffer_Args = "-Xplain -Xallow-non-tty";
                }
                else 
                {
                    dtls_server0.Unbuffer = "stdbuf";
                    dtls_server0.Unbuffer_Args = "-i0 -o0";
                    dtls_server1.Unbuffer = "stdbuf";
                    dtls_server1.Unbuffer_Args = "-i0 -o0";
                }

                

            dtls_server0.Start();
            dtls_server1.Start();

            TCPCommunication.send_message_tcp(listen_stream, "ACCEPT");

            byte[] data = new Byte[256];
            listen_stream.Read(data, 0, data.Length);
            string response = Encoding.UTF8.GetString(data);

            PublicKeyCoordinates listen_pub_key = JsonConvert.DeserializeObject<PublicKeyCoordinates>(response);
            client_keys[listen_ip] = listen_pub_key;

            while(client_keys[listen_ip] == listen_pub_key);

            data = new Byte[256];
            data = Encoding.UTF8.GetBytes(client_keys[listen_ip].ToString());
            listen_stream.Write(data);
            listen_stream.Flush();

            listen_stream.Close();

            new Thread(() => dtls_server0.GetStream().CopyTo(dtls_server1.GetStream(), 16)).Start();
            new Thread(() => dtls_server1.GetStream().CopyTo(dtls_server0.GetStream(), 16)).Start();

            dtls_server0.WaitForExit();
            dtls_server1.WaitForExit();
        }
    }
}
