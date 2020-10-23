using System;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

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

        static X509Certificate2 server_cert;
        static IPAddress local_ip;
        static int local_port;
        static string server_ip;
        static int server_port;
        static int peers_count;

        static string neighbour_ip;
        static int neighbour_port;

        static TcpListener server;

        static IPEndPoint ipLocalEndPoint;

        static List<IPEndPoint> exit_neighbours;
        static List<IPEndPoint> change_neighbours;

        static Stopwatch sw;

        public static void insert_peers(string[] new_peers)
        {
            for (int i = 0; i < new_peers.Length - 1; ++i)
            {
                peers[new_peers[i]] = null;
                ++peers_count;
            }
        }

        static void connect_neighbour(IPEndPoint neighbour)
        {
            Console.WriteLine("Connecting new neighbour");
            server.Server.Shutdown(SocketShutdown.Both);
            server.Stop();


            IPEndPoint ipLocalEndPoint = new IPEndPoint(local_ip, local_port);

            //Initiate connection with neighbour (Get 1/3 of neighbours peers)
            TcpClient client = new TcpClient(ipLocalEndPoint);

            client.Connect(neighbour.Address, neighbour.Port);

            SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(SSLValidation.ValidateServerCertificate), null);
            SSLValidation.authenticate_client(sslStream);

            TCPCommunication.send_message_tcp(sslStream, "NEIGHBOUR");

            string response = TCPCommunication.recieve_message_tcp(sslStream);
            Console.WriteLine(response);
            if (String.Compare(response, "SUCCESS") == 0)
            {
                superpeer_neighbours[neighbour] = sslStream;

                KeyValuePair<IPEndPoint, SslStream> new_neighbour = new KeyValuePair<IPEndPoint, SslStream>(neighbour, sslStream);
                new Thread(() => listen_neighbours(new_neighbour)).Start();

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

        //POP
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
                    Console.WriteLine($"Receive({ip}): {response}");
                    if (String.Compare(response, "END") == 0)
                    {
                        TCPCommunication.send_message_tcp(sslStream, "ACCEPT_END");
                        disconnect_neighbour(ip);

                        break;
                        /*disconnect_neighbour = neighbour;
                        break;*/
                    }

                    else if (String.Compare(response, "ACCEPT_END") == 0)
                    {
                        // TCPCommunication.send_message_tcp(sslStream, "ACCEPT_END");

                        disconnect_neighbour(ip);

                        break;
                        /*disconnect_neighbour = neighbour;
                        break;*/
                    }
                    else if (String.Compare(response, "EXIT") == 0)
                    {

                        recieve_peers(sslStream);
                        response = TCPCommunication.recieve_message_tcp(sslStream);

                        Console.WriteLine(response);

                        temp_split = response.Split(':');
                        string neighbour_ip = temp_split[0];
                        int neighbour_port = Int32.Parse(temp_split[1]);
                        string condition = temp_split[2];

                        TCPCommunication.send_message_tcp(sslStream, "ACCEPT_EXIT");
                        if (String.Compare(condition, "Y") == 0)
                        {
                            //Thread.Sleep(2000);
                            Console.WriteLine("Here");
                            connect_neighbour(new IPEndPoint(IPAddress.Parse(neighbour_ip), neighbour_port));

                            //connect_neighbour = new IPEndPoint(IPAddress.Parse(neighbour_ip), neighbour_port);
                        }
                        disconnect_neighbour(ip);
                        //disconnect_neighbour = neighbour;
                        break;
                    }
                    else if (String.Compare(response, "ACCEPT_EXIT") == 0)
                    {
                        disconnect_neighbour(ip);
                        //disconnect_neighbour = neighbour;
                        break;
                    }
                    else
                    {
                        temp_split = response.Split(':');

                        string op_code = temp_split[0];
                        string data0 = (temp_split.Length >= 2) ? temp_split[1] : "";
                        string data1 = (temp_split.Length >= 3) ? temp_split[2] : "";
                        string data2 = (temp_split.Length == 4) ? temp_split[3] : "";

                        if (String.Compare(op_code, "SEARCH") == 0)
                        {
                            Console.WriteLine("search request recieved for: " + data0);
                            if (peers.ContainsKey(data0))
                            {
                                Console.WriteLine("Key is found");
                                //peers.Remove(data0);
                                Console.WriteLine("Sending key");
                                peers[data1] = null;
                                Console.WriteLine("add peer " + data1);
                                TCPCommunication.send_message_tcp(sslStream, "FOUND:" + data0 + ":" + local_ip.ToString() + ":" + local_port);
                                Console.WriteLine("Sent");
                            }
                            else
                            {
                                Console.WriteLine("search recieved from: " + ip);
                                foreach (var dest in superpeer_neighbours)
                                {
                                    if (!dest.Key.Equals(ip))
                                    {
                                        Console.WriteLine("Adding search to buffer for: " + dest.Key);
                                        message_tunnel[dest.Key] = ip;
                                        new Thread(() => remove_tunnel(dest.Key)).Start();
                                        message_buffer[-1 + ":SEARCH:" + data0 + ":" + data1] = dest.Key;
                                    }
                                }
                                /*for (int i = 0; i < superpeer_neighbours.Count; ++i)
                                {
                                    if ()
                                        message_buffer[i + ":" + data0] = neighbour;
                                    Console.WriteLine("Add message " + data0 + " for ip: " + neighbour.ToString());
                                }*/
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
            int count = index * 1000;
            bool exit_neighbour = false;
            bool break_loop = false;
            while (true)
            {
                if (exit_neighbours.Count != 0)
                {

                    foreach (IPEndPoint neighbour in exit_neighbours.ToArray())
                    {
                        Console.WriteLine("Disconnecting neighbour: " + neighbour.ToString());
                        TCPCommunication.send_message_tcp(superpeer_neighbours[neighbour], "EXIT");
                        if (!exit_neighbour)
                        {
                            transfer_peers(superpeer_neighbours[neighbour], 2);
                            TCPCommunication.send_message_tcp(superpeer_neighbours[neighbour], exit_neighbours[superpeer_neighbours.Count - 1].ToString() + ":Y");
                            exit_neighbour = true;
                        }
                        else
                        {
                            transfer_peers(superpeer_neighbours[neighbour], 1);
                            TCPCommunication.send_message_tcp(superpeer_neighbours[neighbour], exit_neighbours[superpeer_neighbours.Count - 1].ToString() + ":N");
                            break_loop = true;

                        }

                    }
                    exit_neighbours.Clear();
                    if (break_loop)
                    {
                        break;
                    }
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



                                //Get corresponding destination of the message
                                IPEndPoint destination_ip = message_buffer[message_full];

                                if (destination_ip == neighbour)
                                {

                                    //message_tunnel[neighbour] = restrict_ip;
                                    //TCPCommunication.send_message_tcp(superpeer_neighbours[neighbour], "SEARCH:" + message);
                                    if (data0 != "")
                                    {
                                        Console.WriteLine($"Sending({neighbour}): {message}:{data0}");
                                        TCPCommunication.send_message_tcp(superpeer_neighbours[neighbour], message + ":" + data0 + ":" + data1);
                                    }
                                    else
                                    {
                                        Console.WriteLine($"Sending({neighbour}): {message}");
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

            IPEndPoint neighbour;
            var neighbour_itr = superpeer_neighbours.GetEnumerator();
            neighbour_itr.MoveNext();
            neighbour = neighbour_itr.Current.Key;
            exit_neighbours.Add(neighbour);
            //Thread.Sleep(1000);

            neighbour_itr.MoveNext();
            neighbour = neighbour_itr.Current.Key;
            exit_neighbours.Add(neighbour);

            Thread.Sleep(4000);

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

            recieve_peers(sslStream);

            response = TCPCommunication.recieve_message_tcp(sslStream);
            Console.WriteLine(response);

            if (response != "SUCCESS")
            {
                temp_split = response.Split(':');
                neighbour_ip = temp_split[0];
                neighbour_port = Int32.Parse(temp_split[1]);
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
                    Thread.Sleep(5000);
                    message_buffer[count + ":HELLO"] = neighbour;
                    count++;
                }
            }
            Console.WriteLine("Exit hello_neighbour thread");
        }
        static void Main(string[] args)
        {
            //To handle on exit function to distribute peers upon exit
            Console.CancelKeyPress += On_exit;
            peers_count = 0;


            neighbour_ip = null;
            neighbour_port = -1;

            Console.Write("Server ip: ");
            server_ip = Console.ReadLine();

            Console.Write("Server port: ");
            server_port = Convert.ToInt32(Console.ReadLine());


            //Initiate database
            superpeer_neighbours = new Dictionary<IPEndPoint, SslStream>();
            peers = new Dictionary<string, IPEndPoint>();
            exit_neighbours = new List<IPEndPoint>();
            change_neighbours = new List<IPEndPoint>();
            message_buffer = new Dictionary<string, IPEndPoint>();
            message_tunnel = new Dictionary<IPEndPoint, IPEndPoint>();
            reply_buffer = new Dictionary<string, string>();
            pending_requests = new Dictionary<IPEndPoint, int>();

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

            init_connection(neighbour_ip, neighbour_port);

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
            string response;
            /*Thread.Sleep(8000);
            if (reply_buffer.ContainsKey(receiver_key))
            {
                //peers[key] = null;
                TCPCommunication.send_message_tcp(sslStream, reply_buffer[receiver_key]);

                reply_buffer.Remove(receiver_key);
                //TCPCommunication.send_message_tcp(sslStream, "FOUND");

                //response = TCPCommunication.recieve_message_tcp(sslStream);
                peers.Remove(sender_key);
                Console.WriteLine(sender_key + " is removed");
                //TCPCommunication.send_message_tcp(sslStream, "SUCCESS");
                sslStream.Close();

            }
            else
            {
                TCPCommunication.send_message_tcp(sslStream, "NOTFOUND");
                sslStream.Close();
            }*/

                while(!reply_buffer.ContainsKey(receiver_key));
                var time = sw.Elapsed;
                Console.WriteLine("Time elapsed: " + time);
                TCPCommunication.send_message_tcp(sslStream, reply_buffer[receiver_key]);

                reply_buffer.Remove(receiver_key);
                //TCPCommunication.send_message_tcp(sslStream, "FOUND");

                //response = TCPCommunication.recieve_message_tcp(sslStream);
                peers.Remove(sender_key);
                Console.WriteLine(sender_key + " is removed");
                //TCPCommunication.send_message_tcp(sslStream, "SUCCESS");
                sslStream.Close();

                
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
                Console.WriteLine(response);
                if (String.Compare(response, "HELLO_S") == 0)
                {
                    Console.WriteLine(((IPEndPoint)client.Client.RemoteEndPoint) + " is requesting to join superpeer network");

                    response = TCPCommunication.recieve_message_tcp(sslStream);


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

                        Thread.Sleep(500);

                        TCPCommunication.send_message_tcp(sslStream, neighbour.ToString());
                        superpeer_neighbours[(IPEndPoint)client.Client.RemoteEndPoint] = sslStream;

                        KeyValuePair<IPEndPoint, SslStream> new_neighbour = new KeyValuePair<IPEndPoint, SslStream>((IPEndPoint)client.Client.RemoteEndPoint, sslStream);
                        new Thread(() => listen_neighbours(new_neighbour)).Start();
                    }
                    else
                    {
                        string[] temp_split = response.Split(':');
                        string neighbour_ip = temp_split[0];
                        int neighbour_port = Int32.Parse(temp_split[1]);

                        IPEndPoint old_neighbour = new IPEndPoint(IPAddress.Parse(neighbour_ip), neighbour_port);


                        TCPCommunication.send_message_tcp(sslStream, "SUCCESS");
                        superpeer_neighbours[(IPEndPoint)client.Client.RemoteEndPoint] = sslStream;

                        KeyValuePair<IPEndPoint, SslStream> new_neighbour = new KeyValuePair<IPEndPoint, SslStream>((IPEndPoint)client.Client.RemoteEndPoint, sslStream);
                        new Thread(() => listen_neighbours(new_neighbour)).Start();
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
                    TCPCommunication.send_message_tcp(sslStream, "SUCCESS");
                    superpeer_neighbours[(IPEndPoint)client.Client.RemoteEndPoint] = sslStream;

                    KeyValuePair<IPEndPoint, SslStream> new_neighbour = new KeyValuePair<IPEndPoint, SslStream>((IPEndPoint)client.Client.RemoteEndPoint, sslStream);
                    new Thread(() => listen_neighbours(new_neighbour)).Start();
                }
                else if (String.Compare(response, "HELLO_P") == 0)
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
                else if (String.Compare(response, "FIND_P") == 0)
                {
                    sw = Stopwatch.StartNew();
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
                                message_buffer[(count++) + ":SEARCH:" + receiver_key + ":" + sender_key] = neighbour;
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
                            Thread.Sleep(1000);
                            pending_requests.Remove(receiver_ip);

                            sslStream.Close();
                            client.Close();
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

                        IPEndPoint relay_ip = (IPEndPoint)client.Client.RemoteEndPoint;

                        pending_requests[relay_ip] = dtls_port;

                        new Thread(() => handle_relay(dtls_port, relay_ip)).Start();
                        Thread.Sleep(1000);

                        TCPCommunication.send_message_tcp(sslStream, "ACCEPT");

                        //TCPCommunication.send_message_tcp(sslStream, "ACCEPT");

                        //pending_requests.Add(relay_ip);

                        sslStream.Close();
                        client.Close();
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

        static void handle_relay(int port, IPEndPoint receiver)
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

            while (pending_requests.ContainsKey(receiver)) ;

            new Thread(() => dtls_server0.GetStream().CopyTo(dtls_server1.GetStream(), 16)).Start();
            new Thread(() => dtls_server1.GetStream().CopyTo(dtls_server0.GetStream(), 16)).Start();

            dtls_server0.WaitForExit();
            dtls_server1.WaitForExit();
        }
    }
}
