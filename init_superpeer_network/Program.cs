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
using System.Security.Cryptography;

namespace superpeer_network
{
    class Program
    {
        static Dictionary<string, IPEndPoint> peers;    //Index of peers
        static Dictionary<IPEndPoint, SslStream> superpeer_neighbours;   //Neighbours of the super peer network

        static List<IPEndPoint> exit_neighbours;

        static Dictionary<string, IPEndPoint> message_buffer;

        static X509Certificate2 server_cert;    //Server authentication certificate
        static int local_port;
        static IPAddress local_ip;
        static int peers_count; //Number of peers

        static int neighbour_count;
        static bool read = false;
        static TcpListener server;


        static List<IPEndPoint> change_neighbours;
        static bool change_neighbour;

        //Create random strings to imitate public keys
        public static string random_string_pop()
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

        public static byte[] GetHash(string inputString)
        {
            using (HashAlgorithm algorithm = SHA256.Create())
                return algorithm.ComputeHash(Encoding.UTF8.GetBytes(inputString));
        }

        public static string GetHashString(string inputString)
        {
            StringBuilder sb = new StringBuilder();
            foreach (byte b in GetHash(inputString))
                sb.Append(b.ToString("X2"));

            return sb.ToString();
        }
        public static string random_string()
        {
            string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            char[] x = new char[88];
            char[] y = new char[88];
            string start = "{\"X\":\"";
            string mid = "\",\"Y\":\"";
            string end = "\"}";

            Random random = new Random();
            for (int i = 0; i < 88; ++i)
            {
                x[i] = chars[random.Next(chars.Length)];
            }

            for (int i = 0; i < 88; ++i)
            {
                y[i] = chars[random.Next(chars.Length)];
            }

            string rand_pubkey = start + (new String(x)) + mid + (new String(y)) + end;
            string hash = GetHashString(rand_pubkey);
            //Console.WriteLine(hash);
            return hash;
        }

        //{"X":"AC5u+XA4AIuOmyn6bPL7XSvqnAp/jAcTmpmCH+WF8NnhFryI28ys5zyybp5APdNAjrzA68Tl+Hmir4TKF5ynRvpw","Y":"AVDMOhraWYBRb9YHJG0XjkWiuJwPo+xYEfUNB6os6L/QlGw3DS44TPZwTKlBpCugmgmAigGZH4GD1RsWGu6hr6qk"}
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
        static void listen_neighbours()
        {
            string response = "";
            IPEndPoint disconnect_neighbour = null;
            IPEndPoint connect_neighbour = null;
            string[] temp_split = null;
            while (true)
            {
                if (exit_neighbours.Count != 0)
                {
                    Console.WriteLine("Exit neighbour");
                }
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
                                Console.WriteLine(response);
                                temp_split = response.Split(':');
                                string neighbour_ip = temp_split[0];
                                int neighbour_port = Int32.Parse(temp_split[1]);
                                string condition = temp_split[2];

                                Console.WriteLine("Sending");
                                send_message_tcp(superpeer_neighbours[neighbour], "ACCEPT_EXIT");
                                Console.WriteLine("Sent");
                                if (String.Compare(condition, "Y") == 0)
                                {
                                    //Thread.Sleep(2000);
                                    Console.WriteLine("Here");
                                    connect_neighbour = new IPEndPoint(IPAddress.Parse(neighbour_ip), neighbour_port);
                                }


                                disconnect_neighbour = neighbour;
                                break;
                            }
                            else if (String.Compare(response, "ACCEPT_EXIT") == 0)
                            {
                                disconnect_neighbour = neighbour;
                                break;
                            }
                            else
                            {
                                temp_split = response.Split(':');
                                string op_code = temp_split[0];
                                string data = (temp_split.Length == 2) ? temp_split[1] : "";

                                if (String.Compare(op_code, "SEARCH") == 0)
                                {
                                    Console.WriteLine("search request recieved for: " + data);
                                    if (peers.ContainsKey(data))
                                    {
                                        Console.WriteLine("Key is found");
                                    }
                                    else
                                    {
                                        for (int i = 0; i < superpeer_neighbours.Count; ++i)
                                        {
                                            message_buffer[i + ":" + data] = neighbour;
                                            Console.WriteLine("Add message " + data + " for ip: " + neighbour.ToString());
                                        }
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

                    client.Connect(temp_split[0], Int32.Parse(temp_split[1]));

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
            int count = index * 1000;
            while (true)
            {
                if (exit_neighbours.Count != 0)
                {

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
                            if (message_buffer.Count != 0)
                            {

                                var message_itr = message_buffer.GetEnumerator();
                                message_itr.MoveNext();
                                string message = message_itr.Current.Key.Split(':')[1];
                                IPEndPoint restrict_ip = message_itr.Current.Value;
                                Console.WriteLine("restrict: " + restrict_ip.ToString());
                                Console.WriteLine("current: " + neighbour.ToString());
                                if (restrict_ip != neighbour)
                                {
                                    Console.WriteLine("Sending search request");
                                    send_message_tcp(superpeer_neighbours[neighbour], "SEARCH:" + message);
                                }
                                message_buffer.Remove(message);
                            }
                            else
                            {
                                Console.WriteLine("sending: " + count);
                                send_message_tcp(superpeer_neighbours[neighbour], "HELLO(" + count++ + ")");
                            }
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

        static void Main(string[] args)
        {
            superpeer_neighbours = new Dictionary<IPEndPoint, SslStream>();
            peers = new Dictionary<string, IPEndPoint>();
            exit_neighbours = new List<IPEndPoint>();
            change_neighbours = new List<IPEndPoint>();


            message_buffer = new Dictionary<string, IPEndPoint>();

            insert_peers_random();

            //Add certificate to the certificate store
            server_cert = new X509Certificate2("/home/pasan/Documents/FYP_certificates/ssl-certificate.pfx", "password", X509KeyStorageFlags.PersistKeySet);
            X509Store store = new X509Store(StoreName.My);
            store.Open(OpenFlags.ReadWrite);
            store.Add(server_cert);

            local_ip = IPAddress.Parse("127.0.0.1");

            //Initiate first and seconds servers of the super peer network
            // TcpListener server;

            Console.Write("Local port: "); //Use 27005 and 28005
            local_port = Convert.ToInt32(Console.ReadLine());

            if (local_port == 27005)
            {
                server = new TcpListener(local_ip, local_port);
                server.Start();

                TcpClient client = server.AcceptTcpClient();
                SslStream sslStream = new SslStream(client.GetStream(), false);
                sslStream.AuthenticateAsServer(server_cert, clientCertificateRequired: false, SslProtocols.Tls13, checkCertificateRevocation: true);

                sslStream.ReadTimeout = 10000;
                sslStream.WriteTimeout = 10000;


                string response = recieve_message_tcp(sslStream);
                Console.WriteLine(response);
                if (String.Compare(response, "SUCCESS") == 0)
                {
                    superpeer_neighbours[(IPEndPoint)client.Client.RemoteEndPoint] = sslStream;
                    new Thread(() => handle_neighbour(0)).Start();
                }
                handle_connections();
            }
            else if (local_port == 28005)
            {
                IPEndPoint ipLocalEndPoint = new IPEndPoint(local_ip, 28005);

                //Initiate connection with neighbour (Get 1/3 of neighbours peers)
                TcpClient client = new TcpClient(ipLocalEndPoint);
                client.Connect("127.0.0.1", 27005);
                SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
                authenticate_client(sslStream);



                superpeer_neighbours[new IPEndPoint(IPAddress.Parse("127.0.0.1"), 27005)] = sslStream;

                send_message_tcp(sslStream, "SUCCESS");
                new Thread(() => handle_neighbour(1)).Start();


                server = new TcpListener(local_ip, local_port);
                server.Start();
                handle_connections();
            }


            //Connecet to neighbour


            //Handle requests from other super peers
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


        public static void insert_peers(string[] new_peers)
        {
            for (int i = 0; i < new_peers.Length - 1; ++i)
            {
                peers[new_peers[i]] = null;
                ++peers_count;
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
                        int neighbour_port = Int32.Parse(temp_split[1]);

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
                    send_message_tcp(sslStream, "SUCCESS");
                    superpeer_neighbours[(IPEndPoint)client.Client.RemoteEndPoint] = sslStream;
                }
                else if (String.Compare(response, "HELLO_P") == 0)
                {
                    Console.WriteLine((IPEndPoint)client.Client.RemoteEndPoint + " peer is registering");
                    send_message_tcp(sslStream, "SUCCESS");
                    response = recieve_message_tcp(sslStream);
                    string hash = GetHashString(response);

                    peers[hash] = (IPEndPoint)client.Client.RemoteEndPoint;

                    Console.WriteLine(response + " is added to peers");
                    sslStream.Close();
                    client.Close();
                }
                else if (String.Compare(response, "FIND_P") == 0)
                {
                    response = recieve_message_tcp(sslStream);
                    if (peers.ContainsKey(GetHashString(response)))
                    {
                        send_message_tcp(sslStream, "FOUND");
                    }
                    else
                    {
                        for (int i = 0; i < superpeer_neighbours.Count; ++i)
                        {
                            message_buffer[i + ":" + GetHashString(response)] = null;
                        }
                        send_message_tcp(sslStream, "NOTFOUND");
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
            Byte[] bytes = new Byte[512];
            sslStream.Read(bytes, 0, bytes.Length);
            string message = Encoding.UTF8.GetString(bytes);
            Request reply = JsonConvert.DeserializeObject<Request>(message);
            return reply.body;
        }
    }
}
