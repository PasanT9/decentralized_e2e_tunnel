using System;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;


using Cryptography;
using Authentication;
using TCP;

namespace superpeer_network
{
    class Program
    {
        static Dictionary<string, IPEndPoint> peers;    //Index of peers
        static Dictionary<IPEndPoint, SslStream> superpeer_neighbours;   //Neighbours of the super peer network

        static List<IPEndPoint> exit_neighbours;

        static Dictionary<string, IPEndPoint> message_buffer;

        static Dictionary<IPEndPoint, IPEndPoint> message_tunnel;

        static Dictionary<string, string> reply_buffer;

        static X509Certificate2 server_cert;    //Server authentication certificate
        static int local_port;
        static IPAddress local_ip;
        static int peers_count; //Number of peers

        static TcpListener server;


        static List<IPEndPoint> change_neighbours;


        //Create random strings to imitate public keys
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
            string hash = HashString.GetHashString(rand_pubkey);
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
                    foreach (var neighbour in superpeer_neighbours_list)
                    {
                        try
                        {
                            response = TCPCommunication.recieve_message_tcp(superpeer_neighbours[neighbour]);
                            Console.WriteLine($"Receive({neighbour}): {response}");
                            if (String.Compare(response, "END") == 0)
                            {

                                TCPCommunication.send_message_tcp(superpeer_neighbours[neighbour], "ACCEPT_END");
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
                                response = TCPCommunication.recieve_message_tcp(superpeer_neighbours[neighbour]);
                                Console.WriteLine(response);
                                temp_split = response.Split(':');
                                string neighbour_ip = temp_split[0];
                                int neighbour_port = Int32.Parse(temp_split[1]);
                                string condition = temp_split[2];

                                Console.WriteLine("Sending");
                                TCPCommunication.send_message_tcp(superpeer_neighbours[neighbour], "ACCEPT_EXIT");
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
                                string data0 = (temp_split.Length >= 2) ? temp_split[1] : "";
                                string data1 = (temp_split.Length == 4) ? temp_split[2] : "";
                                string data2 = (temp_split.Length == 4) ? temp_split[3] : "";

                                if (String.Compare(op_code, "SEARCH") == 0)
                                {
                                    Console.WriteLine("search request recieved for: " + data0);
                                    if (peers.ContainsKey(data0))
                                    {
                                        Console.WriteLine("Key is found");
                                        peers.Remove(data0);
                                        TCPCommunication.send_message_tcp(superpeer_neighbours[neighbour], "FOUND:" + data0 + ":" + local_ip.ToString() + ":" + local_port);
                                    }
                                    else
                                    {
                                        foreach (var dest in superpeer_neighbours)
                                        {
                                            if (dest.Key != neighbour)
                                            {
                                                message_tunnel[dest.Key] = neighbour;
                                                message_buffer[-1 + ":SEARCH:" + data0] = dest.Key;
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
                                    if (message_tunnel.ContainsKey(neighbour))
                                    {
                                        if (message_tunnel[neighbour] != null)
                                        {
                                            Console.WriteLine("Tunnel exists for: " + neighbour + "->" + message_tunnel[neighbour]);
                                            TCPCommunication.send_message_tcp(superpeer_neighbours[message_tunnel[neighbour]], response);
                                        }
                                        else
                                        {
                                            Console.WriteLine("key: " + data0);
                                            Console.WriteLine("Key exists in : " + data1 + ":" + data2);
                                            reply_buffer[data0] = "FOUND:" + data1 + ":" + data2;

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

                    SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(SSLValidation.ValidateServerCertificate), null);
                    SSLValidation.authenticate_client(sslStream);

                    TCPCommunication.send_message_tcp(sslStream, "NEIGHBOUR");
                    response = TCPCommunication.recieve_message_tcp(sslStream);
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
                                string data = (temp_split.Length > 2) ? temp_split[2] : "";
                                //pop


                                //Get corresponding destination of the message
                                IPEndPoint destination_ip = message_buffer[message_full];

                                if (destination_ip == neighbour)
                                {
                                    Console.WriteLine($"Sending({neighbour}): {message}");

                                    //message_tunnel[neighbour] = restrict_ip;
                                    //TCPCommunication.send_message_tcp(superpeer_neighbours[neighbour], "SEARCH:" + message);
                                    if (data != "")
                                    {
                                        TCPCommunication.send_message_tcp(superpeer_neighbours[neighbour], message + ":" + data);
                                    }
                                    else
                                    {
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
                            catch (System.InvalidOperationException e)
                            {
                                Console.WriteLine("neighbours have changed");
                                Thread.Sleep(100);
                                break;
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine(e);
                                break;
                            }
                        }
                    }

                    //Thread.Sleep(2000);
                }
            }
            Console.WriteLine("Thread Closed");
        }

        static void remove_tunnel(IPEndPoint ip)
        {
            Thread.Sleep(10000);
            Console.WriteLine("tunnel " + ip.ToString() + " " + message_tunnel[ip] + " is removed");
            message_tunnel.Remove(ip);
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
            superpeer_neighbours = new Dictionary<IPEndPoint, SslStream>();
            peers = new Dictionary<string, IPEndPoint>();
            exit_neighbours = new List<IPEndPoint>();
            change_neighbours = new List<IPEndPoint>();


            message_buffer = new Dictionary<string, IPEndPoint>();
            message_tunnel = new Dictionary<IPEndPoint, IPEndPoint>();
            reply_buffer = new Dictionary<string, string>();

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

                sslStream.ReadTimeout = 20000;
                sslStream.WriteTimeout = 20000;


                string response = TCPCommunication.recieve_message_tcp(sslStream);
                Console.WriteLine(response);
                if (String.Compare(response, "SUCCESS") == 0)
                {
                    superpeer_neighbours[(IPEndPoint)client.Client.RemoteEndPoint] = sslStream;
                    new Thread(() => handle_neighbour(0)).Start();

                    new Thread(() => hello_neighbour()).Start();
                }
                handle_connections();
            }
            else if (local_port == 28005)
            {
                IPEndPoint ipLocalEndPoint = new IPEndPoint(local_ip, 28005);

                //Initiate connection with neighbour (Get 1/3 of neighbours peers)
                TcpClient client = new TcpClient(ipLocalEndPoint);
                client.Connect("127.0.0.1", 27005);
                SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(SSLValidation.ValidateServerCertificate), null);
                SSLValidation.authenticate_client(sslStream);



                superpeer_neighbours[new IPEndPoint(IPAddress.Parse("127.0.0.1"), 27005)] = sslStream;

                TCPCommunication.send_message_tcp(sslStream, "SUCCESS");
                new Thread(() => handle_neighbour(1)).Start();

                new Thread(() => hello_neighbour()).Start();


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


        public static void insert_peers(string[] new_peers)
        {
            for (int i = 0; i < new_peers.Length - 1; ++i)
            {
                peers[new_peers[i]] = null;
                ++peers_count;
            }
        }

        static void wait_reply(SslStream sslStream, string key)
        {
            string response;
            Thread.Sleep(8000);
            if (reply_buffer.ContainsKey(key))
            {
                peers[key] = null;
                TCPCommunication.send_message_tcp(sslStream, reply_buffer[key]);
                reply_buffer.Remove(key);
                TCPCommunication.send_message_tcp(sslStream, "FOUND");

                /*response = TCPCommunication.recieve_message_tcp(sslStream);

                else if (String.Compare(response, "FIND_P") == 0)
                {
                    response = TCPCommunication.recieve_message_tcp(sslStream);
                    if (peers.ContainsKey(HashString.GetHashString(response)))
                    {
                        TCPCommunication.send_message_tcp(sslStream, "FOUND");
                    }
                    else
                    {//POP
                        List<IPEndPoint> superpeer_neighbours_list = new List<IPEndPoint>(superpeer_neighbours.Keys);
                        int count = 0;
                        foreach (var neighbour in superpeer_neighbours_list)
                        {

                            message_buffer[(count++) + ":SEARCH:" + HashString.GetHashString(response)] = neighbour;
                        }
                        new Thread(() => wait_reply(sslStream, HashString.GetHashString(response))).Start();
                    }
                }
                else
                {
                    Console.WriteLine("Unrecognized command");
                }*/

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
                sslStream.ReadTimeout = 20000;
                sslStream.WriteTimeout = 20000;
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
                    }
                    else
                    {
                        string[] temp_split = response.Split(':');
                        string neighbour_ip = temp_split[0];
                        int neighbour_port = Int32.Parse(temp_split[1]);

                        IPEndPoint old_neighbour = new IPEndPoint(IPAddress.Parse(neighbour_ip), neighbour_port);


                        TCPCommunication.send_message_tcp(sslStream, "SUCCESS");
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
                    TCPCommunication.send_message_tcp(sslStream, "SUCCESS");
                    superpeer_neighbours[(IPEndPoint)client.Client.RemoteEndPoint] = sslStream;
                }
                else if (String.Compare(response, "HELLO_P") == 0)
                {
                    Console.WriteLine((IPEndPoint)client.Client.RemoteEndPoint + " peer is registering");
                    TCPCommunication.send_message_tcp(sslStream, "SUCCESS");
                    response = TCPCommunication.recieve_message_tcp(sslStream);
                    string hash = HashString.GetHashString(response);

                    peers[hash] = (IPEndPoint)client.Client.RemoteEndPoint;

                    Console.WriteLine(response + " is added to peers");
                    sslStream.Close();
                    client.Close();
                }
                else if (String.Compare(response, "FIND_P") == 0)
                {
                    response = TCPCommunication.recieve_message_tcp(sslStream);
                    if (peers.ContainsKey(HashString.GetHashString(response)))
                    {
                        TCPCommunication.send_message_tcp(sslStream, "FOUND");
                    }
                    else
                    {//POP
                        List<IPEndPoint> superpeer_neighbours_list = new List<IPEndPoint>(superpeer_neighbours.Keys);
                        int count = 0;
                        foreach (var neighbour in superpeer_neighbours_list)
                        {
                            message_tunnel[neighbour] = null;
                            message_buffer[(count++) + ":SEARCH:" + HashString.GetHashString(response)] = neighbour;
                        }
                        new Thread(() => wait_reply(sslStream, HashString.GetHashString(response))).Start();
                    }
                }
                else
                {
                    Console.WriteLine("unrecognized command");
                }
            }
        }
    }
}
