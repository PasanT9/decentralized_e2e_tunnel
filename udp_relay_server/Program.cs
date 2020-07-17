using System;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Collections.Generic;  

namespace udp_relay_server
{
class Program
    {
        static Dictionary<int, IPEndPoint> client_map;  
        static Dictionary<IPEndPoint, int> client_map_reverse;
        static string[] client_buffers;
        static int client_count;

        static void Main(string[] args)
        {
            Console.WriteLine("Server is starting");
            client_count = 0;

            client_map = new Dictionary<int, IPEndPoint>();
            client_map_reverse = new Dictionary<IPEndPoint, int>();
            client_buffers = new string[2];
            
            client_buffers[0] = null;
            client_buffers[1] = null;
            con_register();

        }

        public static void con_relay_listner(UdpClient client, IPEndPoint ip, int peer){
            while(true)
            {
                string response = Encoding.UTF8.GetString(client.Receive(ref ip));
                Console.WriteLine("client"+peer+": "+ response);
                client_buffers[peer] = response;
            }

        }

        public static void con_register()
        {
            int port = 27005;
            Console.WriteLine("Server is listening on port " + port + " for registering peers");
            int count = 0;
            while(count < 2)
            {
                UdpClient udpListener = new UdpClient(port);
                IPEndPoint ipEndPoint = new IPEndPoint(IPAddress.Any, port);
                byte[] receivedBytes = udpListener.Receive(ref ipEndPoint);
                string message = Encoding.UTF8.GetString(receivedBytes);   
                if(message == "HELLO"){
                    byte[] response = Encoding.UTF8.GetBytes("ACCEPTED");   // Convert the reponse we want to send to the client to byte array
                    udpListener.Send(response, response.Length, ipEndPoint);
                    Console.WriteLine("Client: " + ipEndPoint + " requesting a connection");
                    if(client_map.ContainsValue(ipEndPoint)){
                        Console.WriteLine("Client is already connected");
                        response = Encoding.UTF8.GetBytes(client_map_reverse[ipEndPoint].ToString());   // Convert the reponse we want to send to the client to byte array
                        udpListener.Send(response, response.Length, ipEndPoint);
                    }
                    else{
                        client_map[client_count] = ipEndPoint;
                        client_map_reverse[ipEndPoint] = client_count++;
                        response = Encoding.UTF8.GetBytes((client_count-1).ToString());   // Convert the reponse we want to send to the client to byte array
                        udpListener.Send(response, response.Length, ipEndPoint);
                    }
                    udpListener.Close();
                    ++count;
                }
                else{
                    byte[] response = Encoding.UTF8.GetBytes("unsuccessful connection establishment");   // Convert the reponse we want to send to the client to byte array
                    udpListener.Send(response, response.Length, ipEndPoint);
                    udpListener.Close();
                }       
            }
            Console.WriteLine("2 clients registered");
            con_request();
        }

        public static void con_request()
        {
            Console.WriteLine("Starting relay service");
            int port = 27005;
            UdpClient udpListener = new UdpClient(port);
            IPEndPoint ipEndPoint = new IPEndPoint(IPAddress.Any, port);
            byte[] receivedBytes = udpListener.Receive(ref ipEndPoint);
            string message = Encoding.UTF8.GetString(receivedBytes);
            int peer0 = client_map_reverse[ipEndPoint];
            int peer1 = Int32.Parse(message);
            Console.WriteLine("Client "+ peer1 + " requesting a connection to " + peer1);
            udpListener.Close();


            UdpClient client0 = new UdpClient();
            IPEndPoint peerIP0 = client_map[peer0];
            byte[] connection_msg0 = Encoding.UTF8.GetBytes("Connected to "+ peer1);

            UdpClient client1 = new UdpClient();
            IPEndPoint peerIP1 = client_map[peer1];
            byte[] connection_msg1 = Encoding.UTF8.GetBytes("Connected to "+ peer0);

            
            client0.Send(connection_msg0, connection_msg0.Length, peerIP0);
            client1.Send(connection_msg1, connection_msg1.Length, peerIP1);

            Thread peer0_t = new Thread(() => con_relay_listner(client0, peerIP0, 0));
            Thread peer1_t = new Thread(() => con_relay_listner(client1, peerIP1, 1));
            peer0_t.Start();
            peer1_t.Start();

            while(true)
            {
                if(client_buffers[0] != null){
                    byte[] data = Encoding.UTF8.GetBytes(client_buffers[0]); 
                    client_buffers[0] = null;
                    client1.Send(data, data.Length, peerIP1);
                }

                if(client_buffers[1] != null){
                    byte[] data = Encoding.UTF8.GetBytes(client_buffers[1]); 
                    client_buffers[1] = null;
                    client0.Send(data, data.Length, peerIP0);
                }
            }
        }

    }
}
