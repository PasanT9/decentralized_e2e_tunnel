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
        static int client_count;
        static void Main(string[] args)
        {
            client_count = 0;
            client_map = new Dictionary<int, IPEndPoint>();
            client_map_reverse = new Dictionary<IPEndPoint, int>();
            Console.WriteLine("Server is starting");
            ServerForm_Load();
        }

        public static void ServerForm_Load()
        {
            int port = 27005;
            Console.WriteLine("Server is listening on port " + port);
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
                    count++;
                    udpListener.Close();
                }
                else{
                    byte[] response = Encoding.UTF8.GetBytes("unsuccessful connection establishment");   // Convert the reponse we want to send to the client to byte array
                    udpListener.Send(response, response.Length, ipEndPoint);
                    udpListener.Close();
                }       
            }
            UdpClient udpListener1 = new UdpClient(port);
            IPEndPoint ipEndPoint1 = new IPEndPoint(IPAddress.Any, port);
            byte[] receivedBytes1 = udpListener1.Receive(ref ipEndPoint1);
            string message1 = Encoding.UTF8.GetString(receivedBytes1);
            int peer0 = client_map_reverse[ipEndPoint1];
            int peer1 = Int32.Parse(message1);
            Console.WriteLine("Client "+ peer1 + " requesting a connection to " + peer1);
            udpListener1.Close();

            string serverResponse = string.Empty;       // The variable which we will use to store the server response
        
            UdpClient client0 = new UdpClient();
            IPEndPoint peerIP0 = client_map[peer0];
            byte[] connection_msg0 = Encoding.UTF8.GetBytes("Connected to "+ peer1);

            UdpClient client1 = new UdpClient();
            IPEndPoint peerIP1 = client_map[peer1];
            byte[] connection_msg1 = Encoding.UTF8.GetBytes("Connected to "+ peer0);

            
            client0.Send(connection_msg0, connection_msg0.Length, peerIP0);
            client1.Send(connection_msg1, connection_msg1.Length, peerIP1);


            while(true)
            {
                string response0 = Encoding.UTF8.GetString(client0.Receive(ref peerIP0));
                byte[] data0 = Encoding.UTF8.GetBytes(response0); 
                client1.Send(data0, data0.Length, peerIP1);
                string response1 = Encoding.UTF8.GetString(client1.Receive(ref peerIP1));
                byte[] data1 = Encoding.UTF8.GetBytes(response1); 
                client0.Send(data1, data1.Length, peerIP0);
            }
        }

    }
}
