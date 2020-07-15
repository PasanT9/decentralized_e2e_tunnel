using System;
using System.Text;
using System.Net;
using System.Net.Sockets;

namespace udp_hole_punching
{
    class Program
    {
        static void Main(string[] args)
        {
            IPAddress serverIP = IPAddress.Parse("80.211.12.100");     // Server IP
            int port = 27006;                                           // Server port
            IPEndPoint ipEndPoint = new IPEndPoint(serverIP,port);      
            
            string response = SendMessageToServer("hello server, this is the client", ipEndPoint);      // Send the message to the server
            Console.WriteLine(response);
            string[] splitter = response.Split(':');
            IPAddress peerIP = IPAddress.Parse(splitter[0]);     // Server IP
            int peerPort = Int32.Parse(splitter[1]);                                    // Server port
            ipEndPoint = new IPEndPoint(peerIP,peerPort);  
            response = SendMessageToServer("hello peer, this is another peer", ipEndPoint);
            Console.WriteLine(response);

        }

        public static string SendMessageToServer(string message, IPEndPoint serverAddress)
        {
            string serverResponse = string.Empty;       // The variable which we will use to store the server response
        
            using (UdpClient client = new UdpClient(1234))
            {
                byte[] data = Encoding.UTF8.GetBytes(message);      // Convert our message to a byte array
                client.Send(data, data.Length, serverAddress);      // Send the date to the server
                serverResponse = Encoding.UTF8.GetString(client.Receive(ref serverAddress));    // Retrieve the response from server as byte array and convert it to string
            }
            return serverResponse;
        }


    }
}