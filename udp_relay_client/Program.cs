using System;
using System.Text;
using System.Net;
using System.Net.Sockets;
namespace udp_relay_client
{
    class Program
    {
        static int address;
        static void Main(string[] args)
        {
            IPAddress serverIP = IPAddress.Parse("127.0.0.1");     // Server IP
            int port = 27005;   // Server port
            IPEndPoint ipEndPoint = new IPEndPoint(serverIP,port);      
            while(true)
            {
                string message = Console.ReadLine();
                SendMessageToServer(message, ipEndPoint);      // Send the message to the server
            }
        }

        public static void SendMessageToServer(string message, IPEndPoint serverAddress)
        {
            string serverResponse = string.Empty;       // The variable which we will use to store the server response

            using (UdpClient client = new UdpClient())
            {
                byte[] data = Encoding.UTF8.GetBytes(message);      // Convert our message to a byte array
                client.Send(data, data.Length, serverAddress);      // Send the date to the server
                serverResponse = Encoding.UTF8.GetString(client.Receive(ref serverAddress)); 
                Console.WriteLine(serverResponse);
                if(serverResponse == "ACCEPTED"){
                    serverResponse = Encoding.UTF8.GetString(client.Receive(ref serverAddress)); 
                    Console.WriteLine(serverResponse);
                    if(serverResponse != "FAIL"){
                        address = Int16.Parse(serverResponse);
                        Console.WriteLine("Successful connection establishment");
                        Console.WriteLine("My peer address: " + address);
                        string init = Console.ReadLine();
                        if(init == "y"){
                            int dest_address = Int32.Parse(Console.ReadLine());
                            data = Encoding.UTF8.GetBytes(dest_address.ToString());      // Convert our message to a byte array
                            client.Send(data, data.Length, serverAddress); 
                            serverResponse = Encoding.UTF8.GetString(client.Receive(ref serverAddress)); 
                            Console.WriteLine(serverResponse);
                            while(true)
                            {
                                string msg = Console.ReadLine();
                                data = Encoding.UTF8.GetBytes(msg);
                                client.Send(data, data.Length, serverAddress); 
                                serverResponse = Encoding.UTF8.GetString(client.Receive(ref serverAddress)); 
                                Console.WriteLine(serverResponse);
                            }
                        }
                        else{
                            serverResponse = Encoding.UTF8.GetString(client.Receive(ref serverAddress)); 
                            Console.WriteLine(serverResponse);
                            while(true)
                            {
                                serverResponse = Encoding.UTF8.GetString(client.Receive(ref serverAddress)); 
                                Console.WriteLine(serverResponse);
                                string msg = Console.ReadLine();
                                data = Encoding.UTF8.GetBytes(msg);
                                client.Send(data, data.Length, serverAddress); 
                            }
                        }
                    }
                }
            }
        }
    }
}
