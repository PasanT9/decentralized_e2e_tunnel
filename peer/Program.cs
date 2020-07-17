using System;
using System.Text;
using System.Net;
using System.Net.Sockets;

namespace peer
{
    class Program
    {
        static int connection_address;
        static void Main(string[] args)
        {
            string server_ip = "127.0.0.1";     // Server IP
            int server_port = 27005;   // Server port

            Random random = new Random();
            int local_port = random.Next(20000, 40000);

            IPAddress ipAddress = Dns.GetHostEntry(Dns.GetHostName()).AddressList[0];
            IPEndPoint ipLocalEndPoint = new IPEndPoint(ipAddress, local_port);
            TcpClient client = new TcpClient(ipLocalEndPoint);
            client.Connect(server_ip, server_port);

            init_connection(client);  
            client.Close();
            Console.Write("Do you wanna create a connection(y/n): ");
            string input = Console.ReadLine();

            IPAddress relay_ip = IPAddress.Parse(server_ip);     // Server IP
            IPEndPoint ipEndPoint = new IPEndPoint(relay_ip,server_port);
            UdpClient peer = new UdpClient(ipLocalEndPoint);

            if(input == "y"){
                req_connection(ipEndPoint, peer);
            }
            else{
                listen_connection(ipEndPoint, peer);
            }
        }

        static void init_connection(TcpClient client)
        {
            Byte[] bytes = new Byte[256];

            NetworkStream stream = client.GetStream();
            send_message_tcp(stream, "HELLO");

            stream.Read(bytes, 0, bytes.Length);
            String response = System.Text.Encoding.ASCII.GetString(bytes, 0, bytes.Length);
            connection_address = Int16.Parse(response);
            Console.WriteLine("Recieved address: "+connection_address);
        }

        static void req_connection(IPEndPoint ip, UdpClient client)
        {
            Console.Write("request connection to peer: ");
            String peer_address = Console.ReadLine();
            send_message_udp(client, ip, peer_address);
            String response = Encoding.UTF8.GetString(client.Receive(ref ip)); 
            Console.WriteLine(response);

            while(true)
            {
                string msg = Console.ReadLine();
                send_message_udp(client, ip,msg);
                response = Encoding.UTF8.GetString(client.Receive(ref ip)); 
                Console.WriteLine(response);
            }
        }

        static void listen_connection(IPEndPoint ip, UdpClient client)
        {
            String response = Encoding.UTF8.GetString(client.Receive(ref ip)); 
            Console.WriteLine(response + " is requesting an connection");
            Console.Write("Accpet request(y/n): ");
            String input = Console.ReadLine();
            if(input == "y"){
                send_message_udp(client, ip, "ACCEPT");
                response = Encoding.UTF8.GetString(client.Receive(ref ip)); 
                Console.WriteLine(response);
                while(true)
                {
                    response = Encoding.UTF8.GetString(client.Receive(ref ip)); 
                    Console.WriteLine(response);
                    string msg = Console.ReadLine();
                    send_message_udp(client, ip,msg);
                }
            }
            else{
                send_message_udp(client, ip, "REJECT");
            }
        }

        static void send_message_tcp(NetworkStream stream, string message)
        {
            Byte[] data = System.Text.Encoding.ASCII.GetBytes(message);
            stream.Write(data, 0, data.Length);
        }

        static void send_message_udp(UdpClient client, IPEndPoint ip, String message)
        {
            byte[] data = Encoding.UTF8.GetBytes(message);
            client.Send(data, data.Length, ip);
        }
    }
}
