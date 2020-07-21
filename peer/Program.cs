using System;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Collections.Generic;  
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace peer
{
    class Program
    {
        public static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if(sslPolicyErrors == SslPolicyErrors.None || sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors)
                return true;

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

            // Do not allow this client to communicate with unauthenticated servers.
            return false;
        }
        static int connection_address;
        static IPEndPoint ipEndPoint;
        static UdpClient peer;
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
            SslStream sslStream = new SslStream(client.GetStream(),false, new RemoteCertificateValidationCallback (ValidateServerCertificate), null);
            //sslStream.Flush();

            init_connection(sslStream);  
            //client.Close();

            Console.Write("Do you wanna create a connection(y/n): ");
            string input = Console.ReadLine();

            IPAddress relay_ip = IPAddress.Parse(server_ip);     // Server IP

            ipEndPoint = new IPEndPoint(relay_ip,server_port);
            peer = new UdpClient(ipLocalEndPoint);

            if(input == "y"){
                //req_connection(ipEndPoint, peer);
                req_connection(sslStream, client);
            }
            else{
                //listen_connection(ipEndPoint, peer);
                listen_connection(sslStream,client);
            }
        }

        static void init_connection(SslStream sslStream)
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
                Console.WriteLine ("Authentication failed - closing the connection.");
                sslStream.Close();
                return;
            }
            send_message_tcp(sslStream, "HELLO");
            String response = recieve_message_tcp(sslStream);

            connection_address = Int16.Parse(response);
            Console.WriteLine("Recieved address: "+connection_address);
            //sslStream.Close();
        }

        //static void req_connection(IPEndPoint ip, UdpClient client)
        static void req_connection(SslStream sslStream, TcpClient client)
        {
            send_message_tcp(sslStream, "REQUEST");
            string response = recieve_message_tcp(sslStream);
            if(String.Compare(response,"ACCEPT") == 0){
                Console.Write("Enter the destination address: ");
                string peer_address = Console.ReadLine();
                send_message_tcp(sslStream, peer_address);
                response = recieve_message_tcp(sslStream);
                if(String.Compare(response, "ACCEPT") == 0){
                    Console.WriteLine("Peer " + peer_address + " accepted the connection");
                    sslStream.Close();
                    client.Close();

                    response = Encoding.UTF8.GetString(peer.Receive(ref ipEndPoint)); 
                    Console.WriteLine(response);
                    while(true)
                    {
                        string msg = Console.ReadLine();
                        send_message_udp(peer, ipEndPoint,msg);
                        response = Encoding.UTF8.GetString(peer.Receive(ref ipEndPoint)); 
                        Console.WriteLine(response);
                    }
                }
                else if(String.Compare(response, "REJECT") == 0){
                    Console.WriteLine("Peer " + peer_address + " rejected the connection");
                }

            }
            else{
                Console.WriteLine("Connection declined");
            }
            
            /*Console.Write("request connection to peer: ");
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
            }*/
        }

        //static void listen_connection(IPEndPoint ip, UdpClient client)
        static void listen_connection(SslStream sslStream,TcpClient client)
        {
            send_message_tcp(sslStream, "LISTEN");
            string response = recieve_message_tcp(sslStream);
            if(String.Compare(response,"ACCEPT") == 0){
                Console.WriteLine("waiting for a connection request...");
                response = recieve_message_tcp(sslStream);
                Console.WriteLine("Peer "+response+" requesting a connection");
                Console.Write("accept request?(y/n): ");
                string input = Console.ReadLine();
                if(input == "y"){
                    send_message_tcp(sslStream, "ACCEPT");
                    sslStream.Close();
                    client.Close();

                    response = Encoding.UTF8.GetString(peer.Receive(ref ipEndPoint)); 
                    Console.WriteLine(response);
                    while(true)
                    {
                        response = Encoding.UTF8.GetString(peer.Receive(ref ipEndPoint)); 
                        Console.WriteLine(response);
                        string msg = Console.ReadLine();
                        send_message_udp(peer, ipEndPoint,msg);
                    }
                }
                else{
                    send_message_tcp(sslStream, "REJECT");
                }

            }
            else{
                Console.WriteLine("Connection declined");
            }
            
            /*String response = Encoding.UTF8.GetString(client.Receive(ref ip)); 
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
            }*/
        }
        static void send_message_tcp(SslStream sslStream, string message)
        {
            byte[] data = Encoding.UTF8.GetBytes(message);
            sslStream.Write(data);
            sslStream.Flush();
        }

        static string recieve_message_tcp(SslStream sslStream)
        {
            Byte[] bytes = new Byte[256];
            sslStream.Read(bytes, 0, bytes.Length);
            string message = Encoding.UTF8.GetString(bytes);
            return message;
        }

        static void send_message_udp(UdpClient client, IPEndPoint ip, String message)
        {
            byte[] data = Encoding.UTF8.GetBytes(message);
            client.Send(data, data.Length, ip);
        }
    }
}
