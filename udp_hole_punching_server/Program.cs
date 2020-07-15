using System;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Collections.Generic;

namespace hole_punching_server
{
    class Program
    {
	    static IPEndPoint[] externIPs = new IPEndPoint[2];
        
        static void Main(string[] args)
        {
            ServerForm_Load();
        }

        public static void ServerForm_Load()
        {

            int port = 27005;
            int count = 0;
            while(count<2)
            {
                UdpClient udpListener = new UdpClient(port);
                IPEndPoint ipEndPoint = new IPEndPoint(IPAddress.Any, port);

                byte[] receivedBytes = udpListener.Receive(ref ipEndPoint);
                string clientMessage = Encoding.UTF8.GetString(receivedBytes);   
                externIPs[count] = ipEndPoint;

                udpListener.Close();  

                count++;
            }

            using (UdpClient client = new UdpClient(27005))
            {
                byte[] data = Encoding.UTF8.GetBytes(externIPs[1].ToString());
                client.Send(data, data.Length, externIPs[0]);
                client.Close();
            } 
            
            using (UdpClient client = new UdpClient(27005))
            {
                byte[] data = Encoding.UTF8.GetBytes(externIPs[0].ToString());
                client.Send(data, data.Length, externIPs[1]);
            }       
        }

    }

}
