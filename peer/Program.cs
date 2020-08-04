using System;
using System.Text;
using System.Net;
using Newtonsoft.Json;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Numerics;
#if !NETSTANDARD2_0
using System.Buffers;
#endif
using System.Runtime.InteropServices;
using dtls_server;

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
        public static ECDiffieHellmanPublicKey peerPubKey;
        static int connection_address;
        static int local_port;
        static IPEndPoint ipEndPoint;
        static UdpClient peer;
        static Aes myAes;
        
        static void Main(string[] args)
        {

            myAes = Aes.Create();
            //myAes.Key = key;
            //myAes.IV = iv;
        myAes.Key = new byte[16] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
        myAes.IV = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            string server_ip = "127.0.0.1";     // Server IP
            int server_port = 28005;   // Server port

            Random random = new Random();
            local_port = random.Next(20000, 40000);

            //IPAddress ipAddress = Dns.GetHostEntry(Dns.GetHostName()).AddressList[0];
            IPAddress ipAddress = IPAddress.Parse("127.0.0.1");
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
            //peer = new UdpClient(ipLocalEndPoint);

            if(input == "y"){
                req_connection(sslStream, client);
            }
            else{
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
            string response = recieve_message_tcp(sslStream);

            connection_address = Int16.Parse(response);
            Console.WriteLine("Recieved address: "+connection_address);
        }

        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                aesAlg.Padding = PaddingMode.Zeros;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;
                aesAlg.Padding = PaddingMode.Zeros;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

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
                    response = recieve_message_tcp(sslStream);
                    Console.WriteLine("server: " + response);


                    byte[] bytes = new byte[256];
                    sslStream.Read(bytes, 0, bytes.Length);
                    string message = Encoding.UTF8.GetString(bytes);
                    PublicKeyCoordinates destPubKey = JsonConvert.DeserializeObject<PublicKeyCoordinates>(message);

                    

                    ECDiffieHellmanOpenSsl peer = new ECDiffieHellmanOpenSsl();
                    ECParameters ep = peer.ExportParameters(false);

                    PublicKeyCoordinates pubKey = new PublicKeyCoordinates(ep.Q.X,ep.Q.Y);
                    byte[] data = Encoding.UTF8.GetBytes(pubKey.ToString());
                    sslStream.Write(data);
                    sslStream.Flush();

                    ECDiffieHellmanOpenSsl temp = new ECDiffieHellmanOpenSsl();
                    ECParameters epTemp = temp.ExportParameters(false);

                    epTemp.Q.X = destPubKey.X;
                    epTemp.Q.Y = destPubKey.Y;

                    ECDiffieHellmanPublicKey servePubKey = ECDiffieHellman.Create(epTemp).PublicKey;
                    byte[] sharedKey = peer.DeriveKeyMaterial(servePubKey);

                    Console.WriteLine(BitConverter.ToString(sharedKey).Replace("-",""));

                    sslStream.Close();
                    client.Close();

                }
                else if(String.Compare(response, "REJECT") == 0){
                    Console.WriteLine("Peer " + peer_address + " rejected the connection");
                }

            }
            else{
                Console.WriteLine("Connection declined");
            }
        }

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
                    response = recieve_message_tcp(sslStream);
                    Console.WriteLine("server: " + response);

                    ECDiffieHellmanOpenSsl peer = new ECDiffieHellmanOpenSsl();
                    ECParameters ep = peer.ExportParameters(false);

                    PublicKeyCoordinates pubKey = new PublicKeyCoordinates(ep.Q.X,ep.Q.Y);
                    byte[] data = Encoding.UTF8.GetBytes(pubKey.ToString());
                    sslStream.Write(data);
                    sslStream.Flush();

                    byte[] bytes = new Byte[256];
                    sslStream.Read(bytes, 0, bytes.Length);
                    string message = Encoding.UTF8.GetString(bytes);
                    PublicKeyCoordinates destPubKey = JsonConvert.DeserializeObject<PublicKeyCoordinates>(message);

                    sslStream.Close();
                    client.Close();

                    
                    ECDiffieHellmanOpenSsl temp = new ECDiffieHellmanOpenSsl();
                    ECParameters epTemp = temp.ExportParameters(false);

                    epTemp.Q.X = destPubKey.X;
                    epTemp.Q.Y = destPubKey.Y;

                    ECDiffieHellmanPublicKey servePubKey = ECDiffieHellman.Create(epTemp).PublicKey;
                    byte[] sharedKey = peer.DeriveKeyMaterial(servePubKey);


                    Console.WriteLine(BitConverter.ToString(sharedKey).Replace("-",""));
                }
                else{
                    send_message_tcp(sslStream, "REJECT");
                }

            }
            else{
                Console.WriteLine("Connection declined");
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
            Byte[] bytes = new Byte[256];
            sslStream.Read(bytes, 0, bytes.Length);
            string message = Encoding.UTF8.GetString(bytes);
            Request reply = JsonConvert.DeserializeObject<Request>(message);
            return reply.body;
        }

        static void send_message_udp(UdpClient client, IPEndPoint ip, String message)
        {
            byte[] data = Encoding.UTF8.GetBytes(message);
            client.Send(data, data.Length, ip);
        }
    }
}
