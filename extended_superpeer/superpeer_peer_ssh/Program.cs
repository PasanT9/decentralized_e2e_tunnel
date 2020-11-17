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
using System.Threading; 
using System.Numerics;
#if !NETSTANDARD2_0
using System.Buffers;
#endif
using System.Runtime.InteropServices;

using TCP;
using dtls_server;
using dtls_client;
using PairStream;
using Cryptography;

namespace superpeer_peer
{

    class Program
    {
        //static string server_ip = "128.199.95.237";
        static string server_ip = "127.0.0.1";
        static int server_port;

        //static string local_ip = "192.168.1.106";
        static string local_ip = "127.0.0.1";
        static int local_port;

        static PublicKeyCoordinates pubKey;
        static ECDiffieHellmanOpenSsl node;
        
        static Aes myAes;

        //static Aes myAes;
        static string dest_ip;
        static int dest_port;

        public static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None || sslPolicyErrors == SslPolicyErrors.RemoteCertificateChainErrors)
                return true;

            Console.WriteLine("Certificate error: {0}", sslPolicyErrors);

            // Do not allow this client to communicate with unauthenticated servers.
            return false;
        }



        static void authenticate_server(SslStream sslStream)
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

        static void Main(string[] args)
        {

            //Get user input for server port
            Console.Write("Server port: ");
            server_port = Int32.Parse(Console.ReadLine());

            //Select a random port as local port
            Random random = new Random();
            local_port = random.Next(20000, 40000);

            //Create local endpoint for connection
            IPAddress ipAddress = IPAddress.Parse(local_ip);
            IPEndPoint ipLocalEndPoint = new IPEndPoint(ipAddress, local_port);

            //Connect to server
            TcpClient client = new TcpClient(ipLocalEndPoint);
            client.Connect(server_ip, server_port);
            SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);


            init_connection(sslStream);

            sslStream.Close();
            client.Close();
            Console.Write("init connection: ");
            string input = Console.ReadLine();
            //locate_peer();
            //anonym_peer();
            if (input == "y")
            {
                find_superpeer();
            }
            else
            {
                listen_superpeer();
            }


        }

        static void anonym_peer()
        {
            IPAddress ipAddress = IPAddress.Parse(local_ip);
            IPEndPoint ipLocalEndPoint = new IPEndPoint(ipAddress, local_port);

            //Connect to server
            TcpClient client = new TcpClient(ipLocalEndPoint);
            client.Connect(server_ip, server_port);
            SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
            authenticate_server(sslStream);

            TCPCommunication.send_message_tcp(sslStream, "ANONYM_P");
            TCPCommunication.send_message_tcp(sslStream, HashString.GetHashString(pubKey.ToString()));

            string response = TCPCommunication.recieve_message_tcp(sslStream);
            if(String.Compare(response, "ACCEPT") == 0)
            {
                node = new ECDiffieHellmanOpenSsl();
                ECParameters node_ep = node.ExportParameters(false);

                pubKey = new PublicKeyCoordinates(node_ep.Q.X, node_ep.Q.Y);
                string hash = HashString.GetHashString(pubKey.ToString());

                TCPCommunication.send_message_tcp(sslStream, hash);

                response = TCPCommunication.recieve_message_tcp(sslStream);

                Console.WriteLine(response);

                sslStream.Close();
                client.Close();
            }
            else if(String.Compare(response, "REJECT") == 0)
            {
                Console.WriteLine("Connection rejected");
                sslStream.Close();
                client.Close();
            }

        }


        static void locate_peer()
        {
            Console.Write("Key: "); 
            string key = Console.ReadLine();
            IPAddress ipAddress = IPAddress.Parse(local_ip);
            IPEndPoint ipLocalEndPoint = new IPEndPoint(ipAddress, local_port);

            //Connect to server
            TcpClient client = new TcpClient(ipLocalEndPoint);
            client.Connect(server_ip, server_port);
            SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
            authenticate_server(sslStream);

            TCPCommunication.send_message_tcp(sslStream, "LOCATE_P");
            TCPCommunication.send_message_tcp(sslStream, HashString.GetHashString(pubKey.ToString()));

            string response = TCPCommunication.recieve_message_tcp(sslStream);
            Console.WriteLine(response);
            if(String.Compare(response, "ACCEPT") == 0)
            {
                TCPCommunication.send_message_tcp(sslStream, key);

                response = TCPCommunication.recieve_message_tcp(sslStream);

                string[] temp_split = response.Split(':');
                dest_ip = temp_split[1];
                dest_port = Int32.Parse(temp_split[2]);

                Console.WriteLine($"destination peer in {dest_ip}:{dest_port}");

                sslStream.Close();
                client.Close();
            }
            else if(String.Compare(response, "REJECT") == 0)
            {
                Console.WriteLine("Connection rejected");
                sslStream.Close();
                client.Close();
            }

        }



        static void init_connection(SslStream sslStream)
        {

            //Authenticate certificate
            authenticate_server(sslStream);

            TCPCommunication.send_message_tcp(sslStream, "INIT_P");
            string response = TCPCommunication.recieve_message_tcp(sslStream);
            Console.WriteLine(response);

            node = new ECDiffieHellmanOpenSsl();
            ECParameters node_ep = node.ExportParameters(false);

            pubKey = new PublicKeyCoordinates(node_ep.Q.X, node_ep.Q.Y);

            Console.WriteLine("My hash key: " + HashString.GetHashString(pubKey.ToString()));

            //Console.WriteLine(pubKey.ToString());

            TCPCommunication.send_message_tcp(sslStream, pubKey.ToString());

        }

        static void find_superpeer()
        {

            Console.Write("Destination: ");
            string dest_key = Console.ReadLine();
            IPAddress ipAddress = IPAddress.Parse(local_ip);
            IPEndPoint ipLocalEndPoint = new IPEndPoint(ipAddress, local_port);

            //Connect to server
            TcpClient client = new TcpClient(ipLocalEndPoint);
            client.Connect(server_ip, server_port);
            SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
            authenticate_server(sslStream);

            TCPCommunication.send_message_tcp(sslStream, "FIND_P");
            TCPCommunication.send_message_tcp(sslStream, HashString.GetHashString(pubKey.ToString()));

            string response = TCPCommunication.recieve_message_tcp(sslStream);
            if(String.Compare(response, "ACCEPT") == 0)
            {
                TCPCommunication.send_message_tcp(sslStream, dest_key);

                response = TCPCommunication.recieve_message_tcp(sslStream);

                string[] temp_split = response.Split(':');
                dest_ip = temp_split[1];
                dest_port = Int32.Parse(temp_split[2]);

                Console.WriteLine($"destination peer in {dest_ip}:{dest_port}");

                //TCPCommunication.send_message_tcp(sslStream, pubKey.ToString());
                //response = TCPCommunication.recieve_message_tcp(sslStream);
                //Console.WriteLine(response);
                sslStream.Close();
                client.Close();

                client = new TcpClient(ipLocalEndPoint);
                client.Connect(dest_ip, dest_port);
                sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
                authenticate_server(sslStream);

                req_connection(sslStream, client, dest_key);


                sslStream.Close();
                client.Close();
            }
            else if(String.Compare(response, "REJECT") == 0)
            {
                Console.WriteLine("Connection rejected");
                sslStream.Close();
                client.Close();
            }



        }

        static void listen_superpeer()
        {
            IPAddress ipAddress = IPAddress.Parse(local_ip);
            IPEndPoint ipLocalEndPoint = new IPEndPoint(ipAddress, local_port);
            TcpClient client = new TcpClient(ipLocalEndPoint);

            client.Connect(server_ip, server_port);
            SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
            authenticate_server(sslStream);

            listen_connection(sslStream, client);
            //req_connection(sslStream, client, dest_key);


            sslStream.Close();
            client.Close();
        }

        static void req_connection(SslStream sslStream, TcpClient client, string dest_key)
        {

            myAes = Aes.Create();
            myAes.Key = new byte[16] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
            myAes.IV = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            TCPCommunication.send_message_tcp(sslStream, "CONNECT_P");
            TCPCommunication.send_message_tcp(sslStream, HashString.GetHashString(pubKey.ToString()));

            string response = TCPCommunication.recieve_message_tcp(sslStream);
            if(String.Compare(response, "ACCEPT") == 0)
            {
                TCPCommunication.send_message_tcp(sslStream, dest_key);

                response = TCPCommunication.recieve_message_tcp(sslStream);
                Console.WriteLine(response);

                if (String.Compare(response, "ACCEPT") == 0)
                {
                    response = TCPCommunication.recieve_message_tcp(sslStream);
                    int dtls_port = Int32.Parse(response);


                    byte[] data = new Byte[256];
                    data = Encoding.UTF8.GetBytes(pubKey.ToString());

                    sslStream.Write(data);
                    sslStream.Flush();

                    data = new Byte[256];
                    sslStream.Read(data, 0, data.Length);
                    response = Encoding.UTF8.GetString(data);
                    PublicKeyCoordinates listen_key = JsonConvert.DeserializeObject<PublicKeyCoordinates>(response);



                    sslStream.Close();
                    client.Close();

                    ECDiffieHellmanOpenSsl temp = new ECDiffieHellmanOpenSsl();
                    ECParameters epTemp = temp.ExportParameters(false);

                    epTemp.Q.X = listen_key.X;
                    epTemp.Q.Y = listen_key.Y;

                    ECDiffieHellmanPublicKey servePubKey = ECDiffieHellman.Create(epTemp).PublicKey;
                    byte[] sharedKey = node.DeriveKeyMaterial(servePubKey);
                    Console.WriteLine(BitConverter.ToString(sharedKey).Replace("-", ""));
                    //myAes.Key = sharedKey;
                    //myAes.Key = new byte[16] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

                    DTLSClient dtls_client = new DTLSClient(server_ip, dtls_port.ToString(), new byte[] {0xBA,0xA0});

                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        dtls_client.Unbuffer="winpty.exe";
                        dtls_client.Unbuffer_Args="-Xplain -Xallow-non-tty";
                    }
                    else
                    {
                        dtls_client.Unbuffer="stdbuf";
                        dtls_client.Unbuffer_Args="-i0 -o0";
                    }
                    dtls_client.Start();
                    
                /*statpair IOStream = new statpair(new StreamReader(Console.OpenStandardInput()), new StreamWriter(Console.OpenStandardOutput()));
                new Thread(() => dtls_client.GetStream().CopyTo(IOStream, 16)).Start();*/

                    //new Thread(() => read_relay(dtls_client)).Start();

                    UdpClient receivingUdpClient = new UdpClient(32000);

                    //Creates an IPEndPoint to record the IP Address and port number of the sender.
                    // The IPEndPoint will allow you to read datagrams sent from any source.
                    IPEndPoint RemoteIpEndPoint = new IPEndPoint(IPAddress.Any, 0);

                    /*Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

                    IPAddress broadcast = IPAddress.Parse("127.0.0.1");

                    //byte[] sendbuf = Encoding.ASCII.GetBytes(args[0]);
                    IPEndPoint ep = new IPEndPoint(broadcast, 11000);*/

                    dtls_client.GetStream().Write(Encoding.Default.GetBytes("SUCCESS\n"));
                     dtls_client.GetStream().Write(Encoding.Default.GetBytes("SUCCESS\n"));
                    //dtls_client.GetStream().Write(Encoding.Default.GetBytes("SUCCESS"));

                    while(true)
                    {
                        byte[] receiveBytes = receivingUdpClient.Receive(ref RemoteIpEndPoint);
                        //dtls_client.GetStream().Write(receiveBytes);
                        //dtls_client.GetStream().Flush();

                        string input = BitConverter.ToString(receiveBytes)+'\n';
                        //Console.WriteLine(input);

                        byte[] send = Encoding.Default.GetBytes(input);
                        
                        //Console.WriteLine(receiveBytes);
                        dtls_client.GetStream().Write(send);
                        //Thread.Sleep(50);
                        
                        


                        
                        //byte[] rec = Encoding.Default.GetBytes(cut_str);
                        //Console.WriteLine(bytes);

                        //s.SendTo(bytes, ep);

                        //dtls_client.GetStream().Write(Encoding.Default.GetBytes(input));

                        /*string input = Encoding.Default.GetString(receiveBytes);

                        byte[] send = Encoding.Default.GetBytes(input);

                        s.SendTo(send, ep);*/

                        /*byte[] out_byte = Encoding.Default.GetBytes(input);

                        string out_str = Encoding.Default.GetString(out_byte);

                        String[] arr=out_str.Split('-');
                        byte[] bytes=new byte[arr.Length];
                        for(int i=0; i<arr.Length; i++) bytes[i]=Convert.ToByte(arr[i],16);

                        s.SendTo(bytes, ep);*/

                        /*String[] arr=input.Split('-');
                        byte[] bytes=new byte[arr.Length];
                        for(int i=0; i<arr.Length; i++) bytes[i]=Convert.ToByte(arr[i],16);*/

                        /*String[] arr_in=input.Split('-');
                        byte[] array_in=new byte[arr.Length];
                        for(int i=0; i<arr.Length; i++) array[i]=Convert.ToByte(arr[i],16);

                        string out_str = BitConverter.ToString(out_bt);

                        String[] arr=out_str.Split('-');
                        byte[] bytes=new byte[arr.Length];
                        for(int i=0; i<arr.Length; i++) bytes[i]=Convert.ToByte(arr[i],16);

                        //byte[] bytes = BitConverter.GetBytes(input);

                        s.SendTo(bytes, ep);*/
                        

                        //string input = BitConverter.ToString(receiveBytes);

                        //byte[] encryptedData = EncryptStringToBytes_Aes(BitConverter.ToString(receiveBytes), myAes.Key, myAes.IV);

                        //dtls_client.GetStream().Write(encryptedData);

                        //dtls_client.GetStream().Write(receiveBytes);
                        //dtls_client.GetStream().Write(bytes);
                        //dtls_client.GetStream().Write();
                    }

                    dtls_client.WaitForExit();
                }
                else if (String.Compare(response, "REJECT") == 0)
                {
                    Console.WriteLine("Connection rejected");
                }
            }
            else if(String.Compare(response, "REJECT") == 0)
            {
                Console.WriteLine("Connection rejected");
                sslStream.Close();
                client.Close();
            }
        }

        static void listen_connection(SslStream sslStream, TcpClient client)
        {

            myAes = Aes.Create();
            myAes.Key = new byte[16] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
            myAes.IV = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };


            TCPCommunication.send_message_tcp(sslStream, "LISTEN_P");
            TCPCommunication.send_message_tcp(sslStream, HashString.GetHashString(pubKey.ToString()));

            string response = TCPCommunication.recieve_message_tcp(sslStream);
            if(String.Compare(response, "ACCEPT") == 0)
            {

                byte[] data = new Byte[256];
                data = Encoding.UTF8.GetBytes(pubKey.ToString());
                sslStream.Write(data);
                sslStream.Flush();

                
                data = new Byte[256];
                sslStream.Read(data, 0, data.Length);
                response = Encoding.UTF8.GetString(data);
                PublicKeyCoordinates request_key = JsonConvert.DeserializeObject<PublicKeyCoordinates>(response);

                sslStream.Close();
                client.Close();

                ECDiffieHellmanOpenSsl temp = new ECDiffieHellmanOpenSsl();
                ECParameters epTemp = temp.ExportParameters(false);

                epTemp.Q.X = request_key.X;
                epTemp.Q.Y = request_key.Y;

                ECDiffieHellmanPublicKey servePubKey = ECDiffieHellman.Create(epTemp).PublicKey;
                byte[] sharedKey = node.DeriveKeyMaterial(servePubKey);
                Console.WriteLine(BitConverter.ToString(sharedKey).Replace("-", ""));

                //myAes.Key = sharedKey;
                //myAes.Key = new byte[16] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
                

                DTLSClient dtls_client = new DTLSClient(server_ip, server_port.ToString(), new byte[] {0xBA,0xA0});
                
		    	if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    dtls_client.Unbuffer="winpty.exe";
                    dtls_client.Unbuffer_Args="-Xplain -Xallow-non-tty";
                }
                else
                {
                    dtls_client.Unbuffer="stdbuf";
                    dtls_client.Unbuffer_Args="-i0 -o0";
                }
                dtls_client.Start();

               /* statpair IOStream = new statpair(new StreamReader(Console.OpenStandardInput()), new StreamWriter(Console.OpenStandardOutput()));
                new Thread(() => dtls_client.GetStream().CopyTo(IOStream, 16)).Start();*/

                read_relay(dtls_client);

                /*while(true)
                {
                    string input = Console.ReadLine();
                    byte[] encryptedData = EncryptStringToBytes_Aes(input, myAes.Key, myAes.IV);
                    dtls_client.GetStream().Write(encryptedData);
                    //dtls_client.GetStream().Write(Encoding.Default.GetBytes(input+Environment.NewLine));
                }*/
                
                dtls_client.WaitForExit();


            }
            else if(String.Compare(response, "REJECT") == 0)
            {
                Console.WriteLine("Connection rejected");
                sslStream.Close();
                client.Close();
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

        static void read_relay(DTLSClient dtls)
        {
            byte[] bytes;
            Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            IPAddress broadcast = IPAddress.Parse("127.0.0.1");

            //byte[] sendbuf = Encoding.ASCII.GetBytes(args[0]);
            IPEndPoint ep = new IPEndPoint(broadcast, 11000);

                    /*string message = "";
                    
                    while(String.Compare(message,"SUCCESS") != 0)
                    {
                        bytes = new byte[16];
                        dtls.GetStream().Read(bytes, 0, bytes.Length);
                        message = Encoding.Default.GetString(bytes);
                        Console.Write(message);  
                    }
                    Console.WriteLine("Done");*/


            //s.SendTo(sendbuf, ep);
            StringBuilder sb = new StringBuilder();
            while (true)
            {
                bytes = new byte[50000];
                dtls.GetStream().Read(bytes, 0, bytes.Length);

                string out_p = Encoding.Default.GetString(bytes);
                //StringBuilder sb = new StringBuilder();
                for(int i=0;i<out_p.Length;++i)
                {
                    if(out_p[i] != '\n')
                    {
                        sb.Append(out_p[i]);
                    }
                    else
                    {
                        string rec = sb.ToString();
                        Console.WriteLine(rec);
                        //Console.WriteLine("------------------------------");

                        String[] arr=rec.Split('-');
                        byte[] bytes_out=new byte[arr.Length];
                        for(int j=0; j<arr.Length; j++)
                        {
                            try
                            {
                                bytes_out[j]=Convert.ToByte(arr[j],16);
                            }
                            catch(Exception e)
                            {

                            }
                        }


                        //Console.WriteLine(bytes_out);
                        //Console.WriteLine("*************************************");
                        s.SendTo(bytes_out, ep);

                        /*String[] arr=rec.Split('-');
                        byte[] bytes_out=new byte[arr.Length];
                        int j=0;
                        try
                        {
                            for(j=0; j<arr.Length; j++) bytes_out[j]=Convert.ToByte(arr[j],16);
                        }
                        catch(Exception e)
                        {
                            Console.WriteLine(e);
                        }

                        Console.WriteLine(vid);
                        s.SendTo(bytes_out, ep);*/

                        sb = new StringBuilder();
                    }
                }

                /*Console.WriteLine("-------------------------------");
                bytes = new byte[10000];
                dtls.GetStream().Read(bytes, 0, bytes.Length);
               // message = Encoding.UTF8.GetString(bytes);
                
                string out_p = Encoding.Default.GetString(bytes);

                String[] arr=out_p.Split('-');
                byte[] bytes_out=new byte[arr.Length];
                int i=0;
                try
                {
                    for(i=0; i<arr.Length; i++) bytes_out[i]=Convert.ToByte(arr[i],16);
                }
                catch(Exception e)
                {
                    bytes = new byte[10000];
                    dtls.GetStream().Read(bytes, 0, bytes.Length);
                    // message = Encoding.UTF8.GetString(bytes);
                    
                    string out_p = Encoding.Default.GetString(bytes);

                    arr=out_p.Split('-');
                    bytes_out=new byte[arr.Length];
                    try
                    {
                        for(int j=i; i<arr.Length; i++) bytes_out[i]=Convert.ToByte(arr[i],16);
                    }
                    catch(Exception e)
                    {
                        Console.WriteLine(e);
                    }
                }

                Console.WriteLine(out_p);

                s.SendTo(bytes_out, ep);*/
                


                /*string out_str = Encoding.Default.GetString(bytes);
                Console.WriteLine(out_str);
                String[] arr=out_str.Split('-');
                byte[] bytes_arr=new byte[arr.Length];
                try
                {
                    for(int i=0; i<arr.Length; i++) bytes_arr[i]=Convert.ToByte(arr[i],16);
                    s.SendTo(bytes_arr, ep);
                }
                catch(Exception)
                {
                    Console.WriteLine("e");
                }*/

                /*string decryptedData = DecryptStringFromBytes_Aes(bytes, myAes.Key, myAes.IV);
                Console.WriteLine(decryptedData);*/
                //Console.WriteLine(BitConverter.ToString(bytes));
                
            }
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



    }

}
