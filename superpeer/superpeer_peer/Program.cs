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
        static string server_ip = "68.183.91.69";
        //static string server_ip = "127.0.0.1";
        static int server_port;

        static string local_ip = "192.168.1.106";
        //static string local_ip = "127.0.0.1";
        static int local_port;

        static PublicKeyCoordinates pubKey;
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
            if (input == "y")
            {
                find_superpeer();
            }
            else
            {
                listen_superpeer();
            }


        }

        static void init_connection(SslStream sslStream)
        {

            //Authenticate certificate
            authenticate_server(sslStream);

            TCPCommunication.send_message_tcp(sslStream, "HELLO_P");
            string response = TCPCommunication.recieve_message_tcp(sslStream);
            Console.WriteLine(response);

            ECDiffieHellmanOpenSsl peer = new ECDiffieHellmanOpenSsl();
            ECParameters ep = peer.ExportParameters(false);

            pubKey = new PublicKeyCoordinates(ep.Q.X, ep.Q.Y);

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

                    sslStream.Close();
                    client.Close();




                    DTLSClient dtls_client = new DTLSClient(server_ip, dtls_port.ToString(), new byte[] {0xBA,0xA0});
                    //DTLSClient dtls_client = new DTLSClient("127.0.0.1", dtls_port.ToString(), new byte[] {0xBA,0xA0});

              if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)){
				dtls_client.Unbuffer="winpty.exe";
				dtls_client.Unbuffer_Args="-Xplain -Xallow-non-tty";
			}
			else{
				dtls_client.Unbuffer="stdbuf";
				dtls_client.Unbuffer_Args="-i0 -o0";
			}
			dtls_client.Start();
			statpair IOStream = new statpair(new StreamReader(Console.OpenStandardInput()), new StreamWriter(Console.OpenStandardOutput()));
			//new Thread(()=>IOStream.CopyTo(dtls_client.GetStream(), 16)).Start();
			new Thread(() => dtls_client.GetStream().CopyTo(IOStream, 16)).Start();
			//new Thread(() => dtls_client.GetStream().Write(Encoding.Default.GetBytes("It Works!"+Environment.NewLine))).Start();
			//pair.BindStreams(dtls_client.GetStream(), IOStream);
			//pair.BindStreams(dtls_client.GetStream(), IOStream);
			while(true)
			{
				string input = Console.ReadLine();
				dtls_client.GetStream().Write(Encoding.Default.GetBytes(input+Environment.NewLine));
			}
			//dtls.WaitForExit();
			dtls_client.WaitForExit();

                    /*DTLSServer dtls = new DTLSServer(local_port.ToString(), new byte[] { 0xBA, 0xA0 });
                    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    {
                        dtls.Unbuffer = "winpty.exe";
                        dtls.Unbuffer_Args = "-Xplain -Xallow-non-tty";
                    }
                    else
                    {
                        dtls.Unbuffer = "stdbuf";
                        dtls.Unbuffer_Args = "-i0 -o0";
                    }
                    dtls.Start();


           dtls.GetStream().Write(Encoding.Default.GetBytes("SUCCESS"));
            byte[] bytes;
            string message = "";
            while (String.Compare(message, "SUCCESS") != 0)
            {
                bytes = new byte[128];
                dtls.GetStream().Read(bytes, 0, bytes.Length);
                message = Encoding.UTF8.GetString(bytes);
                Console.Write(message);
            }

            Console.WriteLine();
            new Thread(() => read_relay(dtls)).Start();

            while (true)
            {
                string input = Console.ReadLine();
                byte[] encryptedData = EncryptStringToBytes_Aes(input, myAes.Key, myAes.IV);
                //dtls.GetStream().Write(Encoding.Default.GetBytes(input+Environment.NewLine));
                dtls.GetStream().Write(encryptedData);
            }
            dtls.WaitForExit();*/
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
                /*response = TCPCommunication.recieve_message_tcp(sslStream);
                Console.WriteLine(response);*/
                sslStream.Close();
                client.Close();

                    DTLSClient dtls_client = new DTLSClient(server_ip, server_port.ToString(), new byte[] {0xBA,0xA0});
                    //DTLSClient dtls_client = new DTLSClient("127.0.0.1", server_port.ToString(), new byte[] {0xBA,0xA0});

		    	if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)){
				dtls_client.Unbuffer="winpty.exe";
				dtls_client.Unbuffer_Args="-Xplain -Xallow-non-tty";
			}
			else{
				dtls_client.Unbuffer="stdbuf";
				dtls_client.Unbuffer_Args="-i0 -o0";
			}
			dtls_client.Start();
			statpair IOStream = new statpair(new StreamReader(Console.OpenStandardInput()), new StreamWriter(Console.OpenStandardOutput()));
			//new Thread(()=>IOStream.CopyTo(dtls_client.GetStream(), 16)).Start();
			new Thread(() => dtls_client.GetStream().CopyTo(IOStream, 16)).Start();
			//new Thread(() => dtls_client.GetStream().Write(Encoding.Default.GetBytes("It Works!"+Environment.NewLine))).Start();
			//pair.BindStreams(dtls_client.GetStream(), IOStream);
			//pair.BindStreams(dtls_client.GetStream(), IOStream);
			while(true)
			{
				string input = Console.ReadLine();
				dtls_client.GetStream().Write(Encoding.Default.GetBytes(input+Environment.NewLine));
			}
			//dtls.WaitForExit();
			dtls_client.WaitForExit();


                /*DTLSServer dtls = new DTLSServer(local_port.ToString(), new byte[] { 0xBA, 0xA0 });
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    dtls.Unbuffer = "winpty.exe";
                    dtls.Unbuffer_Args = "-Xplain -Xallow-non-tty";
                }
                else 
                {
                    dtls.Unbuffer = "stdbuf";
                    dtls.Unbuffer_Args = "-i0 -o0";
                }
                dtls.Start();


           dtls.GetStream().Write(Encoding.Default.GetBytes("SUCCESS"));
            byte[] bytes;
            string message = "";
            while (String.Compare(message, "SUCCESS") != 0)
            {
                bytes = new byte[128];
                dtls.GetStream().Read(bytes, 0, bytes.Length);
                message = Encoding.UTF8.GetString(bytes);
                Console.Write(message);
            }

            Console.WriteLine();
            new Thread(() => read_relay(dtls)).Start();

            while (true)
            {
                string input = Console.ReadLine();
                byte[] encryptedData = EncryptStringToBytes_Aes(input, myAes.Key, myAes.IV);
                //dtls.GetStream().Write(Encoding.Default.GetBytes(input+Environment.NewLine));
                dtls.GetStream().Write(encryptedData);
            }
            dtls.WaitForExit();*/
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
            while (true)
            {
                bytes = new byte[16];
                dtls.GetStream().Read(bytes, 0, bytes.Length);
                //string decryptedData = DecryptStringFromBytes_Aes(bytes, myAes.Key, myAes.IV);
                Console.WriteLine(bytes.ToString());
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
