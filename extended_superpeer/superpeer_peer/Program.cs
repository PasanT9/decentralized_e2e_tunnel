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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.OpenSsl;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Digests;

using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;

using X509Certificate = System.Security.Cryptography.X509Certificates.X509Certificate;

using SecretSaring;


namespace superpeer_peer
{

    class Program
    {
        //static string server_ip = "128.199.95.237";
        static string server_ip;
        static int server_port;

        //static string local_ip;
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

        public static string GetLocalIPAddress()
        {
            string localIP;
            using (Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0))
            {
                socket.Connect("8.8.8.8", 65530);
                IPEndPoint endPoint = socket.LocalEndPoint as IPEndPoint;
                localIP = endPoint.Address.ToString();
            }
            return localIP;
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
            //local_ip = GetLocalIPAddress();
            //Console.WriteLine(local_ip);

            Console.Write("Server ip: ");
            server_ip = Console.ReadLine();
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

            share_key();


            /*Console.Write("init connection: ");
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
            }*/
            //ring_authenticate();


        }

        public static void ring_authenticate(SslStream sslStream)
        {
            byte[][] X = new byte[11][];
            Random rnd = new Random();

            for (int i = 0; i < 11; ++i)
            {
                UTF8Encoding utf8enc = new UTF8Encoding();
                X[i] = utf8enc.GetBytes(rnd.Next().ToString());
            }

            RsaKeyParameters[] P = new RsaKeyParameters[11];

            for (int i = 0; i < 10; ++i)
            {

                RsaKeyPairGenerator rsaKeyPairGnr = new RsaKeyPairGenerator();
                rsaKeyPairGnr.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 512));
                Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair = rsaKeyPairGnr.GenerateKeyPair();

                RsaKeyParameters publicKey = (RsaKeyParameters)keyPair.Public;
                IAsymmetricBlockCipher cipher = new RsaEngine();

                P[i + 1] = publicKey;
            }

            RsaKeyPairGenerator rsaKeyPairGnr_s = new RsaKeyPairGenerator();
            rsaKeyPairGnr_s.Init(new Org.BouncyCastle.Crypto.KeyGenerationParameters(new SecureRandom(), 512));
            Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keyPair_s = rsaKeyPairGnr_s.GenerateKeyPair();

            P[0] = (RsaKeyParameters)keyPair_s.Public;
            RsaKeyParameters Ks = (RsaKeyParameters)keyPair_s.Private;

            string m = "Hello!!";

            byte[] v = ring_sign(P, m, Ks, X);

            Console.WriteLine("v: " + ByteArrayToString(v));
            Console.WriteLine();

            String P_str = "";
            for (int i = 0; i < 11; ++i)
            {
                byte[] publicKeyDer = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(P[i]).GetDerEncoded();
                P_str = P_str + Convert.ToBase64String(publicKeyDer) + "|";
            }

            String X_str = "";
            for (int i = 0; i < 11; ++i)
            {
                X_str = X_str + Encoding.ASCII.GetString(X[i]) + "|";
            }

            Console.WriteLine(P_str);
            Console.WriteLine(X_str);

            byte[] data = Encoding.UTF8.GetBytes(P_str);
            sslStream.Write(data);

            sslStream.Flush();

            data = Encoding.UTF8.GetBytes(X_str);
            sslStream.Write(data);

            sslStream.Flush();

            TCPCommunication.send_message_tcp(sslStream, m);


            sslStream.Write(v);
            sslStream.Flush();


        }

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public static byte[] exclusiveOR(byte[] arr1, byte[] arr2)
        {
            if (arr1.Length != arr2.Length)
                throw new ArgumentException("arr1 and arr2 are not the same length");

            byte[] result = new byte[arr1.Length];

            for (int i = 0; i < arr1.Length; ++i)
                result[i] = (byte)(arr1[i] ^ arr2[i]);

            return result;
        }

        public static byte[] ring_sign(RsaKeyParameters[] P, string m, RsaKeyParameters Ks, byte[][] X)
        {
            Console.WriteLine("Ring signing");
            byte[] k1 = Encoding.UTF8.GetBytes(m);

            byte[] k = new byte[64];

            for (int i = 0; i < k1.Length; ++i)
            {
                k[i] = (byte)(k[i] + k1[i]);
            }


            byte[][] y = new byte[11][];

            for (int i = 0; i < 11; ++i)
            {
                IAsymmetricBlockCipher cipher = new RsaEngine();
                cipher.Init(true, P[i]);

                y[i] = cipher.ProcessBlock(X[i], 0, X[i].Length);
            }

            byte[] ring = y[0];
            for (int i = 1; i < 11; ++i)
            {
                ring = exclusiveOR(ring, k);
                ring = exclusiveOR(ring, y[i]);
            }

            byte[] v = ring;
            return v;
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
            if (String.Compare(response, "ACCEPT") == 0)
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
            else if (String.Compare(response, "REJECT") == 0)
            {
                Console.WriteLine("Connection rejected");
                sslStream.Close();
                client.Close();
            }

        }

        static void share_key()
        {
            Thread.Sleep(2000);
            int polynomsCount = 3;

            var byteKey = KeyGenerator.GenerateKey(polynomsCount * 16);
            var key = KeyGenerator.GenerateDoubleBytesKey(byteKey);
            var hexKey = KeyGenerator.GetHexKey(key);

            Console.WriteLine("sending key: " + hexKey);

            IPAddress ipAddress = IPAddress.Parse(local_ip);
            IPEndPoint ipLocalEndPoint = new IPEndPoint(ipAddress, local_port);

            //Connect to server
            TcpClient client = new TcpClient(ipLocalEndPoint);
            client.Connect(server_ip, server_port);
            SslStream sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
            authenticate_server(sslStream);

            TCPCommunication.send_message_tcp(sslStream, "REG_P");

            sslStream.Write(byteKey);

            sslStream.Flush();


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
            if (String.Compare(response, "ACCEPT") == 0)
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
            else if (String.Compare(response, "REJECT") == 0)
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
            if (String.Compare(response, "ACCEPT") == 0)
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
                Console.WriteLine("Client connecting");
                client.Connect(dest_ip, dest_port);
                Console.WriteLine("Client connected");
                sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
                authenticate_server(sslStream);

                req_connection(sslStream, client, dest_key);


                sslStream.Close();
                client.Close();
            }
            else if (String.Compare(response, "REJECT") == 0)
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

            /*myAes = Aes.Create();
            myAes.Key = new byte[16] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
            myAes.IV = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
*/

            Console.WriteLine("requesting");
            TCPCommunication.send_message_tcp(sslStream, "CONNECT_P");
            TCPCommunication.send_message_tcp(sslStream, HashString.GetHashString(pubKey.ToString()));

            string response = TCPCommunication.recieve_message_tcp(sslStream);
            if (String.Compare(response, "ACCEPT") == 0)
            {
                TCPCommunication.send_message_tcp(sslStream, dest_key);

                response = TCPCommunication.recieve_message_tcp(sslStream);
                Console.WriteLine(response);

                if (String.Compare(response, "ACCEPT") == 0)
                {

                    Console.WriteLine("Start Authenticating");
                    ring_authenticate(sslStream);


                    /*response = TCPCommunication.recieve_message_tcp(sslStream);
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
                    client.Close();*/

                    /*ECDiffieHellmanOpenSsl temp = new ECDiffieHellmanOpenSsl();
                    ECParameters epTemp = temp.ExportParameters(false);

                    epTemp.Q.X = listen_key.X;
                    epTemp.Q.Y = listen_key.Y;

                    ECDiffieHellmanPublicKey servePubKey = ECDiffieHellman.Create(epTemp).PublicKey;
                    byte[] sharedKey = node.DeriveKeyMaterial(servePubKey);
                    Console.WriteLine(BitConverter.ToString(sharedKey).Replace("-", ""));
                    //myAes.Key = sharedKey;
                    //myAes.Key = new byte[16] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };

                    DTLSClient dtls = new DTLSClient(dest_ip, dtls_port.ToString(), new byte[] { 0xBA, 0xA0 });

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
            else if (String.Compare(response, "REJECT") == 0)
            {
                Console.WriteLine("Connection rejected");
                sslStream.Close();
                client.Close();
            }
        }

        static public RsaKeyParameters[] restructure_P(string P_str)
        {
            RsaKeyParameters[] P = new RsaKeyParameters[11];
            string[] P_arr = P_str.Split("|");

            for (int i = 0; i < 11; ++i)
            {
                Console.WriteLine(P_arr[i]);
                byte[] publicKeyDerRestored = Convert.FromBase64String(P_arr[i]);
                P[i] = (RsaKeyParameters)PublicKeyFactory.CreateKey(publicKeyDerRestored);
            }
            return P;
        }

        static public byte[][] restructure_X(string X_str)
        {
            byte[][] X = new byte[11][];
            string[] X_arr = X_str.Split("|");

            for (int i = 0; i < 11; ++i)
            {
                X[i] = Encoding.ASCII.GetBytes(X_arr[i]);
            }

            return X;
        }

        public static bool ring_verify(RsaKeyParameters[] P, byte[] v, byte[][] X, string m)
        {
            Console.WriteLine("Ring signature verification");

            byte[][] y = new byte[11][];

            for (int i = 0; i < 11; ++i)
            {
                IAsymmetricBlockCipher cipher = new RsaEngine();
                cipher.Init(true, P[i]);

                y[i] = cipher.ProcessBlock(X[i], 0, X[i].Length);
            }

            byte[] k1 = Encoding.UTF8.GetBytes(m);

            byte[] k = new byte[64];

            for (int i = 0; i < k1.Length; ++i)
            {
                k[i] = (byte)(k[i] + k1[i]);
            }


            byte[] ring = y[0];
            for (int i = 1; i < 11; ++i)
            {
                ring = exclusiveOR(ring, k);
                ring = exclusiveOR(ring, y[i]);
            }
            Console.WriteLine("v: " + ByteArrayToString(v));
            Console.WriteLine("r: " + ByteArrayToString(ring));

            if (ByteArrayToString(v).Equals(ByteArrayToString(ring)))
            {
                return true;
            }
            else
            {
                return false;
            }

        }

        static void listen_connection(SslStream sslStream, TcpClient client)
        {

            /*myAes = Aes.Create();
            myAes.Key = new byte[16] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 };
            myAes.IV = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
*/

            TCPCommunication.send_message_tcp(sslStream, "LISTEN_P");
            TCPCommunication.send_message_tcp(sslStream, HashString.GetHashString(pubKey.ToString()));

            string response = TCPCommunication.recieve_message_tcp(sslStream);

            if (String.Compare(response, "ACCEPT") == 0)
            {

                Console.WriteLine("Start authenticating");
                Byte[] data = new Byte[2048];
                sslStream.Read(data, 0, data.Length);
                string message = Encoding.UTF8.GetString(data);
                string P_str = message;
                RsaKeyParameters[] P = restructure_P(P_str);

                Console.WriteLine("P: " + P_str);
                Console.WriteLine();

                data = new Byte[2048];
                sslStream.Read(data, 0, data.Length);

                message = Encoding.UTF8.GetString(data);
                string X_str = message;
                byte[][] X = restructure_X(X_str);

                Console.WriteLine("X: " + X_str);
                Console.WriteLine();

                response = TCPCommunication.recieve_message_tcp(sslStream);
                string m = response;
                Console.WriteLine("m: " + m);
                Console.WriteLine();


                data = new Byte[64];
                sslStream.Read(data, 0, data.Length);
                byte[] v = data;
                Console.WriteLine("v: " + ByteArrayToString(v));
                Console.WriteLine();

                if (ring_verify(P, v, X, m))
                {
                    Console.WriteLine("Authentication success");
                }
                else
                {
                    Console.WriteLine("Authentication failure");
                }


                /*byte[] data = new Byte[256];
                data = Encoding.UTF8.GetBytes(pubKey.ToString());
                sslStream.Write(data);
                sslStream.Flush();*/


                /*data = new Byte[256];
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


                DTLSClient dtls = new DTLSClient(server_ip, server_port.ToString(), new byte[] { 0xBA, 0xA0 });

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

                byte[] bytes;

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
                string decryptedData = DecryptStringFromBytes_Aes(bytes, myAes.Key, myAes.IV);
                Console.WriteLine(decryptedData);
                //Console.WriteLine(Encoding.Default.GetString(bytes));
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
