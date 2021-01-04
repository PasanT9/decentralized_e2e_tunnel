using System;
using System.Text;
using System.Net.Security;
using Newtonsoft.Json;

namespace TCP
{
    class TCPCommunication
    {
        public static void send_message_tcp(SslStream sslStream, string message)
        {
            Request req = new Request(200, message);
            string jsonString = JsonConvert.SerializeObject(req);
            byte[] data = Encoding.UTF8.GetBytes(jsonString);
            sslStream.Write(data);

            sslStream.Flush();
        }

        public static string recieve_message_tcp(SslStream sslStream)
        {
            Byte[] bytes = new Byte[512];
            sslStream.Read(bytes, 0, bytes.Length);
            string message = Encoding.UTF8.GetString(bytes);
            Request reply = JsonConvert.DeserializeObject<Request>(message);
            return reply.body;
        }
    }
}