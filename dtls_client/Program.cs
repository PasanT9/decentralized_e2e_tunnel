using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
#if !NETSTANDARD2_0
using System.Buffers;
#endif
using System.Runtime.InteropServices;
using ProxyClient;
using PairStream;
using dtls_server;

namespace dtls_client
{
	class Program
	{
		static void Main(string[] args)
		{
			DTLSClient dtls_client = new DTLSClient("127.0.0.1", "10000", new byte[] {0xBA,0xA0});
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
		}
	}
}
