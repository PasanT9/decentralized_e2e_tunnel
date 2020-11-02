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
			Console.Error.WriteLine("\u001b[31mHey!\u001b[0m");
			Console.Error.WriteLine("Hello World!");
			DTLSClient dtls = new DTLSClient("127.0.0.1", "10000", new byte[] {0xBA,0xA0});
			if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)){
			dtls.Unbuffer="winpty.exe";
			dtls.Unbuffer_Args="-Xplain -Xallow-non-tty";
			}
			else{
			dtls.Unbuffer="stdbuf";
			dtls.Unbuffer_Args="-i0 -o0";
			}
			dtls.Start();
			statpair IOStream = new statpair(new StreamReader(Console.OpenStandardInput()), new StreamWriter(Console.OpenStandardOutput()));
			new Thread(()=>IOStream.CopyTo(dtls.GetStream(), 16)).Start();
			new Thread(() => dtls.GetStream().CopyTo(IOStream, 16)).Start();
			//new Thread(() => dtls.GetStream().Write(Encoding.Default.GetBytes("It Works!"+Environment.NewLine))).Start();
			pair.BindStreams(dtls.GetStream(), IOStream);
			pair.BindStreams(dtls.GetStream(), IOStream);
			Timer T = new Timer((S)=>{float BR = (float)IOStream.BytesRead/(1024*1024*5); float BW = (float)IOStream.BytesWritten/(1024*1024*5);Console.Error.WriteLine($"R: {BR:000.00} MB/s.\tW: {BW:000.00} MB/s.");IOStream.ResetStats();},new AutoResetEvent(false),5000,5000);
			Console.WriteLine("End of File");
			dtls.WaitForExit();
		}
	}
}
