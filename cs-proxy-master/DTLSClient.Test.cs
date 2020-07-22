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
using Rishi.ProxyClient;
using Rishi.PairStream;

namespace Rishi.DTLSC
{
	class Program
	{
		static void SetColour(int fg, int bg){
			System.Console.Error.WriteLine($"\u001b[1;3{fg}m");
			System.Console.Error.WriteLine($"\u001b[4{bg}m");
		}
		static void ResetColour(){
			System.Console.Error.WriteLine("\u001b[39m");
			System.Console.Error.WriteLine("\u001b[49m");
		}
		static void Main(string[] args)
		{
			Console.Error.WriteLine("\u001b[31mHey!\u001b[0m");
			SetColour(2,0);
			Console.Error.WriteLine("Hello World!");
			ResetColour();
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
			Timer T = new Timer((S)=>{float BR = (float)IOStream.BytesRead/(1024*1024*5); float BW = (float)IOStream.BytesWritten/(1024*1024*5); SetColour(2,0);Console.Error.WriteLine($"R: {BR:000.00} MB/s.\tW: {BW:000.00} MB/s.");IOStream.ResetStats();ResetColour();},new AutoResetEvent(false),5000,5000);
			Console.WriteLine("End of File");
			dtls.WaitForExit();
		}
	}
}
