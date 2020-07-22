using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
#if !NETSTANDARD2_0
using System.Buffers;
#endif
using System.Runtime.InteropServices;
using ProxyClient;
using PairStream;

namespace dtls_server
{
class Program
		{
				static void Main(string[] args)
				{
						DTLSServer dtls = new DTLSServer("10000", new byte[] {0xBA,0xA5});
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
						new Thread(() => dtls.GetStream().CopyTo(IOStream, 16)).Start();
						while(true)
						{
							string input = Console.ReadLine();
							dtls.GetStream().Write(Encoding.Default.GetBytes(input+Environment.NewLine));
						}
						dtls.WaitForExit();
				}
		} 
}
