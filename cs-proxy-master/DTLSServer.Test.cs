using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Rishi;


namespace Rishi.DTLSS{
		class Program
		{
				static void Main(string[] args)
				{
						Console.WriteLine("Hello World!");
						DTLSServer dtls = new DTLSServer("10000", new byte[] {0xBA,0xA0});
						if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)){
								dtls.Unbuffer="winpty.exe";
								dtls.Unbuffer_Args="-Xplain -Xallow-non-tty";
						}
						else{
								dtls.Unbuffer="stdbuf";
								dtls.Unbuffer_Args="-i0 -o0";
						}
						dtls.Start();
						dtls.GetStream().Write(Encoding.Default.GetBytes("It's Working!"+Environment.NewLine));
						dtls.WaitForExit();
				}
		}
}
