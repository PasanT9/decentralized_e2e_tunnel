/* Copyright [2019] RISHIKESHAN LAVAKUMAR <github-public [at] ris.fi>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/


using System;
using System.Text;
using System.IO;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
#if !NETSTANDARD2_0
using System.Buffers;
#endif
using Rishi.ProxyClient;
using Rishi.PairStream;

namespace Rishi.ProxyClient
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
			ProxySocket ps = new ProxySocket("google.com", 80, "127.0.0.1", 1080, "5");
			ps.Unbuffer="stdbuf";
			ps.Unbuffer_Args="-i0 -o0";
			ps.Start();
			statpair IOStream = new statpair(new StreamReader(Console.OpenStandardInput()), new StreamWriter(Console.OpenStandardOutput()));
			new Thread(()=>IOStream.CopyTo(ps.GetStream(), 16)).Start();
			new Thread(() => ps.GetStream().CopyTo(IOStream, 16)).Start();
			//new Thread(() => dtls.GetStream().Write(Encoding.Default.GetBytes("It Works!"+Environment.NewLine))).Start();
			pair.BindStreams(ps.GetStream(), IOStream);
			pair.BindStreams(ps.GetStream(), IOStream);
			Timer T = new Timer((S)=>{float BR = (float)IOStream.BytesRead/(1024*1024*5); float BW = (float)IOStream.BytesWritten/(1024*1024*5); SetColour(2,0);Console.Error.WriteLine($"R: {BR:000.00} MB/s.\tW: {BW:000.00} MB/s.");IOStream.ResetStats();ResetColour();},new AutoResetEvent(false),5000,5000);
			Console.WriteLine("End of File");
			ps.WaitForExit();
		}
	}
}
