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
using Rishi.PairStream;
using System.Runtime.InteropServices;
using static System.Runtime.InteropServices.RuntimeInformation;
using System.Net;


namespace Rishi.ShellBind {
		///<summary>
		/// The ShellSocket class of the module Rishi.ShellBind. Binds a command as a stream.
		///</summary>
		public class ShellSocket{

				///<summary>
				///Verbosity.
				///</summary>
				protected bool VERBOSE;
				protected StreamWriter A;
				protected StreamReader B;
				///<summary>
				///The process: <c>System.Diagnostics.Process</c>.
				///</summary>
				protected Process Proc = new Process();
				protected string Command;
				protected string Args;

				///<summary>
				///The shell unbuffer/stdbuf command, default: none.
				///</summary>
				public string Unbuffer;
				///<summary>
				///Arguments to the shell unbuffer/stdbuf command, default: none.
				///</summary>
				public string Unbuffer_Args;
				protected StreamWriter ErrDestination;
				private bool _RedirectErrorsToConsole;
				///<summary>
				///Whether error stream (STDERR) should be redirected to STDOUT.
				///Won't be using UseShellExecute if set.
				///Docs: To use StandardError, you must set ProcessStartInfo.UseShellExecute to false, and you must set ProcessStartInfo.RedirectStandardError to true. Otherwise, reading from the StandardError stream throws an exception. 
				///To be set before Start()ing.
				///</summary>
				public bool RedirectErrorsToConsole{
						get {return _RedirectErrorsToConsole;}
						set {
								if(value==true){
										this.Proc.StartInfo.UseShellExecute=false;
								}
								else
								{
										this.Proc.StartInfo.UseShellExecute=true;
								}
								this._RedirectErrorsToConsole=value;
						}
				}
				///<summary>
				///Whether error stream (STDERR) should be redirected to a stream.
				///Won't be using UseShellExecute if set.
				///Docs: To use StandardError, you must set ProcessStartInfo.UseShellExecute to false, and you must set ProcessStartInfo.RedirectStandardError to true. Otherwise, reading from the StandardError stream throws an exception. 
				///To be set before Start()ing.
				///</summary>
				public bool RedirectErrorsToStream;

				///<summary>
				///Specify whether to use GNU/BSD stdbuf.
				///</summary>
				public bool UseStdbuf;
				///<summary>
				///Specify whether to use GNU/BSD unbuffer (TCL expect).
				///</summary>
				public bool UseUnbuffer;
				///<summary>
				///Specify whether to use WinPTY.
				///</summary>
				public bool UseWinpty;
				///<summary>
				///Auto configure the environment on failure on presumed interactive terminals.
				///</summary>
				public bool AutoConfigure=true;
				///<summary>
				///The package name to download the files, default: WinPTY.
				///</summary>
				public string PackageName = "WinPTY";
				///<summary>
				///Constructor. Uses the GNU/BSD stdbuf by default (Unix/-like) or WinPTY on Windows. If you don't like it, please see the one which specifies it and pass an empty string.
				///</summary>
				/// <param name="Command">A command.</param>
				/// <param name="Args">Arguments.</param>
				///<seealso cref="ShellSocket(string, string, string, string)"/>
				public ShellSocket(string Command, string Args){
						this.Proc = new Process();
						this.Command=Command;
						this.Args=Args;
#if !(NETSTANDARD2_0 || NETCOREAPP2_0 || NETCOREAPP2_1 || NETCOREAPP2_2)
						if ( IsOSPlatform(OSPlatform.Linux) ||  IsOSPlatform(OSPlatform.FreeBSD) ||  IsOSPlatform(OSPlatform.OSX))
#else
								if ( IsOSPlatform(OSPlatform.Linux) ||  IsOSPlatform(OSPlatform.OSX))
#endif
										UseStdbuf=true;
								else  if ( IsOSPlatform(OSPlatform.Windows) ){
										UseStdbuf=false;
										UseWinpty=true;
								}
								else UseStdbuf=false;
						this._RedirectErrorsToConsole=false;
						this.RedirectErrorsToStream=false;
						this.VERBOSE=false;

				}
				///<summary>
				///Constructor.
				///</summary>
				///<seealso cref="ShellSocket(string, string)"/>
				/// <param name="Command">A command.</param>
				/// <param name="Args">Arguments.</param>
				/// <param name="Unbuffer_Command">Unbuffer command. Use "" or null to run directly at your own risk.</param>
				/// <param name="Unbuffer_Args">Unbuffer arguments.</param>
				public ShellSocket(string Command, string Args, string Unbuffer_Command, string Unbuffer_Args){
						this.UseStdbuf=false;
						this.Proc = new Process();
						this.Command=Command;
						this.Args=Args;
						this.Unbuffer = Unbuffer_Command;
						this.Unbuffer_Args=Unbuffer_Args;
						this._RedirectErrorsToConsole=false;
						this.RedirectErrorsToStream=false;
						this.VERBOSE=false;

				}
				///<summary>
				///Starts the process.
				///</summary>
				public void Start(){

						if(UseStdbuf)
						{	
								Unbuffer = "stdbuf";
								Unbuffer_Args="-i0 -o0";
						}
						else if(UseUnbuffer)
						{	
								Unbuffer = "unbuffer";
								Unbuffer_Args="-p";
						}
						else if(UseWinpty)
						{	
								Unbuffer = "winpty.exe";
								Unbuffer_Args="-Xallow-non-tty -Xplain";
						}
						if(Unbuffer == "" || Unbuffer==null){
								this.Proc.StartInfo.FileName=$"{Command}";
								Proc.StartInfo.Arguments=$"{Args}";
						}
						else {
								this.Proc.StartInfo.FileName=$"{Unbuffer}";
								Proc.StartInfo.Arguments=$"{Unbuffer_Args} {Command} {Args}";
						}
						this.Proc.StartInfo.UseShellExecute = false;
						this.Proc.StartInfo.RedirectStandardOutput = true;
						Proc.StartInfo.RedirectStandardInput=true;
						if (RedirectErrorsToConsole){
								CopyErrorsTo(new StreamWriter(Console.OpenStandardError()));
								Proc.StartInfo.RedirectStandardError=true;
								Proc.StartInfo.UseShellExecute=false;
						}
						if(RedirectErrorsToStream){
								Proc.StartInfo.UseShellExecute=false;
								Proc.StartInfo.RedirectStandardError=true;
						}
						try
						{
								Proc.Start();
						}
						catch (System.ComponentModel.Win32Exception)
						{
								if (IsOSPlatform(OSPlatform.Windows) && IsInteractive() && AutoConfigure)
								{
										PromptDownload(PackageName);
										Start();
										return;
								}
						}
						if (VERBOSE){
								SetColour(5,0);
								System.Console.Error.WriteLine(Proc.StartInfo.FileName + " " + Proc.StartInfo.Arguments);
								ResetColour();
						}

						A = Proc.StandardInput;
						B = Proc.StandardOutput;
						if(RedirectErrorsToStream){
								Proc.StandardError.BaseStream.CopyToAsync(ErrDestination.BaseStream);
						}
				}

				///<summary>
				///Get the Stream formed by the process.
				///Should be Start()ed first.
				///</summary>
				public Stream GetStream(){
						if (VERBOSE) if (A==null || B==null)
								System.Console.WriteLine("B/A (I/O Stream) is null. Try start() before calling this. A:{0}, B:{1}.", A, B);
						return new pair(B,A);
				}
				///<summary>
				///Kill the process.
				///</summary>
				public void Kill(){
						Proc.Kill();
				}
				///<summary>
				///Close the process.
				///</summary>
				public void Close(){
						Proc.Close();
				}
				///<summary>
				///Wait for the process to exit.
				///</summary>
				public void WaitForExit(){
						Proc.WaitForExit();
				}

				///<summary>
				///Set the stream to copy STDERR to.
				///</summary>
				public void CopyErrorsTo(StreamWriter Destination){
						this.ErrDestination=Destination;
						RedirectErrorsToStream=true;
				}

				private static void SetColour(int fg, int bg){
						System.Console.Error.WriteLine($"\u001b[1;3{fg}m");
						System.Console.Error.WriteLine($"\u001b[4{bg}m");
				}
				private static void ResetColour(){
						System.Console.Error.WriteLine("\u001b[39m");
						System.Console.Error.WriteLine("\u001b[49m");
				}
				/// <summary>
				/// Hack to check interactiveness.
				/// </summary>
				/// <returns></returns>
				static private bool IsInteractive()
				{
						if (System.Console.IsInputRedirected || System.Console.IsInputRedirected) return false;
						else return true;
				}
				/// <summary>
				/// Prompt and download, with consent, the executable(s).
				/// </summary>
				/// <param name="EXEName">The executable.</param>
				void PromptDownload(string EXEName)
				{
						string Prompt =
@"It appears that the executable " + EXEName + @" is not found in PATH. Would you
like to download the file from the internet? Official builds are hosted
at https://log.sep.al; The service is provided voluntarily by the author
and the author takes no responsibility. Source code of the PHP scripts are
available under 3-ClauseBSD license with query string ?source. Please type
[yes] or [no].  By typing [yes], you agree to these conditions and allow
one-time collection of anonymized (OS, Hardware) statistics for providing a
better service. Alternatively, the executables can be manually placed from
somewhere else.";
						System.Console.WriteLine(Prompt);
						string Input;
						while (true)
						{
								System.Console.WriteLine("[yes]/[no]: ");
								Input = System.Console.ReadLine().ToLower();
								if (Input == "yes" || Input == "no") break;
						}
						if (Input == "yes") DownloadFile(EXEName);
				}
				/// <summary>
				/// Download the files.
				/// </summary>
				/// <param name="EXEName">The executable.</param>
				void DownloadFile(string EXEName)
				{
						WebClient WC = new WebClient();
						string[] URLs;
						URLs = WC.DownloadString($"https://log.sep.al/get.php?packagename={PackageName}&osarchitecture={RuntimeInformation.OSArchitecture}&hwplatform={RuntimeInformation.ProcessArchitecture}&os={OSDescription}").Split('\n');
						foreach (string URL in URLs)
						{
								string[] Fields = URL.Split('$');
								if (Fields.Length == 3)
								{
										System.Console.WriteLine($"Downloading {Fields[2]}: {Fields[1]}");
										try
										{
												WC.DownloadFile(Fields[1], Fields[0]);
										}
										catch (Exception) { };
								}
						}
				}
				/// <summary>
				/// Executable suffix list (auto-appended to files).
				/// </summary>
				/// <returns></returns>
				static string[] ExecutableSuffixList()
				{
						if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
						{
								return new string[] { ".com", ".exe", ".bat", ".cmd", "" };
						}
#if !(NETSTANDARD2_0 || NETCOREAPP2_0 || NETCOREAPP2_1 || NETCOREAPP2_2)
						else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX)|| RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.FreeBSD))
#else
						else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
#endif
						{
								return new string[] { "" };
						}
						else return new string[] { "" };
				}
				/// <summary>
				/// Check for executable's existence in the system PATH.
				/// </summary>
				/// <param name="ExecutableName">Executable name.</param>
				/// <returns></returns>
				public static bool CheckExecutableExistence(string ExecutableName)
				{
						string[] Paths = GetPaths();
						foreach (string Path in Paths)
						{
								foreach (string Suffix in ExecutableSuffixList())
								{
										string Filename = Path + "/" + ExecutableName + Suffix;
										//System.Console.WriteLine("Checking: {0}", Filename);
										if (File.Exists(Filename)) return true;
								}
						}
						return false;
				}
				/// <summary>
				/// Get system PATH as string[].
				/// </summary>
				/// <returns></returns>
				static public string[] GetPaths()
				{
						if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
						{
								return Environment.GetEnvironmentVariable("PATH").Split(';');
						}
#if !(NETSTANDARD2_0 || NETCOREAPP2_0 || NETCOREAPP2_1 || NETCOREAPP2_2)
						else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX)|| RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.FreeBSD))
#else
						else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
#endif
						{
								return Environment.GetEnvironmentVariable("PATH").Split(':');
						}
						else return new string[] { Directory.GetCurrentDirectory() };
				}
		}
}
