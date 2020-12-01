using System;
using System.Diagnostics;

namespace main
{
    class Program
    {
        static void Main(string[] args)
        {
var output = "";
 
        var info = new ProcessStartInfo("free");
        info.FileName = "/bin/bash";
        info.Arguments = "-c \"free\"";
        info.RedirectStandardOutput = true;
        
        using(var process = Process.Start(info))
        {                
            output = process.StandardOutput.ReadToEnd();
            Console.WriteLine(output);
        }
 
        var lines = output.Split("\n");
        var memory = lines[1].Split(" ", StringSplitOptions.RemoveEmptyEntries);
    
        Console.WriteLine("Available: " + memory[6]);

        
        }


    }
}
