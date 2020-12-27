using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Numerics;

using LSAG;


namespace LSAGTest
{
  class Program
  {
    static void Main(string[] args)
    {
      
      var liu2005 = new Liu2005();
      int participants = 100;

      Console.WriteLine("Benchmark for {0} participants", participants);
      liu2005.GroupParameters = KnownGroupParameters.RFC5114_2_1_160;

      var message = "hi";

      var messageBytes = Encoding.UTF8.GetBytes(message);

      var keys = Enumerable.Range(0, participants).Select(i => liu2005.GenerateKeyPair()).ToArray();
      var publicKeys = keys.Select(k => k[1]).ToArray();

      var signature = liu2005.GenerateSignature(messageBytes, publicKeys, keys[0][0], 0);

      var cache = new MultiExponentiation(liu2005.GroupParameters.Prime, publicKeys);


      bool res = liu2005.VerifySignature(messageBytes, signature, cache);
      if(res){
        Console.WriteLine("SUCCESS");      
      }
      else{
        Console.WriteLine("FAILURE");      
      }

    }

  }
}