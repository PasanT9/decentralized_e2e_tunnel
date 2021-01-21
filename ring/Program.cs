using System;
using System.Text;
using System.Security.Cryptography;
using System.Collections;
using System.Collections.Generic;

namespace ring
{
    class Program
    {


        static void Main(string[] args)
        {
            byte[][] y = new byte[10][];
            int[] x = new int[10];
            string message = "Hello!!";

            byte[] msg = Encoding.ASCII.GetBytes(message);

            Dictionary<int, Tuple<RSAParameters, RSAParameters>> keys = new Dictionary<int, Tuple<RSAParameters, RSAParameters>>();

            Random rnd = new Random();

            for (int i = 0; i < 10; ++i)
            {
                x[i] = rnd.Next();
                using (var rsa = new RSACryptoServiceProvider(2048))
                {
                    rsa.PersistKeyInCsp = false; //Don't store the keys in a key container
                    RSAParameters publicKey = rsa.ExportParameters(false);
                    RSAParameters privateKey = rsa.ExportParameters(true);
                    Tuple<RSAParameters, RSAParameters> key = new Tuple<RSAParameters, RSAParameters>(publicKey, privateKey);
                    keys[i] = key;
                }

                y[i] = Encrypt(Encoding.ASCII.GetBytes(x[i].ToString()), keys[i].Item1);

                //Console.WriteLine("->" + x[i]);
                //Console.WriteLine(Encoding.ASCII.GetString(Decrypt(y[i], keys[i].Item2)));

            }
            byte[] ring = y[0];
            for (int i = 1; i < 10; ++i)
            {
                ring = exclusiveOR(ring, y[i]);
            }

            var rsa_s = new RSACryptoServiceProvider(2048);

            rsa_s.PersistKeyInCsp = false;

            RSAParameters publicKey_s = rsa_s.ExportParameters(false);
            RSAParameters privateKey_s = rsa_s.ExportParameters(true);

            xs = rnd.Next();
            ys = Encrypt(Encoding.ASCII.GetBytes(xs.ToString()), publicKey_s);

            byte[] v = exclusiveOR(ring, ys);

        }

        public static byte[] exclusiveOR(byte[] arr1, byte[] arr2)
        {
            if (arr1.Length != arr2.Length)
                throw new ArgumentException("arr1 and arr2 are not the same length");

            byte[] result = new byte[arr1.Length];

            for (int i = 0; i < arr1.Length; ++i)
                result[i] = (byte)(arr1[i] ^ arr2[i]);

            return result;
        }

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        static byte[] Encrypt(byte[] input, RSAParameters publicKey)
        {
            byte[] encrypted;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(publicKey);

                //get public key from file
                //rsa.ImportParameters(StringToKey(File.ReadAllText(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + @"\pubKey.xml")));
                try
                {
                    encrypted = rsa.Encrypt(input, false);
                    return encrypted;
                }
                catch (System.Exception e)
                {
                    System.Console.WriteLine(e);
                    byte[] empty = { };
                    return empty;
                }
            }
        }

        static byte[] Decrypt(byte[] input, RSAParameters privateKey)
        {
            Console.WriteLine(input.Length);
            byte[] decrypted;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.PersistKeyInCsp = false;
                rsa.ImportParameters(privateKey);

                //get private key from file
                //rsa.ImportParameters(StringToKey(File.ReadAllText(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) + @"\priKey.xml")));

                try
                {
                    decrypted = rsa.Decrypt(input, true);
                    return decrypted;
                }
                catch (System.Exception e)
                {
                    System.Console.WriteLine(e);
                    byte[] empty = { };
                    return empty;
                }
            }
        }
    }
}
