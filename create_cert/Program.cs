using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace create_cert
{
    class Program
    {
        public static void Main (string[] args)
        {
            X509Store store = new X509Store ("teststore", StoreLocation.CurrentUser);
            store.Open (OpenFlags.ReadWrite);

            //Create certificates from certificate files.
            //You must put in a valid path to three certificates in the following constructors.
            X509Certificate2 certificate = new X509Certificate2 ("/home/pasan/Documents/FYP_certificates/test.cer");

            //Add certificates to the store.
            store.Add (certificate);

            X509Certificate2Collection storecollection = (X509Certificate2Collection)store.Certificates;
            Console.WriteLine ("Store name: {0}", store.Name);
            Console.WriteLine ("Store location: {0}", store.Location);
            foreach (X509Certificate2 x509 in storecollection)
            {
                Console.WriteLine("certificate name: {0}",x509.Subject);
            }
            //Close the store.
            store.Close ();
        }	
    }
}
