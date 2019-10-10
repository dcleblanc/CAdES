using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace DumpTLSCerts
{
    class Program
    {
        public static bool RemoteCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            X509ChainElementCollection x509ChainElementCollection = chain.ChainElements;

            foreach (X509ChainElement chainElement in x509ChainElementCollection)
            {
                X509Certificate2 cert = chainElement.Certificate;
                X509ChainStatus[] chainStatus = chainElement.ChainElementStatus;
                string info = chainElement.Information;

                // Get the raw bytes so we can write it:
                string name = cert.GetNameInfo(X509NameType.SimpleName, false);
                byte[] rawCert = cert.GetRawCertData();

                // Substitute characters that foul up a shell script or batch file
                string outputName = (name.Replace(' ', '_')).Replace('*', '_').Replace('(', '_').Replace(')', '_') + ".cer";

                using (FileStream fs = new FileStream(outputName, FileMode.Create, FileAccess.Write))
                {
                    fs.Write(rawCert, 0, rawCert.Length);
                }
            }

            return true;
        }

        static void Main(string[] args)
        {
            FileStream inputFile = null;

            if( args.Length != 1 )
            {
                Console.WriteLine("Enter path to file with sites");
                return;
            }

            try
            {
                inputFile = new FileStream(args[0], FileMode.Open);
            }
            catch(Exception fileException)
            {
                Console.WriteLine("File not found: " + args[0] + " " + fileException.Message);
            }

            StreamReader reader = new StreamReader(inputFile);
            string site;

            while((site = reader.ReadLine()) != null)
            {
                if(site.Length == 0)
                    continue;

                string url = "https://" + site;

                HttpWebRequest request = WebRequest.CreateHttp(url);
                request.ServerCertificateValidationCallback = RemoteCertificateValidationCallback;
                try
                {
                    using (HttpWebResponse response = (HttpWebResponse)request.GetResponse()) { }
                }
                catch (Exception doh)
                {
                    Console.WriteLine("Response error: " + site + " " + doh.Message);
                }
            }
        }
    }
}
