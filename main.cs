using System;
using System.IO;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace Mti
{
	class HttpServer
	{ 
		static Encoding enc = Encoding.UTF8;


    public static string CreateToken(string message, string secret)
    {
      secret = secret ?? "";
      var encoding = new System.Text.UTF8Encoding();
      byte[] keyByte = encoding.GetBytes(secret);
      byte[] messageBytes = encoding.GetBytes(message);
      using (var hmacsha256 = new HMACSHA256(keyByte))
      {
        byte[] hashmessage = hmacsha256.ComputeHash(messageBytes);
        return Convert.ToBase64String(hashmessage);
      }
    }

		public static void Main (string[] args)
		{
			TcpListener listener = new TcpListener (IPAddress.Any, 8080);
			listener.Start (); 

			while (true) {
				TcpClient client = listener.AcceptTcpClient (); 
				Console.WriteLine ("Request Incoming");
			 
				NetworkStream stream = client.GetStream (); 
				string request = ToString (stream);

        string received_hmac_signature = "Not Resolved";
        string body = "Not Resolved";

        foreach (string line in request.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries))
        {
          if (line.StartsWith("X-Turn-Hook-Signature"))
          {
              received_hmac_signature = line.Replace("X-Turn-Hook-Signature: ", "").Trim();
          }
          if (line.StartsWith("{"))
          {
              body = line;
          }
        }

        string calculated_hmac_signature = CreateToken(body, Environment.GetEnvironmentVariable("SECRET"));

        Console.WriteLine("Request Body:" + body);
        Console.WriteLine("Received HMAC:" + received_hmac_signature);
        Console.WriteLine("Calculated HMAC:" + calculated_hmac_signature);

				StringBuilder builder = new StringBuilder ();
        if (received_hmac_signature == calculated_hmac_signature) {
          builder.AppendLine (@"HTTP/1.1 200 OK"); 
				  builder.AppendLine (@"Content-Type: text/html");
				  builder.AppendLine (@"");
          builder.AppendLine (@"Valid HMAC received");
        } else {
          builder.AppendLine (@"HTTP/1.1 403 OK"); 
				  builder.AppendLine (@"Content-Type: text/html");
				  builder.AppendLine (@"");
          builder.AppendLine (@"Invalid HMAC received"); 
        }
				
				Console.WriteLine ("Responce:");
				Console.WriteLine (builder.ToString ());
				 
				byte[] sendBytes = enc.GetBytes (builder.ToString ());
				stream.Write (sendBytes, 0, sendBytes.Length);

				stream.Close ();
				client.Close ();
			}
		}
		 
		public static string  ToString (NetworkStream stream)
		{
			MemoryStream memoryStream = new MemoryStream ();
			byte[] data = new byte[256];
			int size;
			do {
				size = stream.Read (data, 0, data.Length);
				if (size == 0) {
					Console.WriteLine ("Client Disconnected");
					Console.ReadLine ();
					return  null; 
				} 
				memoryStream.Write (data, 0, size);
			} while ( stream.DataAvailable); 
			return enc.GetString (memoryStream.ToArray ());
		}
	}
}
