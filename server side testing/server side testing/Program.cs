using System;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;

namespace server_side_testing
{
    
    
    class Program
    {
        public static string data = null;
        public static List<KeyValuePair<string, string>> users = new List<KeyValuePair<string, string>>();
        public static void SendMessage(string inptext, string recipientIP)
        {
            //metacharacters are removed so that the ip address is parsed properly
            recipientIP = recipientIP.Replace("\n","");
            recipientIP = recipientIP.Replace("\r", "");

            try
            {
                Console.WriteLine(recipientIP);
                // Creates a socket which is initialised to the IP of the client device 
                IPAddress ipAddress = IPAddress.Parse(recipientIP.ToString());
                Console.WriteLine(ipAddress.ToString());
                IPEndPoint remoteEP = new IPEndPoint(ipAddress, 11000);
                Console.WriteLine(remoteEP.ToString());
                Socket sender = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                try
                {
                    //socket connects to the client 
                    sender.Connect(remoteEP);
                    Console.WriteLine("connected");
                    // creates an instance of the RSA class which will be used for asymmetric encryption
                    RSA Rsa1 = RSA.Create();
                    //the parameters of the client's public key are exported into an RSAParameters key container
                    RSAParameters rsaKeyinfo = Rsa1.ExportParameters(false);
                    // byte arrays are created to store the public key and exponent so that they can be shared with the server 
                    byte[] modulus = rsaKeyinfo.Modulus;
                    byte[] exponent1 = rsaKeyinfo.Exponent;
                    //public key and exponent are sent to the client
                    sender.Send(modulus);
                    sender.Send(exponent1);
                    // byte arrays are created to store the encrypted shared key and IV to be used for symmetric encryption
                    byte[] encryptedSymmetricKey = new byte[256];
                    byte[] encryptedSymmetricIV = new byte[256];
                    //receives the encrypted shared key and IV from the client
                    sender.Receive(encryptedSymmetricKey);
                    sender.Receive(encryptedSymmetricIV);
                    // byte arrays to store the decrypted versions of the symmetric key and IV 
                    byte[] symmetrickey;
                    byte[] symmetricIV;
                    // the encrypted key and IV are decrypted using the client's private key so they can be used for symmetric encryption
                    try
                    {
                        symmetrickey = Rsa1.Decrypt(encryptedSymmetricKey, RSAEncryptionPadding.Pkcs1);
                        symmetricIV = Rsa1.Decrypt(encryptedSymmetricIV, RSAEncryptionPadding.Pkcs1);

                    }
                    // catch statement for error handling and debugging purposes
                    catch (Exception e)
                    {
                        symmetrickey = null;
                        symmetricIV = null;
                        Console.WriteLine($"Decryption Failed {e}");
                    }
                    //an instance of the AES class is created to be used for symmetric encryption to communicate with the client
                    Aes aes = Aes.Create();
                    // the parameters for the shared key and IV recived from the server are loaded
                    aes.Key = symmetrickey;
                    aes.IV = symmetricIV;
                    var key = symmetrickey;
                    var iv = symmetricIV;
                    //encrypting using the shared symmetric key
                    try
                    {
                        // a networkstream is inintialised so that encrypted data can be streamed to the client
                        NetworkStream networkstream = new NetworkStream(sender);
                        // a cryptostream is initialised which will encrypt all data written to it using AES with the symmetric key and IV
                        CryptoStream cryptstream = new CryptoStream(networkstream, aes.CreateEncryptor(key, iv), CryptoStreamMode.Write);
                        using (cryptstream)
                        {

                            using (StreamWriter encryptwriter = new(cryptstream))
                            {
                                // message is written to the networkstream using the encryptwriter meaning the encrypted data will be written to the stream for the client to read
                                encryptwriter.WriteLine(inptext);
                                Console.WriteLine($"message sent: {inptext}");
                            }
                        }
                    }
                    // catch statement for error handling and debugging purposes
                    catch (Exception e)
                    {

                        Console.WriteLine($"encryption failed exeption:{e}");
                    }

                    // closes the socket 
                    sender.Shutdown(SocketShutdown.Both);
                    sender.Close();
                }
                // catch statements for error handling and debugging purposes
                catch (ArgumentNullException ane)
                {

                    Console.WriteLine($"ArugmentNullException: {ane}");
                }
                catch (SocketException se)
                {
                    Console.WriteLine($"SocketException {se}");
                }
                catch (Exception e)
                {
                    Console.WriteLine($"Unexpected Exception {e}");

                }
            }
            catch (Exception e)
            {

                Console.WriteLine(e.ToString());
            }

        }
        private static void SendUsers ()
        {
            //each user will be sent the usernames of all the users connected to the server, and end statment it then sent to let the client know to stop recieving
            foreach (var ip in users)
            {
                foreach (var users in users)
                {
                    SendMessage(users.Key,ip.Value);
                }
                SendMessage("end",ip.Value);
            }

        }
        public static async Task StartListeningAsync()
        {
            
            // initialises the Host IP 
            IPHostEntry ipHostinfo = Dns.GetHostEntry(Dns.GetHostName());
            IPAddress ipAddress = ipHostinfo.AddressList[0];
            IPEndPoint localEndPoint = new IPEndPoint(ipAddress, 11000);
            Console.WriteLine(ipAddress.ToString());
            // TCP/IP socket created with the host ip 
            Socket listener = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            try
            {
                //socket is bound to the endpoint so that the listen method can be performed
                listener.Bind(localEndPoint);
                // socket listens for a client to connect
                listener.Listen(10);

                while (true)
                {
                    Console.WriteLine("waiting for a user to connect...");
                    // handler socket is created to accept the client that has connected to the server
                    Socket handler = listener.Accept();
                        // byte arrays created to store the key and exponent of the client's public key
                        byte[] modulus = new byte[256];
                        byte[] exponent = new byte[3];
                        // the public key and exponent are received from the client to be used for asymmetric encryption
                        handler.Receive(modulus);
                        
                        handler.Receive(exponent);
                       // an instance of the RSA class is created to be used for asymmetric encryption
                        RSA Rsa1 = RSA.Create();
                       // RSAParameters keycontainer is created to be used to load the client's public key values 
                        RSAParameters rsaKeyInfo = Rsa1.ExportParameters(false);
                       // public key and exponent are loaded to the keycontainer
                        rsaKeyInfo.Modulus = modulus;
                        rsaKeyInfo.Exponent = exponent;
                        // parameters are imported from the keycontainer to the RSA class so that it is set to the client's public key
                        Rsa1.ImportParameters(rsaKeyInfo);
                        // byte arrrays created to store the encrypted symmetric key and IV 
                        byte[] encryptedSymmetricKey;
                        byte[] encryptedSymmetricIV;
                        // instance of the AES class created to be used for symmetric encryption/decryption
                        Aes aes = Aes.Create();
                        // symmetric key and IV are generated
                        aes.GenerateKey();
                        aes.GenerateIV();
                        // symmetric key and IV are encrypted using the clients public key
                        try
                        {
                            encryptedSymmetricIV = Rsa1.Encrypt(aes.IV, RSAEncryptionPadding.Pkcs1);
                            encryptedSymmetricKey = Rsa1.Encrypt(aes.Key, RSAEncryptionPadding.Pkcs1);
                        }
                         // catch statement for error handling and debugging
                        catch (Exception e)
                        {
                            encryptedSymmetricKey = null;
                            encryptedSymmetricIV = null;
                            Console.WriteLine($"Encryption Failed {e}");
                        }
                        // the encrypted shared symmetric key and IV are sent to the client
                        handler.Send(encryptedSymmetricKey);

                        handler.Send(encryptedSymmetricIV);
                       // byte arrays created to store the key and IV values to specify for encryption/decryption
                        var key = aes.Key;
                        var iv = aes.IV;
                        // networkstream created to recieve encrypted data from the client via the socket
                        NetworkStream networkstream = new(handler);
                        while (true)
                        {
                           // for testing/debugging the server states whether the stream has had any data written to it
                            Console.WriteLine(networkstream.DataAvailable.ToString());
                            // server checks if the stream is empty or not if so, it waits a second and checks again
                            if (networkstream.DataAvailable == true)
                            {
                                // crytostream is initialised which decrypts all the data it reads from the networkstream using AES with the symmetric key and IV
                                CryptoStream cryptstream = new CryptoStream(networkstream, aes.CreateDecryptor(key, iv), CryptoStreamMode.Read);
                                using (cryptstream)
                                {
                                    try
                                    {
                                        // streamreader is created to read from the cryptostream
                                        using (StreamReader Decryptreader = new(cryptstream))
                                        {
                                            // enryptreader reads from the networkstream and decrypts the data which is then read by the decrypreader and stored as a string
                                         string data = Decryptreader.ReadToEnd();
                                        Console.WriteLine(data);
                                        if (data.Contains("|") == true)
                                        {
                                            
                                            string[] temp = data.Split('|');
                                            try
                                            {
                                                users.Add(new KeyValuePair<string, string>(temp[0], temp[1]));
                                                try
                                                {
                                                    //a network stream is created to send data(in this case a list of all the usernames) to the client
                                                    NetworkStream sendUsersNetworkStream = new NetworkStream(handler);
                                                    // a cryptostream is created and configured to the exchanged symmetric key, this will encrypt the data that is sent
                                                    CryptoStream sendUsersCryptStream = new CryptoStream(sendUsersNetworkStream, aes.CreateEncryptor(key, iv), CryptoStreamMode.Write);
                                                    using(sendUsersCryptStream)
                                                    {
                                                        using (StreamWriter encryptWriter = new StreamWriter(sendUsersCryptStream))
                                                        {
                                                            foreach (var user in users)
                                                            {
                                                                encryptWriter.Write(user.Key + " ");
                                                                Console.WriteLine($"Username sent: {user.Key}");
                                                            }


                                                        }
                                                    }

                                                }
                                                catch (Exception ex)
                                                {
                                                    Console.WriteLine(ex);
                                                }
                                            }
                                            catch (Exception e)
                                            {

                                                Console.WriteLine(e); ;
                                            }
                                        }
                                        //messages contain ~ to separate the useername of the user sending the message,
                                        // the message itself, and the username of the intended recipient
                                        else if (data.Contains('~') == true)
                                        {
                                            string[] temp = data.Split('~');
                                            foreach (var str in temp)
                                            {
                                                str.Replace("\n", "");
                                                str.Replace("\r", "");

                                            }
                                            foreach (var user in users)
                                            {
                                                if (user.Key == temp[2])
                                                {
                                                    string message = $"From {temp[0]}: {temp[1]}";
                                                    SendMessage(message, user.Value);
                                                }
                                            }
                                        }
                                        
                                        else
                                        {
                                            // message is written to console 
                                            Console.WriteLine(data);
                                            break;
                                        }
                                        }
                                    }
                                    // catch statement for error handling and testing/debugging
                                    catch (Exception e)
                                    {

                                        Console.WriteLine($"Decryption failed: {e}");
                                    }
                                }

                                break;
                            }
                            // if the networkstream is empty, the server will let the user know it is waiting and will wait one second
                            else
                            {
                                Console.WriteLine("waiting...");
                                Thread.Sleep(1000);
                            }
                        

                     }
                        // the handler socket is shut down and the server will return to listening
                        handler.Shutdown(SocketShutdown.Both);
                        handler.Close();
                    }

                
            }
            // catch statement for error handling and testing
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
             }
            Console.WriteLine("\n Press ENTER to continue...");
            Console.Read();

        }
        static void Main(string[] args)
        {
            StartListeningAsync();
            
        }
    }
}
