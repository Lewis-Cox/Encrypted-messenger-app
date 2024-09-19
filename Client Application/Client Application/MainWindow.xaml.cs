using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Security.Cryptography;
using System.Threading;

namespace Client_Application
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow  : Window 
    {
        public static string username = "default";
        public static string talkingToUser = "User1";
        
        public  void Adduser(string username)
        {
            // creates a button for the new user 

            Button Newuser = new Button();
            //the button's content is set to the user's username 
            Newuser.Content = username;
            // button is added to the stack panel
            activeUsersPanel.Children.Add(Newuser);
            // sets the button background and text colour to match the stack panel
            Newuser.Background = new SolidColorBrush(Color.FromRgb(43, 152, 204));
            Newuser.Foreground = new SolidColorBrush(Colors.White);


        }
        public void RecieveUserData ()
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
                // socket listens for a connection
                listener.Listen(10);

                while (true)
                {
                    // handler socket is created to accept the incoming connection that has connected to the server
                    Socket handler = listener.Accept();
                    // byte arrays created to store the key and exponent of the server's public key
                    byte[] modulus = new byte[256];
                    byte[] exponent = new byte[3];
                    // the public key and exponent are received from the server to be used for asymmetric encryption
                    handler.Receive(modulus);

                    handler.Receive(exponent);
                    // an instance of the RSA class is created to be used for asymmetric encryption
                    RSA Rsa1 = RSA.Create();
                    // RSAParameters keycontainer is created to be used to load the servers's public key values 
                    RSAParameters rsaKeyInfo = Rsa1.ExportParameters(false);
                    // public key and exponent are loaded to the keycontainer
                    rsaKeyInfo.Modulus = modulus;
                    rsaKeyInfo.Exponent = exponent;
                    // parameters are imported from the keycontainer to the RSA class so that it is set to the servers's public key
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
                    catch (Exception)
                    {
                        encryptedSymmetricKey = null;
                        encryptedSymmetricIV = null;
                        throw;
                    }
                    // the encrypted shared symmetric key and IV are sent to the server
                    handler.Send(encryptedSymmetricKey);

                    handler.Send(encryptedSymmetricIV);
                    // byte arrays created to store the key and IV values to specify for encryption/decryption
                    var key = aes.Key;
                    var iv = aes.IV;
                    // networkstream created to recieve encrypted data from the client via the socket
                    NetworkStream networkstream = new(handler);
                    bool allusersrecived = false;
                    while (true)
                    {
                        // client checks if the stream is empty or not if so, it waits a second and checks again
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
                                        if (data == "end")
                                        {
                                            allusersrecived = true;
                                        }
                                        else
                                        {
                                            // name of user added as a button 
                                            Adduser(data);
                                        }
                                        
                                    }
                                }
                                // catch statement for error handling and testing/debugging
                                catch (Exception )
                                {
                                    throw;
                                }
                            }

                            break;
                        }
                        // if the networkstream is empty, the client will wait one second
                        else
                        {
                            Thread.Sleep(1000);
                        }


                    }
                    if (allusersrecived == true)
                    {
                        break;
                    }
                    // the handler socket is shut down and the client will return to listening
                    handler.Shutdown(SocketShutdown.Both);
                    handler.Close();
                }


            }
            // catch statement for error handling and testing
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
        }
        public void Receivemessages()
        {
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
                    // socket listens for a connection
                    listener.Listen(10);

                    while (true)
                    {
                        // handler socket is created to accept the server that has connected to the client
                        Socket handler = listener.Accept();
                        // byte arrays created to store the key and exponent of the servers's public key
                        byte[] modulus = new byte[256];
                        byte[] exponent = new byte[3];
                        // the public key and exponent are received from the server to be used for asymmetric encryption
                        handler.Receive(modulus);

                        handler.Receive(exponent);
                        // an instance of the RSA class is created to be used for asymmetric encryption
                        RSA Rsa1 = RSA.Create();
                        // RSAParameters keycontainer is created to be used to load the servers's public key values 
                        RSAParameters rsaKeyInfo = Rsa1.ExportParameters(false);
                        // public key and exponent are loaded to the keycontainer
                        rsaKeyInfo.Modulus = modulus;
                        rsaKeyInfo.Exponent = exponent;
                        // parameters are imported from the keycontainer to the RSA class so that it is set to the servers's public key
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
                        catch (Exception )
                        {
                            encryptedSymmetricKey = null;
                            encryptedSymmetricIV = null;
                            throw;
                        }
                        // the encrypted shared symmetric key and IV are sent to the server
                        handler.Send(encryptedSymmetricKey);

                        handler.Send(encryptedSymmetricIV);
                        // byte arrays created to store the key and IV values to specify for encryption/decryption
                        var key = aes.Key;
                        var iv = aes.IV;
                        // networkstream created to recieve encrypted data from the client via the socket
                        NetworkStream networkstream = new(handler);
                        while (true)
                        {
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
                                            MessageReceiveBox.Text += data;
                                            

                                        }
                                    }
                                    // catch statement for error handling and testing/debugging
                                    catch (Exception)
                                    {
                                        throw;
                                    }
                                }

                                break;
                            }
                            // if the networkstream is empty, the client will let the user know it is waiting and will wait one second
                            else
                            {
                                Thread.Sleep(1000);
                            }


                        }
                        // the handler socket is shut down and the socket will return to listening
                        handler.Shutdown(SocketShutdown.Both);
                        handler.Close();
                    }


                }
                // catch statement for error handling and testing
                catch (Exception )
                {
                    throw;
                }
            }
        }
        public static void SendMessage(string inptext)
        {
            try
            {
                // Creates a socket which is initialised to the IP of the server 
                IPAddress ipAddress = IPAddress.Parse("192.168.1.117");
                IPEndPoint remoteEP = new IPEndPoint(ipAddress, 11000);

                Socket sender = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                try
                {
                    //socket connects to the server 
                    sender.Connect(remoteEP);

                    // creates an instance of the RSA class which will be used for asymmetric encryption
                    RSA Rsa1 = RSA.Create();
                    //the parameters of the client's public key are exported into an RSAParameters key container
                    RSAParameters rsaKeyinfo = Rsa1.ExportParameters(false);
                    // byte arrays are created to store the public key and exponent so that they can be shared with the server 
                    byte[] modulus = rsaKeyinfo.Modulus;
                    byte[] exponent1 = rsaKeyinfo.Exponent;
                    //public key and exponent are sent to the server
                    sender.Send(modulus);
                    sender.Send(exponent1);
                    // byte arrays are created to store the encrypted shared key and IV to be used for symmetric encryption
                    byte[] encryptedSymmetricKey = new byte[256];
                    byte[] encryptedSymmetricIV = new byte[256];
                    //receives the encrypted shared key and IV from the server
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
                    catch (Exception)
                    {
                        symmetrickey = null;
                        symmetricIV = null;
                        throw;
                    }
                    //an instance of the AES class is created to be used for symmetric encryption to communicate with the server
                    Aes aes = Aes.Create();
                    // the parameters for the shared key and IV recived from the server are loaded
                    aes.Key = symmetrickey;
                    aes.IV = symmetricIV;
                    var key = symmetrickey;
                    var iv = symmetricIV;
                    //encrypting using the shared symmetric key
                    try
                    {
                        // a networkstream is inintialised so that encrypted data can be streamed to the server
                        NetworkStream networkstream = new NetworkStream(sender);
                        // a cryptostream is initialised which will encrypt all data written to it using AES with the symmetric key and IV
                        CryptoStream cryptstream = new CryptoStream(networkstream, aes.CreateEncryptor(key, iv), CryptoStreamMode.Write);
                        using (cryptstream)
                        {

                            using (StreamWriter encryptwriter = new(cryptstream))
                            {
                                // message is written to the networkstream using the encryptwriter meaning the encrypted data will be written to the stream for the server to read
                                if (inptext.Contains('|') == true)
                                {
                                    encryptwriter.WriteLine(inptext);
                                }
                                else
                                {
                                    encryptwriter.WriteLine($"{username}~{inptext}~{talkingToUser}");
                                }
                            }
                        }
                    }
                    // catch statement for error handling and debugging purposes
                    catch (Exception)
                    {
                        throw;
                    }

                    // closes the socket so that the server is free again for other users
                    sender.Shutdown(SocketShutdown.Both);
                    sender.Close();
                }
                // catch statement for error handling and debugging purposes
                catch (Exception)
                {
                    throw;
                }
            }
            catch (Exception)
            {
                throw;
            }

        }


        private void Newuser_Click(object sender, RoutedEventArgs e)
        {
            talkingToContentLabel.Content = talkingToUser;

        }
        private static void SendUserdata ()
        {
            // gets the host device's ip address
            IPHostEntry ipHostinfo = Dns.GetHostEntry(Dns.GetHostName());
            IPAddress ipAddress = ipHostinfo.AddressList[0];
            // sends the client's username and ip to the server 
            string userIDtoserver = $"{username}|{ipAddress.ToString()}";
            SendMessage(userIDtoserver);

        }

        public MainWindow()
        {
            
            InitializeComponent();
            username = UsernameValueLabel.Content.ToString();

        }

        private void sendButton_Click(object sender, RoutedEventArgs e)
        {
            // the contents of the Messagebox are sent to the server 
            string texttosend = inputBox.Text;
            inputBox.Text = "";
            MessageReceiveBox.Foreground = new SolidColorBrush (Colors.Red);
            MessageReceiveBox.Text += $"{username}: {texttosend} (sent to {talkingToUser}) \n";
            SendMessage(texttosend);
        }
    }
}
