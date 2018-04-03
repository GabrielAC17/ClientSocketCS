using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ServSocket.Controller
{
    class ClienteRSA
    {
        public static TcpClient cliente = new TcpClient();
        private static BinaryWriter escreve;
        private static BinaryReader ler;
        private static NetworkStream saida;
        private static byte[] publicKey;
        private static RSACryptoServiceProvider RSA = null;

        static void Main(string[] args)
        {
            while (true)
            {
                try
                {
                    Console.WriteLine("Starting Client");
                    cliente.Connect("localhost", 8888);
                    saida = cliente.GetStream();
                    Console.WriteLine("Connected!");
                    break;
                }
                catch (Exception e)
                {
                    Console.WriteLine("Erro ao conectar, tentando novamente em 3 segundos:");
                    Thread.Sleep(3000);
                    continue;
                }
            }
            
            

            escreve = new BinaryWriter(saida);

            ler = new BinaryReader(saida);

            Thread tipoThread = new Thread(new ThreadStart(LerDados));

            tipoThread.Start();

            Console.WriteLine("Ready to send! Type your command to server and press enter to send");

            while (true)
            {
                //Lê do console
                string text = Console.ReadLine();

                //Cria o objeto e associa o texto
                Model.Message msg = new Model.Message();
                msg.text = Encoding.UTF8.GetBytes(text);

                //transforma em JSON e consequentemente em array de bytes
                byte[] bytes = Encoding.ASCII.GetBytes(JsonConvert.SerializeObject(msg));

                //Envia o tamanho da string
                escreve.Write(bytes.Length);

                //Por fim, envia a string
                escreve.Write(bytes);
            }
        }
        private static void LerDados()
        {
            Console.WriteLine("Listening the server in a new thread");
            while (true)
            {
                try
                {
                    //Recebe os dados
                    byte[] lengthBytes = ler.ReadBytes(4);
                    int length = System.BitConverter.ToInt32(lengthBytes, 0);
                    byte[] rcvBytes = ler.ReadBytes(length);

                    //Tira da base64
                    string text = Encoding.UTF8.GetString(rcvBytes);


                    //Tira do JSON
                    Model.Message msg = JsonConvert.DeserializeObject<Model.Message>(text);
                    string mensagemText = Encoding.UTF8.GetString(msg.text);
                    Console.WriteLine("DEBUG: Test: " + mensagemText);

                    string chaveString = Encoding.ASCII.GetString(msg.chave);

                    RSA = DecodeX509PublicKey(Convert.FromBase64String(chaveString));

                    string mensagemHash = Encoding.ASCII.GetString(msg.hash);
                    string mensagemAssinada = Encoding.ASCII.GetString(msg.sign);
                    bool verify = verifySignature(mensagemAssinada, mensagemHash);
                    if (verify)
                    {
                        //Verifica o Hash SHA-256
                        SHA256Managed crypt = new SHA256Managed();
                        StringBuilder hash = new StringBuilder(); //StringBuilder para maior desempenho devido as constantes mudanças na string

                        string hashStr = Encoding.ASCII.GetString(msg.hash);
                        byte[] hashByte = Convert.FromBase64String(hashStr);

                        byte[] hashBytes = crypt.ComputeHash(msg.text);
                        foreach (byte theByte in hashBytes)
                        {
                            hash.Append(theByte.ToString("x2"));
                        }

                        StringBuilder messageHash = new StringBuilder();
                        foreach (byte theByte in hashByte)
                        {
                            messageHash.Append(theByte.ToString("x2"));
                        }

                        if (messageHash.Equals(hash))
                        {
                            Console.WriteLine("Server response: " + Encoding.UTF8.GetString(msg.text));
                        }
                        else
                        {
                            Console.WriteLine("Invalid message hash!");
                        }
                    }
                    Console.WriteLine("Result: " + verify);


                }
                catch (Exception e)
                {
                    Console.WriteLine("Connection with the server was lost, shutting down client...");
                    Environment.Exit(0);
                }

            }
        }
        public static RSACryptoServiceProvider DecodeX509PublicKey(byte[] x509key)
        {
            byte[] SeqOID = { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01 };

            MemoryStream ms = new MemoryStream(x509key);
            BinaryReader reader = new BinaryReader(ms);

            if (reader.ReadByte() == 0x30)
                ReadASNLength(reader); //skip the size
            else
                return null;

            int identifierSize = 0; //total length of Object Identifier section
            if (reader.ReadByte() == 0x30)
                identifierSize = ReadASNLength(reader);
            else
                return null;

            if (reader.ReadByte() == 0x06) //is the next element an object identifier?
            {
                int oidLength = ReadASNLength(reader);
                byte[] oidBytes = new byte[oidLength];
                reader.Read(oidBytes, 0, oidBytes.Length);
                if (oidBytes.SequenceEqual(SeqOID) == false) //is the object identifier rsaEncryption PKCS#1?
                    return null;

                int remainingBytes = identifierSize - 2 - oidBytes.Length;
                reader.ReadBytes(remainingBytes);
            }

            if (reader.ReadByte() == 0x03) //is the next element a bit string?
            {
                ReadASNLength(reader); //skip the size
                reader.ReadByte(); //skip unused bits indicator
                if (reader.ReadByte() == 0x30)
                {
                    ReadASNLength(reader); //skip the size
                    if (reader.ReadByte() == 0x02) //is it an integer?
                    {
                        int modulusSize = ReadASNLength(reader);
                        byte[] modulus = new byte[modulusSize];
                        reader.Read(modulus, 0, modulus.Length);
                        if (modulus[0] == 0x00) //strip off the first byte if it's 0
                        {
                            byte[] tempModulus = new byte[modulus.Length - 1];
                            Array.Copy(modulus, 1, tempModulus, 0, modulus.Length - 1);
                            modulus = tempModulus;
                        }

                        if (reader.ReadByte() == 0x02) //is it an integer?
                        {
                            int exponentSize = ReadASNLength(reader);
                            byte[] exponent = new byte[exponentSize];
                            reader.Read(exponent, 0, exponent.Length);

                            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                            RSAParameters RSAKeyInfo = new RSAParameters();
                            RSAKeyInfo.Modulus = modulus;
                            RSAKeyInfo.Exponent = exponent;
                            RSA.ImportParameters(RSAKeyInfo);
                            return RSA;
                        }
                    }
                }
            }
            return null;
        }

        public static int ReadASNLength(BinaryReader reader)
        {
            //Note: this method only reads lengths up to 4 bytes long as
            //this is satisfactory for the majority of situations.
            int length = reader.ReadByte();
            if ((length & 0x00000080) == 0x00000080) //is the length greater than 1 byte
            {
                int count = length & 0x0000000f;
                byte[] lengthBytes = new byte[4];
                reader.Read(lengthBytes, 4 - count, count);
                Array.Reverse(lengthBytes); //
                length = BitConverter.ToInt32(lengthBytes, 0);
            }
            return length;
        }

        public static bool verifySignature(string signature, string signedData)
        {
            byte[] sign = Convert.FromBase64String(signature);
            byte[] hash = Convert.FromBase64String(signedData);
            try
            {
                if (RSA.VerifyData(hash, "SHA1", sign))
                {
                    //Console.WriteLine("The signature is valid.");
                    return true;
                }
                else
                {
                    //Console.WriteLine("The signature is not valid.");
                    return false;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return false;
            }
           
        }

    }
}
