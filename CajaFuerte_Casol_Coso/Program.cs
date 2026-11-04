using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;

namespace CajaFuerte_Casol_Coso
{
    internal class Program
    {
        static Byte[] key = { 4, 2, 5, 16, 7, 2 };
        static Aes instanciaAes = Aes.Create();
        static HMACSHA256 instanciaHmac = new HMACSHA256(key);

        static void Main(string[] args)
        {
            byte[] secretkey = new Byte[64];

            string fichero_entrada = "firma.txt";
            string fichero_salida = "firmado.caja";

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                // The array is now filled with cryptographically strong random bytes.
                rng.GetBytes(secretkey);

                // Use the secret key to sign the message file.
                FirmarConAutenticador(secretkey, fichero_entrada, fichero_salida);

                Console.ReadLine();

                VerificarFirma(secretkey, fichero_salida);
            }

            bool salir = false;
            while (!salir)
            {
                Console.WriteLine("\nEscoje una opcion:\n" +
                "1: Crear archivo .txt\n" +
                "2: Cifrar archivo de texto\n" +
                "3: Descifrar archivo .caja\n" +
                "4: Salir");
                switch (Console.ReadLine())
                {
                    case "1":
                        opcionMenuCrearFichero();
                        break;
                    case "2":
                        opcionMenuCifrar();
                        break;
                    case "3":
                        opcionMenuDescifrar();
                        break;
                    case "4":
                        salir = true;
                        break;
                    default:
                        Console.WriteLine("No existe esa opcion");
                        break;
                }
            }
        }

        static void opcionMenuCrearFichero()
        {
            Console.WriteLine("Nombre fichero a crear: ");

            String fichero_entrada = Console.ReadLine();

            fichero_entrada += ".txt";

            File.Create(fichero_entrada).Close();

            String ruta = Path.GetFullPath(fichero_entrada);

            Console.WriteLine($"\nArchivo creado en {ruta}");
        }

        static void opcionMenuCifrar()
        {
            Console.WriteLine("Nombre fichero a cifrar: ");

            String fichero_entrada = Console.ReadLine();
            String fichero_salida = fichero_entrada + ".caja";

            fichero_entrada += ".txt";

            Console.WriteLine("Contraseña: ");
            String contrasena = Console.ReadLine();
            cifrar(fichero_entrada, fichero_salida, contrasena);
        }

        static void opcionMenuDescifrar()
        {
            Console.WriteLine("Nombre fichero a descifrar: ");

            String fichero_salida = Console.ReadLine();
            String fichero_recuperado = fichero_salida + ".txt";

            fichero_salida += ".caja";

            Console.WriteLine("Contraseña: ");
            String contrasena = Console.ReadLine();
            descifrar(fichero_salida, fichero_recuperado, contrasena);
        }

        static void cifrar(String fichero_entrada, String fichero_salida, String contrasena)
        {
            if (!File.Exists(fichero_entrada)) { Console.WriteLine($"Fichero de texto {fichero_entrada} no existe"); return; }
            if (File.Exists(fichero_salida)) File.Delete(fichero_salida);

        }
        static void descifrar(String fichero_salida, String fichero_recuperado, String contrasena)
        {
            if (!File.Exists(fichero_salida)) { Console.WriteLine($"Fichero encriptado {fichero_salida} no existe"); return; }
            if (File.Exists(fichero_recuperado)) File.Delete(fichero_recuperado);
        }

        static void FirmarConAutenticador(byte[] key, String fichero_entrada, String fichero_salida)
        {
            HMACSHA256 instanciaHmac = new HMACSHA256(key);

            FileStream streamEntrada = new FileStream(fichero_entrada, FileMode.Open);
            FileStream streamSalida = new FileStream(fichero_salida, FileMode.Create);

            byte[] hashValue = instanciaHmac.ComputeHash(streamEntrada);

            streamEntrada.Position = 0;

            int bytesRead;

            byte[] buffer = new byte[1024];
            do
            {
                bytesRead = streamEntrada.Read(buffer, 0, 1024);
                streamSalida.Write(buffer, 0, bytesRead);
            } while (bytesRead > 0);

            streamSalida.Write(hashValue, 0, hashValue.Length);

            streamSalida.Close();
            streamEntrada.Close();

            return;
        }

        static bool VerificarFirma(byte[] key, String fichero_salida)
        {
            bool err = false;

            HMACSHA256 hmac = new HMACSHA256(key);

            byte[] storedHash = new byte[hmac.HashSize / 8];

            FileStream inStream = new FileStream(fichero_salida, FileMode.Open);


            Console.WriteLine("Before Read");
            Console.ReadLine();
            try
            {
                foreach (byte b in storedHash) { Console.WriteLine(b); }
               
                inStream.Position = inStream.Length - storedHash.Length;


                foreach (byte b in storedHash) { Console.WriteLine(b); }
            }
            catch (Exception e) { Console.WriteLine(e); Console.ReadLine(); }
            Console.WriteLine("After Read");
            Console.ReadLine();

            // Hay que desacerse de la parte final antes de computar
            inStream.Position = 0;

            inStream.SetLength(inStream.Length - storedHash.Length);

            byte[] computedHash = hmac.ComputeHash(inStream);


            for (int i = 0; i < storedHash.Length; i++)
            {
                if (computedHash[i] != storedHash[i])
                {
                    err = true;
                }
            }
            inStream.Close();

            if (err)
            {
                Console.WriteLine("Diferente");
                return false;
            }
            else
            {
                Console.WriteLine("Igual");
                return true;
            }
        }
    }
}
