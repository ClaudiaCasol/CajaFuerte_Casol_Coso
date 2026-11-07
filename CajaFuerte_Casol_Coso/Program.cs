using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;
using System.Security.Permissions;

namespace CajaFuerte_Casol_Coso
{
    internal class Program
    {
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
                        OpcionMenuCrearFichero();
                        break;
                    case "2":
                        FirmarConAutenticador(secretkey, fichero_entrada, fichero_salida);
                        // OpcionMenuCifrar();
                        break;
                    case "3":
                        VerificarFirma(secretkey, fichero_salida);
                        //OpcionMenuDescifrar();
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

        static void OpcionMenuCrearFichero()
        {
            Console.WriteLine("Nombre fichero a crear: ");

            String fichero_entrada = Console.ReadLine();

            fichero_entrada += ".txt";

            File.Create(fichero_entrada).Close();

            String ruta = Path.GetFullPath(fichero_entrada);

            Console.WriteLine($"\nArchivo creado en {ruta}");
        }

        static void OpcionMenuCifrar()
        {
            Console.WriteLine("Nombre fichero a cifrar: ");

            String fichero_entrada = Console.ReadLine();
            String fichero_salida = fichero_entrada + ".caja";

            fichero_entrada += ".txt";

            Console.WriteLine("Contraseña: ");
            String contrasena = Console.ReadLine();
            Cifrar(fichero_entrada, fichero_salida, contrasena);
        }

        static void OpcionMenuDescifrar()
        {
            Console.WriteLine("Nombre fichero a descifrar: ");

            String fichero_salida = Console.ReadLine();
            String fichero_recuperado = fichero_salida + ".txt";

            fichero_salida += ".caja";

            Console.WriteLine("Contraseña: ");
            String contrasena = Console.ReadLine();
            Descifrar(fichero_salida, fichero_recuperado, contrasena);
        }

        static void Cifrar(String fichero_entrada, String fichero_salida, String contrasena)
        {
            if (!File.Exists(fichero_entrada))
            {
                Console.WriteLine($"Fichero de texto {fichero_entrada} no existe");
                return;
            }

            if (File.Exists(fichero_salida)) File.Delete(fichero_salida);

            using (var aes = Aes.Create())
            {
                FileStream inStream = new FileStream(fichero_entrada, FileMode.Open, FileAccess.Read);

                // Preparamos un array para guardar los bytes del archivo.
                byte[] fileRead = new byte[inStream.Length];

                // Leemos el archivo y lo ponemos en el array
                int bytesLeidos = 0;
                int bytesPorLeer = fileRead.Length;
                do
                {
                    int leido = inStream.Read(fileRead, bytesLeidos, bytesPorLeer);

                    bytesLeidos += leido;
                    bytesPorLeer -= leido;
                } while (bytesPorLeer > 0);

                inStream.Close();

                byte[] encryptedFile = new byte[fileRead.Length];
                byte[] iV = GenerarIV();

                encryptedFile = aes.EncryptCbc(fileRead, iV);

                FileStream outStream = new FileStream(fichero_salida, FileMode.Create, FileAccess.Write);

                outStream.Write(sal, 0, sal.Length);

                outStream.Write(iV, 0, iV.Length);

                outStream.Write(encryptedFile, 0, encryptedFile.Length);

                outStream.Close();
            }
        }

        static void Descifrar(String fichero_salida, String fichero_recuperado, String contrasena)
        {
            if (!File.Exists(fichero_salida))
            {
                Console.WriteLine($"Fichero encriptado {fichero_salida} no existe");
                return;
            }

            if (File.Exists(fichero_recuperado)) File.Delete(fichero_recuperado);
        }

        static byte[] GenerarIV()
        {
            byte[] IV = new byte[16];
            RandomNumberGenerator.Create().GetBytes(IV);
            return IV;
        }

        static byte[] GenerarSal()
        {
            byte[] sal = new byte[16];
            RandomNumberGenerator.Create().GetBytes(sal);
            return sal;
        }

// TODO
        static void DerivarClaveDeContraseña(String contrasena, byte[] sal)
        {
            Rfc2898DeriveBytes a = new Rfc2898DeriveBytes(contrasena, sal, 600000, HashAlgorithmName.SHA256);
        }

        static void FirmarConAutenticador(byte[] key, String fichero_entrada, String fichero_salida)
        {
            HMACSHA256 instanciaHmac = new HMACSHA256(key);

            FileStream streamEntrada = new FileStream(fichero_entrada, FileMode.Open, FileAccess.Read);
            FileStream streamSalida = new FileStream(fichero_salida, FileMode.Create, FileAccess.Write);

            byte[] hashValue = instanciaHmac.ComputeHash(streamEntrada);

            streamEntrada.Position = 0;

            int bytesRead;

            byte[] buffer = new byte[1024];
            do
            {
                bytesRead = streamEntrada.Read(buffer, 0, buffer.Length);
                streamSalida.Write(buffer, 0, bytesRead);
            } while (bytesRead > 0);

            streamSalida.Write(hashValue, 0, hashValue.Length);

            streamSalida.Close();
            streamEntrada.Close();
        }

        static bool VerificarFirma(byte[] key, String fichero_salida)
        {
            bool err = false;

            HMACSHA256 hmac = new HMACSHA256(key);

            FileStream inStream = new FileStream(fichero_salida, FileMode.Open, FileAccess.Read);

            // HashSize devuelve bits por lo que hay que dividirlo a numero de bytes
            byte[] storedHash = new byte[hmac.HashSize / 8];
            // Preparamos un array para guardar los bytes del archivo.
            byte[] fileRead = new byte[inStream.Length];

            // Leemos el archivo y lo ponemos en el array
            int bytesLeidos = 0;
            int bytesPorLeer = fileRead.Length;
            do
            {
                int leido = inStream.Read(fileRead, bytesLeidos, bytesPorLeer);

                bytesLeidos += leido;
                bytesPorLeer -= leido;
            } while (bytesPorLeer > 0);

            inStream.Close();

            if (fileRead.Length < storedHash.Length)
            {
                err = true;
            }

            if (!err)
            {
                // Leemos empezando por donde deberia empezar el hash que esta al final.
                for (int i = fileRead.Length - storedHash.Length, j = 0; j < storedHash.Length; i++, j++)
                {
                    // Empezamos a escribir desde 0 en el array del hash
                    storedHash[j] = fileRead[i];
                }

                // Tenemos que generar el hash con el contenido actual pero sin el hash. 
                byte[] fileWithNoHash = new byte[fileRead.Length - storedHash.Length];

                // Leemos lo que quepa, deberia excluir solo el hash.
                for (int i = 0; i < fileWithNoHash.Length; i++)
                {
                    fileWithNoHash[i] = fileRead[i];
                }

                byte[] computedHash = hmac.ComputeHash(fileWithNoHash);

                // Comprobamos byte a byte que sean iguales
                for (int i = 0; i < storedHash.Length; i++)
                {
                    Console.WriteLine(computedHash[i] + ":C S:" + storedHash[i]);
                    if (computedHash[i] != storedHash[i])
                    {
                        err = true;
                    }
                }
            }

            if (err)
            {
                Console.WriteLine("El archivo ha sido modificado!");
                return false;
            }

            Console.WriteLine("El archivo mantiene su integridad");
            return true;
        }
    }
}