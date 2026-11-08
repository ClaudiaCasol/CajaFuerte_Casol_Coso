using System.Security.Cryptography;


namespace CajaFuerte_Casol_Coso
{
    internal class Program
    {
        // Orden de identificadores en archivo cifrado
        // 1. Sal
        // 2. Nonce
        // 3. GCM Tag
        // 4. Texto cifrado.

        private const int IteracionesPbkdf2 = 600000;

        // Numero de bytes

        private const int TamanoTag = 12;
        private const int TamanoNonce = 12;
        private const int TamanoSal = 16;
        private const int TamanoClave = 32;

        private const int InfoDesencriptar = TamanoSal + TamanoNonce + TamanoTag;
        //

        private static readonly HashAlgorithmName AlgoritmoPbkdf2 = HashAlgorithmName.SHA256;

        static void Main(string[] args)
        {
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
                        OpcionMenuCifrar();
                        break;
                    case "3":
                        OpcionMenuDescifrar();
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

        // Verificar que no sea nulo o vacio.
        private static bool ValidarEntrada(String? texto)
        {
            if (String.IsNullOrEmpty(texto))
            {
                Console.WriteLine("Texto no valido");
                return false;
            }

            return true;
        }

        // Para saber donde se guardan los archivos.
        private static void OpcionMenuCrearFichero()
        {
            Console.WriteLine("Nombre fichero a crear: ");

            String? texto = Console.ReadLine();
            if (!ValidarEntrada(texto)) return;

            String fichero_entrada = texto!;

            fichero_entrada += ".txt";

            File.Create(fichero_entrada).Close();

            String ruta = Path.GetFullPath(fichero_entrada);

            Console.WriteLine($"\nArchivo creado en {ruta}");
        }

        private static void OpcionMenuCifrar()
        {
            Console.WriteLine("Nombre fichero a cifrar: ");

            String? texto = Console.ReadLine();
            if (!ValidarEntrada(texto)) return;


            String fichero_entrada = texto!;

            String fichero_salida = fichero_entrada + ".caja";

            // Añadimos el .txt despues asi no tenemos que sobre complicar por culpa del .caja.
            fichero_entrada += ".txt";

            Console.WriteLine("Contraseña: ");

            texto = Console.ReadLine();
            if (!ValidarEntrada(texto)) return;

            String contrasena = texto!;

            Cifrar(fichero_entrada, fichero_salida, contrasena);
        }

        private static void OpcionMenuDescifrar()
        {
            Console.WriteLine("Nombre fichero a descifrar: ");

            String? texto = Console.ReadLine();
            if (!ValidarEntrada(texto)) return;

            String fichero_salida = texto!;
            String fichero_recuperado = fichero_salida + ".txt";

            fichero_salida += ".caja";

            Console.WriteLine("Contraseña: ");

            texto = Console.ReadLine();
            if (!ValidarEntrada(texto)) return;

            String contrasena = texto!;
            Descifrar(fichero_salida, fichero_recuperado, contrasena);
        }

        private static void Cifrar(String fichero_entrada, String fichero_salida, String contrasena)
        {
            if (!File.Exists(fichero_entrada))
            {
                Console.WriteLine($"Fichero de texto {fichero_entrada} no existe");
                return;
            }

            // Si existia lo borramos para crear uno nuevo.
            if (File.Exists(fichero_salida)) File.Delete(fichero_salida);

            byte[] fileRead;

            // Abrimos un FileStream para leer el archivo indicado.
            using (FileStream streamEntrada = new FileStream(fichero_entrada, FileMode.Open, FileAccess.Read))
            {
                // Preparamos un array para guardar los bytes del archivo.
                fileRead = new byte[streamEntrada.Length];

                // Leemos el archivo y lo ponemos en el array
                int bytesLeidos = 0;
                int bytesPorLeer = fileRead.Length;
                do
                {
                    // Devuelve cuantos bytes ha leido
                    int leido = streamEntrada.Read(fileRead, bytesLeidos, bytesPorLeer);

                    bytesLeidos += leido;
                    bytesPorLeer -= leido;

                    // Si no lo ha leido completo volvemos otra ronda.
                } while (bytesPorLeer > 0);
            }

            // Pack de variables de identificacion a guardar.

            byte[] sal = GenerarSal();
            byte[] nonce = GenerarNonce();
            // Perparamos la variable para poner el tag.
            byte[] tag = new byte[TamanoTag];
            //

            // Preparamos variable para guardar el archivo cifrado.
            byte[] encryptedFile = new byte[fileRead.Length];

            byte[] clave = DerivarClaveDeContraseña(contrasena, sal);

            using (var aes = new AesGcm(clave, TamanoTag))
            {
                // Nos da el archivo ecriptado y el tag que ha generado.
                aes.Encrypt(nonce: nonce, plaintext: fileRead, ciphertext: encryptedFile, tag: tag);
            }

            // Abrimos un FileStream para crear y escribir el archivo indicado.
            using (FileStream streamSalida = new FileStream(fichero_salida, FileMode.Create, FileAccess.Write))
            {
                // Escribimos los identificadores y luego el texto cifrado en el archivo indicado.
                streamSalida.Write(sal, 0, sal.Length);

                streamSalida.Write(nonce, 0, nonce.Length);

                streamSalida.Write(tag, 0, tag.Length);

                streamSalida.Write(encryptedFile, 0, encryptedFile.Length);
                //
            }
            
            Console.WriteLine("\n Archivo cifrado");
        }

        private static void Descifrar(String fichero_salida, String fichero_recuperado, String contrasena)
        {
            if (!File.Exists(fichero_salida))
            {
                Console.WriteLine($"Fichero cifrado {fichero_salida} no existe");
                return;
            }

            if (File.Exists(fichero_recuperado)) File.Delete(fichero_recuperado);

            byte[] fileRead;

            using (FileStream streamEntrada = new FileStream(fichero_salida, FileMode.Open, FileAccess.Read))
            {
                fileRead = new byte[streamEntrada.Length];

                int bytesLeidos = 0;
                int bytesPorLeer = fileRead.Length;
                do
                {
                    int leido = streamEntrada.Read(fileRead, bytesLeidos, bytesPorLeer);

                    bytesLeidos += leido;
                    bytesPorLeer -= leido;
                } while (bytesPorLeer > 0);
            }

            // Preparamos pack de variables para leer los identificadores,
            byte[] sal = new byte[TamanoSal];
            byte[] nonce = new byte[TamanoNonce];
            byte[] tag = new byte[TamanoTag];
            //

            // Si el archivo es mas pequeño que el pack de identificadores significa que no se puede verificar.
            if (fileRead.Length < InfoDesencriptar)
            {
                ArchivoComprometido();
                return;
            }

            // Leemos los identificadores.
            for (int i = 0, salIndex = 0, nonceIndex = 0, tagIndex = 0; i < InfoDesencriptar; i++)
            {
                // Sal
                if (i < TamanoSal)
                {
                    sal[salIndex] = fileRead[i];
                    salIndex++;
                }

                // Nonce
                if (i >= TamanoSal && i < TamanoNonce + TamanoSal)
                {
                    nonce[nonceIndex] = fileRead[i];
                    nonceIndex++;
                }

                // Tag
                if (i >= TamanoTag + TamanoSal && i < TamanoTag + TamanoNonce + TamanoSal)
                {
                    tag[tagIndex] = fileRead[i];
                    tagIndex++;
                }
            }

            byte[] clave = DerivarClaveDeContraseña(contrasena, sal);

            // Necesitamos el archivo sin los identificadores para computar el Tag.
            byte[] fileWithNoTags = new byte[fileRead.Length - InfoDesencriptar];
            // Preparamos variable para guardar el archivo final.
            byte[] decryptedFile = new byte[fileWithNoTags.Length];

            // Leemos el texto cifrado saltandonos los identificadores.
            for (int i = InfoDesencriptar, j = 0; i < fileRead.Length; i++, j++)
            {
                fileWithNoTags[j] = fileRead[i];
            }

            using (var aes = new AesGcm(clave, TamanoTag))
            {
                // Si tira un error significa que o no ha podido o ha sido modificado.
                try
                {
                    // Nos da el archivo descifrado.
                    aes.Decrypt(nonce: nonce, ciphertext: fileWithNoTags, tag: tag, plaintext: decryptedFile);
                }
                catch (Exception)
                {
                    ArchivoComprometido();
                    return;
                }
            }

            
            using (FileStream streamSalida = new FileStream(fichero_recuperado, FileMode.Create, FileAccess.Write))
            {
                // Escribimos el texto descifrado en el archivo indicado.
                streamSalida.Write(decryptedFile, 0, decryptedFile.Length);
            }
            
            Console.WriteLine("\n Archivo descifrado");
        }

        // Generamos el Nonce usando el tamaño indicado.
        private static byte[] GenerarNonce()
        {
            byte[] nonce = new byte[TamanoNonce];
            RandomNumberGenerator.Create().GetBytes(nonce);
            return nonce;
        }

        // Generamos la Sal usando el tamaño indicado.
        private static byte[] GenerarSal()
        {
            byte[] sal = new byte[TamanoSal];
            RandomNumberGenerator.Create().GetBytes(sal);
            return sal;
        }

        // Generamos la Clave usando el tamaño, algoritmo y iteraciones indicadas.
        private static byte[] DerivarClaveDeContraseña(String contrasena, byte[] sal)
        {
            return Rfc2898DeriveBytes.Pbkdf2(contrasena, sal, IteracionesPbkdf2, AlgoritmoPbkdf2, TamanoClave);
        }

        // Si occurre un error durante verificacion lo decimos.
        private static void ArchivoComprometido()
        {
            Console.WriteLine("ESTE ARCHIVO NO SE HA VERIFICADO CORRECTAMENTE\n" +
                              "ABORTANDO...");
        }
    }
}