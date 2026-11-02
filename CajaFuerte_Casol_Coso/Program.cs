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
        Aes instanciaAes = Aes.Create();
        HMACSHA256 instanciaHmac = HMACSHA256.Create();

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
    }
}
