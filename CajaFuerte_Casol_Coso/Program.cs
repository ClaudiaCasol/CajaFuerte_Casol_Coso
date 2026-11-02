using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CajaFuerte_Casol_Coso
{
    internal class Program
    {
        String fichero_entrada = ;
        String fichero_salida = ;
        String fichero_recuperado = ;
        String contrasena = ;

        static void Main(string[] args)
        {
            Switch(Console.ReadKey()) {
                case ConsoleKey.key(1):
                    opcionMenuCifrar();
                    break;
                case ConsoleKey.key(2):
                    opcionMenuDescifrar();
                    break;
                }
            }

            void opcionMenuCifrar()
            {
                Console.WriteLine("Nombre fichero a cifrar: ");
                fichero_entrada = Console.ReadLine() + ".txt";
                fichero_salida = fichero_entrada + ".caja";
                cifrar(fichero_entrada, fichero_salida, contrasena);
            }

            void opcionMenuDescifrar()
            {
                Console.WriteLine("Nombre fichero a descifrar: ");
                fichero_salida = Console.ReadLine() + ".caja";
                fichero_recuperado = fichero_salida + ".txt";
                descifrar(fichero_salida, fichero_recuperado, contrasena);
            }
        }
    }
