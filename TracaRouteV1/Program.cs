using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace TracaRouteV1
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            string ip = "www.tni.mil.id";
            PingReply pingReply;
            Ping ping = new Ping();
            PingOptions pingOptions = new PingOptions();
            pingOptions.Ttl = 1;
            int maxHops = 32;
            Console.WriteLine("№\tip\t \tAS\tCountry\tProvaider");
            for (int i = 1; i < maxHops; i++)
            {
                pingReply = ping.Send(ip, 1000, new byte[32], pingOptions);
                if (pingReply.Status != IPStatus.TtlExpired && pingReply.Status != IPStatus.Success)
                {
                    Console.WriteLine("{0} \t{1}", i, pingReply.Status.ToString());
                }
                else
                {
                    var t = AS(pingReply.Address.ToString());
                    Console.WriteLine("{0}\t{1}\t{2}\t{3}\t{4}", i, pingReply.Address, t[0], t[1], t[2]);
                }
                if (pingReply.Status == IPStatus.Success)
                {
                    break;
                }
                pingOptions.Ttl++;
            }
            Console.ReadKey();
        }
       
        public static string[] AS(string address)
        {
            string addrss = address + "\r\n";
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Connect("whois.iana.org", 43);
            byte[] bytes = Encoding.UTF8.GetBytes(addrss);
            socket.Send(bytes);
            byte[] bytes1 = new byte[10000];
            socket.Receive(bytes1);           
            socket.Close();
            string msg=Encoding.UTF8.GetString(bytes1);
            var lineMessage = msg.Split('\n');
            var status = lineMessage.Where(i => i.StartsWith("status:")).ToArray();
            if (status[0].Split(new char[2] {' ', '\t'}, StringSplitOptions.RemoveEmptyEntries)[1] == "RESERVED")
            {
                socket.Close();
                return new string[3];
            }
            var whois =
                lineMessage.Where(i => i.StartsWith("whois")).ToArray()[0]
                .Split(new char[2] {' ', '\t'},
                    StringSplitOptions.RemoveEmptyEntries)[1];
           
            socket.Close();
            return TakeAS(addrss, whois);

        }

        public static string[] TakeAS(string address, string provaider)
        {
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            socket.Connect(provaider, 43);
            byte[] bytes = Encoding.UTF8.GetBytes(address);
            socket.Send(bytes);
            byte[] bytes1 = new byte[10000];
            socket.Receive(bytes1);
            byte[] bytes2 = new byte[10000];
            socket.Receive(bytes2);
            socket.Close();
            string msg = Encoding.UTF8.GetString(bytes2);
            var message = new string[3];
            var dwe = msg.Split(new char[4] {' ', '\t','\n','\r'}, StringSplitOptions.RemoveEmptyEntries).ToArray();
            for (int i = 0; i < dwe.Length; i++)
            {
                if (dwe[i].StartsWith("AS"))
                {
                    var word = dwe[i].Remove(0, 2);
                    Regex reg=new Regex("[^0-9]");
                    if(!reg.IsMatch(word))
                    message[0] = dwe[i];
                }
                if (dwe[i].ToLower().StartsWith("country"))
                {
                    message[1] = dwe[i + 1];
                }
            }
            message[2] = provaider.Split('.').ToArray()[1];
            return new string[3] { message[0], message[1], message[2]};
        }
    }
}
