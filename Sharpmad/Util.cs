using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Net;

namespace Sharpmad
{
    class Util
    {

        public static void GetHelp(string argument)
        {

            if (argument.Equals("HELP") || argument.Equals("ADIDNS"))
            {
                Console.WriteLine("Modules:");
                Console.WriteLine("ADIDNS                       ADIDNS functions.");
                Console.WriteLine("       -Action AddACE        Add ACE to node.");
                Console.WriteLine("       -Action Disable       Tombstone a node.");
                Console.WriteLine("       -Action GetDACL       Get node or zone DACL.");
                Console.WriteLine("       -Action GetOwner      Get node owner.");
                Console.WriteLine("       -Action GetAttribute  Get node attribute value.");
                Console.WriteLine("       -Action GetTombsone   Get node tombstone status.");
                Console.WriteLine("       -Action GetZone       Get zone partition location.");
                Console.WriteLine("       -Action New           Add a node.");
                Console.WriteLine("       -Action GetAttribute  Set node attribute value.");
                Console.WriteLine("       -Action SetOwner      Set node owner.");
                Console.WriteLine("       -Action Remove        Remove a node.");
                Console.WriteLine("       -Action Rename        Rename a node.");
                Console.WriteLine("       -Action RemoveACE     Remove ACE from node.");
                Console.WriteLine("       -Action SetAttribute  Get node attribute value.");
                Console.WriteLine("");
                Console.WriteLine("Example: Sharpmad.exe ADIDNS -Action new -Node test");
                Console.WriteLine("");
            }

            if (argument.Equals("HELP") || argument.Equals("MAQ"))
            {
                Console.WriteLine("MAQ                          Machine account functions.");
                Console.WriteLine("       -Action AgentSmith    Recursive machine account creator.");
                Console.WriteLine("       -Action Disable       Disable a machine account.");
                Console.WriteLine("       -Action GetAttribute  Get machine account attribute value.");
                Console.WriteLine("       -Action GetCreator    Get all machine account creators.");
                Console.WriteLine("       -Action New           Add a machine account.");
                Console.WriteLine("       -Action Remove        Remove a machine account (access required).");
                Console.WriteLine("       -Action SetAttribute  Get machine account attribute value.");
                Console.WriteLine("");
                Console.WriteLine("Example: Sharpmad.exe MAQ -Action new -MachineAccount test -MachinePassword password");
                Console.WriteLine("");
            }

            if (argument.Equals("HELP") || argument.Equals("ADIDNS")|| argument.Equals("MAQ"))
            {
                Console.WriteLine("Common Parameters:");
                Console.WriteLine("-Append              Switch: Append an attribute value rather than overwriting.");
                Console.WriteLine("-Attribute           LDAP attribute to get or set.");
                Console.WriteLine("-Clear               Switch: Clear an attribute value.");
                Console.WriteLine("-DistinguishedName   Distinguished name to use. Do not include the ADIDNS node or MachineAccount name.");
                Console.WriteLine("-Domain              Targeted domain in DNS format.");
                Console.WriteLine("-DomainController    Domain controller to target. This parameter is mandatory on a non-domain attached system.");
                Console.WriteLine("-Username            LDAP username in either domain\\username or UPN format.");
                Console.WriteLine("-Verbose             Switch: Verbose output.");
                Console.WriteLine("-Value               Attribute value.");
                Console.WriteLine("-Password            LDAP password ");
                Console.WriteLine("");
            }

            if (argument.Equals("HELP") || argument.Equals("ADIDNS"))
            {
                Console.WriteLine("ADIDNS Parameters:");
                Console.WriteLine("-Access              ACE access.");
                Console.WriteLine("-AccessType          Allow or Deny for the ACE.");
                Console.WriteLine("-Data                DNS record data.");
                Console.WriteLine("-Forest              AD forest.");
                Console.WriteLine("-Node                DNS record name.");
                Console.WriteLine("-NodeNew             New node name for renames.");
                Console.WriteLine("-Partition           AD partition where the zone is stored. (DomainDNSZones,ForestDNSZones,System)");
                Console.WriteLine("-Principal           ACE principal.");
                Console.WriteLine("-Preference          MX record preference.");
                Console.WriteLine("-Priority            SRV record priority.");
                Console.WriteLine("-SOASerialNumber     SOA serial number that will be incremented by 1.");
                Console.WriteLine("-Static              Switch: Create a static record.");
                Console.WriteLine("-Tombstone           Switch: Set the tombstone attribute to true upon node creation.");
                Console.WriteLine("-TTL                 DNS record TTL..");
                Console.WriteLine("-Type                DNS record type. (A, AAAA, CNAME, DNAME, NS, MX, PTR, SRV, TXT)");
                Console.WriteLine("-Weight              SRV record weight.");
                Console.WriteLine("-Zone                ADIDNS zone.");
                Console.WriteLine("");
            }

            if (argument.Equals("HELP") || argument.Equals("MAQ"))
            {
                Console.WriteLine("MAQ Parameters:");
                Console.WriteLine("-Container           AD container.");
                Console.WriteLine("-MachineAccount      Machine account name.");
                Console.WriteLine("-MachinePassword     Machine account password.");
                Console.WriteLine("-Random              Switch: Create a machine account with a random password.");
                Console.WriteLine("");
            }

            Environment.Exit(0);
        }

        public static string PasswordPrompt()
        {
            string password = "";

            ConsoleKey key;
            do
            {
                var keyInfo = Console.ReadKey(intercept: true);
                key = keyInfo.Key;

                if (key == ConsoleKey.Backspace && password.Length > 0)
                {
                    Console.Write("\b \b");
                    password = password.Remove(password.Length - 1, 1);
                }
                else if (!char.IsControl(keyInfo.KeyChar))
                {
                    Console.Write("*");
                    password += keyInfo.KeyChar;
                }
            } while (key != ConsoleKey.Enter);

            return password;
        }

        public static string DomainExtract(string domainController, string type)
        {
            string domain = "";
            bool domainControllerIP = false;
            IPAddress address;

            if (IPAddress.TryParse(domainController, out address))
            {
                domainControllerIP = true;
            }

            if (!domainControllerIP)
            {

                try
                {
                    domain = domainController.Remove(0, domainController.IndexOf(".") + 1);
                }
                catch
                {
                    Console.WriteLine("[!] Failed to extract -{0} from -DomainController value", type);
                    Environment.Exit(1);
                }

            }
            else
            {
                Console.WriteLine("[!] Define domain with -{0} when using an IP address with -DomainController", type);
                Environment.Exit(1);
            }


            return domain.ToLower();
        }

        public static ushort DataToUInt16(byte[] field)
        {
            Array.Reverse(field);
            return BitConverter.ToUInt16(field, 0);
        }

        public static uint DataToUInt32(byte[] field)
        {
            Array.Reverse(field);
            return BitConverter.ToUInt32(field, 0);
        }

        public static byte[] IntToByteArray2(int field)
        {
            byte[] byteArray = BitConverter.GetBytes(field);
            Array.Reverse(byteArray);
            return byteArray.Skip(2).ToArray();
        }

        public static byte[] NewTimeStampArray()
        {
            string timestamp = BitConverter.ToString(BitConverter.GetBytes(Convert.ToInt64((DateTime.UtcNow - new DateTime(1601, 1, 1)).TotalHours)));
            byte[] timestampArray = new byte[8];
            int i = 0;

            foreach (string character in timestamp.Split('-'))
            {
                timestampArray[i] = Convert.ToByte(Convert.ToInt16(character, 16));
                i++;
            }

            return timestampArray;
        }

        public static string GetLocalIPAddress(string ipVersion)
        {

            List<string> ipAddressList = new List<string>();
            AddressFamily addressFamily;

            if (String.Equals(ipVersion, "IPv4"))
            {
                addressFamily = AddressFamily.InterNetwork;
            }
            else
            {
                addressFamily = AddressFamily.InterNetworkV6;
            }

            foreach (NetworkInterface networkInterface in NetworkInterface.GetAllNetworkInterfaces())
            {

                if (networkInterface.NetworkInterfaceType == NetworkInterfaceType.Ethernet && networkInterface.OperationalStatus == OperationalStatus.Up)
                {

                    foreach (UnicastIPAddressInformation ip in networkInterface.GetIPProperties().UnicastAddresses)
                    {

                        if (ip.Address.AddressFamily == addressFamily)
                        {
                            ipAddressList.Add(ip.Address.ToString());
                        }

                    }

                }

            }

            return ipAddressList.FirstOrDefault().ToString();
        }

    }

}
