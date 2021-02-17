using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.DirectoryServices;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Principal;
using System.Security.AccessControl;

namespace Sharpmad
{
    class ADIDNS
    {

        public static string GetADIDNSDistinguishedName(string node, string distinguishedName, string domain, string partition, string zone, bool verbose)
        {
            string[] dcArray;

            if (string.IsNullOrEmpty(distinguishedName))
            {

                if (!String.IsNullOrEmpty(node))
                {

                    if (string.Equals(partition.ToUpper(), "SYSTEM"))
                    {
                        distinguishedName = String.Concat("DC=", node, ",DC=", zone, ",CN=MicrosoftDNS", ",CN=", partition);
                    }
                    else
                    {
                        distinguishedName = String.Concat("DC=", node, ",DC=", zone, ",CN=MicrosoftDNS", ",DC=", partition);
                    }

                }
                else
                {

                    if (string.Equals(partition.ToUpper(), "SYSTEM"))
                    {
                        distinguishedName = String.Concat("DC=", zone, ",CN=MicrosoftDNS", ",CN=", partition);
                    }
                    else
                    {
                        distinguishedName = String.Concat("DC=", zone, ",CN=MicrosoftDNS", ",DC=", partition);
                    }

                }

                dcArray = domain.Split('.');

                foreach (string dc in dcArray)
                {
                    distinguishedName += String.Concat(",DC=", dc);
                }

                if (verbose) { Console.WriteLine("[+] Distinguished Name = {0}", distinguishedName); };
            }
            else
            {
                distinguishedName = String.Concat("DC=", node, ",", distinguishedName);
            }

            return distinguishedName;
        }

        public static byte[] NewDNSNameArray(string name)
        {
            var indexList = new List<int>();

            for (int i = name.IndexOf('.'); i > -1; i = name.IndexOf('.', i + 1))
            {
                indexList.Add(i);
            }

            using (MemoryStream memoryStream = new MemoryStream())
            {
                string nameSection = "";
                int nameStart = 0;

                if (indexList.Count > 0)
                {
                    int nameEnd = 0;

                    foreach (int index in indexList)
                    {
                        nameEnd = index - nameStart;
                        memoryStream.Write(BitConverter.GetBytes(nameEnd), 0, 1);
                        nameSection = name.Substring(nameStart, nameEnd);
                        memoryStream.Write(Encoding.UTF8.GetBytes(nameSection), 0, nameSection.Length);
                        nameStart = index + 1;
                    }

                }

                nameSection = name.Substring(nameStart);
                memoryStream.Write(BitConverter.GetBytes(nameSection.Length), 0, 1);
                memoryStream.Write(Encoding.UTF8.GetBytes(nameSection), 0, nameSection.Length);

                return memoryStream.ToArray();
            }

        }

        public static byte[] NewSOASerialNumberArray(string domainController, string zone, int soaSerialNumber, int increment)
        {
            byte[] soaSerialNumberArray;

            if (soaSerialNumber == -1)
            {
                TcpClient dnsClient = new TcpClient();
                dnsClient.ReceiveTimeout = 3000;
                byte[] dnsClientReceive = new byte[2048];

                try
                {
                    dnsClient.Connect(domainController, 53);
                    NetworkStream dnsClientStream = dnsClient.GetStream();

                    byte[] nameArray = NewDNSNameArray(zone);
                    byte[] length = Util.IntToByteArray2(nameArray.Length + 17);
                    Random randomTransactionID = new Random();
                    byte[] transactionID = new byte[2];
                    randomTransactionID.NextBytes(transactionID);

                    using (MemoryStream memoryStream = new MemoryStream())
                    {
                        memoryStream.Write(length, 0, length.Length);
                        memoryStream.Write(transactionID, 0, transactionID.Length);
                        memoryStream.Write((new byte[2] { 0x01, 0x00 }), 0, 2); // Flags
                        memoryStream.Write((new byte[2] { 0x00, 0x01 }), 0, 2); // Questions
                        memoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2); // AnswerRRs
                        memoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2); // AuthorityRRs
                        memoryStream.Write((new byte[2] { 0x00, 0x00 }), 0, 2); // AditionalRRs
                        memoryStream.Write(nameArray, 0, nameArray.Length);
                        memoryStream.Write((new byte[1] { 0x00 }), 0, 1);
                        memoryStream.Write((new byte[2] { 0x00, 0x06 }), 0, 2); // Type
                        memoryStream.Write((new byte[2] { 0x00, 0x01 }), 0, 2); // Queries Class
                        dnsClientStream.Write(memoryStream.ToArray(), 0, memoryStream.ToArray().Length);
                    }

                    dnsClientStream.Flush();
                    dnsClientStream.Read(dnsClientReceive, 0, dnsClientReceive.Length);
                    dnsClient.Close();
                }
                catch
                {
                    Console.WriteLine("[-] {0} did not respond on TCP port 53", domainController);
                    throw;
                }

                if (dnsClientReceive[9] == 0)
                {
                    Console.WriteLine("[-] {0} SOA record not found", zone);
                    throw new Exception("SOA record not found");
                }
                else
                {
                    string dnsReplyConverted = BitConverter.ToString(dnsClientReceive).Replace("-", "");
                    int soaAnswerIndex = dnsReplyConverted.IndexOf("C00C00060001");
                    soaAnswerIndex = soaAnswerIndex / 2;
                    byte[] soaLengthArray = new byte[2];
                    Buffer.BlockCopy(dnsClientReceive, (soaAnswerIndex + 10), soaLengthArray, 0, 2);
                    int soaLength = Util.DataToUInt16(soaLengthArray);
                    byte[] soaSerialCurrentArray = new byte[4];
                    Buffer.BlockCopy(dnsClientReceive, (soaAnswerIndex + soaLength - 8), soaSerialCurrentArray, 0, 4);
                    int soaSerialCurrent = (int)Util.DataToUInt32(soaSerialCurrentArray) + increment;
                    soaSerialNumberArray = BitConverter.GetBytes(soaSerialCurrent);
                }

            }
            else
            {
                soaSerialNumberArray = BitConverter.GetBytes(soaSerialNumber + increment);
            }

            Array.Reverse(soaSerialNumberArray);

            return soaSerialNumberArray;
        }

        public static byte[] NewDNSRecordArray(string data, string domainController, string type, string zone, int preference, int priority, int weight, int port, int TTL, int soaSerialNumber, bool staticRecord, bool tombstone, bool verbose)
        {

            if (String.IsNullOrEmpty(data) && type == "A")
            {

                try
                {
                    data = Util.GetLocalIPAddress("IPv4");
                    if (verbose) { Console.WriteLine("[+] Data = {0}", data); }
                }
                catch
                {
                    Console.WriteLine("[-] Error finding local IP, specify manually with -Data");
                    throw;
                }

            }
            if (String.IsNullOrEmpty(data) && type == "AAAA")
            {

                try
                {
                    data = Util.GetLocalIPAddress("IPv6");
                    if (verbose) { Console.WriteLine("[+] Data = {0}", data); }
                }
                catch
                {
                    Console.WriteLine("[-] Error finding local IP, specify manually with -Data");
                    throw;
                }
                
            }
            else if (String.IsNullOrEmpty(data))
            {
                Console.WriteLine("[-] -Data required with record type " + type);
                Environment.Exit(1);
            }

            byte[] soaSerialNumberArray;

            try
            {
                soaSerialNumberArray = NewSOASerialNumberArray(domainController, zone, soaSerialNumber, 1);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw;
            }

            if (verbose) { Console.WriteLine("[+] SOA serial number = {0}", Util.DataToUInt16(soaSerialNumberArray)); }
            byte[] dnsType = new byte[2];
            byte[] dnsData = new byte[2];
            MemoryStream dnsMemoryStream = new MemoryStream();
            byte[] dnsDataLength = BitConverter.GetBytes(data.Length + 2).Take(1).ToArray();
            byte[] dnsDataSplitLength = BitConverter.GetBytes(data.Split('.').Length).Take(1).ToArray();
            byte[] dnsNameArray = NewDNSNameArray(data);

            switch (type)
            {

                case "A":
                    dnsType = new byte[2] { 0x01, 0x00 };
                    dnsData = IPAddress.Parse(data).GetAddressBytes();
                    break;

                case "AAAA":
                    dnsType = new byte[2] { 0x1c, 0x00 };
                    dnsData = IPAddress.Parse(data).GetAddressBytes();
                    Console.WriteLine(dnsData.Length);
                    break;

                case "CNAME":
                    dnsType = new byte[2] { 0x05, 0x00 };
                    dnsMemoryStream.Write(dnsDataLength, 0, dnsDataLength.Length);
                    dnsMemoryStream.Write(dnsDataSplitLength, 0, dnsDataSplitLength.Length);
                    dnsMemoryStream.Write(dnsNameArray, 0, dnsNameArray.Length);
                    dnsMemoryStream.Write((new byte[1] { 0x00 }), 0, 1);
                    dnsData = dnsMemoryStream.ToArray();
                    break;

                case "DNAME":
                    dnsType = new byte[2] { 0x27, 0x00 };
                    dnsMemoryStream.Write(dnsDataLength, 0, dnsDataLength.Length);
                    dnsMemoryStream.Write(dnsDataSplitLength, 0, dnsDataSplitLength.Length);
                    dnsMemoryStream.Write(dnsNameArray, 0, dnsNameArray.Length);
                    dnsMemoryStream.Write((new byte[1] { 0x00 }), 0, 1);
                    dnsData = dnsMemoryStream.ToArray();
                    break;

                case "MX":
                    dnsType = new byte[2] { 0x0f, 0x00 };
                    byte[] dnsPreference = BitConverter.GetBytes(preference).Take(2).ToArray();
                    dnsMemoryStream.Write(dnsPreference, 0, dnsPreference.Length);
                    dnsMemoryStream.Write(dnsDataLength, 0, dnsDataLength.Length);
                    dnsMemoryStream.Write(dnsDataSplitLength, 0, dnsDataSplitLength.Length);
                    dnsMemoryStream.Write(dnsNameArray, 0, dnsNameArray.Length);
                    dnsMemoryStream.Write((new byte[1] { 0x00 }), 0, 1);
                    dnsData = dnsMemoryStream.ToArray();
                    break;

                case "NS":
                    dnsType = new byte[2] { 0x02, 0x00 };
                    dnsMemoryStream.Write(dnsDataLength, 0, dnsDataLength.Length);
                    dnsMemoryStream.Write(dnsDataSplitLength, 0, dnsDataSplitLength.Length);
                    dnsMemoryStream.Write(dnsNameArray, 0, dnsNameArray.Length);
                    dnsMemoryStream.Write((new byte[1] { 0x00 }), 0, 1);
                    dnsData = dnsMemoryStream.ToArray();
                    break;

                case "PTR":
                    dnsType = new byte[2] { 0x0c, 0x00 };
                    dnsMemoryStream.Write(dnsDataLength, 0, dnsDataLength.Length);
                    dnsMemoryStream.Write(dnsDataSplitLength, 0, dnsDataSplitLength.Length);
                    dnsMemoryStream.Write(dnsNameArray, 0, dnsNameArray.Length);
                    dnsMemoryStream.Write((new byte[1] { 0x00 }), 0, 1);
                    dnsData = dnsMemoryStream.ToArray();
                    break;

                case "SRV":
                    dnsType = new byte[2] { 0x21, 0x00 };
                    byte[] dnsPriority = BitConverter.GetBytes(priority).Take(2).ToArray();
                    Array.Reverse(dnsPriority);
                    byte[] dnsWeight = BitConverter.GetBytes(weight).Take(2).ToArray();
                    Array.Reverse(dnsWeight);
                    byte[] dnsPort = BitConverter.GetBytes(port).Take(2).ToArray();
                    Array.Reverse(dnsPort);
                    dnsMemoryStream.Write(dnsPriority, 0, dnsPriority.Length);
                    dnsMemoryStream.Write(dnsWeight, 0, dnsWeight.Length);
                    dnsMemoryStream.Write(dnsPort, 0, dnsPort.Length);
                    dnsMemoryStream.Write(dnsDataLength, 0, dnsDataLength.Length);
                    dnsMemoryStream.Write(dnsDataSplitLength, 0, dnsDataSplitLength.Length);
                    dnsMemoryStream.Write(dnsNameArray, 0, dnsNameArray.Length);
                    dnsMemoryStream.Write((new byte[1] { 0x00 }), 0, 1);
                    dnsData = dnsMemoryStream.ToArray();
                    break;

                case "TXT":
                    dnsType = new byte[2] { 0x10, 0x00 };
                    dnsDataLength = BitConverter.GetBytes(data.Length).Take(1).ToArray();
                    dnsMemoryStream.Write(dnsDataLength, 0, dnsDataLength.Length);
                    byte[] dnsTXT = Encoding.UTF8.GetBytes(data);
                    dnsMemoryStream.Write(dnsTXT, 0, dnsTXT.Length);
                    dnsData = dnsMemoryStream.ToArray();
                    break;
            }

            byte[] dnsTTL = BitConverter.GetBytes(TTL);
            Array.Reverse(dnsTTL);
            byte[] dnsLength = BitConverter.GetBytes(dnsData.Length).Take(2).ToArray();

            using (MemoryStream recordMemoryStream = new MemoryStream())
            {
                recordMemoryStream.Write(dnsLength, 0, dnsLength.Length);
                recordMemoryStream.Write(dnsType, 0, dnsType.Length);
                recordMemoryStream.Write((new byte[4] { 0x05, 0xF0, 0x00, 0x00 }), 0, 4);
                recordMemoryStream.Write(soaSerialNumberArray, 0, soaSerialNumberArray.Length);
                recordMemoryStream.Write(dnsTTL, 0, dnsTTL.Length);
                recordMemoryStream.Write((new byte[4] { 0x00, 0x00, 0x00, 0x00 }), 0, 4);

                if (staticRecord)
                {
                    recordMemoryStream.Write((new byte[4] { 0x00, 0x00, 0x00, 0x00 }), 0, 4);
                }
                else
                {
                    byte[] timestampArray = Util.NewTimeStampArray();
                    recordMemoryStream.Write(timestampArray.Take(4).ToArray(), 0, 4);
                }

                recordMemoryStream.Write(dnsData, 0, dnsData.Length);

                return recordMemoryStream.ToArray();
            }

        }

        public static void DisableADIDNSNode(string distinguishedName, string domain, string domainController, string node, string partition, string zone, int soaSerialNumber, NetworkCredential credential, bool verbose)
        {
            distinguishedName = GetADIDNSDistinguishedName(node, distinguishedName, domain, partition, zone, verbose);
            byte[] soaSerialNumberArray;

            try
            {
                soaSerialNumberArray = NewSOASerialNumberArray(domainController, zone, soaSerialNumber, 1);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw;
            }

            byte[] timestampArray = Util.NewTimeStampArray();

            MemoryStream recordMemoryStream = new MemoryStream();
            recordMemoryStream.Write((new byte[8] { 0x08, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00 }), 0, 8);
            recordMemoryStream.Write(soaSerialNumberArray, 0, soaSerialNumberArray.Length);
            recordMemoryStream.Write((new byte[12] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }), 0, 12);
            recordMemoryStream.Write(timestampArray, 0, timestampArray.Length);
            byte[] dnsRecord = recordMemoryStream.ToArray();
            if (verbose) { Console.WriteLine("[+] DNSRecord = {0}", BitConverter.ToString(dnsRecord)); };

            DirectoryEntry directoryEntry;

            if (!String.IsNullOrEmpty(credential.UserName))
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName), credential.UserName, credential.Password);
            }
            else
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName));
            }

            try
            {
                directoryEntry.InvokeSet("dnsRecord", dnsRecord);
                directoryEntry.InvokeSet("dnsTombstoned", true);
                directoryEntry.CommitChanges();
                Console.WriteLine("[+] ADIDNS node {0} tombstoned", node);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw;
            }

            if(!String.IsNullOrEmpty(directoryEntry.Path))
            {
                directoryEntry.Dispose();
            }

        }

        public static void EnableADIDNSNode(string data, string distinguishedName, string domain, string domainController, string node, string partition, string type, string zone, int preference, int priority, int weight, int port, int TTL, int soaSerialNumber, bool staticRecord, bool tombstone, bool verbose, NetworkCredential credential)
        {
            distinguishedName = GetADIDNSDistinguishedName(node, distinguishedName, domain, partition, zone, verbose);
            byte[] dnsRecord;

            try
            {
                dnsRecord = ADIDNS.NewDNSRecordArray(data, domainController, type, zone, preference, priority, weight, port, TTL, soaSerialNumber, staticRecord, tombstone, verbose);
                if (verbose) { Console.WriteLine("[+] DNSRecord = {0}", BitConverter.ToString(dnsRecord)); };
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw;
            }

            DirectoryEntry directoryEntry;

            if (!String.IsNullOrEmpty(credential.UserName))
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName), credential.UserName, credential.Password);
            }
            else
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName));
            }

            try
            {
                directoryEntry.InvokeSet("dnsRecord", dnsRecord);
                directoryEntry.CommitChanges();
                Console.WriteLine("[+] ADIDNS node {0} enabled", node);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw;
            }

            if (!String.IsNullOrEmpty(directoryEntry.Path))
            {
                directoryEntry.Dispose();
            }

        }

        public static void GetADIDNSNodeAttribute(string distinguishedName, string domain, string domainController, string attribute, string node, string partition, string zone, NetworkCredential credential, bool verbose)
        {
            distinguishedName = GetADIDNSDistinguishedName(node, distinguishedName, domain, partition, zone, verbose);

            DirectoryEntry directoryEntry;

            if (!String.IsNullOrEmpty(credential.UserName))
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName), credential.UserName, credential.Password);
            }
            else
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName));
            }

            try
            {
                PropertyValueCollection value = directoryEntry.Properties[attribute];

                if (String.Equals(value.Value.GetType().ToString(), "System.Byte[]"))
                {
                    BinaryFormatter binaryFormatter = new BinaryFormatter();
                    using (MemoryStream memoryStream = new MemoryStream())
                    {
                        binaryFormatter.Serialize(memoryStream, value.Value);
                    }

                }
                else
                {
                    string valueString = "";

                    foreach (string val in value)
                    {
                        valueString = String.Concat(valueString, ",", val);
                    }

                    valueString = valueString.Substring(1);
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw;
            }

            if (!String.IsNullOrEmpty(directoryEntry.Path))
            {
                directoryEntry.Dispose();
            }

        }

        public static void GetADIDNSNodeOwner(string distinguishedName, string domain, string domainController, string node, string partition, string zone, bool verbose, NetworkCredential credential)
        {
            distinguishedName = GetADIDNSDistinguishedName(node, distinguishedName, domain, partition, zone, verbose);

            DirectoryEntry directoryEntry;

            if (!String.IsNullOrEmpty(credential.UserName))
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName), credential.UserName, credential.Password);
            }
            else
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName));
            }

            try
            {
                ActiveDirectorySecurity owner = directoryEntry.ObjectSecurity;

                try
                {
                    Console.WriteLine("[+] Node {0} owner is {1}", node, owner.GetOwner(typeof(NTAccount)).ToString());
                }
                catch
                {

                    try
                    {
                        Console.WriteLine("[+] Node {0} owner is {1}", node, owner.GetOwner(typeof(SecurityIdentifier)).ToString());
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.ToString());
                        throw;
                    }

                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw;
            }

            if (!String.IsNullOrEmpty(directoryEntry.Path))
            {
                directoryEntry.Dispose();
            }

        }

        public static void GetADIDNSNodeTombstoned(string distinguishedName, string domain, string domainController, string node, string partition, string zone, bool verbose, NetworkCredential credential)
        {
            distinguishedName = GetADIDNSDistinguishedName(node, distinguishedName, domain, partition, zone, verbose);

            DirectoryEntry directoryEntry;

            if (!String.IsNullOrEmpty(credential.UserName))
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName), credential.UserName, credential.Password);
            }
            else
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName));
            }

            object dnsTombstoned;
            object dnsRecord;
            byte[] dnsRecordArray;

            try
            {
                dnsTombstoned = directoryEntry.InvokeGet("dnsTombstoned");
                dnsRecord = (Byte[])directoryEntry.InvokeGet("dnsRecord");
                PropertyValueCollection value = directoryEntry.Properties["dnsRecord"];
                dnsRecordArray = (byte[])directoryEntry.Properties["dnsRecord"].Value;

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw;
            }        

            if (String.Equals(dnsRecordArray[0].GetType().ToString(), "System.Byte"))
            {

                if (dnsRecordArray.Count() >= 32 && dnsRecordArray[2] == 0)
                {
                    Console.WriteLine("[+] Node {0} is tombstoned", node);
                }
                else
                {
                    Console.WriteLine("[+] Node {0} is not tombstoned", node);
                }

            }

            if (!String.IsNullOrEmpty(directoryEntry.Path))
            {
                directoryEntry.Dispose();
            }

        }

        public static void GetADIDNSDACL(string distinguishedName, string domain, string domainController, string node, string partition, string zone, bool verbose, NetworkCredential credential)
        {
            distinguishedName = GetADIDNSDistinguishedName(node, distinguishedName, domain, partition, zone, verbose);
            DirectoryEntry directoryEntry;

            if (!String.IsNullOrEmpty(credential.UserName))
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName), credential.UserName, credential.Password);
            }
            else
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName));
            }

            try
            {
                AuthorizationRuleCollection directoryEntryDACL = directoryEntry.ObjectSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier));

                foreach (ActiveDirectoryAccessRule ace in directoryEntryDACL)
                {
                    string principle = "";
                    string principalDistingushedName = "";             

                    try
                    {
                        principle = ace.IdentityReference.Translate(typeof(NTAccount)).ToString();
                    }
                    catch
                    {
                        DirectoryEntry directoryEntryPrinciple;

                        if (!String.IsNullOrEmpty(credential.UserName))
                        {
                            directoryEntryPrinciple = new DirectoryEntry(String.Concat("LDAP://", domainController, "/<SID=", ace.IdentityReference.Value.ToString(), ">"), credential.UserName, credential.Password);
                        }
                        else
                        {
                            directoryEntryPrinciple = new DirectoryEntry(String.Concat("LDAP://", domainController, "/<SID=", ace.IdentityReference.Value.ToString(), ">"));
                        }

                        if (directoryEntryPrinciple.Properties["userPrincipalname"].Value != null)
                        {
                            principle = directoryEntryPrinciple.Properties["userPrincipalname"].Value.ToString();
                        }
                        else
                        {
                            principle = directoryEntryPrinciple.Properties["sAMAccountName"].Value.ToString();
                            principalDistingushedName = directoryEntryPrinciple.Properties["distinguishedName"].Value.ToString();
                        }

                        directoryEntryPrinciple.Dispose();
                    }


                    var aceList = new List<dynamic>();
                    aceList.Add(String.Concat("Principal             : ", principle));

                    if (!String.IsNullOrEmpty(principalDistingushedName))
                    {
                        aceList.Add(String.Concat("DistinguishedName     : ", principalDistingushedName));
                    }

                    aceList.Add(String.Concat("IdentityReference     : ", ace.IdentityReference.ToString()));
                    aceList.Add(String.Concat("ActiveDirectoryRights : ", ace.ActiveDirectoryRights.ToString()));
                    aceList.Add(String.Concat("InheritanceType       : ", ace.InheritanceType.ToString()));
                    aceList.Add(String.Concat("ObjectType            : ", ace.ObjectType.ToString()));
                    aceList.Add(String.Concat("InheritedObjectType   : ", ace.InheritedObjectType.ToString()));
                    aceList.Add(String.Concat("ObjectFlags           : ", ace.ObjectFlags.ToString()));
                    aceList.Add(String.Concat("AccessControlType     : ", ace.AccessControlType.ToString()));
                    aceList.Add(String.Concat("IsInherited           : ", ace.IsInherited.ToString()));
                    aceList.Add(String.Concat("InheritanceFlags      : ", ace.InheritanceFlags.ToString()));
                    aceList.Add(String.Concat("PropagationFlags      : ", ace.PropagationFlags.ToString()));
                    aceList.ForEach(Console.WriteLine);
                    Console.WriteLine();                
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw;
            }

            if (!String.IsNullOrEmpty(directoryEntry.Path))
            {
                directoryEntry.Dispose();
            }

        }

        public static void GetADIDNSZone(string distinguishedName, string domain, string domainController, string partition, string zone, bool verbose, NetworkCredential credential)
        {
            string[] domainComponent;
            string[] partitionList;

            if (String.IsNullOrEmpty(partition))
            {

                if (!String.IsNullOrEmpty(distinguishedName))
                {
                    partitionList = new string[] { "DomainDNSZones", "ForestDNSZones", "System" }; ;
                }
                else
                {
                    string[] partitionArray = distinguishedName.Split(',');
                    partitionList = new string[] { partitionArray[0].Substring(3) };
                }

            }
            else
            {
                partitionList = new string[] { partition };
            }

            foreach (string partitionEntry in partitionList)
            {
                Console.WriteLine("[+] Partition = {0}", partitionEntry);

                if (String.IsNullOrEmpty(distinguishedName))
                {

                    if (partitionEntry.Equals("System"))
                    {
                        distinguishedName = String.Concat("CN=", partitionEntry);
                    }
                    else
                    {
                        distinguishedName = String.Concat("DC=", partitionEntry);
                    }

                    domainComponent = domain.Split('.');

                    foreach (string dc in domainComponent)
                    {
                        distinguishedName += String.Concat(",DC=", dc);
                    }

                    if (verbose) { Console.WriteLine("[+] Distinguished Name = {0}", distinguishedName); };
                }

            }

            DirectoryEntry directoryEntry;

            if (!String.IsNullOrEmpty(credential.UserName))
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName), credential.UserName, credential.Password);
            }
            else
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName));
            }

            try
            {
                DirectorySearcher directorySearcher = new DirectorySearcher(directoryEntry);

                if (!String.IsNullOrEmpty(zone))
                {
                    directorySearcher.Filter = String.Concat("(&(objectClass=dnszone)(name=", zone, "))");
                }
                else
                {
                    directorySearcher.Filter = "(objectClass=dnszone)";
                }

                SearchResultCollection searchResults = directorySearcher.FindAll();
                int i = 0;

                foreach (SearchResult searchResult in searchResults)
                {
                    Console.WriteLine("[+] Zone Distinguished Name = {0}", searchResult.Properties["DistinguishedName"][i].ToString());
                    i++;
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw;
            }

            if (!String.IsNullOrEmpty(directoryEntry.Path))
            {
                directoryEntry.Dispose();
            }

        }

        public static void AddADIDNSACE(string distinguishedName, string domain, string domainController, string node, string partition, string principal, string type, string zone, string access, bool verbose, NetworkCredential credential)
        {
            distinguishedName = GetADIDNSDistinguishedName(node, distinguishedName, domain, partition, zone, verbose);
            DirectoryEntry directoryEntry;

            if (!String.IsNullOrEmpty(credential.UserName))
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName), credential.UserName, credential.Password);
            }
            else
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName));
            }

            try
            {
                IdentityReference account = new NTAccount(principal);
                IdentityReference principalSID = account.Translate(typeof(SecurityIdentifier));
                ActiveDirectoryRights activeDirectoryRights = (ActiveDirectoryRights)Enum.Parse(typeof(ActiveDirectoryRights), access);
                AccessControlType accessControlType = (AccessControlType)Enum.Parse(typeof(AccessControlType), type);
                AuthorizationRuleCollection directoryEntryDACL = directoryEntry.ObjectSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier));
                ActiveDirectoryAccessRule ace = new ActiveDirectoryAccessRule(principalSID, activeDirectoryRights, accessControlType, ActiveDirectorySecurityInheritance.All);
                directoryEntry.ObjectSecurity.AddAccessRule(ace);
                directoryEntry.CommitChanges();

                if (!String.IsNullOrEmpty(node))
                {
                    Console.WriteLine("[+] ACE added for {0} to {1} DACL", principal, node);
                }
                else
                {
                    Console.WriteLine("[+] ACE added for {0} to {1} DACL", principal, zone);
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw;
            }

            if (!String.IsNullOrEmpty(directoryEntry.Path))
            {
                directoryEntry.Dispose();
            }

        }

        public static void RemoveADIDNSACE(string distinguishedName, string domain, string domainController, string node, string partition, string principal, string type, string zone, string access, bool verbose, NetworkCredential credential)
        {
            distinguishedName = GetADIDNSDistinguishedName(node, distinguishedName, domain, partition, zone, verbose);
            DirectoryEntry directoryEntry;

            if (!String.IsNullOrEmpty(credential.UserName))
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName), credential.UserName, credential.Password);
            }
            else
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName));
            }

            try
            {
                IdentityReference account = new NTAccount(principal);
                IdentityReference principalSID = account.Translate(typeof(SecurityIdentifier));
                ActiveDirectoryRights activeDirectoryRights = (ActiveDirectoryRights)Enum.Parse(typeof(ActiveDirectoryRights), access);
                AccessControlType accessControlType = (AccessControlType)Enum.Parse(typeof(AccessControlType), type);
                AuthorizationRuleCollection directoryEntryDACL = directoryEntry.ObjectSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier));
                ActiveDirectoryAccessRule ace = new ActiveDirectoryAccessRule(principalSID, activeDirectoryRights, accessControlType, ActiveDirectorySecurityInheritance.All);
                directoryEntry.ObjectSecurity.RemoveAccessRule(ace);
                directoryEntry.CommitChanges();

                if (!String.IsNullOrEmpty(node))
                {
                    Console.WriteLine("[+] ACE revoked for {0} to {1} DACL", principal, node);
                }
                else
                {
                    Console.WriteLine("[+] ACE revoked for {0} to {1} DACL", principal, zone);
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw;
            }

            if (!String.IsNullOrEmpty(directoryEntry.Path))
            {
                directoryEntry.Dispose();
            }

        }

        public static void NewADIDNSNode(string data, string distinguishedName, string domain, string domainController, string forest, string node, string partition, string type, string zone, int preference, int priority, int weight, int port, int TTL, int soaSerialNumber, bool staticRecord, bool tombstone, bool verbose, NetworkCredential credential)
        {
            distinguishedName = GetADIDNSDistinguishedName(node, distinguishedName, domain, partition, zone, verbose);
            byte[] dnsRecord;

            try
            {
                dnsRecord = ADIDNS.NewDNSRecordArray(data, domainController, type, zone, preference, priority, weight, port, TTL, soaSerialNumber, staticRecord, tombstone, verbose);
                if (verbose) { Console.WriteLine(String.Concat("[+] DNSRecord = ", BitConverter.ToString(dnsRecord))); };
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw;
            }

            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(domainController, 389);
            LdapConnection connection = new LdapConnection(identifier);

            if (!String.IsNullOrEmpty(credential.UserName))
            {
                connection = new LdapConnection(identifier, credential);
            }

            string objectCatagory = "CN=Dns-Node,CN=Schema,CN=Configuration";
            string[] domainComponent = forest.Split('.');

            foreach (string dc in domainComponent)
            {
                objectCatagory += String.Concat(",DC=", dc);
            }

            try
            {
                connection.SessionOptions.Sealing = true;
                connection.SessionOptions.Signing = true;
                connection.Bind();
                AddRequest request = new AddRequest();
                request.DistinguishedName = distinguishedName;
                request.Attributes.Add(new DirectoryAttribute("objectClass", new string[] { "top", "dnsNode" }));
                request.Attributes.Add(new DirectoryAttribute("objectCategory", objectCatagory));
                request.Attributes.Add(new DirectoryAttribute("dnsRecord", dnsRecord));

                if (tombstone)
                {
                    request.Attributes.Add(new DirectoryAttribute("dNSTombstoned", "TRUE"));
                }

                connection.SendRequest(request);
                Console.WriteLine("[+] ADIDNS node {0} added", node);
                connection.Dispose();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw;
            }

        }

        public static void RenameADIDNSNode(string distinguishedName, string domain, string domainController, string node, string nodeNew, string partition, string zone, bool verbose, NetworkCredential credential)
        {
            distinguishedName = GetADIDNSDistinguishedName(node, distinguishedName, domain, partition, zone, verbose);
            DirectoryEntry directoryEntry;

            if (!String.IsNullOrEmpty(credential.UserName))
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName), credential.UserName, credential.Password);
            }
            else
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName));
            }

            try
            {
                directoryEntry.Rename(String.Concat("DC=", nodeNew));
                Console.WriteLine("[+] ADIDNS node {0} renamed to {1}", node, nodeNew);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw;
            }

            if (!String.IsNullOrEmpty(directoryEntry.Path))
            {
                directoryEntry.Dispose();
            }

        }

        public static void RemoveADIDNSNode(string distinguishedName, string domain, string domainController, string attribute, string node, string nodeNew, string partition, string zone, bool verbose, NetworkCredential credential)
        {
            distinguishedName = GetADIDNSDistinguishedName(node, distinguishedName, domain, partition, zone, verbose);
            DirectoryEntry directoryEntry;

            if (!String.IsNullOrEmpty(credential.UserName))
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName), credential.UserName, credential.Password);
            }
            else
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName));
            }

            try
            {
                directoryEntry.DeleteTree();
                Console.WriteLine("[+] ADIDNS node {0} removed", node);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw;
            }

            if (!String.IsNullOrEmpty(directoryEntry.Path))
            {
                directoryEntry.Dispose();
            }

        }

        public static void SetADIDNSNodeAttribute(string distinguishedName, string domain, string domainController, string attribute, string node, string partition, string value, string zone, bool append, bool clear, bool verbose, NetworkCredential credential)
        {
            distinguishedName = GetADIDNSDistinguishedName(node, distinguishedName, domain, partition, zone, verbose);
            DirectoryEntry directoryEntry;

            if (!String.IsNullOrEmpty(credential.UserName))
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName), credential.UserName, credential.Password);
            }
            else
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName));
            }

            try
            {

                if (append)
                {
                    directoryEntry.Properties[attribute].Add(value);
                    directoryEntry.CommitChanges();
                    Console.WriteLine("[+] ADIDNS node {0} attribute {1} appended", node, attribute);
                }
                else if (clear)
                {
                    directoryEntry.Properties[attribute].Clear();
                    directoryEntry.CommitChanges();
                    Console.WriteLine("[+] ADIDNS node {0} attribute {1} cleared", node, attribute);
                }
                else
                {
                    directoryEntry.InvokeSet(attribute, value);
                    directoryEntry.CommitChanges();
                    Console.WriteLine("[+] ADIDNS node {0} attribute {1} updated", node, attribute);
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw;
            }

            if (!String.IsNullOrEmpty(directoryEntry.Path))
            {
                directoryEntry.Dispose();
            }
        }

        public static void SetADIDNSNodeOwner(string distinguishedName, string domain, string domainController, string node, string partition, string principal, string zone, bool verbose, NetworkCredential credential)
        {
            distinguishedName = GetADIDNSDistinguishedName(node, distinguishedName, domain, partition, zone, verbose);
            DirectoryEntry directoryEntry;

            if (!String.IsNullOrEmpty(credential.UserName))
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName), credential.UserName, credential.Password);
            }
            else
            {
                directoryEntry = new DirectoryEntry(String.Concat("LDAP://", domainController, "/", distinguishedName));
            }

            try
            {
                IdentityReference account = new NTAccount(principal);
                directoryEntry.ObjectSecurity.SetOwner(account);
                directoryEntry.CommitChanges();
                Console.WriteLine("[+] ADIDNS node {0} owner set to {1}", node, principal);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                throw;
            }

            if (!String.IsNullOrEmpty(directoryEntry.Path))
            {
                directoryEntry.Dispose();
            }

        }

    }

}
