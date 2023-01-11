using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.DirectoryServices.Protocols;
using System.Security.AccessControl;
using System.DirectoryServices;
using System.Runtime.Serialization.Formatters.Binary;
using System.IO;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Threading;

namespace Sharpmad
{
    class MAQ
    {

        public static string GetMAQDistinguishedName(string node, string container, string distinguishedName, string domain, bool verbose)
        {
            string[] domainComponent;

            switch (container)
            {

                case "BUILTIN":
                    container = "CN=Builtin";
                    break;

                case "COMPUTERS":
                    container = "CN=Computers";
                    break;

                case "DOMAINCONTROLLERS":
                    container = "OU=Domain Controllers";
                    break;

                case "FOREIGNSECURITYPRINCIPALS":
                    container = "CN=ForeignSecurityPrincipals";
                    break;

                case "KEYS":
                    container = "CN=Keys";
                    break;

                case "LOSTANDFOUND":
                    container = "CN=LostAndFound";
                    break;

                case "MANAGEDSERVICEACCOUNTS":
                    container = "CN=Managed Service Accounts";
                    break;

                case "PROGRAMDATA":
                    container = "CN=Program Data";
                    break;

                case "USERS":
                    container = "CN=Users";
                    break;

                case "ROOT":
                    container = "";
                    break;

            }

            if (string.IsNullOrEmpty(distinguishedName))
            {

                if (!String.IsNullOrEmpty(container))
                {

                    if (!String.IsNullOrEmpty(node))
                    {
                        distinguishedName = String.Concat("CN=", node, ",", container);
                    }
                    else
                    {
                        distinguishedName = container;
                    }

                }

                domainComponent = domain.Split('.');

                foreach (string dc in domainComponent)
                {
                    distinguishedName += String.Concat(",DC=", dc);
                }

                distinguishedName = distinguishedName.TrimStart(',');

                if (verbose) { Console.WriteLine("[+] Distinguished Name = {0}", distinguishedName); };
            }
            else if (!String.IsNullOrEmpty(node))
            {
                distinguishedName = String.Concat("CN=", node, ",", distinguishedName);
            }

            return distinguishedName;
        }

        public static void DisableMachineAccount(string container, string distinguishedName, string domain, string domainController, string machineAccount, bool verbose, NetworkCredential credential)
        {
            distinguishedName = GetMAQDistinguishedName(machineAccount, container, distinguishedName, domain, verbose);

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
                directoryEntry.InvokeSet("AccountDisabled", true);
                directoryEntry.CommitChanges();
                Console.WriteLine("[+] Machine account node {0} disabled", machineAccount);
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

        public static void EnableMachineAccount(string container, string distinguishedName, string domain, string domainController, string machineAccount, bool verbose, NetworkCredential credential)
        {
            distinguishedName = GetMAQDistinguishedName(machineAccount, container, distinguishedName, domain, verbose);

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
                directoryEntry.InvokeSet("AccountDisabled", false);
                directoryEntry.CommitChanges();
                Console.WriteLine("[+] Machine account node {0} enabled", machineAccount);
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

        public static void GetMachineAccountAttribute(string container, string distinguishedName, string domain, string domainController, string attribute, string machineAccount, bool verbose, NetworkCredential credential)
        {
            distinguishedName = GetMAQDistinguishedName(machineAccount, container, distinguishedName, domain, verbose);

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

        public static void GetMachineAccountCreator(string container, string distinguishedName, string domain, string domainController, bool verbose, NetworkCredential credential)
        {
            distinguishedName = GetMAQDistinguishedName(null, container, distinguishedName, domain, verbose);
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
                directorySearcher.SearchRoot = directoryEntry;
                directorySearcher.PageSize = 1000;
                directorySearcher.Filter = "(&(ms-ds-creatorsid=*))";
                directorySearcher.SearchScope = System.DirectoryServices.SearchScope.Subtree;
                SearchResultCollection searchResults = directorySearcher.FindAll();

                if(searchResults.Count == 0)
                {
                    Console.WriteLine("[-] No results found in {0}", distinguishedName);
                }

                foreach (SearchResult searchResult in searchResults)
                {
                    byte[] creatorSIDObject = (byte[])searchResult.Properties["ms-ds-creatorsid"][0];
                    string creatorSID = new SecurityIdentifier(creatorSIDObject, 0).Value;
                    string machineAccount = (string)searchResult.Properties["Name"][0];
                    string accountContainer = (string)searchResult.Properties["distinguishedName"][0];
                    accountContainer = accountContainer.Split(',')[1];
                    string principle = "";
                    string principalDistingushedName = "";               

                    try
                    {
                        DirectoryEntry directoryEntryPrinciple;

                        if (!String.IsNullOrEmpty(credential.UserName))
                        {
                            directoryEntryPrinciple = new DirectoryEntry(String.Concat("LDAP://", domainController, "/<SID=", creatorSID, ">"), credential.UserName, credential.Password);
                        }
                        else
                        {
                            directoryEntryPrinciple = new DirectoryEntry(String.Concat("LDAP://", domainController, "/<SID=", creatorSID, ">"));
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
                    catch
                    {
                        principle = creatorSID;
                    }

                    Console.WriteLine("[+] Account {0} is the creator of {1} in {2}", principle, machineAccount, accountContainer);
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

        public static void NewMachineAccount(string container, string distinguishedName, string domain, string domainController, string machineAccount, string machinePassword, bool verbose, bool random, NetworkCredential credential)
        {
            string samAccountName;

            if (machineAccount.EndsWith("$"))
            {
                samAccountName = machineAccount;
                machineAccount = machineAccount.Substring(0, machineAccount.Length - 1);
            }
            else
            {
                samAccountName = String.Concat(machineAccount, "$");
            }

            byte[] unicodePwd;
            string randomPassword = "";

            if (random)
            {
                Console.WriteLine("[*] Generating random machine account password");
                RNGCryptoServiceProvider cryptoServiceProvider = new RNGCryptoServiceProvider();
                byte[] randomBuffer = new byte[16];
                cryptoServiceProvider.GetBytes(randomBuffer);
                machinePassword = Convert.ToBase64String(randomBuffer);
            }

            domain = domain.ToLower();
            string dnsHostname = String.Concat(machineAccount, ".", domain);
            string[] servicePrincipalName = { String.Concat("HOST/", dnsHostname), String.Concat("RestrictedKrbHost/", dnsHostname), String.Concat("HOST/", machineAccount), String.Concat("RestrictedKrbHost/", machineAccount) };
            unicodePwd = Encoding.Unicode.GetBytes(String.Concat('"', machinePassword, '"'));
            distinguishedName = GetMAQDistinguishedName(machineAccount, container, distinguishedName, domain, verbose);
            LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(domainController, 389);
            LdapConnection connection = new LdapConnection(identifier);

            if (!String.IsNullOrEmpty(credential.UserName))
            {
                connection = new LdapConnection(identifier, credential);
            }

            try
            {
                connection.SessionOptions.Sealing = true;
                connection.SessionOptions.Signing = true;
                connection.Bind();
                AddRequest request = new AddRequest();
                request.DistinguishedName = distinguishedName;
                request.Attributes.Add(new DirectoryAttribute("objectClass", "Computer"));
                request.Attributes.Add(new DirectoryAttribute("sAMAccountName", samAccountName));
                request.Attributes.Add(new DirectoryAttribute("userAccountControl", "4096"));
                request.Attributes.Add(new DirectoryAttribute("dNSHostName", dnsHostname));
                request.Attributes.Add(new DirectoryAttribute("servicePrincipalName", servicePrincipalName));
                request.Attributes.Add(new DirectoryAttribute("unicodePwd", unicodePwd));
                connection.SendRequest(request);
                connection.Dispose();

                if (random)
                {
                    Console.WriteLine("[+] Machine account {0} added with password {1}", machineAccount, randomPassword);
                }
                else
                {
                    Console.WriteLine("[+] Machine account {0} added", machineAccount);
                }

            }
            catch (Exception ex)
            {

                if (ex.Message.Contains("The object exists."))
                {
                    Console.WriteLine("[!] Machine account {0} already exists", machineAccount);
                }
                else if (ex.Message.Contains("The server cannot handle directory requests."))
                {
                    Console.WriteLine("[!] User may have reached ms-DS-MachineAccountQuota limit");
                }

                Console.WriteLine(ex.ToString());
                connection.Dispose();
                throw;
            }

        }

        public static void SetMachineAccountAttribute(string container, string distinguishedName, string domain, string domainController, string attribute, string machineAccount, string value, bool append, bool clear, bool verbose, NetworkCredential credential)
        {
            distinguishedName = GetMAQDistinguishedName(machineAccount, container, distinguishedName, domain, verbose);

            if(attribute.Equals("msDS-AllowedToActOnBehalfOfOtherIdentity"))
            {
                RawSecurityDescriptor rawSecurityDescriptor = new RawSecurityDescriptor("O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;" + value + ")");
                byte[] descriptor = new byte[rawSecurityDescriptor.BinaryLength];
                rawSecurityDescriptor.GetBinaryForm(descriptor, 0);
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

                if (append)
                {
                    directoryEntry.Properties[attribute].Add(value);
                    directoryEntry.CommitChanges();
                    Console.WriteLine("[+] Machine account {0} attribute {1} appended", machineAccount, attribute);
                }
                else if (clear)
                {
                    directoryEntry.Properties[attribute].Clear();
                    directoryEntry.CommitChanges();
                    Console.WriteLine("[+] Machine account {0} attribute {1} cleared", machineAccount, attribute);
                }
                else
                {
                    directoryEntry.InvokeSet(attribute, value);
                    directoryEntry.CommitChanges();
                    Console.WriteLine("[+] Machine account {0} attribute {1} updated", machineAccount, attribute);
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

        public static void RemoveMachineAccount(string container, string distinguishedName, string domain, string domainController, string machineAccount, bool verbose, NetworkCredential credential)
        {
            distinguishedName = GetMAQDistinguishedName(machineAccount, container, distinguishedName, domain, verbose);

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
                directoryEntry.InvokeSet("AccountDisabled", false);
                directoryEntry.CommitChanges();
                Console.WriteLine("[+] Machine account node {0} enabled", machineAccount);
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

        public static void AgentSmith(string container, string distinguishedName, string domain, string domainController, string machineAccount, string machinePassword, bool verbose, NetworkCredential credential)
        {
            int i = 0;
            int j = 1;
            int k = 1;
            int success = 0;
            int machineAccountQuota = 9;
            string account = "";
            bool switchAccount = false;
            string machineAccountPrefix = machineAccount;
            string distinguishedNameOld = distinguishedName;
            string samAccountName;
            domain = domain.ToLower();
            byte[] unicodePwd;
            unicodePwd = Encoding.Unicode.GetBytes(String.Concat('"', machinePassword, '"'));

            while (i <= machineAccountQuota)
            {
                machineAccount = String.Concat(machineAccountPrefix, j);

                try
                {

                    if (machineAccount.EndsWith("$"))
                    {
                        samAccountName = machineAccount;
                        machineAccount = machineAccount.Substring(0, machineAccount.Length - 1);
                    }
                    else
                    {
                        samAccountName = String.Concat(machineAccount, "$");
                    }

                    string dnsHostname = String.Concat(machineAccount, ".", domain);
                    string[] servicePrincipalName = { String.Concat("HOST/", dnsHostname), String.Concat("RestrictedKrbHost/", dnsHostname), String.Concat("HOST/", machineAccount), String.Concat("RestrictedKrbHost/", machineAccount) };            
                    distinguishedName = GetMAQDistinguishedName(machineAccount, container, distinguishedNameOld, domain, verbose);
                    LdapDirectoryIdentifier identifier = new LdapDirectoryIdentifier(domainController, 389);
                    LdapConnection connection = new LdapConnection(identifier);

                    if (!String.IsNullOrEmpty(credential.UserName))
                    {
                        connection = new LdapConnection(identifier, credential);
                    }

                    try
                    {
                        connection.SessionOptions.Sealing = true;
                        connection.SessionOptions.Signing = true;
                        connection.Bind();
                        AddRequest request = new AddRequest();
                        request.DistinguishedName = distinguishedName;
                        request.Attributes.Add(new DirectoryAttribute("objectClass", "Computer"));
                        request.Attributes.Add(new DirectoryAttribute("sAMAccountName", samAccountName));
                        request.Attributes.Add(new DirectoryAttribute("userAccountControl", "4096"));
                        request.Attributes.Add(new DirectoryAttribute("dNSHostName", dnsHostname));
                        request.Attributes.Add(new DirectoryAttribute("servicePrincipalName", servicePrincipalName));
                        request.Attributes.Add(new DirectoryAttribute("unicodePwd", unicodePwd));
                        connection.SendRequest(request);
                        Console.WriteLine("[+] Machine account {0} added", machineAccount);
                        connection.Dispose();
                    }
                    catch (Exception ex)
                    {

                        if (ex.Message.Contains("The server cannot handle directory requests."))
                        {
                            Console.WriteLine("[-] Limit reached with {0}", account);
                            switchAccount = true;
                            j--;
                        }
                        else if (ex.Message.Contains("The supplied credential is invalid."))
                        {

                            if (j > success)
                            {
                                Console.WriteLine("[-] Machine account {0} was not added", account);
                                Console.WriteLine("[-] No remaining machine accounts to try");
                                Console.WriteLine("[+] Total machine accounts added = {0}", j - 1);
                                Environment.Exit(1);
                            }

                            switchAccount = true;
                            j--;
                        }
                        else
                        {
                            Console.WriteLine(ex.ToString());
                            success = j;
                        }

                        connection.Dispose();
                    }                    

                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }

                if (i == 0)
                {
                    account = String.Concat(machineAccountPrefix, k, "$");
                }

                if (i == machineAccountQuota || switchAccount)
                {
                    Console.WriteLine("[*] Trying machine account {0}", account);
                    credential = new NetworkCredential(account, machinePassword, domain);
                    i = 0;
                    k++;
                    switchAccount = false;
                }
                else
                {
                    i++;
                }

                j++;
                Thread.Sleep(5);
            }      

        }

    }

}
