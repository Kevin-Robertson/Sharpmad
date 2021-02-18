using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.DirectoryServices.ActiveDirectory;

namespace Sharpmad
{
    class Program
    {
        static void Main(string[] args)
        {
            string argAccess = "GenericAll";
            string argAccessType = "Allow";
            string argAction = "";
            string argAttribute = "";
            string argContainer = "COMPUTERS";
            string argData = "";
            string argDistinguishedName = "";
            string argDomain = "";
            string argDomainController = "";
            string argForest = "";
            string argMachineAccount = "";
            string argMachinePassword = "";
            string argNode = "";
            string argNodeNew = "";
            string argPartition = "DomainDNSZones";
            string argPrincipal = "";
            string argType = "A";
            string argValue = "";
            string argZone = "";
            string argPreference = "0";
            string argPriority = "0";
            string argWeight = "0";
            string argPort = "0";
            string argTTL = "600";
            string argUsername = "";
            string argPassword = "";
            string argSOASerialNumber = "-1";
            int preference = 0;
            int priority = 0;
            int weight = 0;
            int port = 0;
            int ttl;
            int soaSerialNumber = -1;
            bool argADIDNS = false;
            bool argAppend = false;
            bool argClear = false;
            bool argMAQ = false;
            bool argRandom = false;
            bool argStatic = false;
            bool argTombstone = false;
            bool argVerbose = false;

            if (args.Length > 0)
            {

                switch (args[0].ToUpper())
                {

                    case "ADIDNS":
                        argADIDNS = true;
                        break;

                    case "MAQ":
                        argMAQ = true;
                        break;

                }

                foreach (var entry in args.Select((value, index) => new { index, value }))
                {
                    string argument = entry.value.ToUpper();

                    switch (argument)
                    {      

                        case "-ACCESS":
                        case "/ACCESS":
                            argAccess = args[entry.index + 1];
                            break;

                        case "-ACCESSTYPE":
                        case "/ACCESSTYPE":
                            argAccessType = args[entry.index + 1];
                            break;

                        case "-ACTION":
                        case "/ACTION":
                            argAction = args[entry.index + 1].ToUpper();
                            break;

                        case "-APPEND":
                        case "/APPEND":
                            argAppend = true;
                            break;

                        case "-ATTRIBUTE":
                        case "/ATTRIBUTE":
                            argAttribute = args[entry.index + 1];
                            break;

                        case "-CONTAINER":
                        case "/CONTAINER":
                            argContainer = args[entry.index + 1].ToUpper();
                            break;

                        case "-CLEAR":
                        case "/CLEAR":
                            argClear = true;
                            break;

                        case "-DATA":
                        case "/DATA":
                            argData = args[entry.index + 1];
                            break;

                        case "-DISTINGUISHEDNAME":
                        case "/DISTINGUISHEDNAME":
                            argDistinguishedName = args[entry.index + 1];
                            break;

                        case "-DOMAIN":
                        case "/DOMAIN":
                            argDomain = args[entry.index + 1];
                            break;

                        case "-DOMAINCONTROLLER":
                        case "/DOMAINCONTROLLER":
                            argDomainController = args[entry.index + 1];
                            break;

                        case "-FOREST":
                        case "/FOREST":
                            argForest = args[entry.index + 1];
                            break;

                        case "-MACHINEACCOUNT":
                        case "/MACHINEACCOUNT":
                            argMachineAccount = args[entry.index + 1];
                            break;

                        case "-MACHINEPASSWORD":
                        case "/MACHINEPASSWORD":
                            argMachinePassword = args[entry.index + 1];
                            break;

                        case "-NODE":
                        case "/NODE":
                            argNode = args[entry.index + 1];
                            break;

                        case "-NODENEW":
                        case "/NODENEW":
                            argNodeNew = args[entry.index + 1];
                            break;

                        case "-PARTITION":
                        case "/PARTITION":
                            argPartition = args[entry.index + 1];
                            break;

                        case "-PRINCIPAL":
                        case "/PRINCIPAL":
                            argPrincipal = args[entry.index + 1];
                            break;

                        case "-RANDOM":
                        case "/RANDOM":
                            argRandom = true;
                            break;

                        case "-TYPE":
                        case "/TYPE":
                            argType = args[entry.index + 1].ToUpper();
                            break;

                        case "-ZONE":
                        case "/ZONE":
                            argZone = args[entry.index + 1];
                            break;

                        case "-PREFERENCE":
                        case "/PREFERENCE":
                            argPreference = args[entry.index + 1];
                            break;

                        case "-PRIORITY":
                        case "/PRIORITY":
                            argPriority = args[entry.index + 1];
                            break;

                        case "-WEIGHT":
                        case "/WEIGHT":
                            argWeight = args[entry.index + 1];
                            break;

                        case "-PORT":
                        case "/PORT":
                            argPort = args[entry.index + 1];
                            break;

                        case "-TTL":
                        case "/TTL":
                            argTTL = args[entry.index + 1];
                            break;

                        case "-SOASERIALNUMBER":
                        case "/SOASERIALNUMBER":
                            argSOASerialNumber = args[entry.index + 1];
                            break;

                        case "-STATIC":
                        case "/STATIC":
                            argStatic = true;
                            break;

                        case "-TOMBSTONE":
                        case "/TOMBSTONE":
                            argTombstone = true;
                            break;

                        case "-VERBOSE":
                        case "/VERBOSE":
                            argVerbose = true;
                            break;

                        case "-USERNAME":
                        case "/USERNAME":
                            argUsername = args[entry.index + 1];
                            break;

                        case "-PASSWORD":
                        case "/PASSWORD":
                            argPassword = args[entry.index + 1];
                            break;

                        case "-?":
                        case "/?":
                            string help = "";

                            try
                            {
                                help = args[entry.index + 1].ToUpper();

                                if (help.Equals("ADIDNS"))
                                {
                                    Util.GetHelp("ADIDNS");
                                }
                                else if (help.Equals("MAQ"))
                                {
                                    Util.GetHelp("MAQ");
                                }
                                else
                                {
                                    Util.GetHelp("HELP");
                                }

                            }
                            catch
                            {
                                Util.GetHelp("HELP");
                            }

                            break;

                        default:
                            if (argument.StartsWith("-") || argument.StartsWith("/"))
                                throw new ArgumentException(paramName: argument, message: "Invalid Parameter");
                            break;

                    }

                }

            }
            
            string[] accessTypes = { "CreateChild", "Delete", "DeleteChild", "DeleteTree", "ExtendedRight", "GenericAll", "GenericExecute", "GenericRead", "GenericWrite", "ListChildren", "ListObject", "ReadControl", "ReadProperty", "Self", "Synchronize", "WriteDacl", "WriteOwner", "WriteProperty" };
            string[] recordTypes = { "A", "AAAA", "CNAME", "DNAME", "MX", "NS", "PTR", "SRV", "TXT" };
            string[] containers = { "BUILTIN", "COMPUTERS", "DOMAINCONTROLLERS", "FOREIGNSECURITYPRINCIPALS", "KEYS", "LOSTANDFOUND", "MANAGEDSERVICEACCOUNTS", "PROGRAMDATA", "USERS", "ROOT" };

            if (argADIDNS && (String.Equals(argAction, "ADDACE") || String.Equals(argAction, "REMOVEACE")) && !accessTypes.Any(argAccess.Contains)) throw new ArgumentException("Access value must be CreateChild, Delete, DeleteChild, DeleteTree, ExtendedRight, GenericAll, GenericExecute, GenericRead, GenericWrite, ListChildren, ListObject, ReadControl, ReadProperty, Self, Synchronize, WriteDacl, WriteOwner, or WriteProperty");
            if (argMAQ && !containers.Any(argContainer.Contains)) throw new ArgumentException("Container value must be BUILTIN, COMPUTERS, DOMAINCONTROLLERS, FOREIGNSECURITYPRINCIPALS, KEYS, LOSTANDFOUND, MANAGEDSERVICEACCOUNTS, PROGRAMDATA, or USERS");
            try { preference = Int32.Parse(argPreference); } catch { throw new ArgumentException("Preference value must be an integer"); }
            try { priority = Int32.Parse(argPriority); } catch { throw new ArgumentException("Priority value must be an integer"); }
            try { weight = Int32.Parse(argWeight); } catch { throw new ArgumentException("Weight value must be an integer"); }
            try { port = Int32.Parse(argPort); } catch { throw new ArgumentException("Port value must be an integer"); }
            try { ttl = Int32.Parse(argTTL); } catch { throw new ArgumentException("TTL value must be an integer"); }
            try { soaSerialNumber = Int32.Parse(argSOASerialNumber); } catch { throw new ArgumentException("SOASerialNumber value must be an integer"); }
            if((argADIDNS && (!String.Equals(argAction, "ADDACE") && !String.Equals(argAction, "GETDACL") && !String.Equals(argAction, "GETZONE"))) && String.IsNullOrEmpty(argNode)) throw new ArgumentException("-Node needed");
            if ((argADIDNS && String.Equals(argAction, "ADDACE")) && String.IsNullOrEmpty(argPrincipal)) throw new ArgumentException("-Principal needed");
            if ((argADIDNS && String.Equals(argAction, "RENAME")) && String.IsNullOrEmpty(argNodeNew)) throw new ArgumentException("-NodeNew needed");
            if ((argMAQ && !String.Equals(argAction, "GETCREATOR")) && String.IsNullOrEmpty(argMachineAccount)) throw new ArgumentException("-MachineAccount needed");
            if (String.Equals(argAction, "GETATTRIBUTE") || String.Equals(argAction, "SETATTRIBUTE") && String.IsNullOrEmpty(argAttribute)) throw new ArgumentException("-Attribute needed");
            string credentialDomain = "";
            string credentialUsername = "";

            if (argUsername.Contains("\\"))
            {
                string[]credentialArray = argUsername.Split('\\');
                credentialDomain = credentialArray[0];
                credentialUsername = credentialArray[1];
            }
            else
            {
                credentialUsername = argUsername;
            }

            if (!String.IsNullOrEmpty(argUsername) && String.IsNullOrEmpty(argPassword))
            {
                Console.WriteLine("Enter LDAP password:");
                argPassword = Util.PasswordPrompt();
                Console.WriteLine("");
            }

            if (argMAQ && !argRandom && argAction.Equals("NEW") && String.IsNullOrEmpty(argMachinePassword))
            {
                Console.WriteLine("Enter machine account password:");
                argMachinePassword = Util.PasswordPrompt();
                Console.WriteLine("");
            }

            
            NetworkCredential credential = new NetworkCredential(credentialUsername, argPassword, credentialDomain);
            Domain currentDomain = null;

            if (String.IsNullOrEmpty(argDomainController))
            {

                try
                {
                    currentDomain = Domain.GetCurrentDomain();

                    if (string.IsNullOrEmpty(argDomainController))
                    {
                        argDomainController = currentDomain.PdcRoleOwner.Name;                   
                    }

                    if (string.IsNullOrEmpty(argDomain))
                    {
                        argDomain = currentDomain.Name.ToLower();              
                    }

                    if (string.IsNullOrEmpty(argForest))
                    {
                        argForest = currentDomain.Name.ToLower();    
                    }

                    if (string.IsNullOrEmpty(argZone))
                    {
                        argZone = currentDomain.Name.ToLower();                       
                    }

                }
                catch
                {
                    Console.WriteLine("[!] System is not domain attached, define arguments manually");
                    Environment.Exit(1);
                }

            }

            if (string.IsNullOrEmpty(argDomain))
            {
                argDomain = Util.DomainExtract(argDomainController, "Domain");
            }

            if (string.IsNullOrEmpty(argForest))
            {
                argForest = Util.DomainExtract(argDomainController, "Forest");
            }

            if (string.IsNullOrEmpty(argZone))
            {
                argZone = Util.DomainExtract(argDomainController, "Zone");
            }

            if (argVerbose) { Console.WriteLine(String.Concat("[+] Domain Controller = ", argDomainController)); };
            if (argVerbose) { Console.WriteLine(String.Concat("[+] Domain = ", argDomain)); };

            try
            {

                if (argADIDNS)
                {
                    if (argVerbose) { Console.WriteLine(String.Concat("[+] Forest = ", argForest)); };
                    if (argVerbose) { Console.WriteLine(String.Concat("[+] ADIDNS Zone = ", argZone)); };

                    switch (argAction)
                    {

                        case "DISABLE":
                            ADIDNS.DisableADIDNSNode(argDistinguishedName, argDomain, argDomainController, argNode, argPartition, argZone, soaSerialNumber, credential, argVerbose);
                            break;

                        case "GETATTRIBUTE":
                            ADIDNS.GetADIDNSNodeAttribute(argDistinguishedName, argDomain, argDomainController, argAttribute, argNode, argPartition, argZone, credential, argVerbose);
                            break;

                        case "GETOWNER":
                            ADIDNS.GetADIDNSNodeOwner(argDistinguishedName, argDomain, argDomainController, argNode, argPartition, argZone, argVerbose, credential);
                            break;

                        case "GETDACL":
                            ADIDNS.GetADIDNSDACL(argDistinguishedName, argDomain, argDomainController, argNode, argPartition, argZone, argVerbose, credential);
                            break;

                        case "GETTOMBSTONED":
                            ADIDNS.GetADIDNSNodeTombstoned(argDistinguishedName, argDomain, argDomainController, argNode, argPartition, argZone, argVerbose, credential);
                            break;

                        case "GETZONE":
                            ADIDNS.GetADIDNSZone(argDistinguishedName, argDomain, argDomainController, argPartition, argZone, argVerbose, credential);
                            break;

                        case "ADDACE":
                            ADIDNS.AddADIDNSACE(argDistinguishedName, argDomain, argDomainController, argNode, argPartition, argPrincipal, argAccessType, argZone, argAccess, argVerbose, credential);
                            break;

                        case "NEW":
                            ADIDNS.NewADIDNSNode(argData, argDistinguishedName, argDomain, argDomainController, argForest, argNode, argPartition, argType, argZone, preference, priority, weight, port, ttl, soaSerialNumber, argStatic, argTombstone, argVerbose, credential);
                            break;

                        case "RENAME":
                            ADIDNS.RenameADIDNSNode(argDistinguishedName, argDomain, argDomainController, argNode, argNodeNew, argPartition, argZone, argVerbose, credential);
                            break;

                        case "REMOVEACE":
                            ADIDNS.RemoveADIDNSACE(argDistinguishedName, argDomain, argDomainController, argNode, argPartition, argPrincipal, argAccessType, argZone, argAccess, argVerbose, credential);
                            break;

                        case "SETATTRIBUTE":
                            ADIDNS.SetADIDNSNodeAttribute(argDistinguishedName, argDomain, argDomainController, argAttribute, argNode, argPartition, argValue, argZone, argAppend, argClear, argVerbose, credential);
                            break;

                        case "SETOWNER":
                            ADIDNS.SetADIDNSNodeOwner(argDistinguishedName, argDomain, argDomainController, argNode, argPartition, argPrincipal, argZone, argVerbose, credential);
                            break;

                    }

                }
                else if (argMAQ)
                {

                    switch (argAction)
                    {

                        case "AGENTSMITH":
                            MAQ.AgentSmith(argContainer, argDistinguishedName, argDomain, argDomainController, argMachineAccount, argMachinePassword, argVerbose, credential);
                            break;

                        case "DISABLE":
                            MAQ.DisableMachineAccount(argContainer, argDistinguishedName, argDomain, argDomainController, argMachineAccount, argVerbose, credential);
                            break;

                        case "GETATTRIBUTE":
                            MAQ.GetMachineAccountAttribute(argContainer, argDistinguishedName, argDomain, argDomainController, argAttribute, argMachineAccount, argVerbose, credential);
                            break;

                        case "GETCREATOR":
                            MAQ.GetMachineAccountCreator(argContainer, argDistinguishedName, argDomain, argDomainController, argVerbose, credential);
                            break;

                        case "NEW":
                            MAQ.NewMachineAccount(argContainer, argDistinguishedName, argDomain, argDomainController, argMachineAccount, argMachinePassword, argVerbose, argRandom, credential);
                            break;

                        case "REMOVE":
                            MAQ.RemoveMachineAccount(argContainer, argDistinguishedName, argDomain, argDomainController, argMachineAccount, argVerbose, credential);
                            break;

                        case "SETATTRIBUTE":
                            MAQ.SetMachineAccountAttribute(argContainer, argDistinguishedName, argDomain, argDomainController, argAttribute, argMachineAccount, argValue, argAppend, argClear, argVerbose, credential);
                            break;

                    }

                }

            }
            catch
            {
                Environment.Exit(1);
            }

        }

    }

}
