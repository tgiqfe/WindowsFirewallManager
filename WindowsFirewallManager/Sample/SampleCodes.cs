using NetFwTypeLib;
using System.Text.Json;
using WindowsFirewallManager.WindowsFirewall;

namespace WindowsFirewallManager.Sample
{
    internal class SampleCodes
    {
        public static void Test_ProfileSettings()
        {
            var setting = FirewallSetting.Load();
            setting[0].ToEnable();
            setting[0].SetParameter(false, true, "Deny", "Allow");
            setting[1].ToEnable();
            setting[1].SetParameter(false, true, "Deny", "Allow");
            setting[2].ToEnable();
            setting[2].SetParameter(false, true, "Deny", "Allow");
        }

        public static void Test_FirewallRule_list()
        {
            INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            fwPolicy2.Rules.OfType<INetFwRule3>().
                Where(x => x.Name == "Test Rule from C#").
                ToList().
                ForEach(x =>
                {
                    string json = JsonSerializer.Serialize(x, new JsonSerializerOptions()
                    {
                        WriteIndented = true,
                        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
                    });
                    Console.WriteLine(json);
                });
        }

        public static void Test_FirewallRule_setparameter()
        {
            var rule = new FirewallRuleItem("Test Rule from C#");
            var setRule = rule.SetRule(
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                "all");
            Console.WriteLine("Firewall Rule update result: " + setRule);
        }

        public static void Test_Firewall_rename()
        {
            var rule = new FirewallRuleItem("Test Rule from C#");
            rule.Rename("Renamed Test Rule from C#");
            var statusRet = rule.ToDisable();
        }

        public static void Test_FirewallRule_Create()
        {
            var ret = FirewallRuleItem.New(
                displayName: "Test Rule from C#",
                description: "This is a test rule created from C# code.",
                enabled: true,
                direction: "Inbound",
                actionType: "Allow",
                grouping: "@FirewallAPI.dll,-32752",
                applicationName: @"C:\Windows\System32\notepad.exe",
                profiles: "Private, Public",
                protocol: "TCP",
                localPorts: "8080",
                remotePorts: "",
                localAddresses: "*",
                remoteAddresses: "*"
                );
            Console.WriteLine("New Firewall Rule creation result: " + ret);
        }
    }
}
