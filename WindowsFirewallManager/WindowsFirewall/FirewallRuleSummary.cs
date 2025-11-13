using NetFwTypeLib;
using System.Runtime.InteropServices;

namespace WindowsFirewallManager.WindowsFirewall
{
    internal class FirewallRuleSummary
    {
        public string DisplayName { get; set; }
        public string Direction { get; set; }
        public bool Enabled { get; set; }
        public string ActionType { get; set; }

        public FirewallRuleSummary(string name)
        {
            INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            var rule = fwPolicy2.Rules.
                OfType<INetFwRule3>().
                FirstOrDefault(x => name.Equals(x.Name, StringComparison.OrdinalIgnoreCase));
            if (rule != null)
            {
                this.DisplayName = rule.Name;
                this.Enabled = rule.Enabled;
                this.Direction = FirewallComponents.DirectionMap<NET_FW_RULE_DIRECTION_>.ValueToString(rule.Direction);
                this.ActionType = FirewallComponents.ActionMap<NET_FW_ACTION_>.ValueToString(rule.Action);
                Marshal.ReleaseComObject(rule);
            }
            Marshal.ReleaseComObject(fwPolicy2);
        }

        public FirewallRuleSummary(INetFwRule3 rule)
        {
            this.DisplayName = rule.Name;
            this.Enabled = rule.Enabled;
            this.Direction = FirewallComponents.DirectionMap<NET_FW_RULE_DIRECTION_>.ValueToString(rule.Direction);
            this.ActionType = FirewallComponents.ActionMap<NET_FW_ACTION_>.ValueToString(rule.Action);
        }

        public static FirewallRuleSummary[] Load()
        {
            INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            var rules = fwPolicy2.Rules.OfType<INetFwRule3>().Select(x => new FirewallRuleSummary(x));
            Marshal.ReleaseComObject(fwPolicy2);
            return rules.ToArray();
        }
    }
}
