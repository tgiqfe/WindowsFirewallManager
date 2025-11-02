using NetFwTypeLib;
using System.Data;
using System.Runtime.InteropServices;
using WindowsFirewallManager.Functions;

namespace WindowsFirewallManager.WindowsFirewall
{
    internal class FirewallRule
    {
        #region Public parameter

        public string DisplayName { get; private set; }
        public string Description { get; private set; }
        public bool Enabled { get; private set; }
        public string DisplayGroup { get { return DllResourceReader.ExtractString(this.Grouping); } }
        public string Grouping { get; private set; }
        public string Direction { get; private set; }
        public string Action { get; private set; }
        public string Protocol { get; private set; }
        public string LocalPorts { get; private set; }
        public string RemotePorts { get; private set; }
        public string LocalAddresses { get; private set; }
        public string RemoteAddresses { get; private set; }
        public string ApplicationName { get; private set; }
        public string Profiles { get; private set; }

        #endregion

        private const string _log_target = "firewall rule";

        /// <summary>
        /// Constructor from firewall rule name.
        /// </summary>
        /// <param name="name"></param>
        public FirewallRule(string name)
        {
            INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            var rule = fwPolicy2.Rules.
                OfType<INetFwRule3>().
                FirstOrDefault(x => name.Equals(x.Name, StringComparison.OrdinalIgnoreCase));
            this.DisplayName = rule.Name;
            this.Description = rule.Description;
            this.Enabled = rule.Enabled;
            this.Grouping = rule.Grouping;
            this.Direction = FirewallComponents.DirectionMap<NET_FW_RULE_DIRECTION_>.ValueToString(rule.Direction);
            this.Action = FirewallComponents.ActionMap<NET_FW_ACTION_>.ValueToString(rule.Action);
            this.Protocol = FirewallComponents.GetProtocolName(rule.Protocol);
            this.LocalPorts = rule.LocalPorts;
            this.RemotePorts = rule.RemotePorts;
            this.LocalAddresses = rule.LocalAddresses;
            this.RemoteAddresses = rule.RemoteAddresses;
            this.ApplicationName = rule.ApplicationName;
            this.Profiles = FirewallComponents.GetProfilesName(rule.Profiles);
            Marshal.ReleaseComObject(fwPolicy2);
            Marshal.ReleaseComObject(rule);
        }

        /// <summary>
        /// Constructor from INetFwRule3 instance.
        /// </summary>
        /// <param name="rule"></param>
        public FirewallRule(INetFwRule3 rule)
        {
            this.DisplayName = rule.Name;
            this.Description = rule.Description;
            this.Enabled = rule.Enabled;
            this.Grouping = rule.Grouping;
            this.Direction = FirewallComponents.DirectionMap<NET_FW_RULE_DIRECTION_>.ValueToString(rule.Direction);
            this.Action = FirewallComponents.ActionMap<NET_FW_ACTION_>.ValueToString(rule.Action);
            this.Protocol = FirewallComponents.GetProtocolName(rule.Protocol);
            this.LocalPorts = rule.LocalPorts;
            this.RemotePorts = rule.RemotePorts;
            this.LocalAddresses = rule.LocalAddresses;
            this.RemoteAddresses = rule.RemoteAddresses;
            this.ApplicationName = rule.ApplicationName;
            this.Profiles = FirewallComponents.GetProfilesName(rule.Profiles);
        }

        /// <summary>
        /// Load all firewall rules.
        /// </summary>
        /// <returns></returns>
        public static FirewallRule[] Load()
        {
            INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            var rules = fwPolicy2.Rules.OfType<INetFwRule3>().Select(x => new FirewallRule(x));
            Marshal.ReleaseComObject(fwPolicy2);
            return rules.ToArray();
        }

        /// <summary>
        /// Create new firewall rule.
        /// </summary>
        /// <param name="displayName"></param>
        /// <param name="description"></param>
        /// <param name="enabled"></param>
        /// <param name="direction"></param>
        /// <param name="action"></param>
        /// <param name="grouping"></param>
        /// <param name="applicationName"></param>
        /// <param name="profiles"></param>
        /// <param name="protocol"></param>
        /// <param name="localPorts"></param>
        /// <param name="remotePorts"></param>
        /// <param name="localAddresses"></param>
        /// <param name="remoteAddresses"></param>
        /// <returns></returns>
        public static bool New(
            string displayName,
            string description,
            bool enabled,
            string direction,
            string action,
            string grouping,
            string applicationName,
            string profiles,
            string protocol,
            string localPorts,
            string remotePorts,
            string localAddresses,
            string remoteAddresses)
        {
            Logger.WriteLine("Info", $"Create new {_log_target}: {displayName}");
            try
            {
                if (string.IsNullOrEmpty(displayName))
                {
                    Logger.WriteLine("Warning", "Skip creating firewall rule because display name is empty.");
                }

                var directionFlag = FirewallComponents.DirectionMap<NET_FW_RULE_DIRECTION_>.StringToValue(direction);
                var actionFlag = FirewallComponents.ActionMap<NET_FW_ACTION_>.StringToValue(action);
                var protocolNum = FirewallComponents.GetProtocolNumberFromName(protocol);
                var profilesType = FirewallComponents.GetProfilesTypeFromName(profiles);

                INetFwRule3 newRule = (INetFwRule3)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                newRule.Name = displayName;
                if (description != null) newRule.Description = description;
                newRule.Enabled = enabled;
                newRule.Direction = directionFlag;
                newRule.Action = actionFlag;
                newRule.Grouping = grouping;
                newRule.ApplicationName = applicationName;
                if (protocolNum != null) newRule.Protocol = protocolNum.Value;
                if (!string.IsNullOrEmpty(localPorts) && protocolNum != 256) newRule.LocalPorts = localPorts;
                if (!string.IsNullOrEmpty(remotePorts) && protocolNum != 256) newRule.RemotePorts = remotePorts;
                newRule.LocalAddresses = string.IsNullOrEmpty(localAddresses) ? "*" : localAddresses;
                newRule.RemoteAddresses = string.IsNullOrEmpty(remoteAddresses) ? "*" : remoteAddresses;
                if (profilesType != null) newRule.Profiles = profilesType.Value;

                INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                fwPolicy2.Rules.Add(newRule);
                Marshal.ReleaseComObject(fwPolicy2);
                Marshal.ReleaseComObject(newRule);

                Logger.WriteLine("Info", $"Success created {_log_target}: {displayName}");
                return true;
            }
            catch (Exception e)
            {
                Logger.WriteLine("Error", $"Failed to create {_log_target}. Exception: {e.ToString()}");
                Logger.WriteRaw(e.Message);
                return false;
            }
        }

        /// <summary>
        /// Get FirewallRule instance.
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public static FirewallRule GetRule(string name)
        {
            Logger.WriteLine("Info", $"Get {_log_target}: {name}");
            return new FirewallRule(name);
        }

        /// <summary>
        /// Firewall rule to enable.
        /// </summary>
        /// <returns></returns>
        public bool ToEnable()
        {
            Logger.WriteLine("Info", $"To enable {_log_target}: {this.DisplayName}");
            try
            {
                using (var helper = new FirewallRuleHelper(this.DisplayName))
                {
                    foreach (var rule in helper.Rules)
                    {
                        rule.Enabled = true;
                    }
                }
                Logger.WriteLine("Info", $"Success enabled {_log_target}: {this.DisplayName}");
                return true;
            }
            catch (Exception e)
            {
                Logger.WriteLine("Error", $"Failed to disable {_log_target}. Exception: {e.ToString()}");
                Logger.WriteRaw(e.Message);
            }
            return false;
        }

        /// <summary>
        /// Firewall rule to disable.
        /// </summary>
        /// <returns></returns>
        public bool ToDisable()
        {
            Logger.WriteLine("Info", $"To disable {_log_target}: {this.DisplayName}");
            try
            {
                using (var helper = new FirewallRuleHelper(this.DisplayName))
                {
                    foreach (var rule in helper.Rules)
                    {
                        rule.Enabled = false;
                    }
                }
                Logger.WriteLine("Info", $"Success disabled {_log_target}: {this.DisplayName}");
                return true;
            }
            catch (Exception e)
            {
                Logger.WriteLine("Error", $"Failed to disable {_log_target}. Exception: {e.ToString()}");
                Logger.WriteRaw(e.Message);
            }
            return false;
        }

        /// <summary>
        /// Remove firewall rule.
        /// </summary>
        /// <returns></returns>
        public bool Remove()
        {
            Logger.WriteLine("Info", $"To remove {_log_target}: {this.DisplayName}");
            try
            {
                using (var helper = new FirewallRuleHelper(this.DisplayName))
                {
                    foreach (var rule in helper.Rules)
                    {
                        helper.FwPolicy2.Rules.Remove(rule.Name);
                    }
                }
                Logger.WriteLine("Info", $"Success removed {_log_target}: {this.DisplayName}");
                return true;
            }
            catch (Exception e)
            {
                Logger.WriteLine("Error", $"Failed to remove {_log_target}. Exception: {e.ToString()}");
                Logger.WriteRaw(e.Message);
            }
            return false;
        }

        /// <summary>
        /// Remove firewall rule. (Alias of Remove)
        /// </summary>
        /// <returns></returns>
        public bool Delete()
        {
            return this.Remove();
        }

        /// <summary>
        /// Rename firewall rule.
        /// </summary>
        /// <param name="newName"></param>
        /// <returns></returns>
        public bool Rename(string newName)
        {
            Logger.WriteLine("Info", $"To rename {_log_target}: {this.DisplayName} to {newName}");
            if (string.IsNullOrEmpty(newName))
            {
                Logger.WriteLine("Warning", $"Skip rename {_log_target} cannot be empty.");
                return false;
            }
            try
            {
                using (var helper = new FirewallRuleHelper(this.DisplayName))
                {
                    foreach (var rule in helper.Rules)
                    {
                        rule.Name = newName;
                    }
                }
                Logger.WriteLine("Info", $"Success renamed {_log_target}.");
                return true;
            }
            catch (Exception e)
            {
                Logger.WriteLine("Error", $"Failed to rename {_log_target}. Exception: {e.ToString()}");
                Logger.WriteRaw(e.Message);
            }
            return false;
        }

        /// <summary>
        /// Set firewall rule parameters.
        /// </summary>
        /// <param name="description"></param>
        /// <param name="direction"></param>
        /// <param name="action"></param>
        /// <param name="grouping"></param>
        /// <param name="applicationName"></param>
        /// <param name="protocol"></param>
        /// <param name="localPorts"></param>
        /// <param name="remotePorts"></param>
        /// <param name="localAddresses"></param>
        /// <param name="remoteAddresses"></param>
        /// <param name="profiles"></param>
        /// <returns></returns>
        public bool SetRule(
            string description,
            string direction,
            string action,
            string grouping,
            string applicationName,
            string protocol,
            string localPorts,
            string remotePorts,
            string localAddresses,
            string remoteAddresses,
            string profiles)
        {
            Logger.WriteLine("Info", $"Set parameter to {_log_target}: {this.DisplayName}");
            try
            {
                using (var helper = new FirewallRuleHelper(this.DisplayName))
                {
                    foreach (var rule in helper.Rules)
                    {
                        //  Set description.
                        if (description != null)
                        {
                            Logger.WriteLine("Info", $"Set description to: {description}");
                            rule.Description = description;
                        }
                        //  Set direction. (Inbound/Outbound)
                        if (direction != null)
                        {
                            var directionFlag = FirewallComponents.DirectionMap<NET_FW_RULE_DIRECTION_>.StringToValue(direction);
                            Logger.WriteLine("Info", $"Set direction to: {direction}");
                            rule.Direction = directionFlag;
                        }
                        //  Set action. (Allow/Deny)
                        if (action != null)
                        {
                            var actionFlag = FirewallComponents.ActionMap<NET_FW_ACTION_>.StringToValue(action);
                            Logger.WriteLine("Info", $"Set action to: {action}");
                            rule.Action = actionFlag;
                        }
                        //  Set grouping.
                        if (grouping != null)
                        {
                            Logger.WriteLine("Info", $"Set grouping to: {grouping}");
                            rule.Grouping = grouping;
                        }
                        //  Set application name.
                        if (applicationName != null)
                        {
                            Logger.WriteLine("Info", $"Set application name to: {applicationName}");
                            rule.ApplicationName = applicationName;
                        }
                        //  Set protocol
                        if (protocol != null)
                        {
                            var protocolNum = FirewallComponents.GetProtocolNumberFromName(protocol);
                            if (protocolNum != null)
                            {
                                Logger.WriteLine("Info", $"Set protocol to: {protocol}");
                                rule.Protocol = protocolNum.Value;
                            }
                        }
                        //  Set local ports
                        if (localPorts != null)
                        {
                            Logger.WriteLine("Info", $"Set local ports to: {localPorts}");
                            rule.LocalPorts = localPorts;
                        }
                        //  Set remote ports
                        if (remotePorts != null)
                        {
                            Logger.WriteLine("Info", $"Set remote ports to: {remotePorts}");
                            rule.RemotePorts = remotePorts;
                        }
                        //  Set local addresses
                        if (localAddresses != null)
                        {
                            Logger.WriteLine("Info", $"Set local addresses to: {localAddresses}");
                            rule.LocalAddresses = localAddresses;
                        }
                        //  Set remote addresses
                        if (remoteAddresses != null)
                        {
                            Logger.WriteLine("Info", $"Set remote addresses to: {remoteAddresses}");
                            rule.RemoteAddresses = remoteAddresses;
                        }
                        //  Set profiles    
                        if (profiles != null)
                        {
                            var profilesType = FirewallComponents.GetProfilesTypeFromName(profiles);
                            if (profilesType != null)
                            {
                                Logger.WriteLine("Info", $"Set profiles to: {profiles}");
                                rule.Profiles = profilesType.Value;
                            }
                        }
                    }
                }
                Logger.WriteLine("Info", $"Success set {_log_target}: {this.DisplayName}");
                return true;
            }
            catch (Exception e)
            {
                Logger.WriteLine("Error", $"Failed to set {_log_target}. Exception: {e.ToString()}");
                Logger.WriteRaw(e.Message);
            }
            return false;
        }
    }
}

