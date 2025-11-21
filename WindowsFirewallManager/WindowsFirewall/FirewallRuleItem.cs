using NetFwTypeLib;
using System.Data;
using System.Runtime.InteropServices;
using WindowsFirewallManager.Functions;

namespace WindowsFirewallManager.WindowsFirewall
{
    internal class FirewallRuleItem
    {
        #region Public parameter

        public string DisplayName { get; set; }
        public string Description { get; set; }
        public bool Enabled { get; set; }
        public string DisplayGroup { get { return DllResourceReader.ExtractString(this.Grouping); } }
        public string Grouping { get; set; }
        public string Direction { get; set; }
        public string ActionType { get; set; }
        public string Protocol { get; set; }
        public string LocalPorts { get; set; }
        public string RemotePorts { get; set; }
        public string LocalAddresses { get; set; }
        public string RemoteAddresses { get; set; }
        public string ApplicationName { get; set; }
        public string Profiles { get; set; }

        #endregion

        const string _title = "WindowsFirewall";
        const string _log_target = "firewall rule";

        /// <summary>
        /// Constructor from firewall rule name.
        /// </summary>
        /// <param name="name"></param>
        public FirewallRuleItem(string name)
        {
            INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            var rule = fwPolicy2.Rules.
                OfType<INetFwRule3>().
                FirstOrDefault(x => name.Equals(x.Name, StringComparison.OrdinalIgnoreCase));
            if (rule != null)
            {
                this.DisplayName = rule.Name;
                this.Description = rule.Description;
                this.Enabled = rule.Enabled;
                this.Grouping = rule.Grouping;
                this.Direction = FirewallParser.DirectionToString(rule.Direction);
                this.ActionType = FirewallParser.ActionToString(rule.Action);
                this.Protocol = FirewallParser.ProtocolToString(rule.Protocol);
                this.LocalPorts = rule.LocalPorts;
                this.RemotePorts = rule.RemotePorts;
                this.LocalAddresses = rule.LocalAddresses;
                this.RemoteAddresses = rule.RemoteAddresses;
                this.ApplicationName = rule.ApplicationName;
                this.Profiles = FirewallParser.ProfileToString(rule.Profiles);
                Marshal.ReleaseComObject(rule);
            }
            Marshal.ReleaseComObject(fwPolicy2);
        }

        /// <summary>
        /// Constructor from INetFwRule3 instance.
        /// </summary>
        /// <param name="rule"></param>
        public FirewallRuleItem(INetFwRule3 rule)
        {
            this.DisplayName = rule.Name;
            this.Description = rule.Description;
            this.Enabled = rule.Enabled;
            this.Grouping = rule.Grouping;
            this.Direction = FirewallParser.DirectionToString(rule.Direction);
            this.ActionType = FirewallParser.ActionToString(rule.Action);
            this.Protocol = FirewallParser.ProtocolToString(rule.Protocol);
            this.LocalPorts = rule.LocalPorts;
            this.RemotePorts = rule.RemotePorts;
            this.LocalAddresses = rule.LocalAddresses;
            this.RemoteAddresses = rule.RemoteAddresses;
            this.ApplicationName = rule.ApplicationName;
            this.Profiles = FirewallParser.ProfileToString(rule.Profiles);
        }

        /// <summary>
        /// Load all firewall rules.
        /// </summary>
        /// <returns></returns>
        public static FirewallRuleItem[] Load()
        {
            INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            var rules = fwPolicy2.Rules.OfType<INetFwRule3>().Select(x => new FirewallRuleItem(x));
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
        /// <param name="actionType"></param>
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
            string actionType,
            string grouping,
            string applicationName,
            string profiles,
            string protocol,
            string localPorts,
            string remotePorts,
            string localAddresses,
            string remoteAddresses)
        {
            Logger.WriteLine(LogLevel.Info, _title, $"Create new {_log_target}: {displayName}");
            try
            {
                if (string.IsNullOrEmpty(displayName))
                {
                    Logger.WriteLine(LogLevel.Warning, _title, "Skip creating firewall rule because display name is empty.");
                }

                var directionFlag = FirewallParser.StringToDirection(direction);
                var actionFlag = FirewallParser.StringToAction(actionType);
                var protocolNum = FirewallParser.StringToProtocol(protocol);
                var profilesType = FirewallParser.StringToProfile(profiles);

                INetFwRule3 newRule = (INetFwRule3)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                newRule.Name = displayName;
                if (description != null) newRule.Description = description;
                newRule.Enabled = enabled;
                newRule.Direction = directionFlag;
                newRule.Action = actionFlag;
                newRule.Grouping = grouping;
                newRule.ApplicationName = applicationName;
                newRule.Protocol = protocolNum;
                if (!string.IsNullOrEmpty(localPorts) && protocolNum != 256) newRule.LocalPorts = localPorts;
                if (!string.IsNullOrEmpty(remotePorts) && protocolNum != 256) newRule.RemotePorts = remotePorts;
                newRule.LocalAddresses = string.IsNullOrEmpty(localAddresses) ? "*" : localAddresses;
                newRule.RemoteAddresses = string.IsNullOrEmpty(remoteAddresses) ? "*" : remoteAddresses;
                newRule.Profiles = profilesType;

                INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                fwPolicy2.Rules.Add(newRule);
                Marshal.ReleaseComObject(fwPolicy2);
                Marshal.ReleaseComObject(newRule);

                Logger.WriteLine(LogLevel.Info, _title, $"Success created {_log_target}: {displayName}");
                return true;
            }
            catch (Exception e)
            {
                Logger.WriteLine(LogLevel.Error, _title, $"Failed to create {_log_target}.");
                Logger.WriteRaw(_title, e.ToString());
                return false;
            }
        }

        /// <summary>
        /// Get FirewallRule instance.
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public static FirewallRuleItem GetRule(string name)
        {
            Logger.WriteLine(LogLevel.Info, _title, $"Get {_log_target}: {name}");
            return new FirewallRuleItem(name);
        }

        /// <summary>
        /// Firewall rule to enable.
        /// </summary>
        /// <returns></returns>
        public bool ToEnable()
        {
            Logger.WriteLine(LogLevel.Info, _title, $"To enable {_log_target}: {this.DisplayName}");
            try
            {
                using (var helper = new FirewallRuleHelper(this.DisplayName))
                {
                    foreach (var rule in helper.Rules)
                    {
                        rule.Enabled = true;
                    }
                }
                Logger.WriteLine(LogLevel.Info, _title,  $"Success enabled {_log_target}: {this.DisplayName}");
                return true;
            }
            catch (Exception e)
            {
                Logger.WriteLine(LogLevel.Error, _title, $"Failed to disable {_log_target}.");
                Logger.WriteRaw(_title, e.ToString());
            }
            return false;
        }

        /// <summary>
        /// Firewall rule to disable.
        /// </summary>
        /// <returns></returns>
        public bool ToDisable()
        {
            Logger.WriteLine(LogLevel.Info, _title, $"To disable {_log_target}: {this.DisplayName}");
            try
            {
                using (var helper = new FirewallRuleHelper(this.DisplayName))
                {
                    foreach (var rule in helper.Rules)
                    {
                        rule.Enabled = false;
                    }
                }
                Logger.WriteLine(LogLevel.Info, _title, $"Success disabled {_log_target}: {this.DisplayName}");
                return true;
            }
            catch (Exception e)
            {
                Logger.WriteLine(LogLevel.Error, _title, $"Failed to disable {_log_target}.");
                Logger.WriteRaw(_title, e.ToString());
            }
            return false;
        }

        /// <summary>
        /// Remove firewall rule.
        /// </summary>
        /// <returns></returns>
        public bool Remove()
        {
            Logger.WriteLine(LogLevel.Info, _title, $"To remove {_log_target}: {this.DisplayName}");
            try
            {
                using (var helper = new FirewallRuleHelper(this.DisplayName))
                {
                    foreach (var rule in helper.Rules)
                    {
                        helper.FwPolicy2.Rules.Remove(rule.Name);
                    }
                }
                Logger.WriteLine(LogLevel.Info, _title,  $"Success removed {_log_target}: {this.DisplayName}");
                return true;
            }
            catch (Exception e)
            {
                Logger.WriteLine(LogLevel.Error, _title, $"Failed to remove {_log_target}.");
                Logger.WriteRaw(_title, e.ToString());
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
            Logger.WriteLine(LogLevel.Info, _title,  $"To rename {_log_target}: {this.DisplayName} to {newName}");
            if (string.IsNullOrEmpty(newName))
            {
                Logger.WriteLine(LogLevel.Warning, _title, $"Skip rename {_log_target} cannot be empty.");
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
                Logger.WriteLine(LogLevel.Info, _title,  $"Success renamed {_log_target}.");
                return true;
            }
            catch (Exception e)
            {
                Logger.WriteLine(LogLevel.Error, _title, $"Failed to rename {_log_target}.");
                Logger.WriteRaw(_title, e.ToString());
            }
            return false;
        }

        /// <summary>
        /// Set firewall rule parameters.
        /// </summary>
        /// <param name="description"></param>
        /// <param name="direction"></param>
        /// <param name="actionType"></param>
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
            string actionType,
            string grouping,
            string applicationName,
            string protocol,
            string localPorts,
            string remotePorts,
            string localAddresses,
            string remoteAddresses,
            string profiles)
        {
            Logger.WriteLine(LogLevel.Info, _title,  $"Set parameter to {_log_target}: {this.DisplayName}");
            try
            {
                using (var helper = new FirewallRuleHelper(this.DisplayName))
                {
                    foreach (var rule in helper.Rules)
                    {
                        //  Set description.
                        if (description != null)
                        {
                            Logger.WriteLine(LogLevel.Info, _title,  $"Set description to: {description}");
                            rule.Description = description;
                        }
                        //  Set direction. (Inbound/Outbound)
                        if (direction != null)
                        {
                            var directionFlag = FirewallParser.StringToDirection(direction);
                            Logger.WriteLine(LogLevel.Info, _title,  $"Set direction to: {direction}");
                            rule.Direction = directionFlag;
                        }
                        //  Set action type. (Allow/Deny)
                        if (actionType != null)
                        {
                            var actionFlag = FirewallParser.StringToAction(actionType);
                            Logger.WriteLine(LogLevel.Info, _title,  $"Set action type to: {actionType}");
                            rule.Action = actionFlag;
                        }
                        //  Set grouping.
                        if (grouping != null)
                        {
                            Logger.WriteLine(LogLevel.Info, _title,  $"Set grouping to: {grouping}");
                            rule.Grouping = grouping;
                        }
                        //  Set application name.
                        if (applicationName != null)
                        {
                            Logger.WriteLine(LogLevel.Info, _title,  $"Set application name to: {applicationName}");
                            rule.ApplicationName = applicationName;
                        }
                        //  Set protocol
                        if (protocol != null)
                        {
                            var protocolNum = FirewallParser.StringToProtocol(protocol);
                            Logger.WriteLine(LogLevel.Info, _title,  $"Set protocol to: {protocol}");
                            rule.Protocol = protocolNum;
                        }
                        //  Set local ports
                        if (localPorts != null)
                        {
                            Logger.WriteLine(LogLevel.Info, _title,  $"Set local ports to: {localPorts}");
                            rule.LocalPorts = localPorts;
                        }
                        //  Set remote ports
                        if (remotePorts != null)
                        {
                            Logger.WriteLine(LogLevel.Info, _title,  $"Set remote ports to: {remotePorts}");
                            rule.RemotePorts = remotePorts;
                        }
                        //  Set local addresses
                        if (localAddresses != null)
                        {
                            Logger.WriteLine(LogLevel.Info, _title,  $"Set local addresses to: {localAddresses}");
                            rule.LocalAddresses = localAddresses;
                        }
                        //  Set remote addresses
                        if (remoteAddresses != null)
                        {
                            Logger.WriteLine(LogLevel.Info, _title,  $"Set remote addresses to: {remoteAddresses}");
                            rule.RemoteAddresses = remoteAddresses;
                        }
                        //  Set profiles    
                        if (profiles != null)
                        {
                            var profilesType = FirewallParser.StringToProfile(profiles);
                            Logger.WriteLine(LogLevel.Info, _title,  $"Set profiles to: {profiles}");
                            rule.Profiles = profilesType;
                        }
                    }
                }
                Logger.WriteLine(LogLevel.Info, _title,  $"Success set {_log_target}: {this.DisplayName}");
                return true;
            }
            catch (Exception e)
            {
                Logger.WriteLine(LogLevel.Error, _title, $"Failed to set {_log_target}.");
                Logger.WriteRaw(_title, e.ToString());
            }
            return false;
        }
    }
}

