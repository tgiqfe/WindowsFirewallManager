using NetFwTypeLib;

namespace WindowsFirewallManager.WindowsFirewall
{
    internal class FirewallSetting
    {
        #region Public parameters

        public string Profile { get; set; }
        public bool Enabled { get; set; }
        public bool BlockAllInbound { get; set; }
        public bool NotifyOnListen { get; set; }
        public string DefaultInboundAction { get; set; }
        public string DefaultOutboundAction { get; set; }

        #endregion

        private NET_FW_PROFILE_TYPE2_ _profileType;
        const string _title = "WindowsFirewall";
        const string _log_target = "firewall setting";

        public FirewallSetting(INetFwPolicy2 policy, NET_FW_PROFILE_TYPE2_ profile)
        {
            _profileType = profile;
            this.Profile = profile switch
            {
                NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN => "Domain",
                NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE => "Private",
                NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC => "Public",
                _ => "Unknown",
            };
            this.Enabled = policy.FirewallEnabled[profile];
            this.BlockAllInbound = policy.BlockAllInboundTraffic[profile];
            this.NotifyOnListen = !policy.NotificationsDisabled[profile];
            this.DefaultInboundAction = FirewallParser.ActionToString(policy.DefaultInboundAction[profile]);
            this.DefaultOutboundAction = FirewallParser.ActionToString(policy.DefaultOutboundAction[profile]);
        }

        /// <summary>
        /// Load Firewall settings for Domain, Private, and Public profiles
        /// </summary>
        /// <returns></returns>
        public static FirewallSetting[] Load()
        {
            using (var fwHelper = new FirewallSettingHelper())
            {
                var fwPolicy2 = fwHelper.FwPolicy2;
                var domainProfile = new FirewallSetting(fwPolicy2, NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN);
                var privateProfile = new FirewallSetting(fwPolicy2, NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE);
                var publicProfile = new FirewallSetting(fwPolicy2, NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC);
                return new FirewallSetting[] { domainProfile, privateProfile, publicProfile };
            }
        }

        public bool ToEnable()
        {
            Logger.WriteLine(LogLevel.Info, _title, $"Enable {_log_target} for {this.Profile} profile.");
            try
            {
                using (var fwHelper = new FirewallSettingHelper())
                {
                    fwHelper.FwPolicy2.FirewallEnabled[_profileType] = true;
                    Logger.WriteLine(LogLevel.Info, _title, $"Success {_log_target} profile is enabled.");
                    return true;
                }
            }
            catch (Exception e)
            {
                Logger.WriteLine(LogLevel.Error, _title, $"Failed to enabled {_log_target}. Exception: {e.Message}");
                Logger.WriteRaw(_title, e.Message);
            }
            return false;
        }

        public bool ToDisable()
        {
            Logger.WriteLine(LogLevel.Info, _title, $"Disable {_log_target} for {this.Profile} profile.");
            try
            {
                using (var fwHelper = new FirewallSettingHelper())
                {
                    fwHelper.FwPolicy2.FirewallEnabled[_profileType] = false;
                    Logger.WriteLine(LogLevel.Info, _title, $"Success {_log_target} profile is disabled.");
                    return true;
                }
            }
            catch (Exception e)
            {
                Logger.WriteLine(LogLevel.Error, _title, $"Failed to disable {_log_target}. Exception: {e.Message}");
                Logger.WriteRaw(_title, e.Message);
            }
            return false;
        }

        public bool SetParameter(
            bool? blockAllInbound,
            bool? notifyOnListen,
            string defaultInboundAction,
            string defaultOutboundAction)
        {
            Logger.WriteLine(LogLevel.Info, _title, $"Set {_log_target} for {this.Profile} profile.");
            try
            {
                using (var fwHelper = new FirewallSettingHelper())
                {
                    var fwPolicy2 = fwHelper.FwPolicy2;
                    if (blockAllInbound.HasValue)
                    {
                        Logger.WriteLine(LogLevel.Info, _title, $"Set Block All Inbound Traffic to {blockAllInbound.Value} for {this.Profile} profile.");
                        fwPolicy2.BlockAllInboundTraffic[_profileType] = blockAllInbound.Value;
                    }
                    if (notifyOnListen.HasValue)
                    {
                        Logger.WriteLine(LogLevel.Info, _title, $"Set Notify On Listen to {notifyOnListen.Value} for {this.Profile} profile.");
                        fwPolicy2.NotificationsDisabled[_profileType] = !notifyOnListen.Value;
                    }
                    if (!string.IsNullOrEmpty(defaultInboundAction))
                    {
                        var defInbound = FirewallParser.StringToAction(defaultInboundAction);
                        Logger.WriteLine(LogLevel.Info, _title, $"Set Default Inbound Action to {defaultInboundAction} for {this.Profile} profile.");
                        fwPolicy2.DefaultInboundAction[_profileType] = defInbound;
                    }
                    if (!string.IsNullOrEmpty(defaultOutboundAction))
                    {
                        var defOutbound = FirewallParser.StringToAction(defaultOutboundAction);
                        Logger.WriteLine(LogLevel.Info, _title, $"Set Default Outbound Action to {defaultOutboundAction} for {this.Profile} profile.");
                        fwPolicy2.DefaultOutboundAction[_profileType] = defOutbound;
                    }
                    Logger.WriteLine(LogLevel.Info, _title, $"Success to set {_log_target}.");
                    return true;
                }
            }
            catch (Exception e)
            {
                Logger.WriteLine(LogLevel.Error, _title, $"Failed to set {_log_target}. Exception: {e.Message}");
                Logger.WriteRaw(_title, e.Message);
            }
            return false;
        }
    }
}
