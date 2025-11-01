using NetFwTypeLib;

namespace WindowsFirewallManager.WindowsFirewall
{
    internal class FirewallComponentsMap
    {
        #region Direction Mapping

        /// <summary>
        /// Direction paremter
        /// </summary>
        /// <param name="direction"></param>
        /// <returns></returns>
        public static string GetDirectionName(NET_FW_RULE_DIRECTION_ direction)
        {
            return direction switch
            {
                NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN => "Inbound",
                NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT => "Outbound",
                _ => "Unknown",
            };
        }

        public static NET_FW_RULE_DIRECTION_? GetDirectionFlagFromName(string directionName)
        {
            return directionName.ToLower() switch
            {
                "inbound" or "in" => NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN,
                "outbound" or "out" => NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT,
                _ => null,
            };
        }

        #endregion
        #region Action Mapping

        public static string GetActionName(NET_FW_ACTION_ action)
        {
            return action switch
            {
                NET_FW_ACTION_.NET_FW_ACTION_ALLOW => "Allow",
                NET_FW_ACTION_.NET_FW_ACTION_BLOCK => "Deny",
                _ => "Unknown",
            };
        }

        public static NET_FW_ACTION_? GetActionFlagFromName(string actionName)
        {
            return actionName.ToLower() switch
            {
                "allow" => NET_FW_ACTION_.NET_FW_ACTION_ALLOW,
                "deny" or "block" => NET_FW_ACTION_.NET_FW_ACTION_BLOCK,
                _ => null,
            };
        }

        #endregion
        #region Protocol Mapping

        private readonly static Dictionary<int, string> Protocols = new Dictionary<int, string>
        {
            { 0, "HOPOPT" },
            { 1, "ICMPv4" },
            { 2, "IGMP" },
            { 6, "TCP" },
            { 17, "UDP" },
            { 41, "IPv6" },
            { 43, "IPv6-Route" },
            { 44, "IPv6-Frag" },
            { 47, "GRE" },
            { 58, "ICMPv6" },
            { 59, "IPv6-NoNxt" },
            { 60, "IPv6-Opts" },
            { 112, "VRRP" },
            { 113, "PGM" },
            { 115, "L2TP" },
            { 256, "Any" },
        };

        public static string GetProtocolName(int protocolNumber)
        {
            if (Protocols.TryGetValue(protocolNumber, out string protocolName))
            {
                return protocolName;
            }
            return "Unknown";
        }

        public static int? GetProtocolNumberFromName(string protocolName)
        {
            if (int.TryParse(protocolName, out int protocolNumber))
            {
                return protocolNumber;
            }
            foreach (var kvp in Protocols)
            {
                if (string.Equals(kvp.Value, protocolName, StringComparison.OrdinalIgnoreCase))
                {
                    return kvp.Key;
                }
            }
            return protocolName.ToLower() switch
            {
                "icmp" or "icmp v4" or "icmp4" => 1,
                "icmp v6" or "icmp6" => 58,
                "all" or "any" or "*" => 256,
                _ => null,
            };
        }

        #endregion
        #region Profile Type Mapping

        private enum ProfileType
        {
            Domain = 0x1,
            Private = 0x2,
            Public = 0x4,
            Any = 0x7fffffff,
        }

        private static readonly Dictionary<string[], ProfileType> ProfileTypeMap = new()
        {
            { new string[]{"Any", "all", "*" }, ProfileType.Any },
            { new string[]{"Domain", "dom" }, ProfileType.Domain },
            { new string[]{"Private", "priv" }, ProfileType.Private },
            { new string[]{"Public", "pub" }, ProfileType.Public },
        };

        public static string GetProfilesName(int profileType)
        {
            if (profileType == (int)ProfileType.Any) return ProfileType.Any.ToString();
            var names = new List<string>();
            foreach (ProfileType pt in Enum.GetValues(typeof(ProfileType)))
            {
                if (pt != ProfileType.Any && (profileType & (int)pt) != 0)
                {
                    names.Add(pt.ToString());
                }
            }
            return string.Join(", ", names);
        }

        public static int? GetProfilesTypeFromName(string profilesName)
        {
            int profileType = 0;
            foreach (var profile in profilesName.Split(',').Select(x => x.Trim()))
            {
                foreach (var kvp in ProfileTypeMap)
                {
                    if (kvp.Key.Any(x => x.Equals(profile, StringComparison.OrdinalIgnoreCase)))
                    {
                        profileType |= (int)kvp.Value;
                    }
                }
            }
            return profileType == 0 ? null : profileType;
        }

        #endregion
    }
}
