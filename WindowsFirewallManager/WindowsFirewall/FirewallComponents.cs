using NetFwTypeLib;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace WindowsFirewallManager.WindowsFirewall
{
    internal class FirewallComponents
    {
        /// <summary>
        /// Firewall rule direction mapping.
        /// Enum: NET_FW_RULE_DIR_
        /// </summary>
        /// <typeparam name="T"></typeparam>
        public class DirectionMap<T> where T : Enum
        {
            private static Dictionary<string[], T> _map = null;
            private static void Initialize()
            {
                _map = new()
                {
                    { new string[] { "Inbound", "in", "i" }, (T)Enum.Parse(typeof(T), "NET_FW_RULE_DIR_IN") },
                    { new string[] { "Outbound", "out", "o" }, (T)Enum.Parse(typeof(T), "NET_FW_RULE_DIR_OUT") },
                };
            }
            public static T StringToValue(string text)
            {
                if (_map == null) Initialize();
                foreach (var kvp in _map)
                {
                    if (kvp.Key.Any(x => string.Equals(x, text, StringComparison.OrdinalIgnoreCase)))
                    {
                        return kvp.Value;
                    }
                }
                throw new InvalidEnumArgumentException($"Invalid direction string: {text}");
            }
            public static string ValueToString(T val)
            {
                if (_map == null) Initialize();
                foreach (var kvp in _map)
                {
                    if (kvp.Value.Equals(val))
                    {
                        return kvp.Key[0];
                    }
                }
                return "Unknown";
            }
        }

        /// <summary>
        /// Firewall rule direction mapping.
        /// Enum: NET_FW_ACTION_
        /// </summary>
        /// <typeparam name="T"></typeparam>
        public class ActionMap<T> where T : Enum
        {
            private static Dictionary<string[], T> _map = null;
            private static void Initialize()
            {
                _map = new()
                {
                    { new string[] { "Allow", "accept", "a" }, (T)Enum.Parse(typeof(T), "NET_FW_ACTION_ALLOW") },
                    { new string[] { "Deny", "block", "drop", "d" }, (T)Enum.Parse(typeof(T), "NET_FW_ACTION_BLOCK") },
                };
            }
            public static T StringToValue(string text)
            {
                if (_map == null) Initialize();
                foreach (var kvp in _map)
                {
                    if (kvp.Key.Any(x => string.Equals(x, text, StringComparison.OrdinalIgnoreCase)))
                    {
                        return kvp.Value;
                    }
                }
                throw new InvalidEnumArgumentException($"Invalid action string: {text}");
            }
            public static string ValueToString(T val)
            {
                if (_map == null) Initialize();
                foreach (var kvp in _map)
                {
                    if (kvp.Value.Equals(val))
                    {
                        return kvp.Key[0];
                    }
                }
                return "Unknown";
            }
        }

        /// <summary>
        /// Firewall rule protocol mapping.
        /// int: Protocol number
        /// </summary>
        public class ProtocolsMap
        {
            private static Dictionary<string[], int> _map = null;
            private static void Initialize()
            {
                _map = new()
                {
                    { new string[] { "HOPOPT", "hopopt" }, 0 },
                    { new string[] { "ICMPv4", "ICMP4", "icmp" }, 1 },
                    { new string[] { "IGMP", "igmp" }, 2 },
                    { new string[] { "TCP", "tcp" }, 6 },
                    { new string[] { "UDP", "udp" }, 17 },
                    { new string[] { "IPv6", "ipv6" }, 41 },
                    { new string[] { "IPv6-Route", "ipv6-route" }, 43 },
                    { new string[] { "IPv6-Frag", "ipv6-frag" }, 44 },
                    { new string[] { "GRE", "gre" }, 47 },
                    { new string[] { "ICMPv6", "ICMP6" }, 58 },
                    { new string[] { "IPv6-NoNxt", "ipv6-nonxt" }, 59 },
                    { new string[] { "IPv6-Opts", "ipv6-opts" }, 60 },
                    { new string[] { "VRRP", "vrrp" }, 112 },
                    { new string[] { "PGM", "pgm" }, 113 },
                    { new string[] { "L2TP", "l2tp" }, 115 },
                    { new string[] { "Any", "all", "*" }, 256 },
                };
            }
            public static int StringToValue(string text)
            {
                if (_map == null) Initialize();
                foreach (var kvp in _map)
                {
                    if (kvp.Key.Any(x => string.Equals(x, text, StringComparison.OrdinalIgnoreCase)))
                    {
                        return kvp.Value;
                    }
                }
                throw new InvalidEnumArgumentException($"Invalid action string: {text}");
            }
            public static string ValueToString(int val)
            {
                if (_map == null) Initialize();
                foreach (var kvp in _map)
                {
                    if (kvp.Value.Equals(val))
                    {
                        return kvp.Key[0];
                    }
                }
                return "Unknown";
            }
        }


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
