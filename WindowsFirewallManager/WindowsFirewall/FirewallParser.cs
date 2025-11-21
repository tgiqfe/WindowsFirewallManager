using NetFwTypeLib;

namespace WindowsFirewallManager.WindowsFirewall
{
    /// <summary>
    /// String <-> Object comvert, parse, etc...
    /// </summary>
    internal class FirewallParser
    {
        #region Direction mapping.

        private static Dictionary<string[], NET_FW_RULE_DIRECTION_> _mapDirection = null;
        private static void InitializeDirection()
        {
            _mapDirection = new()
            {
                { new string[] { "Inbound", "in", "i" }, NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN },
                { new string[] { "Outbound", "out", "o" }, NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_OUT },
            };
        }

        public static NET_FW_RULE_DIRECTION_ StringToDirection(string text)
        {
            if (_mapDirection == null) InitializeDirection();
            return Functions.TextFunctions.StringToFlags<NET_FW_RULE_DIRECTION_>(text, _mapDirection);
        }
        public static string DirectionToString(NET_FW_RULE_DIRECTION_ direction)
        {
            if (_mapDirection == null) InitializeDirection();
            return Functions.TextFunctions.FlagsToString<NET_FW_RULE_DIRECTION_>(direction, _mapDirection);
        }
        public static string GetDirectionString(string text)
        {
            if (_mapDirection == null) InitializeDirection();
            return Functions.TextFunctions.GetCorrect<NET_FW_RULE_DIRECTION_>(text, _mapDirection);
        }

        #endregion
        #region Action mapping.

        private static Dictionary<string[], NET_FW_ACTION_> _mapAction = null;
        private static void InitializeAction()
        {
            _mapAction = new()
            {
                { new string[] { "Allow", "accept", "a" }, NET_FW_ACTION_.NET_FW_ACTION_ALLOW},
                { new string[] { "Deny", "block", "drop", "d" }, NET_FW_ACTION_.NET_FW_ACTION_BLOCK },
            };
        }
        public static NET_FW_ACTION_ StringToAction(string text)
        {
            if (_mapAction == null) InitializeAction();
            return Functions.TextFunctions.StringToFlags<NET_FW_ACTION_>(text, _mapAction);
        }
        public static string ActionToString(NET_FW_ACTION_ action)
        {
            if (_mapAction == null) InitializeAction();
            return Functions.TextFunctions.FlagsToString<NET_FW_ACTION_>(action, _mapAction);
        }
        public static string GetActionString(string text)
        {
            if (_mapAction == null) InitializeAction();
            return Functions.TextFunctions.GetCorrect<NET_FW_ACTION_>(text, _mapAction);
        }

        #endregion
        #region Protocol mapping.

        private static Dictionary<string[], int> _mapProtocol = null;
        private static void InitializeProtocols()
        {
            _mapProtocol = new()
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
        public static int StringToProtocol(string text)
        {
            if (_mapProtocol == null) InitializeProtocols();
            return Functions.TextFunctions.StringToFlags(text, _mapProtocol);
        }
        public static string ProtocolToString(int val)
        {
            if (_mapProtocol == null) InitializeProtocols();
            return Functions.TextFunctions.FlagsToString(val, _mapProtocol);
        }
        public static string GetProtocolString(string text)
        {
            if (_mapProtocol == null) InitializeProtocols();
            return Functions.TextFunctions.GetCorrect(text, _mapProtocol);
        }

        #endregion
        #region Profile mapping.

        private static Dictionary<string[], int> _mapProfile = null;
        private static void InitializeProfile()
        {
            _mapProfile = new()
            {
                { new string[] { "Domain", "dom", "1" }, (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_DOMAIN },
                { new string[] { "Private", "priv", "pri", "2" }, (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PRIVATE },
                { new string[] { "Public", "pub", "4" }, (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_PUBLIC },
                { new string[] { "All", "Any", "*", "2147483647" }, (int)NET_FW_PROFILE_TYPE2_.NET_FW_PROFILE2_ALL },
            };
        }
        public static int StringToProfile(string text)
        {
            if (_mapProfile == null) InitializeProfile();
            return Functions.TextFunctions.StringToFlags(text, _mapProfile);
        }
        public static string ProfileToString(int profileNumber)
        {
            int all_flags = 0x7fffffff;
            if (profileNumber == all_flags) return "All";
            if (_mapProfile == null) InitializeProfile();
            List<string> list = new();

            var profiles = _mapProfile.Where(x => x.Value != all_flags && (x.Value & profileNumber) != 0);
            return string.Join(", ", profiles);
        }
        public static string GetProfileString(string text)
        {
            if (_mapProfile == null) InitializeProfile();
            return Functions.TextFunctions.GetCorrect(text, _mapProfile);
        }

        #endregion
    }
}
