using NetFwTypeLib;
using System.Runtime.InteropServices;

namespace WindowsFirewallManager.WindowsFirewall
{
    internal class FirewallRuleHelper : IDisposable
    {
        public INetFwPolicy2 FwPolicy2;
        public IEnumerable<INetFwRule3> Rules { get; set; }

        public FirewallRuleHelper(string name)
        {
            FwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
            this.Rules = FwPolicy2.Rules.
                OfType<INetFwRule3>().
                Where(x => name.Equals(x.Name, StringComparison.OrdinalIgnoreCase));
        }

        #region Dipsosable

        private bool disposedValue;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    Marshal.ReleaseComObject(FwPolicy2);
                }
                disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        #endregion
    }
}
