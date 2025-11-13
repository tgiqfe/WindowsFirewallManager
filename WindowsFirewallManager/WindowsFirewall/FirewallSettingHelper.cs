using NetFwTypeLib;
using System.Runtime.InteropServices;

namespace WindowsFirewallManager.WindowsFirewall
{
    internal class FirewallSettingHelper : IDisposable
    {
        public INetFwPolicy2 FwPolicy2;

        public FirewallSettingHelper()
        {
            FwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(
                Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
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
