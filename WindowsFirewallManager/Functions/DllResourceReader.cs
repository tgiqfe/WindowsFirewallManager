using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace WindowsFirewallManager.Functions
{
    /// <summary>
    /// Read from DLL resource strings.
    /// </summary>
    internal class DllResourceReader
    {
        #region Native methods.

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        private static extern nint LoadLibraryEx(string dllToLoad, nint handle, uint flags);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern int LoadString(nint hInstance, int ID, StringBuilder lpBuffer, int nBufferMax);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FreeLibrary(nint hModule);

        [Flags]
        private enum LoadLibraryFlags : uint
        {
            DONT_RESOLVE_DLL_REFERENCES = 0x00000001,
            LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x00000010,
            LOAD_LIBRARY_AS_DATAFILE = 0x00000002,
            LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x00000040,
            LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020,
            LOAD_LIBRARY_SEARCH_APPLICATION_DIR = 0x00000200,
            LOAD_LIBRARY_SEARCH_DEFAULT_DIRS = 0x00001000,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR = 0x00000100,
            LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800,
            LOAD_LIBRARY_SEARCH_USER_DIRS = 0x00000400,
            LOAD_WITH_ALTERED_SEARCH_PATH = 0x00000008
        }

        #endregion

        /// <summary>
        /// pattern for @filename.dll,-number
        /// </summary>
        private readonly static Regex _pattern = new Regex(@"^@.+\.dll,\-\d+$");

        /// <summary>
        /// dll file and resource number to extract string.
        /// </summary>
        /// <param name="file"></param>
        /// <param name="number"></param>
        /// <returns></returns>
        public static string ExtractString(string file, int number)
        {
            StringBuilder result = new StringBuilder(10240);
            nint lib = nint.Zero;
            lib = LoadLibraryEx(file, nint.Zero, (uint)LoadLibraryFlags.LOAD_LIBRARY_AS_DATAFILE);
            LoadString(lib, number, result, result.Capacity);
            if (lib != nint.Zero) FreeLibrary(lib);
            return result.ToString();
        }

        /// <summary>
        /// dll file and resource number string extractor.
        /// </summary>
        /// <param name="text"></param>
        /// <returns></returns>
        public static string ExtractString(string text)
        {   
            if (!string.IsNullOrEmpty(text) && _pattern.IsMatch(text))
            {
                string fileName = text.Substring(1, text.IndexOf(",") - 1);
                string numString = text.Substring(text.IndexOf(",") + 2);
                string filePath = @"C:\Windows\System32\" + fileName;
                int number = int.TryParse(numString, out int num) ? num : -1;
                return ExtractString(filePath, number);
            }
            return text;
        }
    }
}
