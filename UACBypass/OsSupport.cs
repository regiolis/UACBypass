using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace UACBypass
{
    /// <summary>
    /// Static class providing information about the running OS's version.
    /// </summary>
    public static class OsSupport
    {
        /// <summary>
        /// Gets whether the running operating system is Windows Vista or a more recent
        /// version.
        /// </summary>
        public static bool IsVistaOrBetter
        {
            get
            {
                return Environment.OSVersion.Platform == PlatformID.Win32NT &&
                       Environment.OSVersion.Version.Major >= 6;
            }
        }

        /// <summary>
        /// Gets whether the running operating system is Windows Seven or a more recent
        /// version.
        /// </summary>
        public static bool IsSevenOrBetter
        {
            get
            {
                return Environment.OSVersion.Platform == PlatformID.Win32NT &&
                       Environment.OSVersion.Version >= new Version(6, 1);
            }
        }

        /// <summary>
        /// Gets whether the running operating system is Windows 8 or a more recent
        /// version.
        /// </summary>
        public static bool IsEightOrBetter
        {
            get
            {
                return Environment.OSVersion.Platform == PlatformID.Win32NT &&
                       Environment.OSVersion.Version >= new Version(6, 2, 9200);
            }
        }

        /// <summary>
        /// Gets whether the running operating system is Windows 8.1 or a more recent
        /// version.
        /// </summary>
        public static bool IsEightDotOneOrBetter
        {
            get
            {
                return Environment.OSVersion.Platform == PlatformID.Win32NT &&
                       Environment.OSVersion.Version >= new Version(6, 3);
            }
        }

        /// <summary>
        /// Gets whether the running operating system is Windows 10 or a more recent
        /// version.
        /// </summary>
        public static bool IsTenOrBetter
        {
            get
            {
                return Environment.OSVersion.Platform == PlatformID.Win32NT &&
                       Environment.OSVersion.Version >= new Version(10, 0);
            }
        }

        /// <summary>
        /// Gets whether the running operating system is Windows 10 "Creators Edition"
        /// or a more recent version.
        /// </summary>
        public static bool IsTenCreatorsOrBetter
        {
            get
            {
                return Environment.OSVersion.Platform == PlatformID.Win32NT &&
                       Environment.OSVersion.Version >= new Version(10, 0, 15063);
            }
        }

        /// <summary>
        /// Gets whether the running operating system is Windows 11
        /// or a more recent version.
        /// </summary>
        public static bool IsElevenOrBetter
        {
            get
            {
                return Environment.OSVersion.Platform == PlatformID.Win32NT &&
                       Environment.OSVersion.Version >= new Version(11, 0);
            }
        }
    }
}
