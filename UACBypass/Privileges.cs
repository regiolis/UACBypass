using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace UACBypass
{
    class Privileges
    {
        /// <summary>
        /// The function checks whether the current process is run as administrator.
        /// In other words, it dictates whether the primary access token of the 
        /// process belongs to user account that is a member of the local 
        /// Administrators group and it is elevated.
        /// </summary>
        /// <returns>
        /// Returns true if the primary access token of the process belongs to user 
        /// account that is a member of the Administrators group and it is 
        /// elevated. Returns false if the token does not.
        /// </returns>
        public static bool IsRunningAsAdmin()
        {
            WindowsIdentity id = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(id);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        /// <summary>
        /// The function checks whether the current process is run as administrator.
        /// In other words, it dictates whether the primary access token of the 
        /// process belongs to user account that is a member of the local 
        /// NT AUTHORITY group and it is elevated.
        /// </summary>
        /// <returns>
        /// Returns true if the primary access token of the process belongs to user 
        /// account that is a member of the NT AUTHORITY group and it is 
        /// elevated. Returns false if the token does not.
        /// </returns>
        public static bool IsRunningAsSystem()
        {
            WindowsIdentity id = WindowsIdentity.GetCurrent();
            return id.IsSystem;
        }

        /// <summary>
        /// The function check if the given fileName exists.
        /// </summary>
        /// <returns>
        /// Returns true if the fileName exists
        /// </returns>
        public static bool ExistsOnPath(string fileName)
        {
            return GetFullPath(fileName) != null;
        }

        /// <summary>
        /// The function provide the full path of a given fileName.
        /// </summary>
        /// <returns>
        /// Returns a string that represents the full path the given fileName.
        /// </returns>
        public static string GetFullPath(string fileName)
        {
            if (File.Exists(fileName))
                return Path.GetFullPath(fileName);

            var values = Environment.GetEnvironmentVariable("PATH");
            foreach (var path in values.Split(';'))
            {
                var fullPath = Path.Combine(path, fileName);
                if (File.Exists(fullPath))
                    return fullPath;
            }
            return null;
        }

        private static bool StartTiService()
		{
			try
			{
				NativeMethods.TryStartService("TrustedInstaller");
				System.Threading.Thread.Sleep(500);
				return true;
			}
			catch (Exception)
			{
				return false;
			}
		}

		public static void ElevateToSystem(string program)
        {
			if (Privileges.StartTiService())
				NativeMethods.RunAsSystem("TrustedInstaller", program);
			else NativeMethods.RunAsSystem("winlogon.exe", program);
		}
	}
}
