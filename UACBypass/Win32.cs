using System;
using System.Runtime.InteropServices;
using System.Drawing;
using Microsoft.Win32;
using System.Diagnostics;
using System.Security.Principal;
using System.IO;
using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Management;
using System.Collections.Generic;

namespace UACBypass
{
    public static class Win32
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
        public static bool IsRunAsAdmin()
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
        public static bool IsRunAsSystem()
        {
            WindowsIdentity id = WindowsIdentity.GetCurrent();
            return id.IsSystem;
        }
    }
}
