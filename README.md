# UACBypass
An application that allows the user to make a privilege escalation using Registry hijacking.

It uses two methods based on self-elevated processes :

- eventvwr (for windows 10 build 1703 (Anniversary Update) and older)
- sdclt (for windows 10 build 1709 (Fall Creators Update) and newer) 

The program creates a registry key HKCU\Software\Classes\ms-settings\Shell\Open\command and a new value with the full path of the program to execute with administratives privileges.

It then run the auto-elevated program which will itself launch the program whose path has been written in the registry with the same privileges.
As soon as the program has been run with admin rights it deletes the registry key that was created at the risk of causing errors when opening MMC components.

This method only works on an account with administrator privileges. It won't work on a standard user account. Since Windows Vista by default each program is executed with user privileges even if the user has administrator rights on the machine.

UAC should not be configured with the most restrictive settings : "Always notify me when". The program makes sure this is not the case by checking the ConsentPromptBehaviorAdmin value in the registry HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System.  So it won't work on Windows Vista.

As soon as the program has been restarted with admin rights, it will try to grab the system rights by creating a new child process on the winlogon or trusted installer process.

The program will try to restart the trusted service installer to be able to run the software with the same rights as it.

TrustedInstaller is the program with the most privileges on the system.
If it can't start it, it will elevate the program using winlogon.
