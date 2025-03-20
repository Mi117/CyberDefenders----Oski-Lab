# CyberDefenders----Oski-Lab
CyberDefenders — Oski Lab Walkthrough

INTRO

The lab focuses on the detailed analysis of a malicious campaign involving a file associated with the STEALC malware, part of the InfoStealer family. It emerged in early 2023 and is sold as a Malware-as-a-Service (MaaS) on underground forums. Stealc is designed to steal sensitive information such as usernames, passwords, credit card numbers, and data from web browsers, cryptocurrency wallets, email clients, and messaging apps.

SCENARIO

The accountant at the company received an email titled "Urgent New Order" from a client late in the afternoon. When he attempted to access the attached invoice, he discovered it contained false order information. Subsequently, the SIEM solution generated an alert regarding downloading a potentially malicious file. Upon initial investigation, it was found that the PPT file might be responsible for this download. Could you please conduct a detailed examination of this file?

TOOLS
- VIRUS TOTAL [https://www.virustotal.com/gui/]: for identifying details about the malware, by submitting the file(s) hashes to get comprehensive scan results and analysis.
- ANYRUN [https://app.any.run/]: used in this case for interactive online malware analysis. It allows cybersecurity specialists to detect, monitor, and research cyber threats in real-time by providing an interactive sandbox environment where they can influence the virtual machine and control the analysis process. It helps analyze suspicious files, examine malware behavior, and collect threat intelligence.
- MITRE ATT&CK [https://attack.mitre.org/]: a comprehensive, globally accessible knowledge base framework that documents and categorizes the tactics, techniques, and procedures (TTPs) used by cyber adversaries. It stands for Adversarial Tactics, Techniques, and Common Knowledge. comprehensive, globally accessible knowledge base that documents and categorizes the tactics, techniques, and procedures (TTPs) used by cyber adversaries. It stands for Adversarial Tactics, Techniques, and Common Knowledge.

Link to the challenge: https://cyberdefenders.org/blueteam-ctf-challenges/oski/

WALKTHROUGH

Q1) Determining the creation time of the malware can provide insights into its origin. What was the time of malware creation?

Heading onto VirusTotal the answer to our question is soon found, right in the Details > History where the first malware creation time is 2022-09-28 17:40.

![q1](https://github.com/user-attachments/assets/5461f395-b4e7-428d-a28e-f57c9ebe852c)

Q2) Identifying the command and control (C2) server that the malware communicates with can help trace back to the attacker. Which C2 server does the malware in the PPT file communicate with?

Command and Control (C2C) servers are critical components of many malware operations, acting as the central hub where an attacker can remotely control infected systems. Once the system is compromised, the malware established a connection with the C2C server to receive instructions  from the attacker, performing any sort of malicious and unauthorized activities.
In the Relationship tab, we can see that the malware established a connection with the following IP address: 171.22.28.221 

![q2-1](https://github.com/user-attachments/assets/7ffa72c3-950d-4910-9efc-8c8d0351fb2f)

The IP address is linked to URLs that the malware attempts to connect to. These URLs often end in .php or .exe, which are common file extensions used by malware for communication with command and control (C2) servers. .php files are typically used for web-based interactions, while .exe files are executable files that can be used to deliver malware payloads.

![q2-2](https://github.com/user-attachments/assets/b4c7dac9-779e-400c-bc45-118ab52d01c4)

With these details we could also set up the firewall to block any incoming traffic from that address allowing us to protect against further exploitation as well providing insights into the attacker’s methodology/infrastructure.

Q3)  Identifying the initial actions of the malware post-infection can provide insights into its primary objectives. What is the first library that the malware requests post-infection?

Analyzing the answer of the previous question, we see that in addition to calling .php, a call is made to a .dll library 

http://171.22.28.221/9e226a84ec50246d/sqlite3.dll

![q3](https://github.com/user-attachments/assets/8e30ae90-71e2-4909-9c74-af53282788a5)

A file DLL (Dynamic Link Library) is a special file that contains code or instructions that can be used by various programs in Windows. Think of a DLL file as a «toolbox » that different programs can open to use some function or tool they need.

This has advantages because it allows:
- Reuse code: You don't have to write the same code for each program, but many programs can share that code.
- Reduce space: By sharing code between programs, you save disk space.
- Facilitate updates: If the DLL file is updated, all programs that use it automatically benefit from that improvement.

However, attackers can also use malicious DLL files to hide malware, as in this case.

This indicates that one of the initial actions of the malware after infecting the equipment is to download and use this library, probably with the intention of storing data or configurations in SQLite databases to maintain persistence or store information collected on the infected machine.

Q4)  Upon examining the malware, it appears to utilize the RC4 key for decrypting a base64 string. What specific RC4 key does this malware use?

Now we jump on AnyRun to perform an analysis and check reports of the malware. Heading into the report section > type in the hash of the file provided to seek for the RC4 key.  

(1)
![q4](https://github.com/user-attachments/assets/aa512e9d-d7c1-4f44-96d7-63ef5407e0bd)

(2)
![q4-1](https://github.com/user-attachments/assets/c595692b-aa73-4755-992e-016b14275699)

Follow this link to locate the report: https://app.any.run/tasks/d55e2294-5377-4a45-b393-f5a8b20f7d44

In simple terms, the RC4 key is a password  used in the encryption algorithm RC4 (Rivest Cipher 4), which is a simple and fast method to encrypt information.
Think of it as a simple digital padlock that protects data by transforming it into something unreadable.
The RC4 key it is like the specific key that opens and closes that padlock, allowing to encrypt and decrypt the information.
When the malware uses an RC4 key, what it does is protect or hide information (for example, commands, addresses, or stolen data), encrypting it to avoid being easily detected. Only the possessor of that key (the attacker or the victim if they recover it) can decrypt that information.

In our context, if we go to the «CFG » configuration option, we can see the activity of that malicious exe and the RC4 key (5329514621441247975720749009).

![q4-2](https://github.com/user-attachments/assets/b346675d-2493-45df-8b2c-727da9534e3c)

Q5) Identifying an adversary's techniques can aid in understanding their methods and devising countermeasures. Which MITRE ATT&CK techniqu![Uploading q4-2.png…]()
e are they employing to steal a user's password?

Firs of all we need to cite what MITRE ATT&CK is and its function:  It is an array that classifies techniques used by cybercriminals at different stages of their attacks. It allows security analysts to clearly identify which specific method a malware used to attack a system. These techniques are grouped by objectives such as theft of credentials, persistence, escalation of privileges, etc.

Here we can see all of the tactics and techniques used by the attacker. Every technique is assigned a unique number, to help with identifying different methodologies.

![q5](https://github.com/user-attachments/assets/328d3419-385f-41fa-ba29-0d6fd78d26c1)

And in this case, it shows that the technique used by the malware according to MITRE ATT & CK is: the T1555 – Credentials from Web Browsers (credentials obtained from web browsers).

![q5-2](https://github.com/user-attachments/assets/ea646446-78bd-4f48-8a44-a64e3646443d)

This sub-technique indicates that malware extracts passwords directly stored in the infected user's web browsers.

Q6) Malicious programs can delete files left by the actions of their intrusion activity. What directory or path does the malware point to for deletion?

Malware (in this case VPN.exe) executes a specific instruction from the Windows command line to remove traces of its actions and make it difficult to detect.

The command you run is this:

"C:\Windows\system32\cmd.exe" /c timeout /t 5 & del /f /q "C:\Users\admin\AppData\Local\Temp\VPN.exe" & del "C:\ProgramData\*.dll"" & exit

We are going to break it down into parts easily:

_ timeout /t 5
Malware awaits 5 seconds before continuing. This is generally to ensure that the malware closes completely before erasing itself.

_ del /f /q "C:\Users\admin\AppData\Local\Temp\VPN.exe"
Here, the malware is self-removing. You are deleting the file VPN.exe original that you downloaded in the user's temporary directory so that there is no evidence of its execution.
delmeans «delete ».
_ /fforces deletion, even if the file is in use or protected.

_ /qprevent Windows from asking you if you really want to delete it.

_ del "C:\ProgramData\*.dll"
Here you are deleting all files with extension .dll inside the directory C:\ProgramData. This indicates that the malware could have downloaded additional files (such as sqlite3.dll), and now it is deleting them to avoid that they can be analyzed later.

_ exit
Finally, the command window closes automatically after executing these commands.

Therefore, the answer to the question about the path or directory that the malware points to for deletion is:

C:\Users\admin\AppData\Local\Temp\VPN.exe (original executable file)
C:\ProgramData\*.dll (all DLL files in this directory)

![q6](https://github.com/user-attachments/assets/a60baec3-41d0-4dce-bf9d-fc25f7086620)

Q7) Understanding the behavior of malware after data exfiltration can help you understand your evasion techniques. After successfully extracting user data, how many seconds does it take for the malware to self-delete?

As we have seen previously, after extracting the user's data, the malware executes the following command, so the answer is 5seconds.

timeout /t 5

![q7](https://github.com/user-attachments/assets/e1f2f8d0-9751-4392-9151-1805555b344b)

This command means that the malware expects exactly 5 seconds before self-removing, deleting your files so as not to leave a trace. This behavior is common in advanced malware to avoid detection and subsequent analysis.

CONCLUSIONS

# Strengthening My Cybersecurity Arsenal: Reflections on the Oski Challenge
 
By dissecting Stealc's sophisticated tactics, including its ability to stealthily exfiltrate sensitive data and act as a loader for additional payloads, I gained invaluable insights into the evolving landscape of cyber threats. This challenge reinforced the critical role of robust endpoint detection, effective email security, multi-factor authentication, and vigilant network monitoring in defending against such threats.

Beyond the technical aspects, this challenge highlighted something I believe is essential in our field—the value of practical, scenario-based training. Theoretical knowledge is important, but there's no substitute for rolling up your sleeves and working through a realistic threat scenario.

As cybersecurity professionals, we're in a constant race to stay ahead of evolving threats like Stealc. This challenge reminded me that our greatest strengths lie in collaborative learning and continuous skill development.

I'd be interested to hear about your experiences with similar training exercises and how they've shaped your approach to cybersecurity.

I want to thank the team of CyberDefenders.org and the challenge creators for a concise, yet insightful Lab as the practical application of concepts made this far more valuable than theoretical learning alone. I appreciate the time and effort put into creating such a valuable resource for the cybersecurity community. Thank you for contributing to my growth as a blue team analyst!

I hope you found this walkthrough insightful as well! If you found this content helpful, please consider giving it a clap! Your feedback is invaluable and motivates me to continue supporting your journey in the cybersecurity community. Remember, LET'S ALL BE MORE SECURE TOGETHER! For more insights and updates on cybersecurity analysis, follow me on Substack! [https://substack.com/@atlasprotect?r=1f5xo4&utm_campaign=profile&utm_medium=profile-page]
