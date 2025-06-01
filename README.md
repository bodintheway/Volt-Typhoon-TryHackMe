![image](https://github.com/user-attachments/assets/785d3ba5-cd52-409c-9828-074f46eebf47)


# Volt-Typhoon-TryHackMe 


This repo contains my blue team walkthrough for the Volt Typhoon challenge on TryHackMe, focusing on detecting and analyzing threat activity using Splunk for log analysis and incident response.



# Volt Typhoon

**Scenario:**  
The SOC has detected suspicious activity indicative of an advanced persistent threat (APT) group known as Volt Typhoon, notorious for targeting high-value organizations. Assume the role of a security analyst and investigate the intrusion by retracing the attacker's steps.

You have been provided with various log types from a two-week time frame during which the suspected attack occurred. Your ability to research the suspected APT and understand how they maneuver through targeted networks will prove to be just as important as your Splunk skills.

Connect to OpenVPN or use the AttackBox to access Splunk. Please give the machine about 4 minutes to boot.

**Splunk Credentials**  
- Username: `volthunter`  
- Password: `voltyp1010`  
- Splunk URL: `http://MACHINE_IP:8000`

# Initial Access
Volt Typhoon often gains initial access to target networks by exploiting vulnerabilities in enterprise software. In recent incidents, Volt Typhoon has been observed leveraging vulnerabilities in Zoho ManageEngine ADSelfService Plus, a popular self-service password management solution used by organizations.

Answer the questions below
### Question 1
### Comb through the ADSelfService Plus logs to begin retracing the attacker’s steps. At what time (ISO 8601 format) was Dean's password changed and their account taken over by the attacker?

The first step was to check what data we were working with by running a broad search query in Splunk:

```
index=*
```

## Checking Sourcetype

Next, I checked the available sourcetypes to focus on relevant logs. Since we are going through adservice plus logs, I found and clicked on the appropriate sourcetype in Splunk to narrow down the data.

![image](https://github.com/user-attachments/assets/c331638f-c6bb-4563-8535-9e8c8e9a31b6)

## Searching for Password Changes

Since we were looking for activity related to a user named **dean** and his password change, I ran a query filtering by username and action, **while keeping the adservice plus index** to stay focused on relevant logs:

```
index=adserviceplus username=dean action="password change"
```
To pinpoint when the password change occurred, I filtered the logs using `status=completed` along with the index to get the exact timestamp of the event:

![image](https://github.com/user-attachments/assets/102f393f-d81c-4fc0-9c52-bf45a25d8180)


Here is out answer: 2024-03-24T11:10:22


### Question 2
### Shortly after Dean's account was compromised, the attacker created a new administrator account. What is the name of the new account that was created?

## Investigating Dean-Admin's WMIC Activity

I searched the logs for WMIC activity related to the user **dean-admin** using this Splunk query:

```
index=* sourcetype=wmic username="dean-admin"
| table _time, ip_address, command, username
```

I used the `table` command to display only the most relevant fields—timestamp, IP address, command, and username—making the output cleaner and easier to analyze.
![image](https://github.com/user-attachments/assets/9c2dc49c-3f4e-4af2-8410-4742c17523ff)

Answer: voltyp-admin

## Execution

Volt Typhoon is known to exploit Windows Management Instrumentation Command-line (WMIC) for various execution techniques. They use WMIC to gather information and dump valuable databases, enabling them to infiltrate and exploit target networks. By leveraging "living off the land" binaries (LOLBins), they blend in with legitimate system activity, making detection more challenging.

## Question 3
In an information gathering attempt, what command does the attacker run to find information about local drives on server01 & server02?

Using the previous query to filter logs by host and command, we were able to identify the exact command the attacker ran to find information about local drives on `server01` and `server02`.
![image](https://github.com/user-attachments/assets/9d6247df-47a3-4662-8a70-11456e4ef49c)

Click exclude from results

Right here is the command
![image](https://github.com/user-attachments/assets/9c475e03-e458-4d98-8046-1d8df74e8d01)
```
wmic /node:server01,server02 logicaldisk get caption, filesystem, freespace, size, volumename
```
What it does:
This command queries the computers server01 and server02 to retrieve information about their disk drives, including:

Caption: Drive letter (e.g., C:)

FileSystem: Type of file system (e.g., NTFS)

FreeSpace: Available free space on the drive

Size: Total size of the drive

VolumeName: Label/name of the drive

### Question 4
### The attacker uses ntdsutil to create a copy of the AD database. After moving the file to a web server, the attacker compresses the database. What password does the attacker set on the archive?

![image](https://github.com/user-attachments/assets/b877a81f-8203-42e6-a8d6-12c1910a473d)
go on page 2 and look it up.


## Persistence

Our target APT frequently employs web shells as a persistence mechanism to maintain a foothold. They disguise these web shells as legitimate files, enabling remote control over the server and allowing them to execute commands undetected.

### Question 5
### To establish persistence on the compromised server, the attacker created a web shell using base64 encoded text. In which directory was the web shell placed?

![image](https://github.com/user-attachments/assets/dc13db47-77fa-4ba3-84c7-0797efcdf858)
### 🔍 Detection: Web Shell Deployment via Base64 on Compromised Host

To investigate potential persistence techniques, we used the following **Splunk query**:

```spl
index=* sourcetype=wmic username="dean-admin"  
| search command="*decode*" OR command="*echo*" OR command="*copy*" OR command="*move*"  
| table _time, ip_address, command  
| sort -_time
```

The query looks for WMIC commands run by the user dean-admin that contain terms commonly used in web shell creation. Commands like decode, echo, copy, and move are typically used to write and deploy base64-decoded payloads to disk.

The answer is C:\Windows\Temp\


## Defense Evasion
Volt Typhoon utilizes advanced defense evasion techniques to significantly reduce the risk of detection. These methods encompass regular file purging, eliminating logs, and conducting thorough reconnaissance of their operational environment.

### In an attempt to begin covering their tracks, the attackers remove evidence of the compromise. They first start by wiping RDP records. What PowerShell cmdlet does the attacker use to remove the “Most Recently Used” record?


![image](https://github.com/user-attachments/assets/fd3295d1-e4bd-4e94-b1c1-b331772ee967)
### How I Found the PowerShell Cmdlet Used to Remove RDP MRU Records

I used the following Splunk query to search for PowerShell commands related to removal actions:

```spl
index=* sourcetype="powershell" *remove*  
| table _time, CommandLine
| sort -_time
```











