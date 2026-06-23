# Threat Hunt Report: Second Vector

**Date:** June 2026

## Platforms and Tools Used
- **Platform:** Microsoft Defender for Endpoint (MDE), Log Analytics Workspace, Windows 11 host `anthony-001`
- **Languages & Tools:** Kusto Query Language (KQL), native Windows executables (powershell.exe, schtasks.exe, cmd.exe, csc.exe)

---

## Scenario Summary
Microsoft Entra ID Protection raised Incident 87241, a Low-severity anonymous IP sign-in flagged on finance user m.smith at LOG(N) Pacific during the early hours of 11 June 2026. The night shift triaged the alert, found no actionable evidence, and left it in the queue. This hunt re-examines the incident under the working hypothesis that the Low verdict understates a patient cloud-native intrusion executed entirely through identity, mail, files, and cloud services, with downstream activity scattered across multiple Sentinel tables.


# Triage
---

## 🔎 Flag Analysis & Findings

### 🏁 Flag 1 – The Compromised Principal
- **Answer:** 'm.smith@lognpacific.org'
- **Discovery:** Located in Defender for Endpoint in the alert left behind in the queue by the night shift. m.smith represents the user account involved in the alert, and within the contact info, I was able to retrieve the UPN(User Principal Name).

![image]()

---

Now I must search to find the IP Address that the flagged sign-on came from.

### 🏁 Flag 2 – The Flagged Source
- **Answer:** '103.69.224.136'
- **Discovery:** At this point, since I already knew the UPN, I was able to make a query searching for all the logs within the timeframe connected to the user. I then searched for the logs with the result signature not equal to success which gave me the IP Address.

```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where ResultSignature != 'SUCCESS'
| project IPAddress
```

![image]()

---

Now that I know must do deeper research on the foreign remote IP, and find out more details. I will start by finding out the OS the device it runs on.

### 🏁 Flag 3 – The Client OS
- **Answer:** 'Linux'
- **Discovery:** After confirming the remote IP address that triggered the alert, I was able to query the Operating System that the IP was running on.

```kql
SigninLogs
| where IPAddress == '103.69.224.136'
| project DeviceDetail
```

![image]()

---

I'm going to go back to the Incident Title and pull the risk telemetry, and get the detection type as it was stored per the instructions from the IR lead.

### 🏁 Flag 4 – The Stored Detection Type
- **Answer:** 'anonymizedIPAddress'
- **Discovery:** 

```kql
AADUserRiskEvents
| where UserPrincipalName == "m.smith@lognpacific.org"
| project DetectedDateTime, UserPrincipalName, RiskEventType
```
![image]()

---

### 🏁 Flag 5 – Audit the Verdict
- **Answer:** 'dismissed'
- **Discovery:** I was asked to summarize the number of risk detections this user had and find the most common one. I wrote a query that summarized the RiskState by counting them. From there, I found that "dismissed' was the most common one.

```kql
AADUserRiskEvents
| where UserPrincipalName == "m.smith@lognpacific.org"
| summarize count() by RiskState
```

![image]()

---
I will now go and find out the accounts' current status. 

### 🏁 Flag 6 – Live Exposure
- **Answer:** 'Enabled
- **Discovery:** After going into the incident alert on Defender, I went to the Assets section to see the account's current status. Upon reviewing it, I could see that the user's current status is active.
  
![image]()

---

# Session Scope

The user has MFA activated, but the remote IP was still able to access his account. I'm going to investigate how this happened.

### 🏁 Flag 7 – How the Session Beat MFA
- **Answer:** 'singleFactorAuthentication'
- **Discovery:** I needed to investigate why a remote IP was able to log in despite the client having MFA enabled. I first needed to check the user's authentication requirements. Upon looking at all of the clients' successful logins, they all happened to be done with single-factor authentication.
  
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == '103.69.224.136'
| where ResultSignature == "SUCCESS"
| project AuthenticationRequirement, AuthenticationMethodsUsed
```

![image]()

---

### 🏁 Flag 8 – The Control Surface That Let Them In
- **Answer:** 'One Outlook Web'
- **Discovery:** There are multiple logs for SUCCESS/FAILURE log-in attempts, but I need to find the turning point where the remote IP was able to sign in and which application allowed that to occur. The first successful login from this IP occurred at 2026-06-11T03:51:26.7032205Z. Now I know that the first successful login came in through One Outlook web.
  
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == '103.69.224.136'
| order by TimeGenerated desc
```

![image]()

---

I am going to look into how many times the remote IP got the credentials incorrect before the first successful login.

### 🏁 Flag 9 – Failed Attempts Before Entry
- **Answer:** '2'
- **Discovery:** To find the number of incorrect logins that occurred before the first successful session, I needed to create a query that first gathered all of the successful sessions that happened, so that I was able to count the failures that occurred before.
  
```kql
let SuccessfulSessionTime =
SigninLogs
| where UserPrincipalName =~ "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| where ResultType == 0
| summarize FirstSuccess = min(TimeGenerated);
SigninLogs
| where UserPrincipalName =~ "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| where TimeGenerated < toscalar(SuccessfulSessionTime)
| where ResultType == 50126
| count
```

![image]()

---
I now need to see the number of distinct apps that were reached during the session.

### 🏁 Flag 10 - Blast Radius of One Token
- **Answer:** '7'
- **Discovery:** To find the number of distinct apps that were reached, I first just had to gather all of the successful login logs. From there, I needed to summarize them and count them only by their names.
  
```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| where ResultSignature == 'SUCCESS'
| summarize DistinctApps = dcount(AppDisplayName)
```

![image]()

---

### 🏁 Flag 11 - One Continuous Session
- **Answer:** '005d431a-380b-1f5e-e554-16d5010dc28e'
- **Discovery:** I first put in a query to investigate whether or not the same session was maintained by the remote login. After confirming the session ID from one of the logins, I then made the query below to see if there were any others, and this seemed to be the only one. They seemed to have accessed several apps such as Outlook Web, Microsoft Teams, and a number of other apps.
  
```kql
SigninLogs
| where UserPrincipalName =~ "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| where ResultType == 0
| summarize 
    DistinctApps = dcount(AppDisplayName),
    Apps = make_set(AppDisplayName),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SessionId
| order by DistinctApps desc
```

![image]()

---
# Directory Recon

### 🏁 Flag 12 - MFA-Posture Profiling
- **Answer:** 'userRegistrationDetails'
- **Discovery:** Early in the session, the attacker moved. I took a look at graphactivityresults to see if I could find anything about authentications. After looking over the log, I can see they requested the client's userRegistrationDetails.
  
```kql
MicrosoftGraphActivityLogs
| where RequestUri contains "/reports/"
| project TimeGenerated, UserId, AppId, RequestMethod, RequestUri, ResponseStatusCode
| sort by TimeGenerated asc
```

![image]()

---

### 🏁 Flag 13 - Group Enumeration
- **Answer:** '/v1.0/me/memberOf'
- **Discovery:** The actor issued GET /v1.0/me/memberOf against Microsoft Graph to enumerate the victim's full set of group, role, and directory object memberships in a single call.
  
```kql
MicrosoftGraphActivityLogs
| where RequestUri contains "/me/member"
| project TimeGenerated, RequestUri, RequestMethod
| sort by TimeGenerated asc
```

![image]()

---
# The Fraud 

### 🏁 Flag 14 = The Fraudulent Request
- **Answer:** 'Updated Banking Details - Pacific IT Monthly'
- **Discovery:** After getting a report that emails were sent from the client after their account was compromised, I was tasked with finding the email subject line that they sent out. At 2026-06-11T04:13:54Z, they sent an email to j.reynolds@lognpacific.org, with the subject Updated Banking Details - Pacific IT Monthly. This was an attempt to have banking details changed to those of the attacker.
  
```kql
EmailEvents
| where SenderDisplayName contains "smith"
```

![image]()

---

### 🏁 Flag 15 - The Thread They Mined
- **Answer:** 'Q1 Vendor Payment Schedule - Review Required'
- **Discovery:** RE: 'Q1 Vendor Payment Schedule - Review Required" originally sent on 2026-02-08T02:53:23Z, approximately four months before the intrusion. The thread documents the internal payment approval process, including dollar thresholds and approver roles, giving the actor the operational context needed to price and structure the fraudulent request (T1114.002).
  
```kql
EmailEvents
| where Subject has_any ("subject","payment","money")
| project Timestamp, Subject 
| order by Timestamp desc
```

![image]()

---
I need to investigate who received the fraudulent email.

### 🏁 Flag 16 - Q16 - The Fraud Target
- **Answer:** 'j.reynolds@lognpacific.org'
- **Discovery:** It appears that only two fraudulent emails were sent out. The first sent out to J.reynolds at 2026-06-11T04:13:54Z, and then that email was forwaded out once again at 2026-06-11T12:41:14Z to merovingian1337@proton.me.
  
```kql
EmailEvents
| where SenderDisplayName has_any ("mark")
| project TimeGenerated, SenderDisplayName, RecipientEmailAddress, Subject
| order by TimeGenerated desc
```

![image]()

---

### 🏁 Flag 17 - Second Channel Reinforcement
- **Answer:** 'Microsoft Teams'
- **Discovery:** It appeared that they sent another request through another service. Since I couldn't pinpoint what it was, I made sure to include the action type as "message sent' by the user and to project the applications used. Microsoft Teams was the only application to be used.
  
```kql
CloudAppEvents
| where AccountDisplayName has "mark"
| where ActionType == "MessageSent"
| project Application
```

![image]()

---
# Persistence Hunt

They changed something on the mailbox so a conversation wouldn't be seen. I am going to find the rule and its name.

### 🏁 Flag 18 - The Concealment Rule
- **Answer:** 'Invoice Processing'
- **Discovery:** After researching the queries, I found that two rules had been created. I then went further into the queries to see what they had been named, and saw that the attacker created a new rule called "Invoice Processing", that would always delete the emails sent out and be put inside an archive folder.
  
```kql
OfficeActivity
| where Operation == "New-InboxRule"
| where UserId =~ "m.smith@lognpacific.org" or MailboxOwnerUPN =~ "m.smith@lognpacific.org"
| extend Params = parse_json(Parameters)
| mv-expand Params
| extend ParamName = tostring(Params.Name), ParamValue = tostring(Params.Value)
| where ParamName == "Name"
| project TimeGenerated, ClientIP, RuleName = ParamValue
```

![image]()

---
IR LEAD: "That rule doesn't delete the mail it catches, it moves it to a normal-looking folder. Tell me why an attacker moves instead of deletes, and what the choice of an ordinary folder buys them."

### 🏁 Flag 19 - Where the Hidden Mail Goes
- **Answer:** 'Avoids deletion alerts and blends with normal mailbox activity; the ordinary folder name doesn't look suspicious to the user or to monitoring.'
- **Discovery:** Hard deletes trigger alerts in most monitored environments. MailItemsAccessed, SoftDelete, and HardDelete operations are watched by DLP and UEBA tooling, and deleted-item recovery is a routine forensic check. A move operation is treated as user filing behavior and rarely fires anything.
  

---
I'm going to investigate the second rule and what it does.

### 🏁 Flag 20 - The Exfiltration Rule
- **Answer:** 'merovingian1337@proton.me'
- **Discovery:** It appears that a second rule, named "Backup Copy" was created at 2026-06-11T03:32:31Z. What this rule does is forward any email from "j.reynolds@lognpacific.org" to "merovingian1337@proton.me". Not only does it do this, but it stop all further processing of any other rules that may have been set up, making the attacker move as efficiently as needed.
  
```kql
OfficeActivity
| where Operation == "New-InboxRule"
| where UserId =~ "m.smith@lognpacific.org" or MailboxOwnerUPN =~ "m.smith@lognpacific.org"
| extend Params = parse_json(Parameters)
| mv-expand Params
| extend ParamName = tostring(Params.Name), ParamValue = tostring(Params.Value)
| where ParamName == "Name"
```

![image]()

---
IR LEAD: "Both mailbox rules act on inbound mail from one person, the same person you named as the fraud target. Tell me why the persistence rules single out THEIR mail specifically. What conversation are the rules built to stop the victim from seeing?"

### 🏁 Flag 21 - Who Both Rules Target

- **Answer:** 'The fraud target's replies to the spoofed payment request, so the victim can't see the questions, confirmations, or denials that would expose the scam.'
- **Discovery:** 

---
# Data Theft

IR LEAD: "This user opens files all day, that's their job and it's noise. One operation in the attacker's session is them taking copies OUT, not reading in place. Name that operation, and tell me how you separated it from the user's ordinary file activity."

Both parts please, the operation and how you told it apart. The name on its own won't land.

### 🏁 Flag 22 - The Exfil Operation
- **Answer:** 'FileDownloaded. Separated from baseline by filtering OfficeActivity to FileDownloaded (the user's noise is FileAccessed and FilePreviewed in-browser reads, not copy-out), then correlating the remaining events on attacker session IP and user agent, tight timing inside the intrusion window, and file relevance to the fraud (payment and approval documents outside the user's normal working set).'

---
### 🏁 Flag 23 - Volume Taken
- **Answer:** '3, I believe that they pulled out specific things they were looking for, for example the files they downloaded consisted of things like banking details and access credentials, which shows these were not pulled at random.  '

---
IR LEAD: "One of those files widens this past the mailbox. Name it."

### 🏁 Flag 24 - The Credential Document
- **Answer:** 'VPN-Access-Credentials.txt'
- **Discovery:** 
  
```kql
OfficeActivity
| where UserId =~ "m.smith@lognpacific.org" 
| where Operation contains "download"
```

![image]()

---
# IR LEAD: "They opened a file that points to a credential store, didn't download it. Look at access. Name the file."

### 🏁 Flag 25
- **Answer:** 'yomark.pdf'
- **Discovery:** The actor accessed all.aspx under the credential store's SharePoint library, enumerating the folder's contents in the browser without opening or downloading any of the files inside (T1083 - File and Directory Discovery).
  
```kql
OfficeActivity
| where UserId =~ "m.smith@lognpacific.org" 
| where Operation == "FileAccessed"
```

![image]()

---
