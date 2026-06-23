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
- **Discovery:** 
  
```kql

```

![image]()

---

### 🏁 Flag 12
- **Answer:** ''
- **Discovery:** 
  
```kql

```

![image]()

---
### 🏁 Flag 13
- **Answer:** ''
- **Discovery:** 
  
```kql

```

![image]()

---
### 🏁 Flag 14
- **Answer:** ''
- **Discovery:** 
  
```kql

```

![image]()

---
