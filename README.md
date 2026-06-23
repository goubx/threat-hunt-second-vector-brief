# Threat Hunt 08: Second Vector (ONGOING)

> Cloud-native identity compromise → internal spearphishing → silent exfiltration

**Stack:** Microsoft Sentinel · Defender XDR · Entra ID · Microsoft 365 · Graph API · KQL

**Techniques:** T1078.004 · T1090.003 · T1110.001 · T1087.004 · T1069.003 · T1534 · T1114.002 · T1114.003 · T1564.008 · T1530 · T1552.001 · T1083

**Flags:** 25 across 6 investigative stages

**Outcome:** Low-rated alert reclassified as confirmed targeted intrusion with active persistence

# Threat Hunt Report: Second Vector

**Hunt ID:** Hunt 08

**Date:** June 11, 2026

**Organization:** LOG(N) Pacific

**Analyst:** Mohamed Yagoub, T2 Threat Hunter

**Incident Reference:** 87241 (Anonymous IP sign-in flagged on `m.smith`)

**Investigation Window:** 2026-06-11 03:00 UTC to 2026-06-11 13:00 UTC

---

## Platforms and Tools Used

- **Incident Management:** Microsoft Defender XDR
- **SIEM / Hunting:** Microsoft Sentinel (Log Analytics Workspace)
- **Identity:** Microsoft Entra ID, Entra ID Protection
- **Productivity / Mail:** Microsoft 365, Exchange Online
- **API Telemetry:** Microsoft Graph Activity Logs
- **Cloud App Telemetry:** Microsoft Defender for Cloud Apps (CloudAppEvents)
- **Query Language:** Kusto Query Language (KQL)

---

## Scenario Summary

Microsoft Entra ID Protection raised Incident 87241, a Low-severity anonymous IP sign-in flagged on finance user `m.smith` at LOG(N) Pacific during the early hours of 11 June 2026. The night shift triaged the alert, found no actionable evidence, and left it in the queue.

This hunt re-examined the incident under the working hypothesis that the Low verdict understated a patient cloud-native intrusion executed entirely through identity, mail, files, and cloud services, with downstream activity scattered across multiple Sentinel tables. The hypothesis was confirmed. The single flagged sign-in opened into a full session covering reconnaissance, internal spearphishing fraud against a second finance user, dual-purpose inbox rule persistence, and targeted credential theft pointing at follow-on access beyond Microsoft 365.

---

## MITRE ATT&CK Summary

| Flag | Technique | MITRE ID | Priority |
|-----:|-----------|----------|----------|
| 1 | Valid Accounts (context) | T1078 | N/A |
| 2 | Proxy: Multi-hop Proxy (anonymization service) | T1090.003 | High |
| 3 | Valid Accounts: Cloud Accounts (non-corp client OS) | T1078.004 | Medium |
| 4 | Entra ID Protection risk detection (anonymizedIPAddress) | T1090.003 | High |
| 5 | Defensive evasion via dismissed risk state | T1078 | High |
| 6 | Active account exposure (context) | T1078 | High |
| 7 | Authentication gap, single-factor path | T1078.004 | Critical |
| 8 | Initial Access via Outlook Web | T1078.004 | High |
| 9 | Brute Force: Password Guessing | T1110.001 | Medium |
| 10 | Cloud lateral movement, multi-app session | T1078.004 | High |
| 11 | Single session reuse across services | T1078.004 | Medium |
| 12 | Account Discovery: Cloud Account (MFA posture) | T1087.004 | Medium |
| 13 | Permission Groups Discovery: Cloud Groups | T1069.003 | Medium |
| 14 | Internal Spearphishing | T1534 | Critical |
| 15 | Email Collection: Remote Email Collection | T1114.002 | High |
| 16 | Internal Spearphishing (recipient context) | T1534 | High |
| 17 | Internal Spearphishing: Cross-channel via Teams | T1534 | High |
| 18 | Hide Artifacts: Email Hiding Rules | T1564.008 | Critical |
| 19 | Defensive evasion rationale (context) | T1564.008 | High |
| 20 | Email Collection: Email Forwarding Rule | T1114.003 | Critical |
| 21 | Persistence targeting rationale (context) | T1564.008, T1114.003 | High |
| 22 | Data from Cloud Storage | T1530 | High |
| 23 | Targeted exfiltration volume (context) | T1530 | High |
| 24 | Unsecured Credentials: Credentials In Files | T1552.001 | Critical |
| 25 | File and Directory Discovery | T1083 | Medium |

---

## Flag Analysis & Findings

### Stage 1: Triage

#### 🏁 Flag 1 - The Compromised Principal

- **Answer:** `m.smith@lognpacific.org`
- **Discovery:** Located in Defender XDR from the alert left in the queue by the night shift. The Evidence and Response pane on Incident 87241 named the principal and exposed the full identity context. The SAM Name in the user object resolves the UPN `m.smith` to **Mark Smith**, which is important context for later pivots where queries filter on the display name "mark" rather than the UPN.

![Flag 1 - Compromised principal in Defender XDR](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%201.png)

---

#### 🏁 Flag 2 - The Flagged Source

- **Answer:** `103.69.224.136`
- **Discovery:** With the UPN confirmed, I queried `SigninLogs` for all activity tied to the user and isolated the records where the result signature was not `SUCCESS`. The anonymous source IP surfaced cleanly from that filter.

```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where ResultSignature != 'SUCCESS'
| project IPAddress
```

![Flag 2 - Flagged source IP](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%202.png)

---

#### 🏁 Flag 3 - The Client OS

- **Answer:** `Linux`
- **Discovery:** With the source IP confirmed, I pulled the `DeviceDetail` field for sign-ins originating from that address. The client operating system was Linux, which is consistent with operator infrastructure rather than the user's corporate device baseline.

```kql
SigninLogs
| where IPAddress == '103.69.224.136'
| project DeviceDetail
```

![Flag 3 - Client OS Linux](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%203.png)

---

#### 🏁 Flag 4 - The Stored Detection Type

- **Answer:** `anonymizedIPAddress`
- **Discovery:** Returned to the incident telemetry to pull the canonical risk event type as Entra ID Protection stored it. Queried `AADUserRiskEvents` filtered to the principal and projected the `RiskEventType` field. The detection that fired against Mark Smith was stored as `anonymizedIPAddress`, which maps to anonymizing services such as Tor or commercial VPN providers.

```kql
AADUserRiskEvents
| where UserPrincipalName == "m.smith@lognpacific.org"
| project DetectedDateTime, UserPrincipalName, RiskEventType
```

![Flag 4 - Stored detection type](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%204.png)

---

#### 🏁 Flag 5 - Audit the Verdict

- **Answer:** `dismissed`
- **Discovery:** I summarized all risk states recorded against Mark Smith to understand how prior detections had been handled. The most common state was `dismissed`. This pattern of repeated dismissals provides the operator with effective defensive evasion through misclassification: each dismissed event lowers the analyst response signal for the next.

```kql
AADUserRiskEvents
| where UserPrincipalName == "m.smith@lognpacific.org"
| summarize count() by RiskState
```

![Flag 5 - Risk state summary](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%205.png)

---

#### 🏁 Flag 6 - Live Exposure

- **Answer:** `Enabled`
- **Discovery:** Confirmed the account's current status from the Assets pane within Incident 87241 in Defender XDR. The account is still Enabled at the time of triage, which means any active sessions or persistence established by the operator continue to act on a live identity.

![Flag 6 - Account status enabled](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%206.png)

---

### Stage 2: Session Scope

The account has MFA, but the remote IP was still able to establish a successful session. The next set of flags scopes how that happened, what the operator reached, and how the session held together.

#### 🏁 Flag 7 - How the Session Beat MFA

- **Answer:** `singleFactorAuthentication`
- **Discovery:** I queried only the successful sign-ins from the attacker IP and projected `AuthenticationRequirement` and `AuthenticationMethodsUsed`. Every successful sign-in from `103.69.224.136` completed under `singleFactorAuthentication`, meaning the MFA enrollment on the account did not enforce on the path the operator used. This is a Conditional Access gap, not a defeated MFA prompt.

```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == '103.69.224.136'
| where ResultSignature == "SUCCESS"
| project AuthenticationRequirement, AuthenticationMethodsUsed
```

![Flag 7 - Single factor authentication path](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%207.png)

---

#### 🏁 Flag 8 - The Control Surface That Let Them In

- **Answer:** `One Outlook Web`
- **Discovery:** I ordered all sign-ins from the attacker IP by time to find the first successful authentication. The earliest success landed at `2026-06-11T03:51:26.7032205Z` against the One Outlook Web client. That timestamp marks the transition from probe attempts to active session, and the application named in that record is the control surface that authorized the operator's first valid token.

```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == '103.69.224.136'
| order by TimeGenerated desc
```

![Flag 8 - First successful login through One Outlook Web](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%208.png)

---

#### 🏁 Flag 9 - Failed Attempts Before Entry

- **Answer:** `2`
- **Discovery:** To count failed attempts strictly before the first successful login, I scoped the first success time into a `let` variable, then counted records before that timestamp where the result type was `50126` (invalid username or password). Only two failures occurred before the operator landed a valid credential. This rules out brute force and is consistent with credential reuse, prior phishing, or a leaked password used with light verification.

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

![Flag 9 - Two failed attempts before entry](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%209.png)

---

#### 🏁 Flag 10 - Blast Radius of One Token

- **Answer:** `7`
- **Discovery:** I scoped to successful sign-ins from the attacker IP and used `dcount` on `AppDisplayName` to measure how many distinct cloud applications the same identity reached during the intrusion. Seven applications were authenticated against, which establishes the operational footprint of a single compromised token.

```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| where ResultSignature == 'SUCCESS'
| summarize DistinctApps = dcount(AppDisplayName)
```

---

#### 🏁 Flag 11 - One Continuous Session

- **Answer:** `005d431a-380b-1f5e-e554-16d5010dc28e`
- **Discovery:** I grouped successful sign-ins by `SessionId` and projected the distinct apps, application names, and first and last seen timestamps per session. A single session ID accounted for all of the cross-app activity, including Outlook Web, Microsoft Teams, and additional Microsoft cloud services. The operator did not establish multiple sessions; they pivoted across services on one token.

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

![Flag 11 - Single session ID](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%2011.png)

---

### Stage 3: Directory Recon

#### 🏁 Flag 12 - MFA Posture Profiling

- **Answer:** `userRegistrationDetails`
- **Discovery:** Early in the session, the operator made Graph API calls under the `/reports/` path. I queried `MicrosoftGraphActivityLogs` filtered to that path and ordered by time. The first request hit `userRegistrationDetails`, which returns each user's authentication method registration state. This is targeted recon to learn which accounts have weak or missing MFA before choosing a follow-on target.

```kql
MicrosoftGraphActivityLogs
| where RequestUri contains "/reports/"
| project TimeGenerated, UserId, AppId, RequestMethod, RequestUri, ResponseStatusCode
| sort by TimeGenerated asc
```

![Flag 12 - userRegistrationDetails reconnaissance](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%2012.png)

---

#### 🏁 Flag 13 - Group Enumeration

- **Answer:** `/v1.0/me/memberOf`
- **Discovery:** I filtered `MicrosoftGraphActivityLogs` for any requests touching `/me/member`. The operator issued `GET /v1.0/me/memberOf` against Microsoft Graph to enumerate the victim's full set of group, role, and directory object memberships in a single call. This is the cloud equivalent of running `whoami /groups` after landing on an endpoint and is used to identify approval paths, distribution lists, and downstream access.

```kql
MicrosoftGraphActivityLogs
| where RequestUri contains "/me/member"
| project TimeGenerated, RequestUri, RequestMethod
| sort by TimeGenerated asc
```

![Flag 13 - Group enumeration via /me/memberOf](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%2013.png)

---

### Stage 4: The Fraud

#### 🏁 Flag 14 - The Fraudulent Request

- **Answer:** `Updated Banking Details - Pacific IT Monthly`
- **Discovery:** After confirming the session reached Outlook Web, I pulled `EmailEvents` filtered on the victim's display name to surface outbound mail from the compromised mailbox. At `2026-06-11T04:13:54Z`, an email was sent to `j.reynolds@lognpacific.org` with the subject `Updated Banking Details - Pacific IT Monthly`. The message is an internal spearphishing request crafted to redirect a recurring payment to attacker-controlled banking details, leveraging the trust of an internal sender (T1534).

```kql
EmailEvents
| where SenderDisplayName contains "smith"
```

![Flag 14 - Fraudulent email subject line](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%2014.png)

---

#### 🏁 Flag 15 - The Thread They Mined

- **Answer:** `Q1 Vendor Payment Schedule - Review Required`
- **Discovery:** I searched `EmailEvents` for mailbox content matching payment-related keywords. The fraudulent message referenced a real prior thread, `Q1 Vendor Payment Schedule - Review Required`, originally sent on `2026-02-08T02:53:23Z`, approximately four months before the intrusion. That thread documents the internal payment approval process, including dollar thresholds and approver roles, giving the operator the operational context needed to price and structure the fraudulent request (T1114.002, Remote Email Collection).

```kql
EmailEvents
| where Subject has_any ("subject","payment","money")
| project Timestamp, Subject 
| order by Timestamp desc
```

![Flag 15 - Mined Q1 payment thread](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%2015.png)

---

#### 🏁 Flag 16 - The Fraud Target

- **Answer:** `j.reynolds@lognpacific.org`
- **Discovery:** Two fraud-related emails surfaced from the compromised mailbox. The first was sent to `j.reynolds@lognpacific.org` at `2026-06-11T04:13:54Z`. That same message thread was forwarded externally at `2026-06-11T12:41:14Z` to `merovingian1337@proton.me`, which becomes relevant in Flag 20. The internal recipient is the fraud target. The external Proton address is the exfiltration destination.

```kql
EmailEvents
| where SenderDisplayName has_any ("mark")
| project TimeGenerated, SenderDisplayName, RecipientEmailAddress, Subject
| order by TimeGenerated desc
```

*Screenshot not captured during hunt.*

---

#### 🏁 Flag 17 - Second Channel Reinforcement

- **Answer:** `Microsoft Teams`
- **Discovery:** Suspecting cross-channel reinforcement of the fraud request, I queried `CloudAppEvents` for `MessageSent` actions tied to the victim's display name and projected the Application field. Microsoft Teams was the only platform returned, confirming the operator sent a follow-up message through Teams to reinforce the email-based fraud request. Layering email and chat is a known social engineering pattern designed to overcome a target's hesitation by making the request appear coordinated and routine.

```kql
CloudAppEvents
| where AccountDisplayName has "mark"
| where ActionType == "MessageSent"
| project Application
```

![Flag 17 - Teams reinforcement message](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%2017.png)

---

### Stage 5: Persistence Hunt

The operator modified the mailbox so that responses to the fraud would not be visible to Mark. The next flags identify the rules they created and what each one does.

#### 🏁 Flag 18 - The Concealment Rule

- **Answer:** `Invoice Processing`
- **Discovery:** I queried `OfficeActivity` for `New-InboxRule` operations tied to the compromised mailbox, expanded the `Parameters` JSON, and extracted the rule names. Two rules were created during the intrusion. The first, named `Invoice Processing`, silently moves any inbound mail matching the fraud-related subject pattern out of the inbox and into a normal-looking folder so Mark never sees replies tied to the spoofed banking request.

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

![Flag 18 - Invoice Processing rule creation](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%2018.png)

---

#### 🏁 Flag 19 - Where the Hidden Mail Goes

- **Answer:** Avoids deletion alerts and blends with normal mailbox activity. The ordinary folder name does not look suspicious to the user or to monitoring.
- **Discovery:** Hard deletes trigger alerts in most monitored environments. `MailItemsAccessed`, `SoftDelete`, and `HardDelete` operations are watched by DLP and UEBA tooling, and deleted-item recovery is a routine forensic check. A move operation, by contrast, is treated as user filing behavior and rarely fires anything. Using a folder named to look like a finance workflow (`Invoice Processing`) means that even if Mark notices the folder, the name reads as routine.

![Flag 19 ](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%2019.png)


---

#### 🏁 Flag 20 - The Exfiltration Rule

- **Answer:** `merovingian1337@proton.me`
- **Discovery:** Pulling the second rule out of the same `OfficeActivity` query, I found a rule named `Backup Copy` created at `2026-06-11T03:32:31Z`. The rule forwards any email from `j.reynolds@lognpacific.org` to the external address `merovingian1337@proton.me` and includes a `StopProcessingRules` flag, which suppresses any other rules that might otherwise act on the same message. This is the exfiltration channel: every reply from the fraud target is silently mirrored to attacker infrastructure regardless of whether the operator is logged in.

```kql
OfficeActivity
| where Operation == "New-InboxRule"
| where UserId =~ "m.smith@lognpacific.org" or MailboxOwnerUPN =~ "m.smith@lognpacific.org"
| extend Params = parse_json(Parameters)
| mv-expand Params
| extend ParamName = tostring(Params.Name), ParamValue = tostring(Params.Value)
| where ParamName == "Name"
```

*Screenshot not captured during hunt.*

---

#### 🏁 Flag 21 - Who Both Rules Target

- **Answer:** The fraud target's replies to the spoofed payment request, so the victim cannot see the questions, confirmations, or denials that would expose the scam.
- **Discovery:** Both rules act on inbound mail from `j.reynolds@lognpacific.org`, the same recipient who received the fraudulent banking request. The Concealment rule (`Invoice Processing`) hides J. Reynolds' replies from Mark's view. The Exfiltration rule (`Backup Copy`) mirrors those same replies to the operator's external mailbox. Together they ensure the conversation continues with full visibility for the operator while remaining completely invisible to the compromised user, which is what allows the fraud to be carried to completion even if Mark logs in to do other work.

*Screenshot not captured during hunt.*

---

### Stage 6: Data Theft

#### 🏁 Flag 22 - The Exfil Operation

- **Answer:** `FileDownloaded`
- **Discovery:** Mark Smith opens files all day as part of his finance role, so `FileAccessed` and `FilePreviewed` events are baseline noise. I separated copy-out activity from in-place reads by filtering `OfficeActivity` to the `FileDownloaded` operation specifically. From that reduced set, I correlated the remaining events on attacker session IP and user agent, tight timing inside the intrusion window, and file relevance to the fraud, which left only payment and approval documents outside the user's normal working set.

---

#### 🏁 Flag 23 - Volume Taken

- **Answer:** `3`
- **Discovery:** Three files were downloaded during the attacker session. The contents indicate selective targeting rather than mass collection: the downloads include banking details and access credentials directly aligned with the fraud objective and follow-on access, not bulk file enumeration. This is consistent with an operator who already knew what they were after before opening the file browser.

---

#### 🏁 Flag 24 - The Credential Document

- **Answer:** `VPN-Access-Credentials.txt`
- **Discovery:** I filtered `OfficeActivity` to the compromised user and any operation containing the string `download`. One of the three downloaded files was `VPN-Access-Credentials.txt`. The presence of this file in the operator's pull widens the incident scope past the mailbox: any credentials stored in that file are presumed exposed and must be rotated, and any VPN session originating from outside the user's normal geography should be reviewed for misuse.

```kql
OfficeActivity
| where UserId =~ "m.smith@lognpacific.org" 
| where Operation contains "download"
```

![Flag 24 - VPN credentials file downloaded](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%2024.png)

---

#### 🏁 Flag 25 - The Browsed Credential Store

- **Answer:** `yomark.pdf`
- **Discovery:** I filtered `OfficeActivity` for `FileAccessed` operations under the same compromised user. The operator accessed `all.aspx` under the credential store's SharePoint library, enumerating the folder's contents in the browser without opening or downloading any of the files inside. The file `yomark.pdf` surfaced in that access path. This is File and Directory Discovery (T1083): the operator inventoried what is in the credential store without leaving the heavier forensic trail that would accompany an actual download.

```kql
OfficeActivity
| where UserId =~ "m.smith@lognpacific.org" 
| where Operation == "FileAccessed"
```

![Flag 25 - Credential store enumeration](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%2025.png)

---
# The Plant and the Trigger 

#### 🏁 Flag 26 - Disprove the Innocent Explanation

- **Answer:** `0`
- **Discovery:** Upon looking at the victim's username and the malicious IP, I found that all of the login attempts were from first form authentication, and the MFA was never used. 

```kql
SigninLogs
| where UserPrincipalName =~ "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| where ResultType == 0
| mv-expand AuthDetail = parse_json(AuthenticationDetails)
| extend StepResult = tostring(AuthDetail.authenticationStepResultDetail),
         Method = tostring(AuthDetail.authenticationMethod),
         Succeeded = tostring(AuthDetail.succeeded)
| project TimeGenerated, Method, StepResult, Succeeded
| sort by TimeGenerated asc
```

[image]

---

#### 🏁 Flag 27 - Catch the Plant

I'm going to take a look at the apps touched during the session, im looking for one that deals with automations.

- **Answer:** `Microsoft Flow Portal`
- **Discovery:** Upon searching the signinlogs and looking at the apps used during the session, it appears the attacker used 'Microsoft Flow Portal', which is used to create automations.

```kql
SigninLogs
| where UserPrincipalName =~ "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| distinct AppDisplayName, AppId
| sort by AppDisplayName asc
```

[image]

---
IR LEAD: "The forward's in the mail logs. No rule made it, user wasn't online. Find the table that records what actually fired it."

Format: the full table name as it appears in the workspace

#### 🏁 Flag 28 - The Cause Behind the Forward

- **Answer:** `MicrosoftGraphActivityLogs`
- **Discovery:** If no rule was created, and the user wasn't online upon the time that the forwarded email was sent, it can only lead me to believe that an API triggered the call that can only be found the through the Microsoft Graph Activity logs.

```kql
MicrosoftGraphActivityLogs
```
---

#### 🏁 Flag 29 - Prove It With the Sequence

IR LEAD: "That forward is recorded twice, an API call and a mail event. Put them in order and tell me which came first."

Format: name the record that came first (the Graph call, or the mail event)

- **Answer:** `the Graph call`
- **Discovery:** For the email to get sent, the API has to get called, or else the event won't get caused.

```kql
MicrosoftGraphActivityLogs
```

---
# Correlation & Containment

Since the forward didn't come from the attacker's IP address or the user's machine, I need to find the IP it was sent from.

#### 🏁 Flag 30 - The Automation Source IP

- **Answer:** `20.150.129.194`
- **Discovery:** I need to search the graph activity logs and search for any request URI that has any instance of forwarding or sending emails. I was able to find only one instance of this happening at 2026-06-11T12:41:09.1296387Z, which corresponds to when the email was forwarded.

```kql
MicrosoftGraphActivityLogs
| where RequestUri has_any ("forward", "sendmail")
```

[image]

---
I need to find the app that signed the forward call.

#### 🏁 Flag 31 - The Automation Identity

- **Answer:** `7ab7862c-4c57-491e-8a45-d52a7e023983`
- **Discovery:** After looking over the MicrosoftGraphActivityLogs, I was able to find the app ID that made the API call. It appears the app is Microsoft Flow.

```kql
MicrosoftGraphActivityLogs
| where RequestUri has_any ("forward", "sendmail")
| project UserAgent, AppId
```

[image]

---

#### 🏁 Flag 32 - Name the Abused Service

- **Answer:** `Microsoft Power Automate`
- **Discovery:** The forward was fired by a Microsoft Power Automate flow (workflow 89a996b4a5ce4cde938ab27e21018d0f, AppId 7ab7862c-4c57-491e-8a45-d52a7e023983) making POST /v1.0/me/messages/{id}/forward to Graph from Azure IP 20.150.129.194, establishing server-side persistence that operates independent of the victim's sessions.

```kql
MicrosoftGraphActivityLogs
| where RequestUri has_any ("forward", "sendmail")
```

---

#### 🏁 Flag 33 - One Actor, Every Source 

- **Answer:** `7`
- **Discovery:** IP 103.69.224.136 appears literally in 7 of 8 in-scope tables across 10-20 June 2026, spanning sign-in, audit, cloud app, mailbox, Graph, mail flow, and identity logon telemetry, which corroborates a single actor across the full 
Identity and collaboration stack.

```kql
let TargetIP = "103.69.224.136";
let WindowStart = datetime(2026-06-10T00:00:00Z);
let WindowEnd = datetime(2026-06-20T23:59:59Z);
union 
(SigninLogs 
    | where TimeGenerated between (WindowStart .. WindowEnd) 
    | where IPAddress == TargetIP 
    | extend Source = "SigninLogs"),
(AuditLogs 
    | where TimeGenerated between (WindowStart .. WindowEnd) 
    | where tostring(InitiatedBy) has TargetIP 
    | extend Source = "AuditLogs"),
(CloudAppEvents 
    | where Timestamp between (WindowStart .. WindowEnd) 
    | where IPAddress == TargetIP 
    | extend Source = "CloudAppEvents"),
(OfficeActivity 
    | where TimeGenerated between (WindowStart .. WindowEnd) 
    | where ClientIP has TargetIP 
    | extend Source = "OfficeActivity"),
(MicrosoftGraphActivityLogs 
    | where TimeGenerated between (WindowStart .. WindowEnd) 
    | where IPAddress == TargetIP 
    | extend Source = "MicrosoftGraphActivityLogs"),
(EmailEvents 
    | where Timestamp between (WindowStart .. WindowEnd) 
    | where SenderIPv4 == TargetIP or tostring(AuthenticationDetails) has TargetIP 
    | extend Source = "EmailEvents"),
(IdentityLogonEvents 
    | where Timestamp between (WindowStart .. WindowEnd) 
    | where IPAddress == TargetIP 
    | extend Source = "IdentityLogonEvents"),
(BehaviorAnalytics 
    | where TimeGenerated between (WindowStart .. WindowEnd) 
    | where SourceIPAddress == TargetIP 
    | extend Source = "BehaviorAnalytics")
| distinct Source
| count
```

[image]

---
IR LEAD: "Before you delete a rule or a flow, one action comes first or they're straight back in. What is it."

Format: a short action phrase, a verb plus what it acts on

#### 🏁 Flag 34 - Containment Ordering

- **Answer:** `Revoke the user's sessions and refresh tokens.`
- **Discovery:** Revoke the user's sessions and refresh tokens before removing the rules or flow, otherwise the attacker re-authenticates with the stolen token and rebuilds them.

---

#### 🏁 Flag 35 - Where the Flow Is Removed

IR LEAD: "That flow can't be removed from Sentinel or the Exchange rules. Where do you go to find and delete it."

Format: the admin console name

- **Answer:** `Power Platform admin center`
- **Discovery:** The flow is removed from the Power Platform admin center, which is the tenant-wide governance surface for Power Automate. Sentinel, Defender, Exchange admin center, and the maker portal cannot see or delete flows owned by another user.

---

#### 🏁 Flag 36 - The Control That Never Fired

IR LEAD: "A foreign single-factor sign-in should have been the easiest thing in the world for Conditional Access to stop. Go and check what Conditional Access actually did on these sign-ins, then tell me what you found and why that's how the session got through."

Format: short phrase (what CA did on these sign-ins, and why that let them in)

- **Answer:** `CA didn't fire because the stolen token already satisfied both factors by claim, so no fresh challenge was issued and the foreign IP slipped through.`

---

#### 🏁 Flag 37 - Why Revoke Before Reset

IR LEAD: "Someone on the bridge wants to reset m.smith's password and call it done. You know better. Tell me why a password reset alone doesn't lock this attacker out, and what action has to come first."

Format: short phrase (what survives a reset, and the action that kills it)


- **Answer:** `Tokens survive a password reset. Revoke sessions and refresh tokens first, then reset the password.`
