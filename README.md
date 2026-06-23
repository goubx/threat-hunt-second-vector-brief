# Threat Hunt 08: Second Vector

> Cloud-native identity compromise → internal spearphishing → silent exfiltration

**Stack:** Microsoft Sentinel · Defender XDR · Entra ID · Microsoft 365 · Graph API · Power Platform · KQL

**Techniques:** T1078.004 · T1090.003 · T1110.001 · T1087.004 · T1069.003 · T1534 · T1114.002 · T1114.003 · T1564.008 · T1530 · T1552.001 · T1083 · T1648 · T1550.001

**Flags:** 37 across 8 investigative stages

**Outcome:** Low-rated alert reclassified as a confirmed targeted intrusion with layered active persistence, including a server-side Power Automate flow operating independent of any user session.

---

# Threat Hunt Report: Second Vector

**Hunt ID:** Hunt 08

**Date:** June 11, 2026

**Organization:** LOG(N) Pacific

**Analyst:** Mohamed Yagoub, T2 Threat Hunter

**Incident Reference:** 87241 (Anonymous IP sign-in flagged on `m.smith`)

**Investigation Window:** 2026-06-11 03:00 UTC to 2026-06-11 13:00 UTC (extended for cross-table correlation through 2026-06-20)

---

## Platforms and Tools Used

- **Incident Management:** Microsoft Defender XDR
- **SIEM / Hunting:** Microsoft Sentinel (Log Analytics Workspace)
- **Identity:** Microsoft Entra ID, Entra ID Protection
- **Productivity / Mail:** Microsoft 365, Exchange Online
- **API Telemetry:** Microsoft Graph Activity Logs
- **Cloud App Telemetry:** Microsoft Defender for Cloud Apps (CloudAppEvents)
- **Automation Platform:** Microsoft Power Automate (identified as abused service)
- **Query Language:** Kusto Query Language (KQL)

---

## Scenario Summary

Microsoft Entra ID Protection raised Incident 87241, a Low-severity anonymous IP sign-in flagged on finance user `m.smith` at LOG(N) Pacific during the early hours of 11 June 2026. The night shift triaged the alert, found no actionable evidence, and left it in the queue.

This hunt re-examined the incident under the working hypothesis that the Low verdict understated a patient cloud-native intrusion executed entirely through identity, mail, files, and cloud services. The hypothesis was confirmed. The single flagged sign-in opened into a full session covering reconnaissance, internal spearphishing fraud, layered mailbox persistence, targeted credential theft, and a Power Automate flow that continues to exfiltrate mail to attacker infrastructure without any user being signed in. The Conditional Access policy on the tenant did not fire on these requests because the operator's session was sustained via a stolen refresh token whose MFA-satisfaction claim rode forward into every reissued access token.

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
| 26 | Refresh-token reuse, MFA bypass confirmation | T1550.001 | Critical |
| 27 | Cloud automation app sign-in (Flow Portal) | T1078.004 | High |
| 28 | Graph-driven persistence trigger identification | T1648 | High |
| 29 | Cause and effect sequencing (context) | N/A | N/A |
| 30 | Serverless execution source IP (Azure) | T1648 | High |
| 31 | Power Automate AppId identification | T1648 | High |
| 32 | Serverless Execution: Power Automate flow | T1648 | Critical |
| 33 | Cross-table actor correlation (context) | N/A | N/A |
| 34 | Containment ordering (response context) | N/A | N/A |
| 35 | Containment surface knowledge (response context) | N/A | N/A |
| 36 | Use Alternate Authentication Material: token claim trust | T1550.001 | Critical |
| 37 | Token lifecycle vs password lifecycle (response context) | N/A | N/A |

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
- **Discovery:** I queried only the successful sign-ins from the attacker IP and projected `AuthenticationRequirement` and `AuthenticationMethodsUsed`. Every successful sign-in from `103.69.224.136` completed under `singleFactorAuthentication`, meaning the MFA enrollment on the account did not enforce on the path the operator used. The deeper cause is identified in Flag 36.

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
- **Discovery:** I scoped to successful sign-ins from the attacker IP and used `dcount` on `AppDisplayName` to measure how many distinct cloud applications the same identity reached during the intrusion. Seven applications were authenticated against, which establishes the operational footprint of a single compromised token. One of those seven apps, Microsoft Flow Portal, becomes the pivot for the persistence finding in Stage 7.

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
- **Discovery:** Two fraud-related emails surfaced from the compromised mailbox. The first was sent to `j.reynolds@lognpacific.org` at `2026-06-11T04:13:54Z`. That same message thread was forwarded externally at `2026-06-11T12:41:14Z` to `merovingian1337@proton.me`, which becomes critical in Stages 5 and 7. The internal recipient is the fraud target. The external Proton address is the exfiltration destination.

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

The operator modified the mailbox so that responses to the fraud would not be visible to Mark. The next flags identify the rules they created and what each one does. A third, more durable persistence mechanism is established later in Stage 7.

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

![Flag 19 - Concealment folder behavior](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%2019.png)

---

#### 🏁 Flag 20 - The Exfiltration Rule

- **Answer:** `merovingian1337@proton.me`
- **Discovery:** Pulling the second rule out of the same `OfficeActivity` query, I found a rule named `Backup Copy` created at `2026-06-11T03:32:31Z`. The rule forwards any email from `j.reynolds@lognpacific.org` to the external address `merovingian1337@proton.me` and includes a `StopProcessingRules` flag, which suppresses any other rules that might otherwise act on the same message. This is one of two exfiltration channels: the second, more durable channel surfaces in Stage 7.

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

### Stage 7: The Plant and the Trigger

The earlier stages reconstructed what the operator did inside their interactive session. This stage asks what they left running after the session ended.

#### 🏁 Flag 26 - Disprove the Innocent Explanation

- **Answer:** `0`
- **Discovery:** To rule out any innocent explanation involving an accidental MFA approval by Mark, I expanded the `AuthenticationDetails` JSON in `SigninLogs` for every successful sign-in from the attacker IP and counted how many second-factor steps were actually completed. The result was zero. Every successful authentication landed under first-factor only, and no MFA challenge was ever issued, much less satisfied. The path the operator used did not invoke MFA at all, which forecloses the "user mistakenly approved a push" theory.

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

![Flag 26 - Zero MFA steps completed](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%2026.png)

---

#### 🏁 Flag 27 - Catch the Plant

- **Answer:** `Microsoft Flow Portal`
- **Discovery:** I enumerated the distinct applications signed into during the attacker session and looked specifically for any cloud automation surface. Microsoft Flow Portal appears in the list, which is the consumer-facing surface for Power Automate. A finance user authenticating to Flow Portal during an active intrusion is a strong indicator the operator built automation-based persistence rather than relying only on mailbox rules.

```kql
SigninLogs
| where UserPrincipalName =~ "m.smith@lognpacific.org"
| where IPAddress == "103.69.224.136"
| distinct AppDisplayName, AppId
| sort by AppDisplayName asc
```

![Flag 27 - Microsoft Flow Portal sign-in](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%2027.png)

---

> **IR Lead:** "The forward's in the mail logs. No rule made it, user wasn't online. Find the table that records what actually fired it."

#### 🏁 Flag 28 - The Cause Behind the Forward

- **Answer:** `MicrosoftGraphActivityLogs`
- **Discovery:** The 12:41 UTC forward to `merovingian1337@proton.me` occurred well after the operator's interactive session ended and with no inbox rule responsible for that specific message. With the user offline and no rule firing, the forward must have been driven by an application calling Graph on the user's behalf. Application-level Graph activity is recorded in `MicrosoftGraphActivityLogs`, not in the mail or sign-in tables, which is why nothing surfaced in earlier pivots.

```kql
MicrosoftGraphActivityLogs
```

---

> **IR Lead:** "That forward is recorded twice, an API call and a mail event. Put them in order and tell me which came first."

#### 🏁 Flag 29 - Prove It With the Sequence

- **Answer:** `the Graph call`
- **Discovery:** Each forward operation produces two records: the Graph API call that invokes it and the resulting mail event. Joining the timestamps for the 12:41 UTC forward, the Graph call (`POST /v1.0/me/messages/{id}/forward`) precedes the mail event by several seconds. This ordering confirms that the API call is the cause and the mail event is the effect, which rules out any user-driven mail action and points cleanly at an automation.

---

### Stage 8: Correlation & Containment

#### 🏁 Flag 30 - The Automation Source IP

- **Answer:** `20.150.129.194`
- **Discovery:** I filtered `MicrosoftGraphActivityLogs` for any RequestUri containing forward or sendmail to locate the API call behind the forward. A single record matched at `2026-06-11T12:41:09.1296387Z`, sourced from `20.150.129.194`, which belongs to Microsoft Azure infrastructure. The forward was issued from an Azure-hosted service running on the operator's behalf rather than from the operator's anonymous IP, which means the persistence mechanism executes inside the trust boundary of the cloud platform itself.

```kql
MicrosoftGraphActivityLogs
| where RequestUri has_any ("forward", "sendmail")
```

![Flag 30 - Azure source IP for the forward](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%2030.png)

---

#### 🏁 Flag 31 - The Automation Identity

- **Answer:** `7ab7862c-4c57-491e-8a45-d52a7e023983`
- **Discovery:** I projected `UserAgent` and `AppId` for the same matched Graph record. The AppId `7ab7862c-4c57-491e-8a45-d52a7e023983` corresponds to Microsoft Flow (Power Automate). This is the application identity that issued the forward call using Mark Smith's delegated permissions.

```kql
MicrosoftGraphActivityLogs
| where RequestUri has_any ("forward", "sendmail")
| project UserAgent, AppId
```

![Flag 31 - Microsoft Flow AppId](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%2031.png)

---

#### 🏁 Flag 32 - Name the Abused Service

- **Answer:** `Microsoft Power Automate`
- **Discovery:** The combination of AppId `7ab7862c-4c57-491e-8a45-d52a7e023983`, source IP `20.150.129.194` (Azure), and the Graph endpoint `POST /v1.0/me/messages/{id}/forward` establishes that the operator built a Power Automate flow (workflow ID `89a996b4a5ce4cde938ab27e21018d0f`) configured to forward inbound mail to `merovingian1337@proton.me` on a trigger. This is server-side persistence (T1648 Serverless Execution) that runs entirely outside the operator's session and is invisible to Exchange admin center, Sentinel rule monitoring, and Defender XDR's standard mail telemetry.

```kql
MicrosoftGraphActivityLogs
| where RequestUri has_any ("forward", "sendmail")
```

---

#### 🏁 Flag 33 - One Actor, Every Source

- **Answer:** `7`
- **Discovery:** To corroborate single-actor attribution across the intrusion, I built a union query against eight in-scope telemetry tables (`SigninLogs`, `AuditLogs`, `CloudAppEvents`, `OfficeActivity`, `MicrosoftGraphActivityLogs`, `EmailEvents`, `IdentityLogonEvents`, `BehaviorAnalytics`) for any record containing the attacker IP `103.69.224.136` between 10 and 20 June 2026. The IP appeared in seven of eight tables, spanning sign-in, audit, cloud app, mailbox, Graph, mail flow, and identity logon telemetry. The cross-table footprint corroborates a single actor operating across the full identity and collaboration stack during the intrusion window.

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

![Flag 33 - Cross-table actor correlation](https://github.com/goubx/threat-hunt-second-vector-brief/blob/main/screenshots/flag%2033.png)

---

> **IR Lead:** "Before you delete a rule or a flow, one action comes first or they're straight back in. What is it."

#### 🏁 Flag 34 - Containment Ordering

- **Answer:** Revoke the user's sessions and refresh tokens.
- **Discovery:** Removing the inbox rules or the Power Automate flow without first revoking the operator's tokens does not contain the intrusion. The stolen refresh token continues to mint new access tokens against Entra ID until explicitly revoked, and the operator can re-authenticate and rebuild any persistence Sentinel just took down. Session and refresh token revocation is therefore the first action; rule and flow deletion follow only after that revocation lands.

---

> **IR Lead:** "That flow can't be removed from Sentinel or the Exchange rules. Where do you go to find and delete it."

#### 🏁 Flag 35 - Where the Flow Is Removed

- **Answer:** `Power Platform admin center`
- **Discovery:** Power Automate flows owned by a user account are not visible or actionable from Sentinel, Defender XDR, Exchange admin center, or another user's maker portal. The tenant-wide governance surface for Power Automate is the Power Platform admin center. From there, an administrator can locate the flow by owner and workflow ID and delete it. Removing it from any other console will not work.

---

> **IR Lead:** "A foreign single-factor sign-in should have been the easiest thing in the world for Conditional Access to stop. Go and check what Conditional Access actually did on these sign-ins, then tell me what you found and why that's how the session got through."

#### 🏁 Flag 36 - The Control That Never Fired

- **Answer:** CA didn't fire because the stolen token already satisfied both factors by claim, so no fresh challenge was issued and the foreign IP slipped through.
- **Discovery:** Conditional Access evaluates token claims. When a token is reissued via the refresh-token flow, the claims from the original interactive sign-in (including the MFA satisfaction claim) ride along with the refresh. The operator's session never produced a fresh interactive sign-in from a foreign IP; it presented a refresh token whose claims already showed MFA as satisfied. Conditional Access saw "MFA satisfied" in the token and had no reason to challenge again, so the policy effectively did not fire on these requests. This is not a CA misconfiguration in the policy itself; it is a token-trust pattern that needs to be addressed with session-binding controls (Continuous Access Evaluation, Token Protection, sign-in frequency).

---

> **IR Lead:** "Someone on the bridge wants to reset m.smith's password and call it done. You know better. Tell me why a password reset alone doesn't lock this attacker out, and what action has to come first."

#### 🏁 Flag 37 - Why Revoke Before Reset

- **Answer:** Tokens survive a password reset. Revoke sessions and refresh tokens first, then reset the password.
- **Discovery:** Resetting Mark's password invalidates future password-based logons but does not invalidate already-issued OAuth tokens. The operator's refresh token continues to mint access tokens against any service the user is entitled to until the token itself is revoked. The correct ordering is: revoke all sessions and refresh tokens, then reset the password, then remove the persistence mechanisms (Power Automate flow and inbox rules). Skipping the revocation step lets the operator keep their existing access even with a new password in place.

---

## Detection Gaps & Recommendations

### Observed Gaps

- Entra ID Protection rated this incident Low based on the anonymous IP detection in isolation. The risk score did not update as the same session subsequently exhibited cross-application lateral movement, Graph reconnaissance, internal spearphishing, inbox rule creation, credential file downloads, and Power Automate flow creation.
- Conditional Access did not fire on any of the foreign sign-ins because the operator sustained the session via a refresh token whose MFA-satisfaction claim carried forward. CA evaluated trust against token claims, not against the current sign-in conditions (IP, geography, device). This is a tenant-wide gap, not a misconfiguration on a single policy.
- Power Automate flow creation and execution are not monitored. A user-owned flow that forwards mail externally is functionally equivalent to an inbox rule with external forwarding but generates no alert, lives in a separate admin surface, and is invisible to Sentinel's standard mail and identity analytics.
- The historical pattern of `dismissed` risk states on this account lowered the analyst response signal. The night shift's verdict followed the path of least resistance because that path had been validated by repeated prior dismissals.
- `New-InboxRule` operations did not trigger an alert, including the `Backup Copy` rule that forwards mail to an external `proton.me` address. External mail forwarding rule creation is a high-confidence persistence indicator and should not be silent.
- A subject-line filter inbox rule named `Invoice Processing` that catches mail from a specific internal sender and routes it to a non-default folder is a strong fraud-concealment signature. No detection fired on the rule's logic, only on its existence in the audit trail.
- Cross-channel reinforcement of a single request (email plus Teams to the same recipient inside a short window) was not correlated by any UEBA control.
- A file with `credentials` in its name was downloaded by a finance user during an actively flagged risk session. No DLP or naming-pattern detection fired.
- Cross-table correlation of a single attacker IP across seven of eight in-scope tables surfaced only because I built a union query for it. No scheduled analytic raises an alert on this pattern automatically.

### Recommendations

- Enable Continuous Access Evaluation (CAE) and Token Protection on sensitive applications so token claims are re-evaluated against current sign-in conditions rather than trusted statically.
- Enable Sign-in Frequency in Conditional Access for high-risk personas including finance, to force reauthentication periodically even on existing sessions.
- Update Conditional Access to require MFA on all interactive sign-ins including legacy and web-only authentication paths. Block any sign-in that completes under `singleFactorAuthentication` for accounts with MFA enrolled.
- Build a Sentinel analytic on `MicrosoftGraphActivityLogs` that alerts on Graph calls from the Power Automate AppId (`7ab7862c-4c57-491e-8a45-d52a7e023983`) targeting mail forwarding endpoints (`/messages/{id}/forward`, `/sendMail`) for any user who has not historically used Power Automate.
- Onboard Power Platform audit logs into Sentinel (via the Defender for Cloud Apps connector) and alert on flow creation by users in finance and other sensitive roles, especially flows that include mail-related connectors and external endpoints.
- Build a Sentinel analytic that escalates a risk event if the same `SessionId` or source IP subsequently performs any of: inbox rule creation, external mail forwarding, mass file access, sign-in to more than three distinct applications, or Power Automate flow creation.
- Alert on `New-InboxRule` operations that contain an external recipient in the `ForwardTo` or `RedirectTo` parameters. Alert with higher severity when the rule includes `StopProcessingRules`.
- Alert on inbox rules whose subject filters match payment or fraud keyword sets (`payment`, `banking`, `invoice`, `wire`, `ACH`, `vendor`).
- Build a correlation rule that joins `EmailEvents` and `CloudAppEvents` to flag the same sender messaging the same recipient across both Outlook and Teams within a short window when the email contains payment-related content.
- Alert on downloads of files whose names match credential indicators (`vpn`, `credential`, `password`, `secret`, `recovery`) from any user, with higher severity when the user is currently flagged in Entra ID Protection.
- Schedule a recurring hunt that unions the in-scope telemetry tables and flags any IP appearing in more than three tables within a short window, regardless of individual event risk score.
- Review the `dismissed` risk state pattern on finance and other privileged users. Any account with three or more dismissed events in the prior 90 days should require Tier 2 sign-off on the next dismissal.

---

## Final Assessment

The Low severity verdict on Incident 87241 was incorrect. The flagged sign-in opened into a deliberate, cloud-native intrusion that progressed through reconnaissance, internal spearphishing, layered persistence, targeted credential theft, and serverless exfiltration inside a single ten-hour window. The operator never touched an endpoint and never used malware. Every action was authorized by a valid token, including the persistence that continued to operate after the operator's interactive session ended.

**Attribution character.** The evidence supports a single, patient operator with prior knowledge of the environment. They mined a four-month-old internal payment thread for fraud credibility, profiled MFA posture before any visible action, enumerated group memberships before sending the fraud request, and built layered persistence that targets one specific recipient through three complementary mechanisms (a concealment inbox rule, a forwarding inbox rule, and a Power Automate flow). They downloaded a VPN credentials file pointing at follow-on access outside Microsoft 365. The operator's source IP appears in seven of eight in-scope telemetry tables across the intrusion window, corroborating a single actor operating across the full identity and collaboration stack.

**What is still acting with nobody online.** Three mechanisms continue to operate without any user session.

1. The `Backup Copy` inbox rule silently forwards inbound mail from `j.reynolds@lognpacific.org` to `merovingian1337@proton.me`.
2. The `Invoice Processing` inbox rule keeps the same mail out of Mark Smith's view.
3. A Power Automate flow (workflow `89a996b4a5ce4cde938ab27e21018d0f`, owned by Mark and operating under his delegated permissions) issues `POST /v1.0/me/messages/{id}/forward` against Graph from Azure IP `20.150.129.194`, mirroring inbound mail to the same Proton address.

The Power Automate flow is the most resilient of the three. It is invisible to Sentinel's rule-based mailbox monitoring, invisible to Exchange admin center, invisible to Defender XDR's mail telemetry, and can only be removed from the Power Platform admin center. Standard mailbox cleanup does not touch it. Anyone who deletes the inbox rules and considers the case closed has left a functionally equivalent forwarder running in Azure.

**Why Conditional Access did not block any of this.** Conditional Access evaluates token claims. The operator's session was sustained via the refresh-token flow, which carries forward the MFA-satisfaction claim from the original interactive sign-in. CA saw MFA as satisfied in every reissued token and had no reason to challenge again, even from a foreign IP. The policy did not misfire; the policy was looking at the wrong thing. Closing this gap requires session-binding controls (Continuous Access Evaluation, Token Protection, reduced sign-in frequency for sensitive applications), not additional CA rules layered on top of the same trust model.

**Response order.** Sequence matters here. Removing persistence without first revoking the operator's tokens lets them re-authenticate and rebuild it. The correct order is:

1. Revoke all active sessions and refresh tokens for `m.smith@lognpacific.org`. This is the first action; everything else assumes it has landed.
2. Disable the Power Automate flow (workflow `89a996b4a5ce4cde938ab27e21018d0f`) via the Power Platform admin center. This cannot be done from Sentinel, Defender XDR, or Exchange admin center.
3. Delete the `Invoice Processing` and `Backup Copy` inbox rules from Mark's mailbox.
4. Reset Mark's password. Resetting earlier without first revoking tokens leaves the operator's existing access intact.
5. Notify `j.reynolds@lognpacific.org` through a verified out-of-band channel that the banking details request is fraudulent. Halt any pending payment changes against that request.
6. Rotate every credential stored in `VPN-Access-Credentials.txt` and review VPN logs for any session originating from `103.69.224.136`, `20.150.129.194`, or other anonymizing or unexpected cloud infrastructure.
7. Block inbound and outbound mail flow with `merovingian1337@proton.me` at the gateway, and add the address and the Azure source IP to threat intelligence watchlists.
8. Audit the SharePoint credential store and confirm whether `yomark.pdf` or anything else under the same library should be removed or relocated behind tighter access controls.
9. Re-examine the Q1 vendor payment thread to determine how the operator gained visibility into it. Possible answers include earlier mailbox access, a different compromised account on the thread, or insider exposure. The four-month gap between the thread and the intrusion is the most important unresolved question coming out of this hunt.
10. Sweep other finance and finance-adjacent accounts for: any Power Automate flows owned by the user that forward mail externally, `singleFactorAuthentication` successes from foreign IPs, `New-InboxRule` events with external forwarding, and `dismissed` Entra ID Protection events in the prior 90 days.

---

## Analyst Notes

- Hunt scoped to a cloud-only intrusion across Microsoft 365 and Entra ID. No endpoint telemetry was in play.
- Evidence was assembled by pivoting across `SigninLogs`, `AADUserRiskEvents`, `MicrosoftGraphActivityLogs`, `EmailEvents`, `OfficeActivity`, `CloudAppEvents`, `AuditLogs`, `IdentityLogonEvents`, and `BehaviorAnalytics`. Schema discovery via `take 1` and `getschema` was used to map unfamiliar tables before querying.
- The cross-table union in Flag 33 was the single highest-value query of the hunt. It established single-actor attribution across the full stack and would have surfaced the intrusion automatically if it had been a scheduled analytic.
- All techniques mapped to MITRE ATT&CK Enterprise.
- IR framework reference: NIST SP 800-61 (Computer Security Incident Handling Guide).
- Report structured for interview and portfolio review.

---
