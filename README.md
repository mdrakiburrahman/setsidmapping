# Virtual User SID Creation and SQL Login

<!-- TOC -->

- [Virtual User SID Creation and SQL Login](#virtual-user-sid-creation-and-sql-login)
    - [References](#references)
    - [Examples](#examples)
    - [Debug with Visual Studio.](#debug-with-visual-studio)
    - [Get a Token](#get-a-token)
    - [Assign to Login and user on SSMS](#assign-to-login-and-user-on-ssms)

<!-- /TOC -->

Copyright (C) 2020 - James Forshaw.

Simple tool to use *LsaManageSidNameMapping* get LSA to add or remove SID to name mappings.

To use you need to have *SeTcbPrivilege* and the SID you map a name to must meet the following
criteria.

- The SID security authority must be NT (5)
- The first RID of the SID must be between 80 and 111 inclusive.
- You must register a domain SID first.

## References

* [Using LsaManageSidNameMapping to add a name to a SID](https://www.tiraniddo.dev/2020/10/using-lsamanagesidnamemapping-to-add.html)
* [Creating your own Virtual Service Accounts](https://www.tiraniddo.dev/2020/10/creating-your-own-virtual-service.html)
* [Virtual Service Accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts#virtual-accounts)
* [LogonUserExEx](https://learn.microsoft.com/en-us/windows/win32/secauthn/logonuserexexw)

## Examples

Add the domain SID ABC and a user SID.
`SetSidMapping.exe S-1-5-101=ABC S-1-5-101-1-2-3=ABC\User`

Remove the domain SID and all its related SIDs.
`SetSidMapping.exe -r ABC`

## Debug with Visual Studio.

```powershell
# Install psexec
choco install psexec /y

# Launch Visual Studio as Local System:
psexec -i -s "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\devenv.exe"

# Set args: S-1-5-101=ABC S-1-5-101-1-2-3=ABC\User
```

## Get a Token

Follow [these](https://github.com/mdrakiburrahman/sandbox-attacksurface-analysis-tools?tab=readme-ov-file#steps) steps to get `NtObjectManager` installed as a PowerShell module.

```powershell

# Launch Powershell via psexec
psexec -i -s powershell.exe

# Import module
Import-Module -Name "C:\Users\mdrrahman\Documents\WindowsPowerShell\Modules\NtObjectManager\NtObjectManager.psm1"

# Give Logon right to the user we created above
Add-NtAccountRight -Sid 'S-1-5-101-1-2-3' -LogonType SeInteractiveLogonRight

# Get token
$token = Get-NtToken -Logon -LogonType Interactive -User 'User' -Domain 'ABC' -LogonProvider Virtual

Format-NtToken $token

# ABC\User

$token

# User                            : ABC\User
# Groups                          : {Mandatory Label\Medium Mandatory Level, Everyone, BUILTIN\Performance Log Users,
#                                   BUILTIN\Users...}
# EnabledGroups                   : {Everyone, BUILTIN\Performance Log Users, BUILTIN\Users, NT AUTHORITY\INTERACTIVE...}
# DenyOnlyGroups                  : {}
# GroupCount                      : 10
# AuthenticationId                : 00000002-25F9186C
# TokenType                       : Primary
# ExpirationTime                  : 441481572610010000
# Id                              : 00000002-25F91876
# ModifiedId                      : 00000002-25F9187C
# Owner                           : S-1-5-101-1-2-3
# PrimaryGroup                    : S-1-5-101-1-2-3
# DefaultDacl                     : {Type Allowed - Flags None - Mask 10000000 - Sid S-1-5-18, Type Allowed - Flags None
#                                   - Mask 10000000 - Sid S-1-5-101-1-2-3}
# Source                          : Identifier = 00000002-25F91864 - Name = Advapi
# RestrictedSids                  : {}
# RestrictedSidsCount             : 0
# ImpersonationLevel              : Impersonation
# SessionId                       : 1
# SandboxInert                    : False
# Origin                          : 00000000-000003E7
# ElevationType                   : Default
# Elevated                        : False
# HasRestrictions                 : False
# UIAccess                        : False
# VirtualizationAllowed           : True
# VirtualizationEnabled           : False
# Restricted                      : False
# WriteRestricted                 : False
# Filtered                        : False
# NotLow                          : True
# Flags                           : VirtualizeAllowed, NotLow
# NoChildProcess                  : False
# Capabilities                    : {}
# MandatoryPolicy                 : NoWriteUp, NewProcessMin
# LogonSid                        : NT AUTHORITY\LogonSessionId_2_637081707
# IntegrityLevelSid               : Mandatory Label\Medium Mandatory Level
# AppContainerNumber              : 0
# IntegrityLevel                  : Medium
# SecurityAttributes              : {}
# DeviceClaimAttributes           : {}
# UserClaimAttributes             : {}
# RestrictedUserClaimAttributes   :
# RestrictedDeviceClaimAttributes :
# AppContainer                    : False
# LowPrivilegeAppContainer        : False
# AppContainerSid                 :
# PackageName                     :
# DeviceGroups                    : {}
# RestrictedDeviceGroups          :
# Privileges                      : {SeShutdownPrivilege, SeChangeNotifyPrivilege, SeUndockPrivilege,
#                                   SeIncreaseWorkingSetPrivilege...}
# FullPath                        : ABC\User - 00000002-25F9186C
# TrustLevel                      :
# IsPseudoToken                   : False
# IsSandbox                       : False
# PackageFullName                 :
# AppId                           :
# AppModelPolicies                : {}
# AppModelPolicyDictionary        : {}
# BnoIsolationPrefix              :
# PackageIdentity                 :
# AuditPolicy                     :
# PrivateNamespace                : False
# IsRestricted                    : False
# ProcessUniqueAttribute          :
# GrantedAccess                   : AssignPrimary, Duplicate, Impersonate, Query, QuerySource, AdjustPrivileges,
#                                   AdjustGroups, AdjustDefault, AdjustSessionId, Delete, ReadControl, WriteDac,
#                                   WriteOwner
# GrantedAccessGeneric            : GenericAll
# GrantedAccessMask               : 983551
# SecurityDescriptor              : O:BAG:SYD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;SWRC;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDR
#                                   CWDWO;;;S-1-5-101-1-2-3)S:(ML;;NW;;;ME)
# Sddl                            : O:BAG:SYD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;SWRC;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDR
#                                   CWDWO;;;S-1-5-101-1-2-3)S:(ML;;NW;;;ME)
# Handle                          : 0xF2C
# NtTypeName                      : Token
# NtType                          : Name = Token - Index = 5
# Name                            : User - 00000002-25F9186C
# CanSynchronize                  : False
# CreationTime                    : 1600-12-31 7:00:00 PM
# AttributesFlags                 : None
# HandleReferenceCount            : 1
# PointerReferenceCount           : 32691
# Inherit                         : False
# ProtectFromClose                : False
# Address                         : 0
# IsContainer                     : False
# IsClosed                        : False
# ObjectName                      : ABC\User - 00000002-25F9186C

```

## Assign to Login and user on SSMS


```sql
-- Create virtual user login
-- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/create-a-login?view=sql-server-ver16#TsqlProcedure
CREATE LOGIN [ABC\User] FROM WINDOWS;

-- Alter server role and add this user, can also add to custom roles as well, like `Marketing` etc.
-- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/join-a-role?view=sql-server-ver16
ALTER SERVER ROLE diskadmin ADD MEMBER [ABC\User];

-- Create Database user
-- https://learn.microsoft.com/en-us/sql/relational-databases/security/authentication-access/create-a-database-user?view=sql-server-ver16
USE [msdb]; CREATE USER [ABC\User] FOR LOGIN [ABC\User];
```

![Success](/_images/ssms-success.png)