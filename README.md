# VRFEM - Vcudachi RPC Filter Enumeration Module
## Description
This module contains cmdlets designed to retrieve information from WFP (Windows Filtering Platform) about installed RPC filters via API Win32:
* FwpmFilterEnum0

## Important information
* This module is canonical because does not contain C# code snippets. 
* This module supports Windows platform only.
* This module supports unicode platform only, **do not run in non-unicode environment**.
* This module supports Powershell 5.1 and Powershell 7. Powershell 5.1 is minimal requirement because of .NET Framework 4.6 usage
* The caller needs FWPM_ACTRL_OPEN access to the filter engine, basicaly, this module requres Administrator privileges on common system. If inacceptance, access may be configured as described in https://learn.microsoft.com/en-us/windows/win32/fwp/access-control
* Result same as "netsh rpc filter show filter"

## Created by
- vcudachi

## Special thx to
- https://t.me/ru_powershell
- https://learn.microsoft.com/
- Google Search
