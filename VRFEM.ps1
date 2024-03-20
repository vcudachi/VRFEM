#requires -version 5.1
<#
.SYNOPSIS
  VRFEM - Vcudachi RPC Filter Enumeration Module
.DESCRIPTION
  This module contains cmdlets designed to retrieve information from WFP (Windows Filtering Platform) about installed RPC filters via API Win32:
    FwpmFilterEnum0
  This module is canonical because does not contain C# code snippets. 
  This module supports Windows platform only.
  This module supports unicode platform only, do not run in non-unicode environment.
  This module supports Powershell 5.1 and Powershell 7. Powershell 5.1 is minimal requirement because of .NET Framework 4.6 usage
  The caller needs FWPM_ACTRL_OPEN access to the filter engine, basicaly, this module requres Administrator privileges on common system. If inacceptance, access may be configured as described in https://learn.microsoft.com/en-us/windows/win32/fwp/access-control
  Result same as "netsh rpc filter show filter"
.NOTES
  Version:        1.0
  Author:         vcudachi
  Creation Date:  2024-0318@1005
  License:        MIT
  
.EXAMPLE
  To get RPC filtrters info:
  Get-VRFEMrpcFilters | Out-GridView
#>

<#
MEMO:
https://www.akamai.com/blog/security/guide-rpc-filter
https://learn.microsoft.com/en-us/windows/win32/fwp/wfp-error-codes
https://github.com/danmar/clang-headers/blob/master/fwpmu.h
https://github.com/wmliang/wdk-10/blob/master/Include/10.0.14393.0/km/fwpmk.h
#>

#-----------------------------------------------------------[Functions]------------------------------------------------------------

#Creates in-memory module VRFEM and populates it with Win32 functions, enums and structures
#Does not support powershell prior to 5.1 because of .NET Framework 4.6 usage

Function Import-VRFEModule {
    Try {
        #Security checks
        If ($PSVersionTable.PSVersion -lt [Version]'5.1') {
            Return [UInt32]'0xffffffff'
        }
        $TestCount = 0
        Try {
            $null = [VRFEM.Fwpuclnt]
        }
        Catch {
            $TestCount++
        }
        If ($TestCount -eq 0) {
            Return [UInt32]'0x0'
        }
        #ElseIf ($TestCount -gt 0 -and $TestCount -lt 3) {
        #    Return [UInt32]'0xffffffff'
        #}

        #In-memory module builder
        $ModuleName = 'VRFEM' #Vcudachi RPC Filter Enumeration Module
        $AssemblyBuilder = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($ModuleName, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName)
    
        $DllImport = [Runtime.InteropServices.DllImportAttribute]
        $SetLastErrorField = $DllImport.GetField('SetLastError')
        $CallingConventionField = $DllImport.GetField('CallingConvention')
        $CharsetField = $DllImport.GetField('CharSet')
        $EntryPointField = $DllImport.GetField('EntryPoint')
        $SLEValue = $True
        $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])

        #Enum FWP_DATA_TYPE https://learn.microsoft.com/en-us/windows/win32/api/fwptypes/ne-fwptypes-fwp_data_type
        $FWP_DATA_TYPE_TypeBuilder = $ModuleBuilder.DefineEnum("$ModuleName.FWP_DATA_TYPE", 'Public', [UInt32])
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_EMPTY', [UInt32] 0)
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_UINT8', [UInt32] 1)
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_UINT16', [UInt32] 2)
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_UINT32', [UInt32] 3)
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_UINT64', [UInt32] 4)
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_INT8', [UInt32] 5)
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_INT16', [UInt32] 6)
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_INT32', [UInt32] 7)
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_INT64', [UInt32] 8)
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_FLOAT', [UInt32] 9)
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_DOUBLE', [UInt32] 10)
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_BYTE_ARRAY16_TYPE', [UInt32] 11)
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_BYTE_BLOB_TYPE', [UInt32] 12)
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_SID', [UInt32] 13)
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_SECURITY_DESCRIPTOR_TYPE', [UInt32] 14)
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_TOKEN_INFORMATION_TYPE', [UInt32] 15)
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_TOKEN_ACCESS_INFORMATION_TYPE,', [UInt32] 16)
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_UNICODE_STRING_TYPE', [UInt32] 17)
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_BYTE_ARRAY6_TYPE', [UInt32] 18)
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_SINGLE_DATA_TYPE_MAX', [UInt32] 255)
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_V4_ADDR_MASK', [UInt32] 256)
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_V6_ADDR_MASK', [UInt32] 257)
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_RANGE_TYPE', [UInt32] 258)
        $null = $FWP_DATA_TYPE_TypeBuilder.DefineLiteral('FWP_DATA_TYPE_MAX', [UInt32] 259)
        $null = $FWP_DATA_TYPE_TypeBuilder.CreateType()

        #Enum FWP_MATCH_TYPE https://learn.microsoft.com/en-us/windows/win32/api/fwptypes/ne-fwptypes-fwp_match_type
        $FWP_MATCH_TYPE_TypeBuilder = $ModuleBuilder.DefineEnum("$ModuleName.FWP_MATCH_TYPE", 'Public', [UInt32])
        $null = $FWP_MATCH_TYPE_TypeBuilder.DefineLiteral('FWP_MATCH_EQUAL', [UInt32] 0)
        $null = $FWP_MATCH_TYPE_TypeBuilder.DefineLiteral('FWP_MATCH_GREATER', [UInt32] 1)
        $null = $FWP_MATCH_TYPE_TypeBuilder.DefineLiteral('FWP_MATCH_LESS', [UInt32] 2)
        $null = $FWP_MATCH_TYPE_TypeBuilder.DefineLiteral('FWP_MATCH_GREATER_OR_EQUAL', [UInt32] 3)
        $null = $FWP_MATCH_TYPE_TypeBuilder.DefineLiteral('FWP_MATCH_LESS_OR_EQUAL', [UInt32] 4)
        $null = $FWP_MATCH_TYPE_TypeBuilder.DefineLiteral('FWP_MATCH_RANGE', [UInt32] 5)
        $null = $FWP_MATCH_TYPE_TypeBuilder.DefineLiteral('FWP_MATCH_FLAGS_ALL_SET', [UInt32] 6)
        $null = $FWP_MATCH_TYPE_TypeBuilder.DefineLiteral('FWP_MATCH_FLAGS_ANY_SET', [UInt32] 7)
        $null = $FWP_MATCH_TYPE_TypeBuilder.DefineLiteral('FWP_MATCH_FLAGS_NONE_SET', [UInt32] 8)
        $null = $FWP_MATCH_TYPE_TypeBuilder.DefineLiteral('FWP_MATCH_EQUAL_CASE_INSENSITIVE', [UInt32] 9)
        $null = $FWP_MATCH_TYPE_TypeBuilder.DefineLiteral('FWP_MATCH_NOT_EQUAL', [UInt32] 10)
        $null = $FWP_MATCH_TYPE_TypeBuilder.DefineLiteral('FWP_MATCH_PREFIX', [UInt32] 11)
        $null = $FWP_MATCH_TYPE_TypeBuilder.DefineLiteral('FWP_MATCH_NOT_PREFIX', [UInt32] 12)
        $null = $FWP_MATCH_TYPE_TypeBuilder.DefineLiteral('FWP_MATCH_TYPE_MAX', [UInt32] 13)
        $null = $FWP_MATCH_TYPE_TypeBuilder.CreateType()

        #Struct FWPM_DISPLAY_DATA0 https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_provider0
        $FWPM_DISPLAY_DATA0_TypeBuilder = $ModuleBuilder.DefineType("$ModuleName.FWPM_DISPLAY_DATA0", 'Public,BeforeFieldInit,SequentialLayout', [System.ValueType], [Reflection.Emit.PackingSize]::Unspecified)
        $null = $FWPM_DISPLAY_DATA0_TypeBuilder.DefineField('name', [IntPtr], 'Public') #[Runtime.InteropServices.Marshal]::PtrToStringUni()
        $null = $FWPM_DISPLAY_DATA0_TypeBuilder.DefineField('description', [IntPtr], 'Public')  #[Runtime.InteropServices.Marshal]::PtrToStringUni()
        $null = $FWPM_DISPLAY_DATA0_TypeBuilder.CreateType()

        #Struct FWP_BYTE_BLOB https://learn.microsoft.com/en-us/windows/win32/api/fwptypes/ns-fwptypes-fwp_byte_blob
        $FWP_BYTE_BLOB_TypeBuilder = $ModuleBuilder.DefineType("$ModuleName.FWP_BYTE_BLOB", 'Public,BeforeFieldInit,SequentialLayout', [System.ValueType], [Reflection.Emit.PackingSize]::Unspecified)
        $null = $FWP_BYTE_BLOB_TypeBuilder.DefineField('size', [UInt32], 'Public')
        $null = $FWP_BYTE_BLOB_TypeBuilder.DefineField('data', [IntPtr], 'Public')
        $null = $FWP_BYTE_BLOB_TypeBuilder.CreateType()

        #Struct FWP_VALUE0 https://learn.microsoft.com/en-us/windows/win32/api/fwptypes/ns-fwptypes-fwp_value0
        $FWP_VALUE0_TypeBuilder = $ModuleBuilder.DefineType("$ModuleName.FWP_VALUE0", 'Public,BeforeFieldInit,SequentialLayout', [System.ValueType], [Reflection.Emit.PackingSize]::Unspecified)
        $null = $FWP_VALUE0_TypeBuilder.DefineField('type', [VRFEM.FWP_DATA_TYPE], 'Public')
        $null = $FWP_VALUE0_TypeBuilder.DefineField('data', $(If ([Environment]::Is64BitProcess) {[UInt64]} Else {[UInt32]}), 'Public')
        $null = $FWP_VALUE0_TypeBuilder.CreateType()

        #Struct FWP_CONDITION_VALUE0 https://learn.microsoft.com/en-us/windows/win32/api/fwptypes/ns-fwptypes-fwp_value0
        $FWP_CONDITION_VALUE0_TypeBuilder = $ModuleBuilder.DefineType("$ModuleName.FWP_CONDITION_VALUE0", 'Public,BeforeFieldInit,SequentialLayout', [System.ValueType], [Reflection.Emit.PackingSize]::Unspecified)
        $null = $FWP_CONDITION_VALUE0_TypeBuilder.DefineField('type', [VRFEM.FWP_DATA_TYPE], 'Public')
        $null = $FWP_CONDITION_VALUE0_TypeBuilder.DefineField('data', [IntPtr], 'Public')   #may be [UInt64].
        $null = $FWP_CONDITION_VALUE0_TypeBuilder.CreateType()

        #Struct FWPM_FILTER_CONDITION0 https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_condition0
        $FWPM_FILTER_CONDITION0_TypeBuilder = $ModuleBuilder.DefineType("$ModuleName.FWPM_FILTER_CONDITION0", 'Public,BeforeFieldInit,SequentialLayout', [System.ValueType], [Reflection.Emit.PackingSize]::Unspecified)
        $null = $FWPM_FILTER_CONDITION0_TypeBuilder.DefineField('fieldKey00', [byte], 'Public')  #this for GUID 16 bytes
        $null = $FWPM_FILTER_CONDITION0_TypeBuilder.DefineField('fieldKey01', [byte], 'Public')
        $null = $FWPM_FILTER_CONDITION0_TypeBuilder.DefineField('fieldKey02', [byte], 'Public')
        $null = $FWPM_FILTER_CONDITION0_TypeBuilder.DefineField('fieldKey03', [byte], 'Public')
        $null = $FWPM_FILTER_CONDITION0_TypeBuilder.DefineField('fieldKey04', [byte], 'Public')
        $null = $FWPM_FILTER_CONDITION0_TypeBuilder.DefineField('fieldKey05', [byte], 'Public')
        $null = $FWPM_FILTER_CONDITION0_TypeBuilder.DefineField('fieldKey06', [byte], 'Public')
        $null = $FWPM_FILTER_CONDITION0_TypeBuilder.DefineField('fieldKey07', [byte], 'Public')
        $null = $FWPM_FILTER_CONDITION0_TypeBuilder.DefineField('fieldKey08', [byte], 'Public')
        $null = $FWPM_FILTER_CONDITION0_TypeBuilder.DefineField('fieldKey09', [byte], 'Public')
        $null = $FWPM_FILTER_CONDITION0_TypeBuilder.DefineField('fieldKey10', [byte], 'Public')
        $null = $FWPM_FILTER_CONDITION0_TypeBuilder.DefineField('fieldKey11', [byte], 'Public')
        $null = $FWPM_FILTER_CONDITION0_TypeBuilder.DefineField('fieldKey12', [byte], 'Public')
        $null = $FWPM_FILTER_CONDITION0_TypeBuilder.DefineField('fieldKey13', [byte], 'Public')
        $null = $FWPM_FILTER_CONDITION0_TypeBuilder.DefineField('fieldKey14', [byte], 'Public')
        $null = $FWPM_FILTER_CONDITION0_TypeBuilder.DefineField('fieldKey15', [byte], 'Public')
        $null = $FWPM_FILTER_CONDITION0_TypeBuilder.DefineField('matchType', [VRFEM.FWP_MATCH_TYPE], 'Public')
        $null = $FWPM_FILTER_CONDITION0_TypeBuilder.DefineField('conditionValue', [VRFEM.FWP_CONDITION_VALUE0], 'Public')
        $null = $FWPM_FILTER_CONDITION0_TypeBuilder.CreateType()

        #Struct FWPM_ACTION0 https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_action0
        $FWPM_ACTION0_TypeBuilder = $ModuleBuilder.DefineType("$ModuleName.FWPM_ACTION0", 'Public,BeforeFieldInit,SequentialLayout', [System.ValueType], [Reflection.Emit.PackingSize]::Unspecified)
        $null = $FWPM_ACTION0_TypeBuilder.DefineField('type', [UInt32], 'Public')
        $null = $FWPM_ACTION0_TypeBuilder.DefineField('filterType00', [byte], 'Public')  #this for GUID 16 bytes
        $null = $FWPM_ACTION0_TypeBuilder.DefineField('filterType01', [byte], 'Public')
        $null = $FWPM_ACTION0_TypeBuilder.DefineField('filterType02', [byte], 'Public')
        $null = $FWPM_ACTION0_TypeBuilder.DefineField('filterType03', [byte], 'Public')
        $null = $FWPM_ACTION0_TypeBuilder.DefineField('filterType04', [byte], 'Public')
        $null = $FWPM_ACTION0_TypeBuilder.DefineField('filterType05', [byte], 'Public')
        $null = $FWPM_ACTION0_TypeBuilder.DefineField('filterType06', [byte], 'Public')
        $null = $FWPM_ACTION0_TypeBuilder.DefineField('filterType07', [byte], 'Public')
        $null = $FWPM_ACTION0_TypeBuilder.DefineField('filterType08', [byte], 'Public')
        $null = $FWPM_ACTION0_TypeBuilder.DefineField('filterType09', [byte], 'Public')
        $null = $FWPM_ACTION0_TypeBuilder.DefineField('filterType10', [byte], 'Public')
        $null = $FWPM_ACTION0_TypeBuilder.DefineField('filterType11', [byte], 'Public')
        $null = $FWPM_ACTION0_TypeBuilder.DefineField('filterType12', [byte], 'Public')
        $null = $FWPM_ACTION0_TypeBuilder.DefineField('filterType13', [byte], 'Public')
        $null = $FWPM_ACTION0_TypeBuilder.DefineField('filterType14', [byte], 'Public')
        $null = $FWPM_ACTION0_TypeBuilder.DefineField('filterType15', [byte], 'Public')
        $null = $FWPM_ACTION0_TypeBuilder.CreateType()

        #Struct FWPM_PROVIDER0 https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_provider0
        $FWPM_PROVIDER0_TypeBuilder = $ModuleBuilder.DefineType("$ModuleName.FWPM_PROVIDER0", 'Public,BeforeFieldInit,SequentialLayout', [System.ValueType], [Reflection.Emit.PackingSize]::Unspecified)
        $null = $FWPM_PROVIDER0_TypeBuilder.DefineField('providerKey00', [byte], 'Public')  #this for GUID 16 bytes
        $null = $FWPM_PROVIDER0_TypeBuilder.DefineField('providerKey01', [byte], 'Public')
        $null = $FWPM_PROVIDER0_TypeBuilder.DefineField('providerKey02', [byte], 'Public')
        $null = $FWPM_PROVIDER0_TypeBuilder.DefineField('providerKey03', [byte], 'Public')
        $null = $FWPM_PROVIDER0_TypeBuilder.DefineField('providerKey04', [byte], 'Public')
        $null = $FWPM_PROVIDER0_TypeBuilder.DefineField('providerKey05', [byte], 'Public')
        $null = $FWPM_PROVIDER0_TypeBuilder.DefineField('providerKey06', [byte], 'Public')
        $null = $FWPM_PROVIDER0_TypeBuilder.DefineField('providerKey07', [byte], 'Public')
        $null = $FWPM_PROVIDER0_TypeBuilder.DefineField('providerKey08', [byte], 'Public')
        $null = $FWPM_PROVIDER0_TypeBuilder.DefineField('providerKey09', [byte], 'Public')
        $null = $FWPM_PROVIDER0_TypeBuilder.DefineField('providerKey10', [byte], 'Public')
        $null = $FWPM_PROVIDER0_TypeBuilder.DefineField('providerKey11', [byte], 'Public')
        $null = $FWPM_PROVIDER0_TypeBuilder.DefineField('providerKey12', [byte], 'Public')
        $null = $FWPM_PROVIDER0_TypeBuilder.DefineField('providerKey13', [byte], 'Public')
        $null = $FWPM_PROVIDER0_TypeBuilder.DefineField('providerKey14', [byte], 'Public')
        $null = $FWPM_PROVIDER0_TypeBuilder.DefineField('providerKey15', [byte], 'Public')
        $null = $FWPM_PROVIDER0_TypeBuilder.DefineField('displayData', [VRFEM.FWPM_DISPLAY_DATA0], 'Public')
        $null = $FWPM_PROVIDER0_TypeBuilder.DefineField('flags', [UInt32], 'Public')
        $null = $FWPM_PROVIDER0_TypeBuilder.DefineField('providerData', [VRFEM.FWP_BYTE_BLOB], 'Public')
        $null = $FWPM_PROVIDER0_TypeBuilder.DefineField('serviceName', [IntPtr], 'Public')  #[Runtime.InteropServices.Marshal]::PtrToStringUni()
        $null = $FWPM_PROVIDER0_TypeBuilder.CreateType()

        #Struct FWPM_FILTER0 https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
        $FWPM_FILTER0_TypeBuilder = $ModuleBuilder.DefineType("$ModuleName.FWPM_FILTER0", 'Public,BeforeFieldInit,SequentialLayout', [System.ValueType], [Reflection.Emit.PackingSize]::Unspecified)
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('filterKey00', [byte], 'Public')  #this for GUID 16 bytes
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('filterKey01', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('filterKey02', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('filterKey03', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('filterKey04', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('filterKey05', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('filterKey06', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('filterKey07', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('filterKey08', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('filterKey09', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('filterKey10', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('filterKey11', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('filterKey12', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('filterKey13', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('filterKey14', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('filterKey15', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('displayData', [VRFEM.FWPM_DISPLAY_DATA0], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('flags', [UInt32], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('providerKey', [IntPtr], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('providerData', [VRFEM.FWP_BYTE_BLOB], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('layerKey00', [byte], 'Public')  #this for GUID 16 bytes
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('layerKey01', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('layerKey02', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('layerKey03', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('layerKey04', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('layerKey05', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('layerKey06', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('layerKey07', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('layerKey08', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('layerKey09', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('layerKey10', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('layerKey11', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('layerKey12', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('layerKey13', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('layerKey14', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('layerKey15', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('sublayerKey00', [byte], 'Public')  #this for GUID 16 bytes
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('sublayerKey01', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('sublayerKey02', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('sublayerKey03', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('sublayerKey04', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('sublayerKey05', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('sublayerKey06', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('sublayerKey07', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('sublayerKey08', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('sublayerKey09', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('sublayerKey10', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('sublayerKey11', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('sublayerKey12', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('sublayerKey13', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('sublayerKey14', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('sublayerKey15', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('weight', [VRFEM.FWP_VALUE0], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('numFilterConditions', [UInt32], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('filterCondition', [IntPtr], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('action', [VRFEM.FWPM_ACTION0], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('providerContextKey00', [byte], 'Public')  #this for GUID 16 bytes
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('providerContextKey01', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('providerContextKey02', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('providerContextKey03', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('providerContextKey04', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('providerContextKey05', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('providerContextKey06', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('providerContextKey07', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('providerContextKey08', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('providerContextKey09', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('providerContextKey10', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('providerContextKey11', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('providerContextKey12', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('providerContextKey13', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('providerContextKey14', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('providerContextKey15', [byte], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('reserved', [IntPtr], 'Public')
        If (-not [Environment]::Is64BitProcess) {$null = $FWPM_FILTER0_TypeBuilder.DefineField('__IGNORE_THIS__', [IntPtr], 'Public')} #There is a packaging gap on 32-bit systems
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('filterId', [UInt64], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.DefineField('effectiveWeight', [VRFEM.FWP_VALUE0], 'Public')
        $null = $FWPM_FILTER0_TypeBuilder.CreateType()

        #Struct FWPM_FILTER_ENUM_TEMPLATE0 https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter_enum_template0
        $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder = $ModuleBuilder.DefineType("$ModuleName.FWPM_FILTER_ENUM_TEMPLATE0", 'Public,BeforeFieldInit,SequentialLayout', [System.ValueType], [Reflection.Emit.PackingSize]::Unspecified)
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('providerKey', [IntPtr], 'Public') 
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('layerKey00', [byte], 'Public')  #this for GUID 16 bytes
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('layerKey01', [byte], 'Public')
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('layerKey02', [byte], 'Public')
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('layerKey03', [byte], 'Public')
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('layerKey04', [byte], 'Public')
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('layerKey05', [byte], 'Public')
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('layerKey06', [byte], 'Public')
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('layerKey07', [byte], 'Public')
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('layerKey08', [byte], 'Public')
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('layerKey09', [byte], 'Public')
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('layerKey10', [byte], 'Public')
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('layerKey11', [byte], 'Public')
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('layerKey12', [byte], 'Public')
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('layerKey13', [byte], 'Public')
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('layerKey14', [byte], 'Public')
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('layerKey15', [byte], 'Public')
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('enumType', [UInt32], 'Public')
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('flags', [UInt32], 'Public')
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('providerContextTemplate', [IntPtr], 'Public') 
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('numFilterConditions', [UInt32], 'Public')
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('filterCondition', [IntPtr], 'Public') 
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('actionMask', [UInt32], 'Public')
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.DefineField('calloutKey', [IntPtr], 'Public') 
        $null = $FWPM_FILTER_ENUM_TEMPLATE0_TypeBuilder.CreateType()

        #FWPUCLNT.dll
        $Fwpuclnt_TypeBuilder = $ModuleBuilder.DefineType("$ModuleName.Fwpuclnt", 'Public,BeforeFieldInit')

        #Function FwpmEngineOpen0 https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0
        $FwpmEngineOpen0_method = $Fwpuclnt_TypeBuilder.DefineMethod(
            'FwpmEngineOpen0',
            'Public,Static,PinvokeImpl',
            [UInt32],
            @(
                [IntPtr], # [in, optional] const wchar_t             *serverName,
                [UInt32], # [in]           UINT32                    authnService,
                [IntPtr], # [in, optional] SEC_WINNT_AUTH_IDENTITY_W *authIdentity,
                [IntPtr], # [in, optional] const FWPM_SESSION0       *session,
                [IntPtr].MakeByRefType() # [out]          HANDLE                    *engineHandle
            )
        )
        
        #Function FwpmFilterCreateEnumHandle0 https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfiltercreateenumhandle0
        $FwpmFilterCreateEnumHandle0_method = $Fwpuclnt_TypeBuilder.DefineMethod(
            'FwpmFilterCreateEnumHandle0',
            'Public,Static,PinvokeImpl',
            [UInt32],
            @(
                [IntPtr], # [in]           HANDLE                           engineHandle,
                [IntPtr], # [in, optional] const FWPM_FILTER_ENUM_TEMPLATE0 *enumTemplate,
                [IntPtr].MakeByRefType() # [out]          HANDLE            *enumHandle
            )
        )

        #Function FwpmFilterEnum0 https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilterenum0
        $FwpmFilterEnum0_method = $Fwpuclnt_TypeBuilder.DefineMethod(
            'FwpmFilterEnum0',
            'Public,Static,PinvokeImpl',
            [UInt32],
            @(
                [IntPtr], # [in]  HANDLE       engineHandle,
                [IntPtr], # [in]  HANDLE       enumHandle,
                [UInt32], # [in]  UINT32       numEntriesRequested,
                [IntPtr].MakeByRefType(), # [out] FWPM_FILTER0 ***entries,
                [UInt32].MakeByRefType()    # [out] UINT32       *numEntriesReturned
            )
        )

        #Function FwpmProviderCreateEnumHandle0 https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmprovidercreateenumhandle0
        $FwpmProviderCreateEnumHandle0_method = $Fwpuclnt_TypeBuilder.DefineMethod(
            'FwpmProviderCreateEnumHandle0',
            'Public,Static,PinvokeImpl',
            [UInt32],
            @(
                [IntPtr], # [in]           HANDLE                           engineHandle,
                [IntPtr], # [in, optional] const FWPM_FILTER_ENUM_TEMPLATE0 *enumTemplate,
                [IntPtr].MakeByRefType() # [out]          HANDLE            *enumHandle
            )
        )

        #Function FwpmProviderEnum0 https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmproviderenum0
        $FwpmProviderEnum0_method = $Fwpuclnt_TypeBuilder.DefineMethod(
            'FwpmProviderEnum0',
            'Public,Static,PinvokeImpl',
            [UInt32],
            @(
                [IntPtr], # [in]  HANDLE       engineHandle,
                [IntPtr], # [in]  HANDLE       enumHandle,
                [UInt32], # [in]  UINT32       numEntriesRequested,
                [IntPtr].MakeByRefType(), # [out] FWPM_PROVIDER0 ***entries,
                [UInt32].MakeByRefType()    # [out] UINT32       *numEntriesReturned
            )
        )

        #Function FwpmEngineClose0 https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineclose0
        $FwpmEngineClose0_method = $Fwpuclnt_TypeBuilder.DefineMethod(
            'FwpmEngineClose0',
            'Public,Static,PinvokeImpl',
            [UInt32],
            @(
                [IntPtr] # [in]  HANDLE       engineHandle
            )
        )

        #Function FwpmFilterDestroyEnumHandle0 https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilterdestroyenumhandle0
        $FwpmFilterDestroyEnumHandle0_method = $Fwpuclnt_TypeBuilder.DefineMethod(
            'FwpmFilterDestroyEnumHandle0',
            'Public,Static,PinvokeImpl',
            [UInt32],
            @(
                [IntPtr], # [in]  HANDLE       engineHandle,
                [IntPtr] # [in]  HANDLE       enumHandle
            )
        )

        #Function FwpmFreeMemory0 https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfreememory0
        $FwpmFreeMemory0_method = $Fwpuclnt_TypeBuilder.DefineMethod(
            'FwpmFreeMemory0',
            'Public,Static,PinvokeImpl',
            [Void],
            @(
                [IntPtr].MakeByRefType() # [in, out] void **p
            )
        )

        #Build attributes
        @('Fwpuclnt', $FwpmEngineOpen0_method), `
        @('Fwpuclnt', $FwpmFilterCreateEnumHandle0_method), `
        @('Fwpuclnt', $FwpmFilterEnum0_method), `
        @('Fwpuclnt', $FwpmProviderCreateEnumHandle0_method), `
        @('Fwpuclnt', $FwpmProviderEnum0_method), `
        @('Fwpuclnt', $FwpmEngineClose0_method), `
        @('Fwpuclnt', $FwpmFilterDestroyEnumHandle0_method), `
        @('Fwpuclnt', $FwpmFreeMemory0_method) | ForEach-Object {
            $DllImportAttribute = [Reflection.Emit.CustomAttributeBuilder]::New(
                $Constructor,
                $_[0], 
                [Reflection.PropertyInfo[]] @(), 
                [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField, $EntryPointField),
                [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention]::StdCall), ([Runtime.InteropServices.CharSet]::Unicode), $_[1].Name)
            )
            $_[1].SetCustomAttribute($DllImportAttribute)
        }

        #Create types
        $null = $Fwpuclnt_TypeBuilder.CreateType()

        #Success
        Return [UInt32]'0x0'
    }
    Catch {
        #Failed
        Return [UInt32]'0xffffffff'
    }
}

Function Convert-BytePropsToGUID {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        $InputObject,
        [Parameter(Mandatory = $true)]
        [String]$PropMask
    )
    $Values = $InputObject.psobject.Members | Where-Object { $_.Name -like $PropMask } | ForEach-Object Value
    $BA = [Byte[]]::New(16)
    If ($Values.Count -eq 16) {
        $i = 0
        $Values | ForEach-Object {
            $BA[($i++)] = $_
        }
        Return [Guid]::New($BA)
    }
}

Function Decode-Action {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [UInt32]$Action
    )
    # DOCS HERE: https://android.googlesource.com/toolchain/mingw/+/refs/heads/main/mingw-w64-v6.x/mingw-w64-headers/include/fwptypes.h
    If (($Action -band 5) -eq 5) {
        Return 'FWP_ACTION_CALLOUT_UNKNOWN'
    }
    ElseIf (($Action -band 4) -eq 4) {
        Return 'FWP_ACTION_CALLOUT_INSPECTION'
    }
    ElseIf (($Action -band 3) -eq 3) {
        Return 'FWP_ACTION_CALLOUT_TERMINATING'
    }
    ElseIf (($Action -band 2) -eq 2) {
        Return 'FWP_ACTION_PERMIT'
    }
    ElseIf (($Action -band 1) -eq 1) {
        Return 'FWP_ACTION_BLOCK'
    }
}

Function Decode-FilterFlags {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [UInt32]$Flags
    )
    Function Decode-FilterFlag {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $true)]
            [UInt32]$Flag
        )
        # Constanfs from here: https://github.com/tpn/winsdk-10/blob/master/Include/10.0.10240.0/shared/fwpmtypes.idl
        Switch ($Flag) {
            ([UInt32]'0x00000000') {
                Return 'FWPM_FILTER_FLAG_NONE'
            }
            ([UInt32]'0x00000001') {
                Return 'FWPM_FILTER_FLAG_PERSISTENT'
            }
            ([UInt32]'0x00000002') {
                Return 'FWPM_FILTER_FLAG_BOOTTIME'
            }
            ([UInt32]'0x00000004') {
                Return 'FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT'
            }
            ([UInt32]'0x00000008') {
                Return 'FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT'
            }
            ([UInt32]'0x00000010') {
                Return 'FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED'
            }
            ([UInt32]'0x00000020') {
                Return 'FWPM_FILTER_FLAG_DISABLED'
            }
            ([UInt32]'0x00000040') {
                Return 'FWPM_FILTER_FLAG_INDEXED'
            }
            ([UInt32]'0x00000080') {
                Return 'FWPM_FILTER_FLAG_HAS_SECURITY_REALM_PROVIDER_CONTEXT'
            }
        }
    }
    If ($Flags -eq [UInt32]'0x00000000') {
        Return (Decode-FilterFlag -Flag $Flags)
    }
    $Results = @()
    0..7 | ForEach-Object {
        $Prover = [UInt32][Math]::Pow(2, $_)
        If (($Flags -band $Prover) -eq $Prover) {
            $Results += (Decode-FilterFlag -Flag $Prover)
        }
    }
    Return ($Results -join '|')
}

Function Get-VRFEMrpcFilters {
    [CmdletBinding()]
    Param()

    If ((Import-VRFEModule) -ne 0) {
        Write-Error -Message 'Unable to create in-memory module. Please, rerun this cmdlet in new powershell process (version 5.1/7.0 or above)'
        Return
    }

    #Layers
    #https://learn.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
    # GUIDS HERE: https://github.com/wmliang/wdk-10/blob/master/Include/10.0.14393.0/km/fwpmk.h
    $FWPM_LAYER_RPC_UM = [Guid]::New('75a89dda-95e4-40f3-adc7-7688a9c847e1')
    $FWPM_LAYER_RPC_EPMAP = [Guid]::New('9247bc61-eb07-47ee-872c-bfd78bfd1616')
    $FWPM_LAYER_RPC_EP_ADD = [Guid]::New('618dffc7-c450-4943-95db-99b4c16a55d4')
    $FWPM_LAYER_RPC_PROXY_CONN = [Guid]::New('94a4b50b-ba5c-4f27-907a-229fac0c2a7a')
    $FWPM_LAYER_RPC_PROXY_IF = [Guid]::New('f8a38615-e12c-41ac-98df-121ad981aade')

    $engine = [IntPtr]::Zero
    $null = [VRFEM.Fwpuclnt]::FwpmEngineOpen0(
        [IntPtr]::Zero,
        10, #RPC_C_AUTHN_WINNT https://learn.microsoft.com/ru-ru/windows/win32/rpc/authentication-service-constants
        [IntPtr]::Zero,
        [IntPtr]::Zero,
        [ref]$engine
    )
    $FWPM_LAYER_RPC_UM, $FWPM_LAYER_RPC_EPMAP, $FWPM_LAYER_RPC_EP_ADD, $FWPM_LAYER_RPC_PROXY_CONN, $FWPM_LAYER_RPC_PROXY_IF | ForEach-Object {
        $cnt = [uint32]0
        $FilterEntries = [IntPtr]::Zero
        $EnumHandle = [IntPtr]::Zero
        $enumTemplate = [VRFEM.FWPM_FILTER_ENUM_TEMPLATE0]::New()
        $enumTemplate.enumType = 1 #FWP_FILTER_ENUM_OVERLAPPING
        $enumTemplate.flags = 2    #FWP_FILTER_ENUM_FLAG_SORTED
        $enumTemplate.actionMask = [uint32]'0xFFFFFFFF'    #Ignore the filter's action type when enumerating.
        $gba = $_.ToByteArray() #guid to byte array
        $enumTemplate.layerKey00 = $gba[0]
        $enumTemplate.layerKey01 = $gba[1]
        $enumTemplate.layerKey02 = $gba[2]
        $enumTemplate.layerKey03 = $gba[3]
        $enumTemplate.layerKey04 = $gba[4]
        $enumTemplate.layerKey05 = $gba[5]
        $enumTemplate.layerKey06 = $gba[6]
        $enumTemplate.layerKey07 = $gba[7]
        $enumTemplate.layerKey08 = $gba[8]
        $enumTemplate.layerKey09 = $gba[9]
        $enumTemplate.layerKey10 = $gba[10]
        $enumTemplate.layerKey11 = $gba[11]
        $enumTemplate.layerKey12 = $gba[12]
        $enumTemplate.layerKey13 = $gba[13]
        $enumTemplate.layerKey14 = $gba[14]
        $enumTemplate.layerKey15 = $gba[15]
        $SSyze = [System.Runtime.InteropServices.Marshal]::SizeOf([System.Type][VRFEM.FWPM_FILTER_ENUM_TEMPLATE0])
        $enumTemplatePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SSyze)
        [System.Runtime.InteropServices.Marshal]::Copy([Byte[]]::New($SSyze), 0, $enumTemplatePtr, $SSyze)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($enumTemplate, $enumTemplatePtr, $false)

        $null = [VRFEM.Fwpuclnt]::FwpmFilterCreateEnumHandle0($engine, $enumTemplatePtr, [ref]$EnumHandle)

        $null = [VRFEM.Fwpuclnt]::FwpmFilterEnum0($engine, $EnumHandle, [int32]::MaxValue, [ref]$FilterEntries, [ref]$cnt)
        If ($cnt -gt 0) {
            0..($cnt - 1) | ForEach-Object {
                $FilterEntry = [IntPtr]::Zero
                $FilterEntry = [Runtime.InteropServices.Marshal]::PtrToStructure([intptr]::Add($FilterEntries, ($_ * [System.IntPtr]::Size)), [system.type][System.IntPtr])
                $Filter = $null
                $Filter = [Runtime.InteropServices.Marshal]::PtrToStructure($FilterEntry, [System.Type][VRFEM.FWPM_FILTER0])
                $Result = $null
                $Result = [PSCustomObject]@{
                    FilterId          = '0x' + [Convert]::ToString($Filter.FilterId, 16).PadLeft(8, '0')
                    FilterGuid        = Convert-BytePropsToGUID -InputObject $Filter -PropMask 'filterKey*'
                    FilterName        = [Runtime.InteropServices.Marshal]::PtrToStringUni($Filter.displayData.Name)
                    FilterDescription = [Runtime.InteropServices.Marshal]::PtrToStringUni($Filter.displayData.Description)
                    Flags             = Decode-FilterFlags -Flags $Filter.flags
                    LayerGuid         = Convert-BytePropsToGUID -InputObject $Filter -PropMask 'layerKey*'
                    SublayerGuid      = Convert-BytePropsToGUID -InputObject $Filter -PropMask 'sublayerKey*'
                    Action            = Decode-Action -Action $Filter.action.type
                    FilterCondition   = [PSCustomObject[]]::New($Filter.numFilterConditions)
                    RawFilter         = $Filter
                }
                If ($Filter.numFilterConditions -gt 0) {
                    0..($Filter.numFilterConditions - 1) | ForEach-Object {
                        $Condition = $null
                        $Condition = [Runtime.InteropServices.Marshal]::PtrToStructure([intptr]::Add($Filter.filterCondition, ($_ * [System.Runtime.InteropServices.Marshal]::SizeOf([System.Type][VRFEM.FWPM_FILTER_CONDITION0]))), [System.Type][VRFEM.FWPM_FILTER_CONDITION0])
                        $Result.filterCondition[$_] = [PSCustomObject]@{
                            fieldKey                = Convert-BytePropsToGUID -InputObject $Condition -PropMask 'fieldKey*'
                            matchType               = $Condition.matchType
                            conditionValueType      = $Condition.conditionValue.Type
                            conditionValueInterpret = If ($Condition.conditionValue.type -eq [VRFEM.FWP_DATA_TYPE]::FWP_BYTE_ARRAY16_TYPE) {
                                $ba = [byte[]]::New(16)
                                [System.Runtime.InteropServices.Marshal]::Copy($Condition.conditionValue.data, $ba, 0, 16)
                                [guid]::New($ba)
                            } 
                            Else {
                                $null
                            };
                        }
                    }
                }
                $Result
            }
        }
        $null = [VRFEM.Fwpuclnt]::FwpmFilterDestroyEnumHandle0($engine, $EnumHandle)
        $null = [VRFEM.Fwpuclnt]::FwpmFreeMemory0([ref]$FilterEntries)
    }
    $null = [VRFEM.Fwpuclnt]::FwpmEngineClose0($engine)
}