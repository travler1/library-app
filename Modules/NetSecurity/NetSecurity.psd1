@{
    ModuleVersion = '2.0.0.0'
    FormatsToProcess = 'NetSecurity.formats.ps1xml'
    TypesToProcess = 'NetSecurity.types.ps1xml'
    NestedModules = @(
        "Microsoft.Windows.Firewall.Commands.dll",
        "NetFirewallRule.cmdletDefinition.cdxml",
        "NetIPsecRule.cmdletDefinition.cdxml",
        "NetIPsecMainModeRule.cmdletDefinition.cdxml",
        "NetFirewallAddressFilter.cmdletDefinition.cdxml",
        "NetFirewallApplicationFilter.cmdletDefinition.cdxml",
        "NetFirewallInterfaceFilter.cmdletDefinition.cdxml",
        "NetFirewallInterfaceTypeFilter.cmdletDefinition.cdxml",
        "NetFirewallSecurityFilter.cmdletDefinition.cdxml",
        "NetFirewallPortFilter.cmdletDefinition.cdxml",
        "NetFirewallServiceFilter.cmdletDefinition.cdxml",
        "NetIPsecPhase1AuthSet.cmdletDefinition.cdxml",
        "NetIPsecPhase2AuthSet.cmdletDefinition.cdxml",
        "NetIPsecMainModeCryptoSet.cmdletDefinition.cdxml",
        "NetIPsecQuickModeCryptoSet.cmdletDefinition.cdxml",
        "NetFirewallProfile.cmdletDefinition.cdxml",
        "NetIPsecPolicyChange.cmdletDefinition.cdxml",
        "NetIPsecDospSetting.cmdletDefinition.cdxml",
        "NetIPsecIdentity.cmdletDefinition.cdxml",
        "NetIPsecMainModeSA.cmdletDefinition.cdxml",
        "NetIPsecQuickModeSA.cmdletDefinition.cdxml",
        "NetFirewallSetting.cmdletDefinition.cdxml",
        "NetFirewallDynamicKeywordAddress.cmdletDefinition.cdxml",
        "NetGPO.cmdletDefinition.cdxml"
    )
    GUID = '{4B26FF51-7AEE-4731-9CF7-508B82532CBF}'
    Author = 'Microsoft Corporation'
    CompanyName = 'Microsoft Corporation'
    PowerShellVersion = '3.0'
    ClrVersion = '4.0'
    Copyright = '(c) Microsoft Corporation. All rights reserved.'
    HelpInfoUri = "https://go.microsoft.com/fwlink/?linkid=285764"
    CompatiblePSEditions = 'Desktop', 'Core'

    FunctionsToExport = @(
        "Copy-NetFirewallRule",
        "Copy-NetIPsecMainModeCryptoSet",
        "Copy-NetIPsecMainModeRule",
        "Copy-NetIPsecPhase1AuthSet",
        "Copy-NetIPsecPhase2AuthSet",
        "Copy-NetIPsecQuickModeCryptoSet",
        "Copy-NetIPsecRule",
        "Disable-NetFirewallRule",
        "Disable-NetIPsecMainModeRule",
        "Disable-NetIPsecRule",
        "Enable-NetFirewallRule",
        "Enable-NetIPsecMainModeRule",
        "Enable-NetIPsecRule",
        "Get-NetFirewallAddressFilter",
        "Get-NetFirewallApplicationFilter",
        "Get-NetFirewallDynamicKeywordAddress",
        "Get-NetFirewallInterfaceFilter",
        "Get-NetFirewallInterfaceTypeFilter",
        "Get-NetFirewallPortFilter",
        "Get-NetFirewallProfile",
        "Get-NetFirewallRule",
        "Get-NetFirewallSecurityFilter",
        "Get-NetFirewallServiceFilter",
        "Get-NetFirewallSetting",
        "Get-NetIPsecDospSetting",
        "Get-NetIPsecMainModeCryptoSet",
        "Get-NetIPsecMainModeRule",
        "Get-NetIPsecMainModeSA",
        "Get-NetIPsecPhase1AuthSet",
        "Get-NetIPsecPhase2AuthSet",
        "Get-NetIPsecQuickModeCryptoSet",
        "Get-NetIPsecQuickModeSA",
        "Get-NetIPsecRule",
        "New-NetFirewallRule",
        "New-NetFirewallDynamicKeywordAddress",
        "New-NetIPsecDospSetting",
        "New-NetIPsecMainModeCryptoSet",
        "New-NetIPsecMainModeRule",
        "New-NetIPsecPhase1AuthSet",
        "New-NetIPsecPhase2AuthSet",
        "New-NetIPsecQuickModeCryptoSet",
        "New-NetIPsecRule",
        "Open-NetGPO",
        "Remove-NetFirewallRule",
        "Remove-NetFirewallDynamicKeywordAddress",
        "Remove-NetIPsecDospSetting",
        "Remove-NetIPsecMainModeCryptoSet",
        "Remove-NetIPsecMainModeRule",
        "Remove-NetIPsecMainModeSA",
        "Remove-NetIPsecPhase1AuthSet",
        "Remove-NetIPsecPhase2AuthSet",
        "Remove-NetIPsecQuickModeCryptoSet",
        "Remove-NetIPsecQuickModeSA",
        "Remove-NetIPsecRule",
        "Rename-NetFirewallRule",
        "Rename-NetIPsecMainModeCryptoSet",
        "Rename-NetIPsecMainModeRule",
        "Rename-NetIPsecPhase1AuthSet",
        "Rename-NetIPsecPhase2AuthSet",
        "Rename-NetIPsecQuickModeCryptoSet",
        "Rename-NetIPsecRule",
        "Save-NetGPO",
        "Find-NetIPsecRule",
        "Set-NetFirewallAddressFilter",
        "Set-NetFirewallApplicationFilter",
        "Set-NetFirewallInterfaceFilter",
        "Set-NetFirewallInterfaceTypeFilter",
        "Set-NetFirewallPortFilter",
        "Set-NetFirewallProfile",
        "Set-NetFirewallRule",
        "Set-NetFirewallSecurityFilter",
        "Set-NetFirewallServiceFilter",
        "Set-NetFirewallSetting",
        "Set-NetIPsecDospSetting",
        "Set-NetIPsecMainModeCryptoSet",
        "Set-NetIPsecMainModeRule",
        "Set-NetIPsecPhase1AuthSet",
        "Set-NetIPsecPhase2AuthSet",
        "Set-NetIPsecQuickModeCryptoSet",
        "Set-NetIPsecRule",
        "Show-NetFirewallRule",
        "Show-NetIPsecRule",
        "Sync-NetIPsecRule",
        "Update-NetIPsecRule",
        "Update-NetFirewallDynamicKeywordAddress"
    )
    CmdletsToExport = @(
        "Get-DAPolicyChange",
        "New-NetIPsecAuthProposal",
        "New-NetIPsecMainModeCryptoProposal",
        "New-NetIPsecQuickModeCryptoProposal"
    )
    AliasesToExport = @(
    )
}

