[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)]
    [String] $Scope,

    [Parameter(Mandatory = $true)]
    [String] $PolicyType,

    [Parameter(Mandatory = $true)]
    [String] $Policy,

    [Parameter(Mandatory = $true)]
    [String] $ManagementGroupId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Set-PolicyInitiative {
    Param (
        [Parameter(Mandatory = $true)]
        [String] $policyFile
    )

    Write-Output "Retrieving content from policy file '$policyFile'."
    $policyContent = Get-Content -Path $policyFile | ConvertFrom-Json
    Write-Output "Uploading policy initiative '$($policyContent.name)' to Management Group '$ManagementGroupId'."

    $policyDefinitions = $policyContent.properties.policyDefinitions | ConvertTo-Json -Depth 50
    $policyParameters  = $policyContent.properties.parameters | ConvertTo-Json -Depth 50
    $policyMetadata    = $policyContent.properties.metadata | ConvertTo-Json -Depth 50

    $policies = Get-AzPolicySetDefinition -ManagementGroupName $ManagementGroupId -Custom
    $currentPolicy = $policies | Where-Object {$_.Name -eq $policyContent.name}

    if ($currentPolicy) {
        Write-Output "Policy already exists, updating the policy initiative."
        Set-AzPolicySetDefinition `
            -Name $policyContent.name `
            -DisplayName $policyContent.properties.displayName `
            -Description $policyContent.properties.description `
            -PolicyDefinition $policyDefinitions `
            -ManagementGroupName $ManagementGroupId `
            -Parameter $policyParameters `
            -Metadata $policyMetadata
    }
    else {
        Write-Output "Policy does not exist yet, creating the policy initiative."
        New-AzPolicySetDefinition `
            -Name $policyContent.name `
            -DisplayName $policyContent.properties.displayName `
            -Description $policyContent.properties.description `
            -PolicyDefinition $policyDefinitions `
            -ManagementGroupName $ManagementGroupId `
            -Parameter $policyParameters `
            -Metadata $policyMetadata
    }
}

function Set-PolicyDefinition {
    Param (
        [Parameter(Mandatory = $true)]
        [String] $policyFile
    )

    $policyContent = Get-Content -Path $policyFile | ConvertFrom-Json
    Write-Output "Uploading policy definition '$($policyContent.name)'."

    $policyRule        = $policyContent.properties.policyRule | ConvertTo-Json -Depth 50
    $policyParameters  = $policyContent.properties.parameters | ConvertTo-Json -Depth 50
    $policyMetadata    = $policyContent.properties.metadata | ConvertTo-Json -Depth 50

    $policies = Get-AzPolicyDefinition -ManagementGroupName $ManagementGroupId -Custom
    $currentPolicy = $policies | Where-Object {$_.Name -eq $policyContent.name}

    if ($currentPolicy) {
        Write-Output "Policy already exists, updating the policy definition."
        Set-AzPolicyDefinition `
            -Name $policyContent.name `
            -DisplayName $policyContent.properties.displayName `
            -Description $policyContent.properties.description `
            -Policy $policyRule `
            -ManagementGroupName $ManagementGroupId `
            -Parameter $policyParameters `
            -Metadata $policyMetadata `
            -Mode $policyContent.properties.mode
    }
    else {
        Write-Output "Policy does not exist yet, creating the policy definition."
        New-AzPolicyDefinition `
            -Name $policyContent.name `
            -DisplayName $policyContent.properties.displayName `
            -Description $policyContent.properties.description `
            -Policy $policyRule `
            -ManagementGroupName $ManagementGroupId `
            -Parameter $policyParameters `
            -Metadata $policyMetadata `
            -Mode $policyContent.properties.mode
    }
}

if (-not (Test-Path -Path $Policy -PathType Any)) {
    Write-Error "Could not find the policy file or folder: '$Policy'."
}
$isFolder = Test-Path -Path $Policy -PathType Container

if ($PolicyType -eq "definition") {
    if ($isFolder) {
        Write-Output "The provided policy input is a folder. Searching for policy definition files in '$Policy' using the '*.json' filter."
        $policyFiles = @(Get-ChildItem -Path $Policy -File -Recurse -Filter "*.json")
        Write-Output "Found $($policyFiles.Count) policy definition files."

        foreach ($policyFile in $policyFiles) {
            Set-PolicyDefinition -policyFile $policyFile.FullName
        }
    }
    else {
        Set-PolicyDefinition -policyFile $Policy
    }
}
else {
    if ($isFolder) {
        Write-Output "The provided policy input is a folder. Searching for policy initiative files in '$Policy' using the '*.initiative.json' filter."
        $policyFiles = @(Get-ChildItem -Path $Policy -File -Recurse -Filter "*.initiative.json")
        Write-Output "Found $($policyFiles.Count) policy initiative files."

        foreach ($policyFile in $policyFiles) {
            Set-PolicyInitiative -policyFile $policyFile.FullName
        }
    }
    else {
        Set-PolicyInitiative -policyFile $Policy
    }
}