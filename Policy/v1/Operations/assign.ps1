[CmdletBinding()]
Param (
    [Parameter(Mandatory = $true)]
    [String] $Scope,

    [Parameter(Mandatory = $true)]
    [String] $PolicyType,

    [Parameter(Mandatory = $true)]
    [String] $Policy,

    [Parameter(Mandatory = $true)]
    [String] $Location,

    [Parameter(Mandatory = $true)]
    [Bool] $PolicyHasParameters,

    [Parameter(Mandatory = $false)]
    [String] $PolicyParameters,

    [Parameter(Mandatory = $false)]
    [String] $ManagementGroupId,

    [Parameter(Mandatory = $false)]
    [String] $SubscriptionId,

    [Parameter(Mandatory = $false)]
    [String] $ResourceGroupName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Set-PolicyAssignment {
    Param (
        [Parameter(Mandatory = $true)]
        [String] $policyFile
    )

    Write-Output "Retrieving content from policy file '$policyFile'."
    $policyContent = Get-Content -Path $policyFile | ConvertFrom-Json
    Write-Output "Assigning policy initiative '$($policyContent.name)' to scope '$policyScope'."

    switch ($Scope) {
        "ManagementGroup" {
            $currentPolicy = Get-AzPolicySetDefinition -ManagementGroup $ManagementGroupId -Custom | Where-Object { $_.Name -eq $policyContent.name }
            $managementGroupName = (Get-AzManagementGroup -GroupName $ManagementGroupId).DisplayName
            $policyAssignmentDisplayName = "$($policyContent.name) (Management Group: $managementGroupName)"
        }
        "Subscription" {
            $currentPolicy = Get-AzPolicySetDefinition -SubscriptionId $SubscriptionId -Custom | Where-Object { $_.Name -eq $policyContent.name }
            $subscriptionName = (Get-AzSubscription -SubscriptionId $SubscriptionId).Name
            $policyAssignmentDisplayName = "$($policyContent.name) (Subscription: $subscriptionName)"
        }
        Default {
            $currentPolicy = Get-AzPolicySetDefinition -Custom | Where-Object { $_.Name -eq $policyContent.name }
            $policyAssignmentDisplayName = $policyContent.name
        }
    }

    $policyAssignmentName = $policyContent.name.Replace(" ","")
    if ($policyAssignmentName.Length -gt 24) {
        $policyAssignmentName = $policyAssignmentName.Substring(0,23)
    }

    if (-not $currentPolicy) {
        Write-Error "Could not assign the Azure Policy '$($policyContent.name)' since it's not uploaded yet."
    }

    $argHash = @{
        "DisplayName"    = $policyAssignmentDisplayName
        "Description"    = $policyContent.properties.description
        "Metadata"       = @{'assignedBy'=$currentIdentity} | ConvertTo-Json
        "Location"       = $Location
        "AssignIdentity" = $true
    }

    if ($PolicyHasParameters) {
        $argHash.PolicyParameter = $PolicyParameters
    }

    $currentAssignment = Get-AzPolicyAssignment -PolicyDefinitionId $currentPolicy.ResourceId -Scope $policyScope
    if ($currentAssignment) {
        $argHash.Id = $currentAssignment.ResourceId

        Write-Output "Policy assignment already exists, updating current assignment using the following parameters:"
        Write-Output $argHash
        Set-AzPolicyAssignment @argHash
    }
    else {
        $argHash.Name                = $policyAssignmentName
        $argHash.Scope               = $policyScope
        $argHash.PolicySetDefinition = $currentPolicy

        Write-Output "Policy assignment does not exist yet, creating new policy assignment using the following parameters:"
        Write-Output $argHash
        New-AzPolicyAssignment @argHash
    }
}

if (-not (Test-Path -Path $Policy)) {
    Write-Error "Could not find the policy file or folder: '$Policy'."
}
if ($PolicyHasParameters -and (Test-Path -Path $Policy -PathType Container)) {
    Write-Error "When assigning an Azure Policy with parameters, a specific policy definition or initiative should be selected and not a folder."
}
if ($PolicyType -ne "initiative") {
    Write-Error "Only policy initiatives can be assigned to a scope."
}

try {
    $currentIdentity = (Get-AzADServicePrincipal -ApplicationId (Get-AzContext).Account.Id).DisplayName
}
catch {
    $currentIdentity = "Unknown"
}

switch ($Scope) {
    "ManagementGroup" {
        $policyScope = "/providers/Microsoft.Management/managementgroups/$ManagementGroupId"
    }
    "Subscription" {
        if ($SubscriptionId) {
            $policyScope = "/subscriptions/$SubscriptionId"
        }
        else {
            $policyScope = "/subscriptions/$((Get-AzContext).Subscription.Id)"
        }
    }
    "ResourceGroup" {
        if ($ResourceGroupName) {
            $policyScope = (Get-AzResourceGroup -Name $ResourceGroupName).ResourceId
        }
        else {
            Write-Error "No Resource Group name is provided while the assignment scope is set to Resource Group."
        }
    }
}

$isFolder = Test-Path -Path $Policy -PathType Container
if ($isFolder) {
    $fileFilter = "*.initiative.json"
    Write-Output "The provided policy input is a folder. Searching for policy files in '$Policy' using the '$fileFilter' filter."
    $policyFiles = @(Get-ChildItem -Path $Policy -File -Recurse -Filter $fileFilter)
    Write-Output "Found $($policyFiles.Count) policy files."

    foreach ($policyFile in $policyFiles) {
        Set-PolicyAssignment -policyFile $policyFile.FullName
    }
}
else {
    Set-PolicyAssignment -policyFile $Policy
}