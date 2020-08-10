<#
.SYNOPSIS
Removes policy and policy initiative definitions at subscription scope after removing initiave assignments.

.DESCRIPTION
Removes policy and policy initiative definitions at subscription scope. The identifiers for the
policies to remove come from files matching a filename convention in the specified folder or subfolders thereof.

-Policy definition file names must match "policy*.json".
-Policy initiative file names must match "initiative*.json".

There must be a current authenticated Azure context with Owner permissions on the
subscription level before invoking this script.

.PARAMETER PolicyFilesPath
This path in which (sub)folders will be scanned for policy and policy initiative
definition files identifying items to remove.

.OUTPUTS
None
#>
[CmdletBinding()]
Param (
    [Parameter(Mandatory = $false)]
    [String] $PolicyFilesPath,

    [Parameter(Mandatory = $false)]
    [String] $InitiativeFilesPath,

    [Parameter(Mandatory = $false)]
    [String] $ManagementGroupId,

    [Parameter(Mandatory = $false)]
    [String] $initiativeId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$paramPolicySetDefinition = @{}
$policyDefinitions = @{}

if ($ManagementGroupId) {
    $paramPolicySetDefinition.ManagementGroupName = $ManagementGroupId
    $policyDefinitions.ManagementGroupName = $ManagementGroupId
    $PolicyScope = "/providers/Microsoft.Management/managementgroups/$managementGroupId"
}

if ($InitiativeFilesPath) {
    $initiativeFiles = @(Get-ChildItem -Path $InitiativeFilesPath -File -Recurse -Filter "initiative*.json")
    $fileCounter = 1

    ForEach ($initiativeFile In $initiativeFiles) {
        Write-Host "Processing policy initiative file $fileCounter/$($initiativeFiles.Count) with name '$($initiativeFile.FullName)'."
        $fileCounter++

        $initiative = Get-AzPolicySetDefinition -Custom -ManagementGroup $ManagementGroupId |
        Where-Object { $_.Name -eq (Get-Content -Path $initiativeFile.FullName | ConvertFrom-Json).name }

        Write-Host "Removing policy assignments for initiative [$($initiative.ResourceId)]."
        Get-AzPolicyAssignment -PolicyDefinitionId $initiative.ResourceId -Scope $policyScope |
        ForEach-Object {
            Remove-AzPolicyAssignment -PolicyDefinitionId $_.ResourceId
        }

        if ($RemoveAll) {
            Write-Host "Removing initiative [$($initiative.ResourceId)]."
            Remove-AzPolicySetDefinition -PolicyDefinitionId $initiative.ResourceId -Force
        }
    }
}

if($initiativeId) {

    Write-Output "Retrieving Azure Policy Assignment with ID [$initiativeId]"
    $initiative = Get-AzPolicyAssignment -Id $initiativeId

    if ($initiative) {
        Write-Output "Removing policy assignment"
        Remove-AzPolicyAssignment -id $initiativeId
    }
}