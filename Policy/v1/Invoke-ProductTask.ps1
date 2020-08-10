Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. $PSScriptRoot\Common\Functions.ps1

function Main {
    $action = Get-VstsInput -Name action -Require
    $argHash = @{}

    $scope      = Get-VstsInput -Name deploymentScope -Require
    $policyType = Get-VstsInput -Name policyType -Require

    $ResourceDeploymentName = "Azure Policy"
    $managementGroupId = $null
    $subscriptionId    = $null
    $resourceGroupName = $null

    switch ($scope) {
        "ManagementGroup" {
            $serviceName        = Get-VstsInput -Name "connectedServiceName" -Require
            $endpoint           = Get-VstsEndpoint -Name $serviceName -Require
            $managementGroupId  = $endpoint.data.managementGroupId
        }
        "Subscription" {
            $subscriptionId = Get-VstsInput -Name subscriptionName -Require
        }
        "ResourceGroup" {
            $resourceGroupName = Get-VstsInput -Name resourceGroupName -Require
        }
        "default" {
            Write-Error "No valid scope selected"
        }
    }

    switch ($policyType) {
        "definition" {
            $argHash.Scope      = $scope
            $argHash.PolicyType = $policyType
            $definitionLocation = Get-VstsInput -Name definitionLocation

            if ($definitionLocation -eq "linked") {
                $argHash.Policy = Get-VstsInput -Name definitionFileLink -Require
            }
            elseif ($definitionLocation -eq "url") {
                $argHash.Policy = Get-VstsInput -Name definitionFileUrl -Require
            }
            else {
                Write-Output "No definition location selected"
            }
        }
        "initiative" {
            $argHash.Scope      = $scope
            $argHash.PolicyType = $policyType
            $initiativeLocation = Get-VstsInput -Name initiativeLocation

            if ($initiativeLocation -eq "linked") {
                $argHash.Policy = Get-VstsInput -Name initiativeFileLink -Require
            }
            elseif ($initiativeLocation -eq "url") {
                $argHash.Policy = Get-VstsInput -Name initiativeFileUrl -Require
            }
            else {
                Write-Output "No Initiative location selected"
            }
        }
        "default" {
            Write-Error "No valid PolicyType found"
        }
    }

    switch ($action) {
        "upload" {
            Write-Output "Uploading Azure Policy."
            $argHash.Scope      = $Scope
            $argHash.PolicyType = $policyType

            if ($argHash.Scope -eq "ResourceGroup") {
                Write-Error "Policies can only be uploaded to Management Group or Subscription level, not to a Resource Group."
            }

            if ($managementGroupId) {
                $argHash.ManagementGroupId = $managementGroupId
            }
            else {
                # Context of service connection is used
            }

            & $PSScriptRoot\Operations\$action.ps1 @argHash
        }
        "assign" {
            Write-Output "Assigning Azure Policy."

            $argHash.Scope               = $Scope
            $argHash.PolicyType          = $policyType
            $argHash.Location            = Get-VstsInput -Name location -Require
            $argHash.PolicyHasParameters = Get-VstsInput -Name initiativeHasParameters -Require -AsBool

            $initiativeParametersLocation = Get-VstsInput -Name initiativeParametersLocation -Require
            if ($initiativeParametersLocation -eq "linked") {
                $argHash.PolicyParameters = Get-VstsInput -Name initiativeParameterFileLink -Require
            }
            else {
                $argHash.PolicyParameters = Get-VstsInput -Name initiativeParameterFileUrl -Require
            }

            if ($managementGroupId) {
                $argHash.ManagementGroupId = $managementGroupId
            }
            if ($subscriptionId) {
                $argHash.SubscriptionId = $subscriptionId
            }
            if ($resourceGroupName) {
                $argHash.ResourceGroupName = $resourceGroupName
            }

            & $PSScriptRoot\Operations\$action @argHash
        }
        "remove" {
            Write-Output "Removing Azure Policy."
            $argHash.clear()
            $argHash.initiativeId = Get-VstsInput -Name initiativeId  -Require

            $removeAssignment = Get-VstsInput -Name removeAssignment -Require -AsBool
            Write-Verbose "removeAssignment: $removeAssignment"

            if ($removeAssignment -ne $true) {
                Write-Error "$ResourceDeploymentName deletion must be confirmed by checking the remove confirmation."
            }

            $ResourceGroupName = Get-VstsInput -Name ResourceGroupName
            if ($ResourceGroupName) {
                $argHash.ResourceGroupName = $ResourceGroupName
            }

            Write-Output "Remove the $ResourceDeploymentName"
            & $PSScriptRoot\Operations\$action.ps1 @argHash

        }
    }
}

Invoke-Main -TargetAzurePs "3.8.0"