# This file contains functions that are commonly useful across products and are non-product specific.
# Known good with Az module 1.0.0.

Function Invoke-Main {
    Param (
        [String] $TargetAzurePs = '1.6.0'
    )

    Import-Module $PSScriptRoot\..\ps_modules\VstsTaskSdk
    Trace-VstsEnteringInvocation $MyInvocation

    . $PSScriptRoot\Utility.ps1

    $serviceName = Get-VstsInput -Name ConnectedServiceName -Require
    $endpoint = Get-VstsEndpoint -Name $serviceName -Require

    Update-PSModulePathForHostedAgent -targetAzurePs $TargetAzurePs
    Import-Module $PSScriptRoot\..\ps_modules\VstsAzureHelpers_

    Try {
        # The hosted agent has both modules and since some tasks use the Az module and some uses the AzureRM module, we want to hide the warning fom our customers.
        $env:SkipAzInstallationChecks = "true"

        Initialize-AzModule -Endpoint $endpoint -azVersion $TargetAzurePs

        Main
    }
    Finally {
        Disconnect-AzureAndClearContext -ErrorAction SilentlyContinue
        Trace-VstsLeavingInvocation $MyInvocation
    }
}