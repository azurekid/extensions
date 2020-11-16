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
        # Ignore warnings for the Az module when both modules are installed on the agent.
        $env:SkipAzInstallationChecks = "true"

        Initialize-AzModule -Endpoint $endpoint -azVersion $TargetAzurePs
        
        Main
    }
    Finally {
        Disconnect-AzureAndClearContext -ErrorAction SilentlyContinue
        Trace-VstsLeavingInvocation $MyInvocation
    }
}