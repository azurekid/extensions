Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

. $PSScriptRoot\Common\Functions.ps1

function Main {

    $bicepLocation = Get-VstsInput -Name BicepLocation
    $preview = Get-VstsInput -Name Preview

    if ($bicepLocation -eq "linked") {
        $FilesPath = Get-VstsInput -Name BicepFileLink -Require
    }
    elseif ($bicepLocation -eq "url") {
        $FilesPath = Get-VstsInput -Name BicepFileUrl -Require
    }
    else {
        Write-Output "No valid location selected"
    }


    $bicepFiles = @()
    $resourcesProviders = Get-AzResourceProvider

    $bicepFiles = @(Get-ChildItem -Path $FilesPath -Recurse -Filter "*.bicep")

    function Get-ApiVersion ($ResourceProvider, $apiVersion) {
        Write-Verbose $ResourceProvider
        $typeArray = ($ResourceProvider) -Split ('/'), 2

        switch ($typeArray[1]) {
            "locks" {
                $ProviderNamespace = "Microsoft.Authorization"
                $type = $typeArray[1]
            }
            "diagnosticSettings" {
                $ProviderNamespace = "Microsoft.Insights"
                $type = $typeArray[1]
            }
            default {
                if ($ResourceProvider -like '*locks*') {
                    $ProviderNamespace = "Microsoft.Authorization"
                    $type = "locks"
                }
                elseif ($ResourceProvider -like '*diagnosticSettings*') {
                    $ProviderNamespace = "Microsoft.Insights"
                    $type = "diagnosticSettings"
                }
                else {
                    $ProviderNamespace = $typeArray[0]
                    $type = $typeArray[1]
                }
            }
        }

        try {
            $apiVersions = ((($resourcesProviders | Where-Object { $_.ProviderNamespace -eq $ProviderNamespace }).ResourceTypes `
                    | Where-Object { $_.ResourceTypeName -eq $type }) `
                | Sort-Object -Descending)

            if ($apiVersions) {
                if ($Preview) {
                    $latestApi = ($apiVersions.ApiVersions | Sort-Object -Descending)
                }
                else {
                    $latestApi = ($apiVersions.ApiVersions | Where-Object { $_ -notlike "*preview*" } | Sort-Object -Descending)
                }

                $hashTable = [ordered]@{
                    "Filename"            = $bicepFile.Fullname
                    "Resource Provider"   = $ResourceProvider
                    "Current API version" = $apiVersion
                    "Latest API version"  = $latestApi[0]
                }

                $d1 = [datetime]::ParseExact("$apiVersion".Substring(0, 10), "yyyy-MM-dd", $null)
                $d2 = [datetime]::ParseExact($latestApi[0].Substring(0, 10), "yyyy-MM-dd", $null)
                $ts = (New-TimeSpan -Start $d1 -End $d2).Days.toString()

                if ($ts -ne "0") {
                    Write-Warning "New API version available"
                    Write-Output $hashTable
                    Write-Output ""
                    $hashTable.Clear()
                }
            }
        }
        catch {
            Write-Verbose "resource provider: $($ResourceProvider) not found. Please check the provider is available in the subscription"
        }
    }

    if ($bicepFiles) {
        $fileCounter = 1
        ForEach ($bicepFile in $bicepFiles) {
            Write-Output "Processing Bicep template $fileCounter/$($bicepFiles.Count) with name '$($bicepFile.Fullname)'."
            $fileCounter++
    
            $resources = ($bicepFile | `
                    Select-String -Pattern "(?<=')(.*)(?=' )" `
                    -AllMatches | `
                    ForEach-Object { $_.matches.value })

            foreach ($resource in $resources) {
                if ($resource -like "*@*") {
                    $object = $resource -split '@'
                
                    Get-ApiVersion `
                        -ResourceProvider $($object[0]) `
                        -apiVersion $($object[1])
                }
            }   
        }
    }
}

Invoke-Main -TargetAzurePs "3.8.0"