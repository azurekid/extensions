# This file contains functions that are commonly useful across products and are non-product specific.
# Known good with Az module 1.0.0.

<#
.SYNOPSIS
Removes the resource locks from the given resource

.DESCRIPTION
This function checks for locks on the given resource and removes them.

.PARAMETER Resource
The resource to remove the locks from

.OUTPUTS
The collection of locks that have been removed
#>
Function Unlock-Resource {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $Resource
    )

    Write-Verbose "Unlock requested for $($Resource.ResourceId)"
    $locks = Get-AzResourceLock -ResourceName $Resource.Name `
                                -ResourceGroupName $Resource.ResourceGroupName `
                                -ResourceType $Resource.ResourceType `
                                -ErrorAction SilentlyContinue
    If ($locks) {
        ForEach ($lock In $locks) {
            Write-Host "Removing lock with name $($lock.Name) from resource $($lock.ResourceName) of type $($Resource.ResourceType)."
            Remove-AzResourceLock -LockName $lock.Name `
                                  -ResourceName $lock.ResourceName `
                                  -ResourceGroupName $lock.ResourceGroupName `
                                  -ResourceType $lock.ResourceType `
                                  -Force | Out-Null
        }
    }
    Else {
        Write-Host "No locks found for resource $($Resource.Name) of type $($Resource.ResourceType)"
    }

    Return $locks
}

<#
.SYNOPSIS
Get the standard public IP ranges for outgoing traffic to the Internet for the customer

.DESCRIPTION
This function returns the standard public IP ranges for outgoing traffic to the 
Internet for the customer.

.OUTPUTS
An array of strings of IP ranges in CIDR notation
#>
Function Get-CustomerStandardPublicIPRanges {
    Return @(
        "104.210.234.2/32", # ExpressRoute NAT #1
        "104.210.235.2/32", # ExpressRoute NAT #2
        "167.202.0.0/16", # Public ABN AMRO IP addresses
        "87.213.22.0/26"  # ABN AMRO Guest Wifi
    )
}

<#
.SYNOPSIS
Re-applies the locks on a resource

.DESCRIPTION
Re-applies the locks on the specified resource, generally use the collection of locks
of the Remove-Locks method output.

.PARAMETER Locks
The locks that have been removed
#>
Function Add-Locks {
    Param (
        [Parameter(Mandatory = $true)]
        [Array] $Locks
    )
    ForEach ($lock In $Locks) {
        Write-Verbose "Applying resource lock $($lock.Name)"
        New-AzResourceLock -LockName $lock.Name `
                           -LockLevel $lock.Properties.level `
                           -ResourceGroupName $lock.ResourceGroupName `
                           -ResourceType $lock.ResourceType `
                           -ResourceName $lock.ResourceName `
                           -Force | Out-Null
    }
}

<#
.SYNOPSIS
Get the task variable WorkspaceResourceId

.DESCRIPTION
This function gets the task variable WorkspaceResourceId, an optional parameter can be 
specified to ensure it exists and otherwise stop the script.

.PARAMETER Require
This will ensure the variable is present, otherwise the script will stop executing

.OUTPUTS
The value of the WorkspaceResourceId variable
#>
Function Get-WorkspaceResourceId {
    [CmdletBinding()]
    Param (
        [Switch] $Require
    )

    $WorkspaceResourceId = Get-VstsTaskVariable -Name WorkspaceResourceId
    Write-Verbose "WorkspaceResourceId: $WorkspaceResourceId"

    If ([String]::IsNullOrWhiteSpace($WorkspaceResourceId) -and $Require) {
        Throw "Release pipeline or stage must have a variable named WorkspaceResourceId defined with a value that points to the Log Analytics workspace to be used for logging."
    }

    Return $WorkspaceResourceId
}

<#
.SYNOPSIS
Validates a collection of IP ranges whether it has valid entries

.DESCRIPTION
This function validates a collection of IP ranges whether they have a valid IPv4 CIDR notation

.PARAMETER IpRanges
An array of strings of IP ranges (in CIDR notation)

.OUTPUTS
True when all the IP's are valid, false when not
#>
Function Validate-IpRanges {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Array] $IpRanges
    )

    $isValid = $true
    ForEach ($ipRange In $IpRanges) {
        [Bool]$isValidIPv4CIDR = $ipRange -Match '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$'

        If (!$isValidIPv4CIDR) {
            Write-Error "The specified '$ipRange' is not a valid IPv4 CIDR range."
            $isValid = $false
        }
    }

    Return $isValid
}

<#
.SYNOPSIS
Removes/Adds the resource locks from the given resource

.DESCRIPTION
This function checks for locks on the given resource, removes or adds them accordingly.

.PARAMETER Locks
The array of resource locks to add or remove

.PARAMETER Remove
When specified the action is remove, otherwise it is add

.OUTPUTS
Nothing
#>
Function Set-AzureResourceLock {
    Param (
        [Parameter(Mandatory = $false)]
        [Array] $Locks,

        [Parameter(Mandatory = $false)]
        [Switch] $Remove = $false
    )

    If (!$Locks) {
        Return
    }

    ForEach ($lock In $Locks) {
        $argHash = @{
            "LockName"          = $lock.Name
            "ResourceGroupName" = $lock.ResourceGroupName
            "ResourceName"      = $lock.ResourceName
            "ResourceType"      = $lock.ResourceType
            "Force"             = $true
        }

        If ($Remove) {
            Write-Verbose "Removing Resource Lock '$($lock.Name)'."
            Remove-AzResourceLock @argHash | Out-Null
        }
        Else {
            Write-Verbose "Adding Resource Lock '$($lock.Name)'."
            $argHash += @{
                "LockLevel" = $lock.Properties.level
            }

            New-AzResourceLock @argHash | Out-Null
        }
    }
}

Function Get-DeploymentServicePrincipalCredentials {
    Write-Verbose "Obtaining service principal credentials for the selected service connection."

    $serviceName = Get-VstsInput -Name "ConnectedServiceName" -Require
    $endpoint = Get-VstsEndpoint -Name $serviceName -Require
    $clientId = $Endpoint.Auth.Parameters.ServicePrincipalId
    $clientSecret = $Endpoint.Auth.Parameters.ServicePrincipalKey

    $context = Get-AzContext
    $tenantId = $Context.Tenant.Id

    Return @{
        "ClientId" = $clientId
        "ClientSecret" = $clientSecret
        "TenantId" = $tenantId
    }
}

<#
.SYNOPSIS
Generates a complex password

.DESCRIPTION
This function generates a complex password which also can be used for SQL accounts

.PARAMETER PasswordLength
The length of the complex password (default value is: 12)

.OUTPUTS
Returns a plaintext complex password
#>
Function New-ComplexPassword {
    Param (
        [Parameter(Mandatory = $false, ParameterSetName = 'FixedLength')]
        [ValidateRange(1, 32)]
        [Int] $PasswordLength = 12
    )

    $random = ""
    $digits = "1234567890".ToCharArray()
    $special = "#%^&()+?".ToCharArray()
    $lower = "abcdefghijklmnopqrstuvwxyz".ToCharArray()
    $upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray()

    1..2 | ForEach-Object { $random += Get-Random -InputObject $digits }
    1..2 | ForEach-Object { $random += Get-Random -InputObject $special }
    1..(Get-Random ($PasswordLength - $random.Length)) | ForEach-Object { $random += Get-Random -InputObject $upper }
    1..($PasswordLength - $random.Length) | ForEach-Object { $random += (Get-Random -InputObject $lower) }

    $password = ($random -split '' | Sort-Object { Get-Random }) -join ''

    Return $password
}

Function Get-ApiAccessToken {
    Param (
        [Parameter(Mandatory)]
        [String] $Resource
    )

    $creds = Get-DeploymentServicePrincipalCredentials

    $tokenEndPoint = {https://login.microsoftonline.com/{0}/oauth2/token} -f $creds.TenantId

    $body = @{
        'resource'      = $Resource
        'client_id'     = $creds.ClientId
        'grant_type'    = 'client_credentials'
        'client_secret' = $creds.ClientSecret
    }

    $params = @{
        ContentType = 'application/x-www-form-urlencoded'
        Headers     = @{'accept' = 'application/json'}
        Body        = $body
        Method      = 'POST'
        URI         = $tokenEndPoint
    }

    Write-Verbose "Obtaining access token using deploying service principal credentials for resource '$Resource'."
    $token = Invoke-RestMethod @params
    $accessToken = $token.access_token

    # Prevent accidental clear text logging in an Azure DevOps pipeline
    Set-VstsTaskVariable -Name "DONOTLOG" -Value $accessToken -Secret

    Return $accessToken
}

<#
.SYNOPSIS
Executes a provided 'delete resource' script block and retries when necessary

.DESCRIPTION
Executes a provided 'delete resource' script block and retries up to 12 times
when locks are still present preventing the deletion. Handles two different types
of exceptions.

.PARAMETER ResourceName
The name of the resource being deleted. Used for constructing output messages, warnings and errors.

.PARAMETER ResourceGroupName
The name of the resource group in which the resource is being deleted.
Used for constructing output messages, warnings and errors.

.PARAMETER ResourceDisplayType
The "friendly" name of the type of resource being deleted. Used for constructing output messages, warnings and errors.

.PARAMETER RemovalCode
The script block that should be executed that does the actual delete. It must not require parameters.
The other parameters are just being used to construct messages.

.OUTPUTS
Nothing
#>
Function Remove-UnlockedResource {
    Param (
        [Parameter(Mandatory)]
        [String] $ResourceName,

        [Parameter(Mandatory)]
        [String] $ResourceGroupName,

        [Parameter(Mandatory)]
        [String] $ResourceDisplayType,

        [Parameter(Mandatory)]
        [ScriptBlock] $RemovalCode
    )

    Write-Host "Removing $ResourceDisplayType '$ResourceName' from resource group '$ResourceGroupName'."

    $retryInSeconds = 5
    $maxRetries = 12
    $retryAttempts = 0
    Do {
        Try {
            $retry = $false

            & $RemovalCode

            Write-Host "The $ResourceDisplayType '$ResourceName' has been removed from resource group '$ResourceGroupName'."
        }
        Catch [Microsoft.Rest.Azure.CloudException] {
            Write-Verbose "An error occurred of type [Microsoft.Rest.Azure.CloudException]."

            $response = $_.Exception.Response
            If ($response) {
                Write-Warning "The $ResourceDisplayType '$ResourceName' cannot be removed (yet). Error message: '$($_.Exception.Message)', status code: '$($response.StatusCode)', reason phrase: '$($response.ReasonPhrase)'."

                If ($response.StatusCode -ne [System.Net.HttpStatusCode]::Conflict) {
                    Write-Error "The error does not indicate that a retry of the removal of the $ResourceDisplayType '$ResourceName' will work. Will not retry. Error message: '$($_.Exception.Message)'."
                }
            }
            Else {
                Write-Warning "The $ResourceDisplayType '$ResourceName' cannot be removed (yet). Error message: '$($_.Exception.Message)'."
            }

            If ($retryAttempts -ge $maxRetries) {
                Write-Error "The $ResourceDisplayType '$ResourceName' cannot be removed from resource group '$ResourceGroupName' after $maxRetries attempts. Will not retry. Error message: '$($_.Exception.Message)'."
            }

            $retryAttempts++
            $retry = $true

            Write-Host "Will attempt retry #$retryAttempts in $retryInSeconds seconds."
            Start-Sleep -Seconds $retryInSeconds
        }
        Catch [Microsoft.Azure.Commands.ResourceManager.Cmdlets.Entities.ErrorResponses.ErrorResponseMessageException] {
            Write-Verbose "An error occurred of type [Microsoft.Azure.Commands.ResourceManager.Cmdlets.Entities.ErrorResponses.ErrorResponseMessageException]."

            If ($null -ne $_.Exception.ErrorResponseMessage) {
                $errorOnRemove = $_.Exception.ErrorResponseMessage.Error
                Write-Warning "The $ResourceDisplayType '$ResourceName' cannot be removed (yet). Code: '$($errorOnRemove.Code)', message: '$($errorOnRemove.Message)."

                Switch ($errorOnRemove.Code) {
                    'AuthorizationFailed' {
                        $resource = Confirm-ResourceExistence -ResourceGroupName $ResourceGroupName -ResourceName $ResourceName -ResourceType $ResourceDisplayType

                        If ($resource.Properties.provisioningState -eq 'Deleting') {
                            Write-Warning "The $ResourceDisplayType '$ResourceName' is currently being removed. This may take some time."
                            Break
                        }
                        Else {
                            Write-Error "$ResourceDisplayType '$ResourceName' is not removed. Will not retry. The provisioning state is '$($resource.Properties.provisioningState)'. Code: '$($errorOnRemove.Code)', message: '$($errorOnRemove.Message)."
                        }
                    }
                    'ResourceNotFound' {
                        Write-Warning "The $ResourceDisplayType '$ResourceName' appears to be already removed."
                        Break
                    }
                    'ScopeLocked' {
                        If ($retryAttempts -ge $maxRetries) {
                            Write-Error "The $ResourceDisplayType '$ResourceName' cannot be removed from resource group '$ResourceGroupName' after $maxRetries attempts. Will not retry. Error message: '$($_.Exception.Message)'."
                        }

                        $retryAttempts++
                        $retry = $true

                        Write-Host "Will attempt retry #$retryAttempts in $retryInSeconds seconds."
                        Start-Sleep -Seconds $retryInSeconds
                    }
                    Default {
                        Write-Error "The error does not indicate that a retry of the removal of the $ResourceDisplayType '$ResourceName' will work. Will not retry. Code: '$($errorOnRemove.Code)', message: '$($errorOnRemove.Message)."
                    }
                }
            }
            Else {
                $retryAttempts++
                $retry = $true

                $exceptionObject = $_.Exception.Message | ConvertFrom-Json

                Switch ($exceptionObject.Code) {
                    'PreconditionFailed' {
                        Write-Warning "There is already an operation in progress which requires exlusive lock on $ResourceDisplayType '$ResourceName'. Will attempt retry #$retryAttempts in 30 seconds."
                        Start-Sleep -Seconds 30
                    }
                    Default {
                        Write-Error "The $ResourceDisplayType '$ResourceName' cannot be removed from resource group '$ResourceGroupName' due to an unknown error. Will not retry. Code: '$($exceptionObject.Code)', message: '$($exceptionObject.Message)'."
                    }
                }
            }
        }
        Catch {
            Write-Verbose "An unknown error occured."
            Write-Error "The $ResourceDisplayType '$ResourceName' cannot be removed from resource group '$ResourceGroupName' due to an unknown error. Will not retry. Type: '$($_.Exception.GetType())', error message: '$($_.Exception.Message)'."
        }
    }
    While ($retry)
}

<#
.SYNOPSIS
Confirms the existence of the specified resource

.DESCRIPTION
Confirms the existence of the specified resource and returns it when found. If not found a warning is written and $null is returned. For other error cases it writes an error.

.PARAMETER ResourceName
The name of the resource being confirmed.

.PARAMETER ResourceGroupName
The name of the resource group in which the resource must be confirmed.

.PARAMETER ResourceType
The resource type of the resource that must be confirmed.

.OUTPUTS
The resource object if found, or $null if it cannot be found or read.
#>
Function Confirm-ResourceExistence {
    Param (
        [Parameter(Mandatory = $true)]
        [String] $ResourceName,

        [Parameter(Mandatory = $true)]
        [String] $ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [String] $ResourceType,

        [Parameter(Mandatory = $false)]
        [Switch] $TreatAsError
    )

    $messageWhenMissing = "The resource '$ResourceName' of type '$ResourceType' in resource group '$ResourceGroupName' does not exist or there is no read access."

    Try {
        $resource = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceName $ResourceName -ResourceType $ResourceType -ExpandProperties

        Write-Verbose "Verified existence of resource '$ResourceName' of type '$ResourceType' in resource group '$ResourceGroupName'."

        Return $resource
    }
    Catch [Microsoft.Rest.Azure.CloudException] {
        $response = $_.Exception.Response

        If ($response.StatusCode -eq [System.Net.HttpStatusCode]::NotFound) {
            If ($TreatAsError) {
                Write-Error $messageWhenMissing
            }
            Else {
                Write-Warning $messageWhenMissing
                Return $null
            }
        }

        Write-Error "Cannot verify existence of resource '$ResourceName' of type '$ResourceType' in resource group '$ResourceGroupName'. Error message: '$($_.Exception.Message)', status code: '$($response.StatusCode)', reason phrase: '$($response.ReasonPhrase)'."
    }
    Catch [Microsoft.Azure.Commands.ResourceManager.Cmdlets.Entities.ErrorResponses.ErrorResponseMessageException] {
        $responseError = $_.Exception.ErrorResponseMessage.Error

        If ($responseError.Code -eq "ResourceNotFound") {
            If ($TreatAsError) {
                Write-Error $messageWhenMissing
            }
            Else {
                Write-Warning $messageWhenMissing
                Return $null
            }
        }

        Write-Error "Cannot verify existence of resource '$ResourceName' of type '$ResourceType' in resource group '$ResourceGroupName'. Error message: '$($_.Exception.Message)', status code: '$($responseError.Code)', reason phrase: '$($responseError.Message)'."
    }
}

<#
.SYNOPSIS
Assigns RBAC permissions for a security principal to an existing Azure resource

.DESCRIPTION
Assigns RBAC permissions for a security principal to an existing Azure resource

.PARAMETER ResourceGroupName
The name of a resource group. It must already exist within the subscription context.

.PARAMETER ResourceType
Resource type of the resource in Azure

.PARAMETER ResourceName
Resource name 

.PARAMETER AzureAdObjectId
Azure AD ObjectId of a user, group or service principal

.PARAMETER RoleId
The id of the RBAC role to assign (such as the GUID for Contributor)

.OUTPUTS
Progress messages
#>
<#
.SYNOPSIS
Assigns RBAC permissions for a security principal to an existing Azure resource

.DESCRIPTION
Assigns RBAC permissions for a security principal to an existing Azure resource

.PARAMETER ResourceGroupName
The name of a resource group. It must already exist within the subscription context.

.PARAMETER ResourceType
Resource type of the resource in Azure

.PARAMETER ResourceName
Resource name 

.PARAMETER AzureAdObjectId
Azure AD ObjectId of a user, group or service principal

.PARAMETER RoleId
The id of the RBAC role to assign (such as the GUID for Contributor)

.OUTPUTS
Progress messages
#>
Function Add-ResourcePermission {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [String] $ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [String] $ResourceType,

        [Parameter(Mandatory = $true)]
        [String] $ResourceName,

        [Parameter(Mandatory = $true)]
        [Guid] $AzureAdObjectId,

        [Parameter(Mandatory = $true)]
        [Guid] $RoleId
    )

    # This will throw if the resource doesn't exist
    $resource = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType $ResourceType -ResourceName $ResourceName

    # Check if the Azure AD object exists, this line will throw if it does not exist
    Get-AzureAdObjectById -AzureAdObjectId $AzureAdObjectId

    # This will throw if the role doesn't exist
    $roleDefinition = Get-AzRoleDefinition -Id $RoleId

    $roleAssignment = Get-AzRoleAssignment -ObjectId $AzureAdObjectId -RoleDefinitionId $roleDefinition.Id -Scope $resource.ResourceId | Where-Object -FilterScript { $_.Scope -eq $resource.ResourceId }
    If ($roleAssignment) {
        Write-Host "Azure AD object with id [$AzureAdObjectId] already member of the role [$($roleDefinition.Name) ($($roleDefinition.Description))] for the resource [$($resource.ResourceId)]"
    }
    Else {
        Write-Host "Adding role [$($roleDefinition.Name) ($($roleDefinition.Description))] for Azure AD object with id [$($AzureAdObjectId.Guid)] to resource [$($resource.ResourceId)]"
        If ($roleAssignment = New-AzRoleAssignment -Scope $resource.ResourceId -RoleDefinitionId $roleDefinition.Id -ObjectId $AzureAdObjectId) {
            Write-Host "Assigned role [$($roleDefinition.Name)] to [$AzureAdObjectId] for the Resource within ResourceGroupName [$($resource.ResourceGroupName)], ResourceType [$($resource.ResourceType)] and ResourceName [$($resource.Name)]"
        }
        Else {
            Write-Error "Failed to assign role [$($roleDefinition.Name)] to [$AzureAdObjectId] for the Resource within ResourceGroupName [$($resource.ResourceGroupName)], ResourceType [$($resource.ResourceType)] and ResourceName [$($resource.Name)]"
        }
    }
}

<#
.SYNOPSIS
Removes RBAC permissions based on a specified role for a security principal from an existing Azure resource

.DESCRIPTION
Removes RBAC permissions based on a specified role for a security principal from an existing Azure resource

.PARAMETER ResourceGroupName
The name of a resource group. It must already exist within the subscription context.

.PARAMETER ResourceType
Resource type of the resource in Azure

.PARAMETER ResourceName
Resource name

.PARAMETER AzureAdObjectId
Azure AD objectId of a user, group or service principal

.PARAMETER RoleId
The id of the RBAC role to remove (such as the GUID for Contributor).

.OUTPUTS
Progress messages
#>
Function Remove-ResourcePermission {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [String] $ResourceGroupName,

        [Parameter(Mandatory = $true)]
        [String] $ResourceType,

        [Parameter(Mandatory = $true)]
        [String] $ResourceName,

        [Parameter(Mandatory = $true)]
        [Guid]$AzureAdObjectId,

        [Parameter(Mandatory = $true)]
        [Guid] $RoleId
    )

    # This will throw if the resource doesn't exist
    $resource = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType $ResourceType -ResourceName $ResourceName

    # Check if the Azure AD object exists, this line will throw if it does not exist
    Get-AzureAdObjectById -AzureAdObjectId $AzureAdObjectId

    # This will throw if the role doesn't exist
    $roleDefinition = Get-AzRoleDefinition -Id $RoleId

    $roleAssignment = Get-AzRoleAssignment -ObjectId $AzureAdObjectId -RoleDefinitionId $roleDefinition.Id -Scope $resource.ResourceId | Where-Object -FilterScript { $_.Scope -eq $resource.ResourceId }
    If (!$roleAssignment) {
        Write-Warning "Role assignment not found. Cannot remove."
    }
    Else {
        $locks = Unlock-Resource -Resource $resource

        Write-Host "Removing role assignment for Azure AD object with object id [$AzureAdObjectId] from [$($resource.ResourceId)]."
        Remove-AzRoleAssignment -InputObject $roleAssignment | Out-Null

        If ($locks) {
            Add-Locks -Locks $locks
        }
    }
}

<#
.SYNOPSIS
Get Azure AD ObjectId via object name and type

.DESCRIPTION
Get Azure AD ObjectId via object name and type

.OUTPUTS
ObjectId of AAD object (as a Guid type) or throws an error if the object does not exist

.PARAMETER AadObjectType
Type of object in Azure Active Directory. Can be on of the following values: user, group, serviceprincipal

.PARAMETER AadObjectName
Name of the object in Azure Active Directory. Should be the following:
- UPN (in case of user)
- DisplayName (for a group)
- DisplayName (for a service principal)

#>
Function Get-AzureAdObjectId {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("user", "group", "serviceprincipal")]
        [String] $AADObjectType,

        [Parameter(Mandatory = $true)]
        [String] $AADObjectName
    )

    Switch ($AADObjectType) {
        "user" {
            $aadObject = (Get-AzADUser -UserPrincipalName $AADObjectName)
        }
        "group" {
            $aadObject = (Get-AzADGroup -SearchString $AADObjectName)
        }
        "serviceprincipal" {
            $aadObject = (Get-AzADServicePrincipal -SearchString $AADObjectName)
        }
        default {
            Throw "Get-AzureAdObjectId: Unknown aadObjectType '$AADObjectType'"
        }
    }

    If (!$aadObject) {
        Throw "No Azure AD security principal with name [$AADObjectName] of type $AADObjectType found."
    }
    Else {
        #Check the type of result. Should not be an array. Should be 1 result of the requested AD Type
        If ($aadObject -is [Array]) {
            Throw "More than 1 Azure AD object of type $AADObjectType found where name starts with [$AADObjectName]. Please change to make sure the name matches uniquely."
        }
        Else {
            #Only for groups and service principals check if the object name exactly matches the input (startsWith comparison is done)
            #UserPrincipalName always uses an exact match
            If (($AADObjectType -eq "group" -Or $AADObjectType -eq "serviceprincipal") -And $AADObjectName -ne $aadObject.DisplayName) {
                Throw "No Azure AD object has been found where display name matches [$AADObjectName]. Please change and make sure the name matches exactly."
            }
            Else {
                Return $aadObject.Id
            }
        }
    }
}

<#
.SYNOPSIS
Get Azure AD ObjectId via objectId

.DESCRIPTION
Get Azure AD ObjectId via object name and type

.OUTPUTS
Type of PSADUser, PSADGroup or PSADServicePrincipal depending on the found object
An error is thrown if the object does not exist

.PARAMETER AzureAdObjectId
Id of the object in Azure Active Directory
#>
Function Get-AzureAdObjectById {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [Guid] $AzureAdObjectId
    )

    $user = (Get-AzADUser -ObjectId $AzureAdObjectId)
    $group = (Get-AzADGroup -ObjectId $AzureAdObjectId)
    $servicePrincipal = (Get-AzADServicePrincipal -ObjectId $AzureAdObjectId)
    If ($user) {
        Write-Host "Found user with name [$($user.DisplayName)]"
        Return $user
    }
    If ($group) {
        Write-Host "Found group with name [$($group.DisplayName)]"
        Return $group
    }
    If ($servicePrincipal) {
        Write-Host "Found service principal with name [$($servicePrincipal.DisplayName)]"
        Return $servicePrincipal
    }

    Throw "No user, group or service principal found with object id [$AzureAdObjectId]."
}

<#
.SYNOPSIS
Validate the existence of an Azure AD object by objectId and type

.DESCRIPTION
Validate the existence of an Azure AD object by objectId and type.

.OUTPUTS
Nothing in case the object exists. Throws an error if it doesn't exist.

.PARAMETER AzureAdObjectId
Id of the object in Azure Active Directory

.PARAMETER Type
Type of the object in Azure Active Directory
#>
Function Confirm-AzureAdObjectByIdAndType {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [Guid] $AzureAdObjectId,
        [Parameter(Mandatory = $true)]
        [ValidateSet('group', 'servicePrincipal', 'user')]
        [String] $Type
    )

    Switch ($Type) {
        "group" {
            $group = (Get-AzADGroup -ObjectId $AzureAdObjectId)
            If ($group) {
                Write-Verbose "Confirmed group exists with name [$($group.DisplayName)]"
            }
            Else {
                Throw "No group found with object id [$($AzureAdObjectId.Guid)]"
            }
        }
        "user" {
            $user = (Get-AzADUser -ObjectId $AzureAdObjectId)
            If ($user) {
                Write-Verbose "Confirmed user exists with name [$($user.DisplayName)]"
            }
            Else {
                Throw "No user found with object id [$($AzureAdObjectId.Guid)]"
            }
        }
        "servicePrincipal" {
            $servicePrincipal = (Get-AzADServicePrincipal -ObjectId $AzureAdObjectId)
            If ($servicePrincipal) {
                Write-Host "Confirmed service principal exists with name [$($servicePrincipal.DisplayName)]"
            }
            Else {
                Throw "No service principal found with object id [$($AzureAdObjectId.Guid)]"
            }
        }
    }
}

<#
.SYNOPSIS
	The script generates a SAS token for a storage container based on the parameters.

.DESCRIPTION
    The script generate SAS tokens for a container in a (blog) storage account and returns it.
    If the storage container doesn't exist yet, it will be created.

.PARAMETER ResourceGroupName
    The name of an existing resource group.

.PARAMETER StorageAccountName
    The name of an existing storage account in the resource group.

.PARAMETER MonthsToExpiry
    The number of months from now before the SAS token will expire.

.PARAMETER ContainerName
    The name of the container for which a SAS token will be generated. The container will be
    created if it doesn't exist yet.

.PREREQUISITES
	+ The specified storage account must exist.

.OUTPUTS
	+ The SAS token for the storage container.
#>

Function Get-StorageContainerSasToken {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        [string]$ResourceGroupName,
        [Parameter(Mandatory = $True)]
        [string]$StorageAccountName,
        [Parameter(Mandatory = $True)]
        [int]$MonthsToExpiry,
        [Parameter(Mandatory = $True)]
        [string]$ContainerName
    )

    Try {
        $ErrorActionPreference = "Stop"

        $storageAccountKey1 = ""

        Write-Host "Validating storage account with name '$StorageAccountName' in resource group '$ResourceGroupName'"
        Get-AzStorageAccount `
            -ResourceGroupName $ResourceGroupName `
            -Name $StorageAccountName `
            | Out-Null

        Write-Host "Retreiving key from storage account '$StorageAccountName'"
        $storageAccountKey1 = (Get-AzStorageAccountKey `
                                -ResourceGroupName $ResourceGroupName `
                                -Name $StorageAccountName)[0].Value

        Write-Host "Setting storage context for storage account '$StorageAccountName' and the retreived key."
        $storageContext = New-AzureStorageContext `
            -StorageAccountName $StorageAccountName `
            -StorageAccountKey $storageAccountKey1

        $now = Get-Date

        Write-Host "Validating container '$ContainerName' of Storage Account '$ContainerName'"
        if (-not (Get-AzureStorageContainer -Context $storageContext -Name $ContainerName -ErrorAction SilentlyContinue)) {
            Write-Host "Storage account container '$ContainerName' was not found in storage account '$StorageAccountName'. Creating..."
            New-AzureStorageContainer `
                -Context $storageContext `
                -Name $ContainerName `
                -Permission Off `
                | Out-Null
        }
        Write-Host "Creating SAS token for container '$ContainerName'"
        $SAStokenURL = New-AzureStorageContainerSASToken `
                        -Name $ContainerName `
                        -Context $storageContext `
                        -Permission RWDL `
                        -StartTime $now.AddHours(-1) `
                        -ExpiryTime $now.AddMonths($MonthsToExpiry) `
                        -FullUri

        Return $SAStokenURL
    }
    Catch {
        Write-Error $_.Exception.Message
    }
}

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