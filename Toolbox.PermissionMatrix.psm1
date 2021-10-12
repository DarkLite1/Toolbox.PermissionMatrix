#Requires -Version 5.1

Function ConvertTo-AceHC {
    <#
    .SYNOPSIS
        Convert an AD Object name and a permission character to a valid ACE.

    .DESCRIPTION
        Convert an AD Object name and a permission character to a valid Access Control List Entry.

    .PARAMETER Type
        The permission character defining the access to the folder.

    .PARAMETER Name
        Name of the AD object, used to identify the user or group within AD.
#>

    Param (
        [Parameter(Mandatory)]
        [ValidateSet('L', 'R', 'W', 'F', 'M')]
        [String]$Type,
        [Parameter(Mandatory)]
        [String]$Name
    )

    Switch ($Type) {
        'L' {
            New-Object System.Security.AccessControl.FileSystemAccessRule(
                "$env:USERDOMAIN\$Name",
                [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
                [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            Break
        }
        'W' {
            # This folder only
            New-Object System.Security.AccessControl.FileSystemAccessRule(
                "$env:USERDOMAIN\$Name",
                [System.Security.AccessControl.FileSystemRights]'CreateFiles, AppendData, DeleteSubdirectoriesAndFiles, ReadAndExecute, Synchronize',
                [System.Security.AccessControl.InheritanceFlags]::None,
                [System.Security.AccessControl.PropagationFlags]::InheritOnly,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            # Subfolders and files only
            New-Object System.Security.AccessControl.FileSystemAccessRule(
                "$env:USERDOMAIN\$Name",
                [System.Security.AccessControl.FileSystemRights]'DeleteSubdirectoriesAndFiles, Modify, Synchronize',
                [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                [System.Security.AccessControl.PropagationFlags]::InheritOnly,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            Break
        }
        'R' {
            New-Object System.Security.AccessControl.FileSystemAccessRule(
                "$env:USERDOMAIN\$Name",
                [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
                [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            Break
        }
        'F' {
            New-Object System.Security.AccessControl.FileSystemAccessRule(
                "$env:USERDOMAIN\$Name",
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            Break
        }
        'M' {
            New-Object System.Security.AccessControl.FileSystemAccessRule(
                "$env:USERDOMAIN\$Name",
                [System.Security.AccessControl.FileSystemRights]::Modify,
                [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            Break
        }
        Default {
            throw "Permission character '$_' not supported."
        }
    }
}
Function ConvertTo-MatrixADNamesHC {
    <#
    .SYNOPSIS
        Generate AD SamAccountNames from the first three rows in the Excel file.

    .DESCRIPTION
        Generate AD SamAccountNames from the first three rows in worksheet 
        'Permissions' by replacing strings with the correct values.

        In case the value in A2 and B2 are equal, they are replaced by the 
        string defined in 'Middle'. In case the value in A3 and B3 are equal, 
        they are replaced by the value in 'Begin'.

        The template name to replace is always defined in cell A2 and A3 for 
        their respective row.

    .PARAMETER ColumnHeaders
        The first 3 rows (objects) of the worksheet 'Permissions'. These objects
        contain the values to create the correct SamAccountNames.

    .PARAMETER Begin
        The value of the first part of the newly generated string. Usually this 
        is the beginning of an AD GroupName like 'BEL ROL-AGG-SAGREX'.

    .PARAMETER Middle
        The value of the middle part of the newly generated string. Usually 
        this is something like 'North'.
 #>

    [CmdLetBinding()]
    [OutputType([HashTable])]
    Param (
        [Parameter(Mandatory)]
        [ValidateCount(3, 1000)]
        [PSCustomObject[]]$ColumnHeaders,
        [String]$Begin,
        [String]$Middle,
        [String]$BeginReplace = 'GroupName',
        [String]$MiddleReplace = 'SiteCode'
    )

    Process {
        Try {
            Write-Verbose 'Convert to matrix AD object names'

            $firstProperty = @($ColumnHeaders[0].PSObject.Properties.Name)[0]

            $result = @{}

            $ColumnHeaders[0].PSObject.Properties.Name.Where( { 
                    $_ -ne $firstProperty 
                }).Foreach( {
                    Write-Verbose "Property '$_'"

                    #region Get original values
                    $names = @($ColumnHeaders.$_)[0..2]
                    $original = [ordered]@{
                        Begin  = $names[2]
                        Middle = $names[1]
                        End    = $names[0]
                    }
                    Write-Verbose "Original value begin '$($original.Begin)' middle '$($original.Middle)' end $($original.End)"
                    #endregion

                    #region Convert placeholder to proper values
                    $converted = [ordered]@{
                        Begin  = $names[2]
                        Middle = $names[1]
                        End    = $names[0]
                    }

                    if (($original.Begin -eq $BeginReplace) -and ($Begin)) { 
                        $converted.Begin = $Begin
                    }
                    if (($original.Middle -eq $MiddleReplace) -and ($Middle)) {
                        $converted.Middle = $Middle
                    }
                    Write-Verbose "Converted value begin '$($converted.Begin)' middle '$($converted.Middle)' end $($converted.End)"
                    #endregion

                    #region Create SamAccountName
                    $SamAccountName = @(
                        $converted.Begin ,
                        $converted.Middle ,
                        $converted.End
                    ).Where( { $_ }) -join ' '
                    Write-Verbose "SamAccountName '$SamAccountName'"
                    #endregion

                    $result.$_ = @{
                        SamAccountName = $SamAccountName
                        Original       = $original
                        Converted      = $converted
                    }
                })

            $result
        }
        Catch {
            throw "Failed generating the correct AD object name for begin '$Begin' and middle '$Middle': $_"
        }
    }
}
Function ConvertTo-MatrixAclHC {
    <#
    .SYNOPSIS
        Convert the Excel sheet 'Permissions' to permission objects.

    .DESCRIPTION
        Convert the Excel sheet 'Permissions' to permission objects, by using 
        the 'GroupName' and 'SiteCode' defined in the Excel sheet 'Settings'.

        Each object will contain the complete 'SamAccountName', the folder 
        'Path' on the local machine and the type of access ('ACE') to that 
        folder.

    .PARAMETER NonHeaderRows
        The objects coming from the Excel sheet 'Permissions', as retrieved by
        Import-Excel, but without the header columns. The header columns are 
        replaced with ADObjects.

    .PARAMETER ADObjects
        A hashtable containing the property name and the SamAccountName 
        belonging to that column.
#>

    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    Param (
        [parameter(Mandatory)]
        [PSCustomObject[]]$NonHeaderRows,
        [parameter(Mandatory)]
        [HashTable]$ADObjects
    )

    Begin {
        Try {
            $FirstProperty = @($NonHeaderRows[0].PSObject.Properties.Name)[0]
        }
        Catch {
            throw "Failed converting to matrix ACL: $_"
        }
    }

    Process {
        Try {
            $FirstTimeThrough = $true

            foreach ($N in $NonHeaderRows) {
                $Obj = [PSCustomObject]@{
                    Path   = $N.$FirstProperty
                    Parent = $false
                    Ignore = $false
                    ACL    = @{}
                }

                if ($FirstTimeThrough) {
                    $FirstTimeThrough = $false
                    $Obj.Parent = $true
                }

                $Props = $N.PSObject.Properties.Where( { 
                        $_.Name -ne $FirstProperty })

                $ACL = @{}

                if ($Props.Value -contains 'i') {
                    $Obj.Ignore = $true
                }
                else {
                    $Props.Foreach( {
                            if ($Ace = $_.Value) {
                                <#
                                there tests are done after building the matrix 
                                because AD Object names can be duplicate after 
                                they are generated with a manual entry in the 
                                column header
                            #>
                                if (-not ($SamAccountName = $ADObjects.($_.Name).SamAccountName)) {
                                    throw 'When permissions are set an AD object name is required.'
                                }

                                if ($ACL.ContainsKey($SamAccountName)) {
                                    throw "The AD object name '$SamAccountName' is not unique."
                                }

                                if ($Ace) {
                                    $ACL.Add($SamAccountName, $Ace)
                                }
                            }
                        })
                }
                $Obj.ACL = $ACL
                $Obj
            }
        }
        Catch {
            throw "Failed converting to matrix ACL: $_"
        }
    }
}
Function Format-PermissionsStringsHC {
    <#
    .SYNOPSIS
        String manipulations on values in the 'Permissions' sheet.

    .DESCRIPTION
        Remove leading and trailing spaces from strings, remove leading and 
        trailing slashes from the path locations, change lower case permission 
        characters to upper case, ...

    .PARAMETER Permissions
        Content of the Excel worksheet 'Permissions'.
#>

    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    Param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$Permissions
    )

    Process {
        $FirstPropertyName = $Permissions[0].PSObject.Properties.Name[0]

        for ($i = 0; $i -lt $Permissions.Length; $i++) {
            foreach ($P in $Permissions[$i].PSObject.Properties) {
                $Value = if ($tmpVal = $P.Value) { $tmpVal.ToString().Trim() }

                if ($Value) {
                    if ($P.Name -eq $FirstPropertyName) {
                        $Value = $Value.Trim('\')
                    }
                    elseif ($i -ge 3) {
                        $Value = $Value.ToUpper()
                    }
                }

                $P.Value = $Value
            }

            $Permissions[$i]
        }
    }
}
Function Format-SettingStringsHC {
    <#
    .SYNOPSIS
        String manipulations on values in the 'Settings' sheet.

    .DESCRIPTION
        Remove leading and trailing spaces from strings. Add the domain name to 
        the ComputerName property when it's not there. Remove trailing slashes 
        from the Path. ...

        Spaces are converted to NULL values.

    .PARAMETER Settings
        One row in the Excel sheet 'Settings'.
#>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject]$Settings
    )

    Process {
        $Obj = @{}

        ($Settings.PSObject.Properties).Foreach( {

                $Value = if ($tmpVal = $_.Value) { $tmpVal.ToString().Trim() }

                $Obj.($_.Name) = Switch ($_.Name) {
                    'Action' {
                        if ($Value) {
                            $Value.SubString(0, 1).ToUpper() + $Value.SubString(1).ToLower()
                        }
                        break
                    }
                    'ComputerName' {
                        if ($Value) {
                            $Value = $Value.ToUpper()
                            if ($Value -like "*.$env:USERDNSDOMAIN") {
                                $Value = $Value -Replace ".$env:USERDNSDOMAIN"
                            }
                            $Value
                        }
                        break
                    }
                    'Path' {
                        if ($Value) {
                            $Value.TrimEnd('\')
                        }
                        break
                    }
                    'Status' {
                        if ($Value) {
                            $Value.SubString(0, 1).ToUpper() + $Value.SubString(1).ToLower()
                        }
                        break
                    }
                    Default {
                        $Value
                    }
                }
            })

        [PSCustomObject]$Obj
    }
}
Function Get-DefaultAclHC {
    <#
    .SYNOPSIS
        Get the ACL from the default settings.

    .DESCRIPTION
        Retrieve the 'ADObjectName' and the 'Permission' properties and combine them into a hash table.
        Also tests if the permission characters are correct and throws an error in case they're not. The
        ADObjectName is not tested and needs to be checked afterwards.

    .PARAMETER Sheet
        The Excel worksheet containing the permission parameters.
#>

    [CmdletBinding()]
    [OutputType([HashTable])]
    Param (
        [PSCustomObject[]]$Sheet
    )

    Process {
        Try {
            $ACL = @{}

            $Sheet.Where( { $_.ADObjectName -or $_.Permission }).ForEach( {
                    $ADObjectName = $_.ADObjectName
                    $Permission = $_.Permission

                    if (-not $Permission) {
                        throw "AD object name '$ADObjectName' has no permission."
                    }

                    if ($Permission -notMatch '^(L|R|W|C|F)$') {
                        throw "Permission character '$Permission' unknown."
                    }

                    if (-not $ADObjectName) {
                        throw "Permission '$Permission' has no AD object name."
                    }

                    Try {
                        $ACL.Add($ADObjectName, $Permission)
                    }
                    Catch {
                        throw "AD Object name '$ADObjectName' is not unique."
                    }
                })

            $ACL
        }
        Catch {
            throw "Failed retrieving the ACL from the default settings file: $_"
        }
    }
}
Function Get-ExecutableMatrixHC {
    <#
    .SYNOPSIS
        Retrieve only those matrix that are able to be executed.

    .DESCRIPTION
        Filter out matrix that have a FatalError object in the File, 
        Permissions or in the Settings object itself. Only those matrix that 
        are flawless can be executed to set permissions on folders.

    .PARAMETER From
        One object for each file, containing the File, Settings and Permissions 
        properties.
#>

    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    Param (
        [Parameter(Mandatory = $false)]
        [PSCustomObject[]]$From
    )

    Try {
        @((@($From).Where( {
                        ($_.File.Check.Type -notContains 'FatalError') -and
                        ($_.Permissions.Check.Type -notContains 'FatalError') })).Settings).Where( {
                ($_.Check.Type -notContains 'FatalError') -and ($_.Matrix)
            })
    }
    Catch {
        throw "Failed retrieving the executable matrix: $_"
    }
}
Function Get-JobErrorHC {
    <#
    .SYNOPSIS
        Retrieve errors from executed jobs.

    .DESCRIPTION
        Retrieve non terminating and terminating job errors and create an object of type
        FatalError. When the remote machine can not be reached a FatalError object with
        name 'Connection error' is created.

        In case no error is found then no object is created. Job results need to be retrieved
        separately. This function only handles the errors. So when importing the job results
        one should use '-ErrorAction Ignore'.

    .PARAMETER Job
        The job object to check for errors.
#>

    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param (
        [Parameter(Mandatory)]
        [System.Management.Automation.Job]$Job
    )

    Try {
        $Check = @{}

        Switch ($Job.State) {
            'Completed' {
                if ($Job.ChildJobs[0].Error) {
                    $Check.Type = 'FatalError'
                    $Check.Value = $Job.ChildJobs[0].Error.Exception.Message
                    $Check.Name = 'Non terminating error'
                    $Check.Description = "A non terminating error occurred while executing the job '$($Job.Name)'."
                }
                Break
            }
            'Failed' {
                $Check.Type = 'FatalError'
                $Check.Value = $Job.ChildJobs[0].JobStateInfo.Reason.Message

                if ($Job.ChildJobs[0].JobStateInfo.Reason.ErrorRecord.CategoryInfo.Category -eq 'ResourceUnavailable') {
                    $Check.Name = 'Connection error'
                    $Check.Description = 'Connecting to the remote machine failed. Most likely the machine is offline or the computer name is incorrect.'
                }
                else {
                    $Check.Name = 'Terminating error'
                    $Check.Description = "A terminating error occurred while executing the job '$($Job.Name)'."
                }
                Break
            }
            Default {
                throw "Job state '$_' is unsupported."
            }
        }

        if ($Check.Count -ne 0) {
            [PSCustomObject]$Check
        }
    }
    Catch {
        throw "Failed retrieving the job errors for job '$($Job.Name)' on '$($Job.Location)': $_"
    }
}
Function Get-ADObjectNotExistingHC {
    <#
    .SYNOPSIS
        Check if a SamAccountName exists in AD.

    .DESCRIPTION
        Check if a SamAccountName for a group or user object exists in active directory.
        When the object is not found, the function will output its name.

    .PARAMETER Name
        SamAccountName of the active directory object.

    .EXAMPLE
        Test if two SamAccountNames exist in the active directory and return the ones that don't
        Get-ADObjectNotExistingHC -Name 'UserExists', 'UserDoesNotExist'
        Output: 'UserDoesNotExist'
s#>

    [CmdletBinding()]
    [OutputType([String[]])]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory, ValueFromPipeline)]
        [String[]]$Name
    )

    Process {
        Try {
            foreach ($N in $Name) {
                if (-not (Get-ADObject -Filter "SAMAccountName -eq '$N'")) {
                    $N
                }
            }
        }
        Catch {
            throw "Failed to test if SamAccountName '$Name' exists: $_"
        }
    }
}
Function Get-AdUserPrincipalNameHC {
    <#
    .SYNOPSIS
        Convert a list of e-mail addresses to a list of UserPrincipalNames.

    .DESCRIPTION
        The list to convert can contain user e-mail addresses or group e-mail
        addresses. For groups the user members are retrieved. The result will
        only contain UserPrincipalNames from AD user accounts that are enabled.

    .PARAMETER Name
        Can be an e-mail address or a SamAccountName of a user object or a
        group object in AD.
#>

    [CmdletBinding()]
    [OutputType([HashTable])]
    Param(
        [Parameter(Mandatory)]
        [String[]]$Name
    )

    try {
        $notFound = @()

        $result = foreach ($N in  ($Name | Sort-Object -Unique)) {
            $adObject = Get-ADObject -Filter "ProxyAddresses -eq 'smtp:$N' -or SAMAccountName -eq '$N'" -Property 'mail'

            if ($adObject.Count -ge 2) {
                throw "Multiple results found for name '$N': $($adObject.Name)"
            }
    
            if (-not $adObject) {
                $notFound += $N
                Continue
            }
    
            $adUsers = if ($adObject.ObjectClass -eq 'group') {
                Get-ADGroupMember $adObject -Recursive
            }
            elseif ($adObject.ObjectClass -eq 'user') {
                $adObject
            }
    
            $adUsers | Get-ADUser |
            Where-Object { $_.Enabled } |
            Select-Object -ExpandProperty 'UserPrincipalName'
        }
    
        @{
            notFound          = $notFound
            userPrincipalName = $result | Sort-Object -Unique
        }    
    }
    catch {
        throw "Failed converting email address or SamAccountName to userPrincipalName: $_"       
    }
}
Function Test-AclEqualHC {
    <#
	.SYNOPSIS
		Compare two ACL's. Will return True if the Access Rules match and will return
        false if the Access rules do not match.

	.DESCRIPTION
		Checks if two ACL's are matching by finding identical ACE's in the Source and
        Destination ACL's. Returns False if all Destination ACE's match
        the Source ACE's, even if there is not the same amount of ACE's in each.
	#>

    Param (
        [Parameter(Mandatory)]
        [System.Security.AccessControl.FileSystemSecurity]$DestinationAcl,
        [Parameter(Mandatory)]
        [System.Security.AccessControl.FileSystemSecurity]$SourceAcl
    )

    Try {
        $DestinationRules = $DestinationAcl.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])
        $SourceRules = $SourceAcl.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])

        $Matches = @()

        foreach ($D in $DestinationRules) {
            $Match = @($SourceRules).Where( {
                    ($D.FileSystemRights -eq $_.FileSystemRights) -and
                    ($D.AccessControlType -eq $_.AccessControlType) -and
                    ($D.IdentityReference -eq $_.IdentityReference) -and
                    ($D.InheritanceFlags -eq $_.InheritanceFlags) -and
                    ($D.PropagationFlags -eq $_.PropagationFlags)
                })

            if ($Match) {
                $Matches += $Match
            }
            else {
                Return $False
            }
        }

        if ($Matches.Count -ne $SourceRules.Count) {
            Return $False
        }

        Return $True
    }
    Catch {
        throw "Failed testing the ACL for equality: $_"
    }
}
Function Test-AclIsInheritedOnlyHC {
    <#
	.SYNOPSIS
		Test if an ACL only contains inherited ACE's.

	.DESCRIPTION
		Test if an ACL only contains inherited ACE's and no other manually added ACE's.
        Returns true when the ACL is inherited and false when it contains extra added
        ACE's or the ACL is not set to inherit ACE's.
	#>

    Param (
        [Parameter(Mandatory)]
        [System.Security.AccessControl.FileSystemSecurity]$Acl
    )

    Try {
        if ($Acl.AreAccessRulesProtected) {
            Return $false
        }

        if ($Acl.GetAccessRules($true, $false, [System.Security.Principal.NTAccount]).Where( {
                    ($_.IdentityReference -ne 'BUILTIN\Administrators') -and
                    ($_.IdentityReference -ne 'NT AUTHORITY\SYSTEM') }).Count -ne 0) {
            Return $false
        }

        Return $true
    }
    Catch {
        throw "Failed testing the ACL for inherited ACE's only: $_"
    }
}
Function Test-AdObjectsHC {
    Param(
        [parameter(Mandatory)]
        [HashTable]$ADObjects
    )

    try {
        #region Duplicate AD Objects
        if ($NotUniqueADObjects = @($ADObjects.Values.SamAccountName | Group-Object).Where( { $_.Count -ge 2 })) {
            [PSCustomObject]@{
                Type        = 'FatalError'
                Name        = 'AD Object not unique'
                Description = "All objects defined in the matrix need to be unique. Duplicate AD Objects can also be generated from the 'Settings' worksheet combined with the header rows in the 'Permissions' worksheet."
                Value       = $NotUniqueADObjects.Name
            }
        }
        #endregion
    
        #region AD Object name missing
        if (@(($ADObjects.Values.SamAccountName).Where( { -not $_ })).Count -ge 1) {
            [PSCustomObject]@{
                Type        = 'FatalError'
                Name        = 'AD Object name missing'
                Description = "Every column in the worksheet 'Permissions' needs to have an AD object name in the header row. The AD object name can not be blank."
                Value       = $null
            }
        }
        #endregion
    }
    catch {
        throw "Failed testing AD object names: $_"
    }
}
Function Test-ExpandedMatrixHC {
    <#
    .SYNOPSIS
        Verify the data in the matrix.

    .DESCRIPTION
        Test the validity of the content of a matrix once it's expanded.

    .PARAMETER Matrix
        The single complete matrix containing the folder names and the 
        permissions on them as generated by 'ConvertTo-MatrixHC'.

    .PARAMETER ADObjects
        A collection of all the objects used in the matrix containing the 
        details about each object. Is it found in the active directory? Does it 
        have user accounts as member that are not place holder accounts? ... As 
        generated by 'Get-ADObjectDetailHC'.
#>

    [CmdLetBinding()]
    [OutputType([PSCustomObject[]])]
    Param (
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Matrix,
        [Parameter(Mandatory)]
        [PSCustomObject[]]$ADObject,
        [String[]]$ExcludedSamAccountName,
        [HashTable]$DefaultAcl
    )

    Try {
        #region Check if the matrix contains objects not available in ADObjects
        $Matrix.ACL.Keys.Where( 
            { $ADObject.samAccountName -notContains $_ }
        ).Foreach( {
                throw "Unknown AD Object '$_' found in the matrix."
            })
        #endregion

        #region Non existing AD Objects
        if ($ADObjectsUnknown = $ADObject.Where( 
                { -not $_.adObject }
            ).samAccountName
        ) {
            if ($result = $ADObjectsUnknown.Where( 
                    { $Matrix.ACL.Keys -contains $_ })
            ) {
                [PSCustomObject]@{
                    Type        = 'FatalError'
                    Name        = 'Unknown AD object'
                    Description = "Every AD object defined in the header row needs to exist before the matrix can be correctly executed."
                    Value       = $result
                }
            }
        }
        #endregion

        #region Empty AD groups
        $emptyAdGroups = foreach ($group in $ADObject.Where( 
                { $_.adObject.ObjectClass -eq 'group' })
        ) {
            $groupMembers = @($group.adGroupMember.SamAccountName).Where( {
                    $ExcludedSamAccountName -notContains $_
                })
            if (-not $groupMembers) {
                $group.samAccountName
            }
        }

        if ($emptyAdGroups) {
            if ($result = $emptyAdGroups.Where( 
                    { $Matrix.ACL.Keys -contains $_ })
            ) {
                [PSCustomObject]@{
                    Type        = 'Information'
                    Name        = 'Empty groups'
                    Description = 'Every active directory security group defined in the header row needs to have at least one user account as a member, excluding the place holder account.'
                    Value       = $result
                }
            }
        }
        #endregion

        #region Inaccessible folders
        $validAdObjects = $ADObject.Where( {
                (
                    ($_.ADObject.ObjectClass -eq 'group') -and 
                    ($emptyAdGroups -notContains $_.samAccountName)
                ) -or
                ($_.ADObject.ObjectClass -eq 'user')
            }).samAccountName

        if ($result = ($Matrix.Where( {
                        ($_.ACL.Keys.Count -ne 0) -and
                        (-not ($_.ACL.Keys.Where( { $validAdObjects -contains $_ }))) })).Path) {
            [PSCustomObject]@{
                Type        = 'Warning'
                Name        = 'No folder access'
                Description = "Every folder defined in the first column needs to have at least one user account that is able to access it. Group membership is checked to verify if groups granting access to the folder have at least one user account as a member that is not a place holder account."
                Value       = $result
            }
        }
        #endregion

        #region Duplicate AD objects between matrix and default
        if (($DefaultAcl.Count -ne 0) -and ($Matrix.ACL.Count -ne 0)) {
            $tempHash = @{}

            @(@($DefaultAcl.Keys | Select-Object -Unique) +
                @($Matrix.ACL.Keys | Select-Object -Unique)).ForEach( {
                    $tempHash["$_"] += 1
                })

            if ($duplicateAdObject = $tempHash.Keys.Where( { $tempHash["$_"] -gt 1 })) {
                [PSCustomObject]@{
                    Type        = 'Information'
                    Name        = 'Conflicting AD Objects'
                    Description = "AD Objects defined in the matrix are duplicate with the ones defined in the default permissions. In such cases the AD objects in the matrix win over those in the default permissions. This to ensure a folder can be made completely private to those defined in the matrix. This can be desired for departments like 'Legal' or 'HR' where data might contain sensitive information that should not be visible to IT admins defined in the default permissions."
                    Value       = $duplicateAdObject
                }
            }
        }
        #endregion
    }
    Catch {
        throw "Failed validating the expanded matrix: $_"
    }
}
Function Test-FormDataHC {
    <#
    .SYNOPSIS
        Verify input for the Excel sheet 'FormData'.

    .DESCRIPTION
        Verify if the Excel sheet 'FormData' contains the correct data.

    .PARAMETER FormData
        Represents the data coming from the Excel sheet 'FormData'.
#>

    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    Param (
        [Parameter(Mandatory)]
        [PSCustomObject[]]$FormData
    )

    Process {
        Try {
            if ($FormData.Count -ge 2) {
                return [PSCustomObject]@{
                    Type        = 'FatalError'
                    Name        = 'Only one row allowed'
                    Description = "Found $($FormData.Count) rows of data were only one row is allowed."
                    Value       = $MissingProperty
                }
            }

            $Properties = ($FormData | Get-Member -MemberType NoteProperty).Name

            #region Test mandatory property MatrixFormStatus
            if ($Properties -notContains 'MatrixFormStatus') {
                return [PSCustomObject]@{
                    Type        = 'FatalError'
                    Name        = 'Missing column header'
                    Description = "The column header MatrixFormStatus is mandatory."
                    Value       = 'MatrixFormStatus'
                }
            }
            #endregion

            #region Mandatory property
            $mandatoryProperties = @(
                'MatrixFormStatus',
                'MatrixCategoryName' , 
                'MatrixSubCategoryName' , 
                'MatrixResponsible',
                'MatrixFolderDisplayName' , 
                'MatrixFolderPath'  
            )

            if ($MissingProperty = $mandatoryProperties.Where( { 
                        $Properties -notContains $_ })) {
                return [PSCustomObject]@{
                    Type        = 'FatalError'
                    Name        = 'Missing column header'
                    Description = "The column headers $mandatoryProperties are mandatory."
                    Value       = $MissingProperty
                }
            }
            #endregion

            if ($FormData.MatrixFormStatus -eq 'Enabled') {
                $mandatoryPropertyValues = $mandatoryProperties.Where( {
                        $_ -ne 'MatrixFormStatus' })

                #region Mandatory property value
                if ($BlankProperty = $mandatoryPropertyValues.Where( {
                            (-not ($FormData.$_)) -and 
                            ($Properties -contains $_) })) {
                    return [PSCustomObject]@{
                        Type        = 'FatalError'
                        Name        = 'Missing value'
                        Description = "Values for $mandatoryPropertyValues are mandatory."
                        Value       = $BlankProperty
                    }
                }
                #endregion
            }
        }
        Catch {
            throw "Failed testing the Excel sheet 'FormData': $_"
        }
    }
}
Function Test-MatrixPermissionsHC {
    <#
    .SYNOPSIS
        Verify input for the Excel sheet 'Permissions'.

    .DESCRIPTION
        Verify if all input in the Excel sheet 'Permissions' is correct. When 
        incorrect input is detected an object is returned containing all the 
        details about the issue.

        This test is best run before expanding the matrix. as it will gain time.

    .PARAMETER Permissions
        The objects coming from the Excel sheet 'Permissions', as retrieved by
        Import-Excel.
    #>

    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    Param (
        [parameter(Mandatory)]
        [PSCustomObject[]]$Permissions
    )

    Process {
        Try {
            $Props = $Permissions[0].PSObject.Properties.Name
            $FirstProperty = $Props[0]

            #region At least 5 rows
            if (@($Permissions).Count -lt 4) {
                Return [PSCustomObject]@{
                    Type        = 'FatalError'
                    Name        = 'Missing rows'
                    Description = 'At least 4 rows are required: 3 header rows and 1 row for the parent folder.'
                    Value       = "$(@($Permissions).Count) rows"
                }
            }
            #endregion

            #region At least 2 columns
            if (@($Props).Count -lt 2) {
                Return [PSCustomObject]@{
                    Type        = 'FatalError'
                    Name        = 'Missing columns'
                    Description = 'At least 2 columns are required: 1 for the folder names and 1 where the permissions are defined.'
                    Value       = "$(@($Props).Count) column"
                }
            }
            #endregion

            $NonHeaderRows = $Permissions | Select-Object -Skip 3

            #region Permission character unknown
            $UnknownPermChar = foreach ($N in $NonHeaderRows) {
                $Props = ($N.PSObject.Properties).Where( { $_.Name -ne $FirstProperty })

                $Props.Foreach( {
                        $Ace = if ($tmpVal = $_.Value) { $tmpVal }

                        if (($Ace) -and ($Ace -notMatch '^(L|R|W|I|C|F)$')) {
                            $Ace
                        }
                    })
            }

            if ($UnknownPermChar) {
                [PSCustomObject]@{
                    Type        = 'FatalError'
                    Name        = 'Permission character unknown'
                    Description = "The only supported characters, to define permissions on a folder, are 'F' (FullControl), 'W' (Write/Modify), 'R' (Read), 'L' (List) or ' ' (blank)."
                    Value       = $UnknownPermChar | Select-Object -Unique
                }
            }
            #endregion

            $ParentFolderPermissions = ($Permissions[3].PSObject.Properties.Where( { $_.Name -ne $FirstProperty }).Where( {
                        $_.Value })).Value

            #region Permissions missing for parent folder
            if (@(($ParentFolderPermissions).Where( { $_ })).Count -eq 0) {
                [PSCustomObject]@{
                    Type        = 'FatalError'
                    Name        = 'Permissions missing on parent folder'
                    Description = 'Missing permissions on the parent folder. At least one permission character needs to be set.'
                    Value       = $null
                }
            }

            if ($ParentFolderPermissions -contains 'i') {
                [PSCustomObject]@{
                    Type        = 'FatalError'
                    Name        = 'Permissions missing on parent folder'
                    Description = "The permission ignore 'i' cannot be used on the parent folder."
                    Value       = $null
                }
            }
            #endregion

            #region Folder name missing
            $FolderNames = $NonHeaderRows | Select-Object -Skip 1

            if (-not @(@($FolderNames.$FirstProperty).Where( { -not ($_) }).Count -eq 0)) {
                [PSCustomObject]@{
                    Type        = 'FatalError'
                    Name        = 'Folder name missing'
                    Description = 'Missing folder name in the first column. A folder name is required to be able to set permissions on it.'
                    Value       = $null
                }
            }
            #endregion

            #region Duplicate folder name
            $NotUniqueFolder = @($FolderNames.$FirstProperty | Group-Object).Where( { $_.Count -ge 2 })

            if ($NotUniqueFolder) {
                Return [PSCustomObject]@{
                    Type        = 'FatalError'
                    Name        = 'Folder name not unique'
                    Description = 'Every folder name in the first column needs to be unique. This is required to be able to set the correct permissions.'
                    Value       = $NotUniqueFolder.Name
                }

            }
            #endregion

            #region Deepest folder has only List permissions or none at all
            $FolderRows = @($Permissions | Select-Object -Skip 4)
            $Paths = @($FolderRows.$FirstProperty)

            $DeepestFolders = @(foreach ($P in $Paths) {
                    if (-not ($Paths.Where( { $_ -like "$P\*" }))) {
                        $P
                    }
                })

            $ParentFolderHasPermission = $ParentFolderPermissions.Where( { $_ -ne 'L' })

            $inAccessibleFolder = foreach ($N in ($FolderRows.Where( { $DeepestFolders -contains $_.$FirstProperty }))) {
                $Perms = (($N.PSObject.Properties).Where( {
                            ($_.Name -ne $FirstProperty) -and ($_.Value) -and ($_.Value -ne 'L') })).Value

                if ((-not $Perms) -and (-not $ParentFolderHasPermission)) {
                    $N.$FirstProperty
                }
            }

            if ($inAccessibleFolder) {
                [PSCustomObject]@{
                    Type        = 'Warning'
                    Description = "All folders need to be accessible by the end user. Please define at least (R)ead or (W)rite permissions on the deepest folder or use the permission (I) ignore."
                    Name        = 'Matrix design flaw'
                    Value       = $inAccessibleFolder
                }
            }
            #endregion
        }
        Catch {
            throw "Failed testing the Excel sheet 'Permissions' for incorrect data: $_"
        }
    }
}
Function Test-MatrixSettingHC {
    <#
    .SYNOPSIS
        Verify input for the Excel sheet 'Settings'.

    .DESCRIPTION
        Verify if one Excel row in the Excel sheet 'Settings' is correct. A FatalError object is created
        for each incorrect setting found (missing ComputerName parameter, ...)

        All rows are tested. In case only 'Status -eq Enabled' rows need to be tested,
        a filter needs to be applied upfront.

    .PARAMETER Setting
        Represents one row in the Excel sheet 'Settings', as retrieved by Import-Excel.

    .PARAMETER Location
        The string used to define the location in the Excel file where the error occurred.
#>

    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    Param (
        [Parameter(Mandatory)]
        [PSCustomObject]$Setting
    )

    Process {
        Try {
            $Properties = ($Setting | Get-Member -MemberType NoteProperty).Name

            #region Missing property
            if ($MissingProperty = @('ComputerName' , 'Path' , 'Action').Where( { $Properties -notContains $_ })) {
                [PSCustomObject]@{
                    Type        = 'FatalError'
                    Name        = 'Missing column header'
                    Description = "The column headers 'ComputerName', Path' and 'Action' are mandatory."
                    Value       = $MissingProperty
                }
            }
            #endregion

            #region Blank property value
            if ($BlankProperty = @('ComputerName' , 'Path' , 'Action').Where( {
                        (-not ($Setting.$_)) -and ($Properties -contains $_) })) {
                [PSCustomObject]@{
                    Type        = 'FatalError'
                    Name        = 'Missing value'
                    Description = "Values for 'ComputerName', Path' and 'Action' are mandatory."
                    Value       = $BlankProperty
                }
            }
            #endregion

            #region Action can only be New, Fix or Check
            if (($Setting.Action) -and ($Setting.Action -notMatch '^(New|Fix|Check)$')) {
                [PSCustomObject]@{
                    Type        = 'FatalError'
                    Name        = 'Action value incorrect'
                    Description = "Only the values 'New', 'Fix' or 'Check' are supported in the field 'Action'."
                    Value       = $Setting.Action
                }
            }
            #endregion

            #region Path needs to be valid local path
            if (($Setting.Path) -and ($Setting.Path -notMatch '^[a-zA-Z]:\\(\w+)')) {
                [PSCustomObject]@{
                    Type        = 'FatalError'
                    Name        = 'Path value incorrect'
                    Description = "The 'Path' needs to be defined as a local folder (Ex. 'E:\Department\Finance')."
                    Value       = $Setting.Path
                }
            }
            #endregion
        }
        Catch {
            throw "Failed testing the Excel sheet 'Settings' row for incorrect data: $_"
        }
    }
}

Export-ModuleMember -Function * -Alias *