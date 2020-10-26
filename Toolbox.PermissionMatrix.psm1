#Requires -Version 5.1

# obsolete:
Function Get-MatrixAdObjectNamesHC {
    <#
    .SYNOPSIS
        Get all AD object names used in a matrix Excel file

    .DESCRIPTION
        Get all AD object names used in a matrix Excel file. Generate the complete AD name from the
        Excel sheet 'Settings' together with the sheet 'Permissions'.

    .PARAMETER Path
        Location to the Excel file or folder, containing the Excel files. Each file is assumed to have a worksheet 'Permissions' and 'Settings'.
 #>

    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    Param (
        [Parameter(Mandatory)]
        [ValidateScript( { Test-Path -Path $_ })]
        [String]$Path
    )

    Try {
        $ItemPath = Get-Item -LiteralPath $Path

        $ExcelFiles = @($ItemPath)

        if ($ItemPath.PSIsContainer) {
            $ExcelFiles = Get-ChildItem $Path\* -Include *.xlsx -File
        }

        foreach ($F in $ExcelFiles) {
            if ($Settings = Import-Excel $F -Sheet Settings -DataOnly | 
                Where-Object Status -EQ Enabled) {
                $Permissions = Import-Excel $F -Sheet Permissions -DataOnly -NoHeader

                $Matrix = Expand-MatrixHC -Permissions $Permissions -Settings $Settings

                [PSCustomObject]@{
                    FileName = $F.Name
                    ADObject = $Matrix.Permissions.ACL.Keys | 
                    Sort-Object -Unique
                }
            }
        }
    }
    Catch {
        throw "Failed retrieving matrix AD objects from path '$Path': $_"
    }
}

Function ConvertTo-AceHC {
    <#
    .SYNOPSIS
        Convert an AD Object name and a permission character to a valid ACE.

    .DESCRIPTION
        Convert an AD Object name and a permission character to a valid Access Control List Entry.

    .PARAMETER Type
        The permission character defining the access to the folder.

    .PARAMETER Name
        Name of the AD object, used to identify the user or group witin AD.

    .NOTES
	    CHANGELOG
	    2018/08/07 Function born

	    AUTHOR Brecht.Gijbels@heidelbergcement.com #>

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

Function Expand-MatrixHC {
    <#
    .SYNOPSIS
        Create a new permission matrix for each row in the Excel sheet 
        'Settings'.

    .DESCRIPTION
        Create a new permission matrix for each row in the excel sheet 
        'Settings'. In case only 'Status -eq Enabled' rows are required, please 
        filter these upfront.

        The 'GroupName' and the 'SiteCode' are read from the 'Settings' sheet. 
        These are then used to generate the correct 'SamAccountName' with the 
        column headers found in the 'Permissions' sheet.

    .PARAMETER Permissions
        The objects coming from the Excel sheet 'Permissions', as retrieved by
        Import-Excel.

    .PARAMETER Settings
        The objects coming from the Excel sheet 'Settings', as retrieved by
        Import-Excel.

    .NOTES
        2016/06/20 Rewrote the whole thing from a function to a workflow.
        2016/07/06 Rewrote the 'InlineScript' function 'New-MatrixHC' to not use 'Copy-ArrayHC'.
                    This isn't needed in a workflow as we don't alter the workflow variable and each
                    'InlineScript' runs in its own scope.
        2018/06/12 Reverted back from Workflow to Function, as Workflow will no longer be supported
                   in PSCore

        AUTHOR Brecht.Gijbels@heidelbergcement.com #>

    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    Param (
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Permissions,
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Settings
    )

    Try {
        $Done = @{}

        foreach ($S in $Settings) {
            $formattedSettingsRow = Format-SettingStringsHC -Settings $S

            $Key = ($formattedSettingsRow.GroupName + ' - ' + $formattedSettingsRow.SiteCode)

            if ($Done.ContainsKey($Key)) {
                $ACL = $Done.$Key
            }
            else {
                $ADObjectParams = @{
                    Begin         = $formattedSettingsRow.GroupName
                    Middle        = $formattedSettingsRow.SiteCode
                    ColumnHeaders = $Permissions
                }
                $ADObjects = ConvertTo-MatrixADNamesHC @ADObjectParams

                $Params = @{
                    NonHeaderRows = $Permissions | Select-Object -Skip 3
                    ADObjects     = $ADObjects
                }
                $ACL = ConvertTo-MatrixAclHC @Params

                $Done.Add($Key, $ACL)
            }

            [PSCustomObject]$formattedSettingsRow | 
            Select-Object *, @{N = 'Permissions'; E = { $ACL } }
        }
    }
    Catch {
        throw "Failed to expand the matrix sheet 'Permissions' based on the sheet 'Settings': $S"
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

    .NOTES
    	CHANGELOG
    	2018/07/30 Function born
        2018/08/22 Change permission char to upper case

    	AUTHOR Brecht.Gijbels@heidelbergcement.com #>

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

    .NOTES
    	CHANGELOG
    	2018/06/20 Function born
        2018/07/12 Added pipeline support

    	AUTHOR Brecht.Gijbels@heidelbergcement.com #>

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

Function Get-ADObjectDetailHC {
    <#
    .SYNOPSIS
        Retrieve details about an AD object.

    .DESCRIPTION
        Check if a SamAccountName for a group or user exists in active 
        directory and in case it's a group, check if it has members. When 
        checking for members the users defined in 'ExcludeMember'
        are not considered as member of a group.

    .PARAMETER Name
        SamAccountName of the active directory object.

    .PARAMETER ExcludeMember
        Members to excluded from the member list. These users are ignored. If a 
        group has only one of the users defined in ExcludeMember as a member, 
        the group will be reported as an empty group. In that case the property 
        'Members' will be set to 'False'.

    .NOTES
        CHANGELOG
        2018/07/24 Function born
        2020/05/06 Fixed typo, better error handling
                   fixed timeout for retrieving 'Domain users' as they always have members

        AUTHOR Brecht.Gijbels@heidelbergcement.com #>

    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    Param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory, ValueFromPipeline)]
        [String[]]$Name,
        [String[]]$ExcludeMember
    )

    Process {
        foreach ($n in $Name) {
            Try {
                $result = @{
                    Name     = $n
                    ADObject = Get-ADObject -Filter "SAMAccountName -eq '$n'"
                    Member   = $null
                }
                
                if ($result.ADObject.ObjectClass -eq 'group') {
                    if ($result.Name -eq 'domain users') { $result.Member = $true }
                    else {
                        $Member = @(Get-ADGroupMember -Identity $result.ADObject -Recursive).Where(
                            { 
                                ($_.ObjectClass -eq 'user') -and 
                                ($ExcludeMember -notcontains $_.SamAccountName) 
                            }, 'First')

                        $result.Member = if ($Member) { $true } else { $false }
                    }
                }

                [PSCustomObject]$result # users return as member null
            }
            Catch {
                throw "Failed to test if SamAccountName '$n' exists in AD: $_"
            }
        }
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

    .NOTES
	    CHANGELOG
	    2018/06/21 Function born

	    AUTHOR Brecht.Gijbels@heidelbergcement.com #>

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

                    if ($Permission -notmatch '^(L|R|W|C|F)$') {
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
        Filter out matrix that have a FatalError object in the File, Permissions or in
        the Settings object itself. Only those matrix that are flawless can be executed
        to set permissions on folders.

    .PARAMETER From
        One object for each file, containing the File, Settings and Permissions properties.

    .NOTES
	    CHANGELOG
	    2018/07/20 Function born

	    AUTHOR Brecht.Gijbels@heidelbergcement.com #>

    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    Param (
        [Parameter(Mandatory = $false)]
        [PSCustomObject[]]$From
    )

    Try {
        @((@($From).Where( {
                        ($_.File.Check.Type -notcontains 'FatalError') -and
                        ($_.Permissions.Check.Type -notcontains 'FatalError') })).Settings).Where( {
                ($_.Check.Type -notcontains 'FatalError') -and ($_.Matrix)
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

    .NOTES
	    CHANGELOG
	    2018/07/20 Function born

	    AUTHOR Brecht.Gijbels@heidelbergcement.com #>

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
                    $Check.Description = "A non terminating error occured while executing the job '$($Job.Name)'."
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
                    $Check.Description = "A terminating error occured while executing the job '$($Job.Name)'."
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
        throw "Failed retreiving the job errors for job '$($Job.Name)' on '$($Job.Location)': $_"
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

    .NOTES
        CHANGELOG
        2018/06/21 Function born

        AUTHOR Brecht.Gijbels@heidelbergcement.com #>

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

Function Test-AclEqualHC {
    <#
	.SYNOPSIS
		Compare two ACL's. Will return True if the Access Rules match and will return
        false if the Access rules do not match.

	.DESCRIPTION
		Checks if two ACL's are matching by finding identical ACE's in the Source and
        Destination ACL's. Returns False if all Destination ACE's match
        the Source ACE's, even if there is not the same amount of ACE's in each.

    .NOTES
        2018/08/06 Function born

        AUTHOR Brecht.Gijbels@heidelbergcement.com
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

    .NOTES
        2018/08/06 Function born
        2018/08/16 Exclude 'BUILTIN\Adminstrators
        2018/08/17 Exclude 'NT AUTHORITY\SYSTEM'
        '
        AUTHOR Brecht.Gijbels@heidelbergcement.com
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

Function Test-ExpandedMatrixHC {
    <#
    .SYNOPSIS
        Verify the data in the matrix.

    .DESCRIPTION
        Test the validity of the content of a matrix once it's expanded.

    .PARAMETER Matrix
        The single complete matrix containing the folder names and the permissions on them
        as generated by 'Expand-MatrixHC'.

    .PARAMETER ADObjects
        A collection of all the objects used in the matrix containing the details about each object.
        Is it found in the active directory? Does it have user accounts as member that are not place
        holder accounts? ... As generated by 'Get-ADObjectDetailHC'.

    .NOTES
	    CHANGELOG
	    2018/07/25 Function born
        2018/07/30 Added duplicate AD objects between matrix and default

	    AUTHOR Brecht.Gijbels@heidelbergcement.com #>

    [CmdLetBinding()]
    [OutputType([PSCustomObject[]])]
    Param (
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Matrix,
        [Parameter(Mandatory)]
        [PSCustomObject[]]$ADObject,
        [HashTable]$DefaultAcl
    )

    Try {
        #region Check if the matrix contains objects not available in ADObjects
        $Matrix.ACL.Keys.Where( { $ADObject.Name -notcontains $_ }).Foreach( {
                throw "Unknown AD Object '$_' found in the matrix."
            })
        #endregion

        #region Non existing AD Objects
        if ($ADObjectsUnknown = $ADObject.Where( { -not $_.ADObject }).Name) {
            if ($result = $ADObjectsUnknown.Where( { $Matrix.ACL.Keys -contains $_ })) {
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
        if ($ADGroupEmpty = $ADObject.Where( { ($_.ADObject.ObjectClass -eq 'group') -and (-not $_.Member) }).Name) {
            if ($result = $ADGroupEmpty.Where( { $Matrix.ACL.Keys -contains $_ })) {
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
        $ADvalidAccessAccounts = $ADObject.Where( {
                (($_.ADObject.ObjectClass -eq 'group') -and ($_.Member)) -or
                ($_.ADObject.ObjectClass -eq 'user')
            }).Name

        if ($result = ($Matrix.Where( {
                        ($_.ACL.Keys.Count -ne 0) -and
                        (-not ($_.ACL.Keys.Where( { $ADvalidAccessAccounts -contains $_ }))) })).Path) {
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

            if ($duplicateADobject = $tempHash.Keys.Where( { $tempHash["$_"] -gt 1 })) {
                [PSCustomObject]@{
                    Type        = 'Information'
                    Name        = 'Conflichting AD Objects'
                    Description = "AD Objects defined in the matrix are duplicate with the ones defined in the default permissions. In such cases the AD objects in the matrix win over those in the default permissions. This to ensure a folder can be made completely private to those defined in the matrix. This can be desired for departments like 'Legal' or 'HR' where data might contian sensitive information that should not be visible to IT admins defined in the default permissions."
                    Value       = $duplicateADobject
                }
            }
        }
        #endregion
    }
    Catch {
        throw "Failed validating the expanded matrix: $_"
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

    .PARAMETER FatalErrorType
        The string used for defining a fatal error message.

    .PARAMETER Location
        The string used to define the location in the Excel file where the 
        error ocurred.

    .NOTES
	    CHANGELOG
	    2018/06/19 Function born
        2018/07/12 Create objects instead of throwing an error
        2018/07/25 Added test for permissions on deepest folder

	    AUTHOR Brecht.Gijbels@heidelbergcement.com #>

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
            if (@($Permissions).Count -lt 5) {
                Return [PSCustomObject]@{
                    Type        = 'FatalError'
                    Name        = 'Missing rows'
                    Description = 'At least 5 rows are required: 3 header rows. 1 row for the parent folder and at least 1 row for defining permissions on a sub folder.'
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

            $HeaderRows = $Permissions | Select-Object -First 3
            $ADObjects = ConvertTo-MatrixADNamesHC -ColumnHeaders $HeaderRows

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
            if (@(($ADObjects.Values.SamAccountName).Where( { $_ })).Count -eq 0) {
                [PSCustomObject]@{
                    Type        = 'FatalError'
                    Name        = 'AD Object name missing'
                    Description = "Every column in the worksheet 'Permissions' needs to have an AD object name in the header row. The AD object name can not be blank."
                    Value       = $null
                }
            }
            #endregion

            $NonHeaderRows = $Permissions | Select-Object -Skip 3

            #region Permission character unknown
            $UnknownPermChar = foreach ($N in $NonHeaderRows) {
                $Props = ($N.PSObject.Properties).Where( { $_.Name -ne $FirstProperty })

                $Props.Foreach( {
                        $Ace = if ($tmpVal = $_.Value) { $tmpVal }

                        if (($Ace) -and ($Ace -notmatch '^(L|R|W|I|C|F)$')) {
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
                    Description = "All folders need to be accessible by the end user. Please define at least (R)ead or (W)rite permissions on the deepest folder or use the permission (I)gnore."
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
        The string used to define the location in the Excel file where the error occured.

    .NOTES
	    CHANGELOG
	    2018/06/19 Function born
        2018/07/12 Create objects instead of throwing an error

	    AUTHOR Brecht.Gijbels@heidelbergcement.com #>

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
            if ($MissingProperty = @('ComputerName' , 'Path' , 'Action').Where( { $Properties -notcontains $_ })) {
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
            if (($Setting.Action) -and ($Setting.Action -notmatch '^(New|Fix|Check)$')) {
                [PSCustomObject]@{
                    Type        = 'FatalError'
                    Name        = 'Action value incorrect'
                    Description = "Only the values 'New', 'Fix' or 'Check' are supported in the field 'Action'."
                    Value       = $Setting.Action
                }
            }
            #endregion

            #region Path needs to be valid local path
            if (($Setting.Path) -and ($Setting.Path -notmatch '^[a-zA-Z]:\\(\w+)')) {
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