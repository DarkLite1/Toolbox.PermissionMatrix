#Requires -Version 7

function ConvertTo-AceHC {
    <#
    .SYNOPSIS
        Convert an AD Object name and a permission character to a valid ACE.

    .DESCRIPTION
        Convert an AD Object name and a permission character to a valid Access Control List Entry.

    .PARAMETER Type
        The permission character defining the access to the folder. Valid values: L, R, W, F, M.

    .PARAMETER Name
        Name of the AD object, used to identify the user or group within AD.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateSet('L', 'R', 'W', 'F', 'M')]
        [String]$Type,

        [Parameter(Mandatory)]
        [String]$Name
    )

    $Identity = if ($Name -match '\\') { $Name } else { "$env:USERDOMAIN\$Name" }

    switch ($Type) {
        'L' {
            return [System.Security.AccessControl.FileSystemAccessRule]::new(
                $Identity,
                [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
                [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
        }
        'W' {
            # This folder only
            [System.Security.AccessControl.FileSystemAccessRule]::new(
                $Identity,
                [System.Security.AccessControl.FileSystemRights]'CreateFiles, AppendData, DeleteSubdirectoriesAndFiles, ReadAndExecute, Synchronize',
                [System.Security.AccessControl.InheritanceFlags]::None,
                [System.Security.AccessControl.PropagationFlags]::InheritOnly,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            # Subfolders and files only
            [System.Security.AccessControl.FileSystemAccessRule]::new(
                $Identity,
                [System.Security.AccessControl.FileSystemRights]'DeleteSubdirectoriesAndFiles, Modify, Synchronize',
                [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                [System.Security.AccessControl.PropagationFlags]::InheritOnly,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            return
        }
        'R' {
            return [System.Security.AccessControl.FileSystemAccessRule]::new(
                $Identity,
                [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
                [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
        }
        'F' {
            return [System.Security.AccessControl.FileSystemAccessRule]::new(
                $Identity,
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
        }
        'M' {
            return [System.Security.AccessControl.FileSystemAccessRule]::new(
                $Identity,
                [System.Security.AccessControl.FileSystemRights]::Modify,
                [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
        }
    }
}
function ConvertTo-MatrixADNamesHC {
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

    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory)]
        [ValidateCount(3, [int]::MaxValue)]
        [PSCustomObject[]]$ColumnHeaders,
        [String]$Begin,
        [String]$Middle,
        [String]$BeginReplace = 'GroupName',
        [String]$MiddleReplace = 'SiteCode'
    )

    process {
        try {
            Write-Verbose 'Converting to matrix AD object names'

            $Properties = $ColumnHeaders[0].PSObject.Properties.Name
            $FirstProperty = $Properties[0]
            $Result = @{}

            foreach ($Prop in $Properties) {
                # Skip the first column (usually the folder path/row headers)
                if ($Prop -eq $FirstProperty) { continue }

                Write-Verbose "Processing Property: '$Prop'"

                #region Get original values
                $EndVal = $ColumnHeaders[0].$Prop
                $MiddleVal = $ColumnHeaders[1].$Prop
                $BeginVal = $ColumnHeaders[2].$Prop

                $Original = [ordered]@{
                    Begin  = $BeginVal
                    Middle = $MiddleVal
                    End    = $EndVal
                }
                Write-Verbose "Original value begin '$BeginVal' middle '$MiddleVal' end '$EndVal'"
                #endregion

                #region Convert placeholder to proper values
                $ConvBegin = if ($BeginVal -eq $BeginReplace -and $Begin) { $Begin } else { $BeginVal }
                $ConvMiddle = if ($MiddleVal -eq $MiddleReplace -and $Middle) { $Middle } else { $MiddleVal }
                $ConvEnd = $EndVal

                $Converted = [ordered]@{
                    Begin  = $ConvBegin
                    Middle = $ConvMiddle
                    End    = $ConvEnd
                }
                Write-Verbose "Converted value begin '$ConvBegin' middle '$ConvMiddle' end '$ConvEnd'"
                #endregion

                #region Create SamAccountName
                # Filter out nulls/spaces and join
                $SamAccountName = (
                    $ConvBegin, $ConvMiddle, $ConvEnd | Where-Object { 
                        -not [string]::IsNullOrWhiteSpace($_) 
                    }
                ) -join ' '
                
                Write-Verbose "SamAccountName '$SamAccountName'"
                #endregion

                $Result.$Prop = @{
                    SamAccountName = $SamAccountName
                    Original       = $Original
                    Converted      = $Converted
                }
            }

            return $Result
        }
        catch {
            throw "Failed generating the correct AD object name for begin '$Begin' and middle '$Middle': $_"
        }
    }
}
function ConvertTo-MatrixAclHC {
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
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory)]
        [PSCustomObject[]]$NonHeaderRows,

        [Parameter(Mandatory)]
        [hashtable]$ADObjects
    )

    begin {
        try {
            # Cache the column names ONCE instead of evaluating them every row
            $AllProperties = $NonHeaderRows[0].PSObject.Properties.Name
            $FirstProperty = $AllProperties[0]
            
            # Create an array of just the columns that contain permissions
            $PermColumns = $AllProperties | Select-Object -Skip 1
        }
        catch {
            throw "Failed initializing ConvertTo-MatrixAclHC: $_"
        }
    }

    process {
        try {
            for ($i = 0; $i -lt $NonHeaderRows.Count; $i++) {
                $Row = $NonHeaderRows[$i]
                $Path = $Row.$FirstProperty

                $Obj = [PSCustomObject]@{
                    Path   = $Path
                    Parent = ($i -eq 0)
                    Ignore = $false
                    ACL    = @{}
                }

                foreach ($ColName in $PermColumns) {
                    $Ace = $Row.$ColName

                    if ([string]::IsNullOrWhiteSpace($Ace)) { continue }

                    # If we hit an 'i' or 'I', set Ignore, clear any ACLs, and stop checking this row
                    if ($Ace -eq 'i' -or $Ace -eq 'I') {
                        $Obj.Ignore = $true
                        $Obj.ACL.Clear()
                        break
                    }

                    $SamAccountName = $ADObjects.($ColName).SamAccountName

                    if ([string]::IsNullOrWhiteSpace($SamAccountName)) {
                        throw "Missing AD Object for column $($ColName.TrimStart('P')) on folder path '$Path'."
                    }

                    if ($Obj.ACL.ContainsKey($SamAccountName)) {
                        throw "The AD object name '$SamAccountName' is not unique on folder path '$Path'."
                    }

                    $Obj.ACL.Add($SamAccountName, $Ace)
                }

                $Obj
            }
        }
        catch {
            throw "Failed converting to matrix ACL: $_"
        }
    }
}
function Format-PermissionsStringsHC {
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
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject[]]$Permissions
    )

    begin {
        $RowIndex = 0
        $FirstPropertyName = $null
    }

    process {
        foreach ($Row in $Permissions) {
            if ($null -eq $FirstPropertyName) {
                $FirstPropertyName = @($Row.PSObject.Properties.Name)[0]
            }

            foreach ($P in $Row.PSObject.Properties) {
                if (-not [string]::IsNullOrWhiteSpace($P.Value)) {
                    
                    $CleanValue = $P.Value.ToString().Trim()

                    if ($P.Name -eq $FirstPropertyName) {
                        $P.Value = $CleanValue.Trim('\')
                    } 
                    elseif ($RowIndex -ge 3) {
                        $P.Value = $CleanValue.ToUpper()
                    } 
                    else {
                        $P.Value = $CleanValue
                    }
                }
            }

            $Row
            $RowIndex++
        }
    }
}
function Format-SettingStringsHC {
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
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSCustomObject]$Settings
    )

    process {
        $Obj = [ordered]@{}

        foreach ($Prop in $Settings.PSObject.Properties) {
            if ([string]::IsNullOrWhiteSpace($Prop.Value)) {
                $Obj[$Prop.Name] = $null
                continue
            }

            $Value = $Prop.Value.ToString().Trim()

            $Obj[$Prop.Name] = switch ($Prop.Name) {
                { $_ -in 'Action', 'Status' } {
                    $Value.Substring(0, 1).ToUpper() + $Value.Substring(1).ToLower()
                }
                'ComputerName' {
                    $Value = $Value.ToUpper()
                    $Domain = $env:USERDNSDOMAIN
                    
                    if ($Domain -and $Value -like "*.$Domain") {
                        $Value = $Value -ireplace [regex]::Escape(".$Domain"), ''
                    }
                    $Value
                }
                'Path' {
                    $Value.TrimEnd('\')
                }
                default {
                    $Value
                }
            }
        }

        [PSCustomObject]$Obj
    }
}
function Get-DefaultAclHC {
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
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Sheet
    )

    process {
        try {
            $ACL = @{}

            foreach ($Row in $Sheet) {
                $ADObjectName = $Row.ADObjectName
                $Permission = $Row.Permission

                $HasName = -not [string]::IsNullOrWhiteSpace($ADObjectName)
                $HasPerm = -not [string]::IsNullOrWhiteSpace($Permission)

                if ((-not $HasName ) -and (-not $HasPerm)) {
                    continue
                }

                if (-not $HasPerm) {
                    throw "AD object name '$ADObjectName' has no permission."
                }

                if (-not $HasName) {
                    throw "Permission '$Permission' has no AD object name."
                }

                if ($Permission -notmatch '^(L|R|W|M|F)$') {
                    throw "Permission character '$Permission' is unknown."
                }

                if ($ACL.ContainsKey($ADObjectName)) {
                    throw "AD Object name '$ADObjectName' is not unique."
                }

                $ACL.Add($ADObjectName, $Permission)
            }

            return $ACL
        }
        catch {
            throw "Failed retrieving the ACL from the default settings file: $_"
        }
    }
}
function Get-ExecutableMatrixHC {
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
    param (
        [Parameter(Mandatory = $false)]
        [PSCustomObject[]]$From
    )

    try {
        @((@($From).Where( {
                        ($_.File.Check.Type -notcontains 'FatalError') -and
                        ($_.Permissions.Check.Type -notcontains 'FatalError') })).Settings).Where( {
                ($_.Check.Type -notcontains 'FatalError') -and ($_.Matrix)
            })
    }
    catch {
        throw "Failed retrieving the executable matrix: $_"
    }
}
function Get-JobErrorHC {
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
    param (
        [Parameter(Mandatory)]
        [System.Management.Automation.Job]$Job
    )

    try {
        $Check = @{}

        switch ($Job.State) {
            'Completed' {
                if ($Job.ChildJobs[0].Error) {
                    $Check.Type = 'FatalError'
                    $Check.Value = $Job.ChildJobs[0].Error.Exception.Message
                    $Check.Name = 'Non terminating error'
                    $Check.Description = "A non terminating error occurred while executing the job '$($Job.Name)'."
                }
                break
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
                break
            }
            default {
                throw "Job state '$_' is unsupported."
            }
        }

        if ($Check.Count -ne 0) {
            [PSCustomObject]$Check
        }
    }
    catch {
        throw "Failed retrieving the job errors for job '$($Job.Name)' on '$($Job.Location)': $_"
    }
}
function Get-ADObjectNotExistingHC {
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
    param (
        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory, ValueFromPipeline)]
        [String[]]$Name
    )

    process {
        try {
            foreach ($N in $Name) {
                if (-not (Get-ADObject -Filter "SAMAccountName -eq '$N'")) {
                    $N
                }
            }
        }
        catch {
            throw "Failed to test if SamAccountName '$Name' exists: $_"
        }
    }
}
function Get-AdUserPrincipalNameHC {
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
    param(
        [Parameter(Mandatory)]
        [String[]]$Name,
        [String[]]$ExcludeSamAccountName
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
                continue
            }

            $adUsers = if ($adObject.ObjectClass -eq 'group') {
                Get-ADGroupMember $adObject -Recursive
            }
            elseif ($adObject.ObjectClass -eq 'user') {
                $adObject
            }

            $adUsers | Get-ADUser -Properties Enabled, SamAccountName, Mail |
            Where-Object {
                ($_.Mail) -and
                ($_.Enabled) -and
                ($ExcludeSamAccountName -notcontains $_.SamAccountName)
            } |
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
function Test-AclEqualHC {
    <#
	.SYNOPSIS
		Compare two ACL's. Will return True if the Access Rules match and will return
        false if the Access rules do not match.

	.DESCRIPTION
		Checks if two ACL's are matching by finding identical ACE's in the Source and
        Destination ACL's. Returns False if all Destination ACE's match
        the Source ACE's, even if there is not the same amount of ACE's in each.
	#>

    param (
        [Parameter(Mandatory)]
        [System.Security.AccessControl.FileSystemSecurity]$DestinationAcl,
        [Parameter(Mandatory)]
        [System.Security.AccessControl.FileSystemSecurity]$SourceAcl
    )

    try {
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
                return $False
            }
        }

        if ($Matches.Count -ne $SourceRules.Count) {
            return $False
        }

        return $True
    }
    catch {
        throw "Failed testing the ACL for equality: $_"
    }
}
function Test-AclIsInheritedOnlyHC {
    <#
	.SYNOPSIS
		Test if an ACL only contains inherited ACE's.

	.DESCRIPTION
		Test if an ACL only contains inherited ACE's and no other manually added ACE's.
        Returns true when the ACL is inherited and false when it contains extra added
        ACE's or the ACL is not set to inherit ACE's.
	#>

    param (
        [Parameter(Mandatory)]
        [System.Security.AccessControl.FileSystemSecurity]$Acl
    )

    try {
        if ($Acl.AreAccessRulesProtected) {
            return $false
        }

        if ($Acl.GetAccessRules($true, $false, [System.Security.Principal.NTAccount]).Where( {
                    ($_.IdentityReference -ne 'BUILTIN\Administrators') -and
                    ($_.IdentityReference -ne 'NT AUTHORITY\SYSTEM') }).Count -ne 0) {
            return $false
        }

        return $true
    }
    catch {
        throw "Failed testing the ACL for inherited ACE's only: $_"
    }
}
function Test-AdObjectsHC {
    param(
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
                Value       = $NotUniqueADObjects.Name | Sort-Object
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
function Test-ExpandedMatrixHC {
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
    param (
        [Parameter(Mandatory)]
        [PSCustomObject[]]$Matrix,
        [Parameter(Mandatory)]
        [PSCustomObject[]]$ADObject,
        [String[]]$ExcludedSamAccountName,
        [HashTable]$DefaultAcl
    )

    try {
        #region Check if the matrix contains objects not available in ADObjects
        $Matrix.ACL.Keys.Where(
            { $ADObject.samAccountName -notcontains $_ }
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
                    Description = 'Every AD object defined in the header row needs to exist before the matrix can be correctly executed.'
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
                    $ExcludedSamAccountName -notcontains $_
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
                    ($emptyAdGroups -notcontains $_.samAccountName)
                ) -or
                ($_.ADObject.ObjectClass -eq 'user')
            }).samAccountName

        if ($result = ($Matrix.Where( {
                        ($_.ACL.Keys.Count -ne 0) -and
                        (-not ($_.ACL.Keys.Where( { $validAdObjects -contains $_ }))) })).Path) {
            [PSCustomObject]@{
                Type        = 'Warning'
                Name        = 'No folder access'
                Description = 'Every folder defined in the first column needs to have at least one user account that is able to access it. Group membership is checked to verify if groups granting access to the folder have at least one user account as a member that is not a place holder account.'
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
                    Value       = $duplicateAdObject | Sort-Object
                }
            }
        }
        #endregion
    }
    catch {
        throw "Failed validating the expanded matrix: $_"
    }
}
function Test-FormDataHC {
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
    param (
        [Parameter(Mandatory)]
        [PSCustomObject[]]$FormData
    )

    process {
        try {
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
            if ($Properties -notcontains 'MatrixFormStatus') {
                return [PSCustomObject]@{
                    Type        = 'FatalError'
                    Name        = 'Missing column header'
                    Description = 'The column header MatrixFormStatus is mandatory.'
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
                        $Properties -notcontains $_ })) {
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
        catch {
            throw "Failed testing the Excel sheet 'FormData': $_"
        }
    }
}
function Test-MatrixPermissionsHC {
    <#
    .SYNOPSIS
        Verify input for the Excel sheet 'Permissions'.

    .DESCRIPTION
        Verify if all input in the Excel sheet 'Permissions' is correct. When
        incorrect input is detected an object is returned containing all the
        details about the issue. 
        This test is best run before expanding the matrix as it will save time.

    .PARAMETER Permissions
        The objects coming from the Excel sheet 'Permissions', as retrieved by
        Import-Excel.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param (
        [parameter(Mandatory)]
        [PSCustomObject[]]$Permissions
    )

    $ValidationErrors = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $Props = $Permissions[0].PSObject.Properties.Name
        $FirstProperty = $Props[0]

        #region Structural Validation (Fatal - Exits Immediately)
        if ($Permissions.Count -lt 4) {
            return [PSCustomObject]@{
                Type        = 'FatalError'
                Name        = 'Missing rows'
                Description = 'At least 4 rows are required: 3 header rows and 1 row for the parent folder.'
                Value       = "$($Permissions.Count) rows"
            }
        }

        if ($Props.Count -lt 2) {
            return [PSCustomObject]@{
                Type        = 'FatalError'
                Name        = 'Missing columns'
                Description = 'At least 2 columns are required: 1 for the folder names and 1 where the permissions are defined.'
                Value       = "$($Props.Count) column"
            }
        }
        #endregion

        #region Missing header SamAccountName
        foreach ($col in $Props) {
            if ([string]::IsNullOrWhiteSpace($Permissions[0].$col) -and 
                [string]::IsNullOrWhiteSpace($Permissions[1].$col) -and 
                [string]::IsNullOrWhiteSpace($Permissions[2].$col)) {
                
                $ValidationErrors.Add([PSCustomObject]@{
                        Type        = 'FatalError'
                        Name        = 'SamAccountName missing'
                        Description = 'Missing SamAccountName in the header row'
                        Value       = "Column number $($col.TrimStart('P'))"
                    })
            }
        }
        #endregion

        # Separate Headers from Data
        $NonHeaderRows = $Permissions | Select-Object -Skip 3
        $FolderNames = $NonHeaderRows | Select-Object -Skip 1

        #region Permission character unknown
        $InvalidChars = [System.Collections.Generic.List[string]]::new()
        
        foreach ($Row in $NonHeaderRows) {
            $PermColumns = $Row.PSObject.Properties.Where({ $_.Name -ne $FirstProperty })
            foreach ($Col in $PermColumns) {
                $Ace = $Col.Value
                if (-not [string]::IsNullOrWhiteSpace($Ace) -and $Ace -notmatch '^(L|R|W|I|C|F)$') {
                    $InvalidChars.Add($Ace)
                }
            }
        }

        if ($InvalidChars.Count -gt 0) {
            $ValidationErrors.Add([PSCustomObject]@{
                    Type        = 'FatalError'
                    Name        = 'Permission character unknown'
                    Description = "Supported characters are 'F', 'W', 'R', 'L', 'I', 'C', or blank."
                    Value       = ($InvalidChars | Select-Object -Unique) -join ', '
                })
        }
        #endregion

        #region Folder name missing
        $MissingFolders = $FolderNames.Where({ [string]::IsNullOrWhiteSpace($_.$FirstProperty) })
        if ($MissingFolders.Count -gt 0) {
            $ValidationErrors.Add([PSCustomObject]@{
                    Type        = 'FatalError'
                    Name        = 'Folder name missing'
                    Description = 'Missing folder name in the first column.'
                    Value       = "$($MissingFolders.Count) missing folder name(s)"
                })
        }
        #endregion

        #region Duplicate folder name
        $NotUniqueFolder = $FolderNames.$FirstProperty | Group-Object | Where-Object Count -GE 2
        if ($NotUniqueFolder) {
            $ValidationErrors.Add([PSCustomObject]@{
                    Type        = 'FatalError'
                    Name        = 'Duplicate folder name'
                    Description = 'Every folder name in the first column needs to be unique.'
                    Value       = ($NotUniqueFolder.Name) -join ', '
                })
        }
        #endregion

        #region Deepest folder has only List permissions or none at all
        $FolderRows = $Permissions | Select-Object -Skip 4
        $Paths = @($FolderRows.$FirstProperty)

        # Faster check for deepest folders
        $DeepestFolders = foreach ($P in $Paths) {
            if (-not ($Paths.Where({ $_ -ne $P -and $_ -like "$P\*" }))) {
                $P
            }
        }

        # Parent folder permissions (Row index 3)
        $ParentFolderPermissions = $Permissions[3].PSObject.Properties.Where({ 
                $_.Name -ne $FirstProperty -and -not [string]::IsNullOrWhiteSpace($_.Value) 
            }).Value

        $ParentFolderHasPermission = [bool]($ParentFolderPermissions.Where({ $_ -ne 'L' }))
        $inAccessibleFolders = [System.Collections.Generic.List[string]]::new()

        foreach ($Row in $FolderRows.Where({ $_.$FirstProperty -in $DeepestFolders })) {
            $Perms = $Row.PSObject.Properties.Where({
                    $_.Name -ne $FirstProperty -and 
                    -not [string]::IsNullOrWhiteSpace($_.Value) -and 
                    $_.Value -ne 'L'
                }).Value

            if ((-not $Perms) -and (-not $ParentFolderHasPermission)) {
                $inAccessibleFolders.Add($Row.$FirstProperty)
            }
        }

        if ($inAccessibleFolders.Count -gt 0) {
            $ValidationErrors.Add([PSCustomObject]@{
                    Type        = 'Warning'
                    Name        = 'Matrix design flaw'
                    Description = 'All folders need to be accessible by the end user. Please define at least (R)ead or (W)rite on the deepest folder.'
                    Value       = $inAccessibleFolders -join ', '
                })
        }
        #endregion

        # Output all collected errors at the end
        if ($ValidationErrors.Count -gt 0) {
            return $ValidationErrors
        }

    }
    catch {
        throw "Failed testing the Excel sheet 'Permissions' for incorrect data: $_"
    }
}
function Test-MatrixSettingHC {
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
    param (
        [Parameter(Mandatory)]
        [PSCustomObject]$Setting
    )

    process {
        try {
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

            #region JobsAtOnce is not an integer or not a number between 1-8
            if ($Setting.JobsAtOnce) {
                try {
                    $incorrectNumber = $false
                    $number = [int]$Setting.JobsAtOnce
                }
                catch {
                    $global:Error.RemoveAt(0)
                    $incorrectNumber = $true
                }

                if (
                    (-not $incorrectNumber) -and
                    (-not (0..8 -contains $number))
                ) {
                    $incorrectNumber = $true
                }

                if ($incorrectNumber) {
                    [PSCustomObject]@{
                        Type        = 'FatalError'
                        Name        = 'JobsAtOnce is not a valid number'
                        Description = "The value for 'JobsAtOnce' needs to be a number between 1 and 8."
                        Value       = $Setting.JobsAtOnce
                    }
                }
            }
            #endregion
        }
        catch {
            throw "Failed testing the Excel sheet 'Settings' row for incorrect data: $_"
        }
    }
}

Export-ModuleMember -Function * -Alias *