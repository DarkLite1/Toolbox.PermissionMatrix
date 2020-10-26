#Requires -Modules Pester
#Requires -Version 5.1

$moduleName = 'Toolbox.PermissionMatrix'

$testScript = $PSCommandPath.Replace('.Tests.ps1', '.psm1')
Remove-Module $moduleName -Force -Verbose:$false -EA Ignore
Import-Module $testScript -Force -Verbose:$false

InModuleScope $moduleName {
    Describe 'ConvertTo-AceHC' {
        It 'L for List' {
            $Expected = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "$env:USERDOMAIN\$env:USERNAME",
                [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
                [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )

            $Actual = ConvertTo-AceHC -Type L -Name $env:USERNAME

            Assert-Equivalent -Actual $Actual -Expected $Expected
        }
        It 'W for Write' {
            $Expected = @(
                New-Object System.Security.AccessControl.FileSystemAccessRule(
                    "$env:USERDOMAIN\$env:USERNAME",
                    [System.Security.AccessControl.FileSystemRights]'CreateFiles, AppendData, DeleteSubdirectoriesAndFiles, ReadAndExecute, Synchronize',
                    [System.Security.AccessControl.InheritanceFlags]::None,
                    [System.Security.AccessControl.PropagationFlags]::InheritOnly,
                    [System.Security.AccessControl.AccessControlType]::Allow
                )
                # Sub folders and files only
                New-Object System.Security.AccessControl.FileSystemAccessRule(
                    "$env:USERDOMAIN\$env:USERNAME",
                    [System.Security.AccessControl.FileSystemRights]'DeleteSubdirectoriesAndFiles, Modify, Synchronize',
                    [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                    [System.Security.AccessControl.PropagationFlags]::InheritOnly,
                    [System.Security.AccessControl.AccessControlType]::Allow
                )
            )

            $Actual = ConvertTo-AceHC -Type W -Name $env:USERNAME

            Assert-Equivalent -Actual $Actual -Expected $Expected
        }
        It 'R for Read' {
            $Expected = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "$env:USERDOMAIN\$env:USERNAME",
                [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
                [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )

            $Actual = ConvertTo-AceHC -Type R -Name $env:USERNAME

            Assert-Equivalent -Actual $Actual -Expected $Expected
        }
        It 'F for FullControl' {
            # Standard List
            $Expected = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "$env:USERDOMAIN\$env:USERNAME",
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )

            $Actual = ConvertTo-AceHC -Type F -Name $env:USERNAME

            Assert-Equivalent -Actual $Actual -Expected $Expected
        }
        It 'M for Modify' {
            $Expected = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "$env:USERDOMAIN\$env:USERNAME",
                [System.Security.AccessControl.FileSystemRights]::Modify,
                [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )

            $Actual = ConvertTo-AceHC -Type M -Name $env:USERNAME

            Assert-Equivalent -Actual $Actual -Expected $Expected
        }
    }
    Describe 'ConvertTo-MatrixADNamesHC' {
        Context 'compose names' {
            $Permissions = @(
                [PSCustomObject]@{P1 = 'x' ; P2 = 'Manager' }
                [PSCustomObject]@{P1 = 'x' ; P2 = 'SiteCode' }
                [PSCustomObject]@{P1 = 'x' ; P2 = 'GroupName' }
            )
            Context 'replace value when' {
                $TestCases = @(
                    @{
                        TestName    = 'the begin value is matching'
                        Permissions = @(
                            [PSCustomObject]@{P1 = 'x'; P2 = 'Manager' }
                            [PSCustomObject]@{P1 = 'x'; P2 = '' }
                            [PSCustomObject]@{P1 = 'x'; P2 = 'A' }
                        )
                        Expected    = @{
                            'P2' = @{
                                SamAccountName = 'BEGIN Manager'
                                Original       = @{
                                    Begin  = 'A'
                                    Middle = ''
                                    End    = 'Manager'
                                }
                                Converted      = @{
                                    Begin  = 'BEGIN'
                                    Middle = ''
                                    End    = 'Manager'
                                }
                            } 
                        }
                    }
                    @{
                        TestName    = 'the middle value is matching'
                        Permissions = @(
                            [PSCustomObject]@{P1 = 'x'; P2 = 'Manager' }
                            [PSCustomObject]@{P1 = 'x'; P2 = 'B' }
                            [PSCustomObject]@{P1 = 'x'; P2 = '' }
                        )
                        Expected    = @{
                            'P2' = @{
                                SamAccountName = 'MIDDLE Manager'
                                Original       = @{
                                    Begin  = ''
                                    Middle = 'B'
                                    End    = 'Manager'
                                }
                                Converted      = @{
                                    Begin  = ''
                                    Middle = 'MIDDLE'
                                    End    = 'Manager'
                                }
                            }
                        }
                    }
                )

                It '<TestName>' -TestCases $TestCases {
                    $testParams = @{
                        ColumnHeaders = $Permissions
                        Begin         = 'BEGIN'
                        Middle        = 'MIDDLE'
                        BeginReplace  = 'A'
                        MiddleReplace = 'B'
                    }
                    $Actual = ConvertTo-MatrixADNamesHC @testParams
                    
                    $Actual.SamAccountName | 
                    Should -BeExactly $Expected.SamAccountName

                    $Actual.P2.Original.Begin | 
                    Should -BeExactly $Expected.P2.Original.Begin
                    $Actual.P2.Original.Middle | 
                    Should -BeExactly $Expected.P2.Original.Middle
                    $Actual.P2.Original.End | 
                    Should -BeExactly $Expected.P2.Original.End

                    $Actual.P2.Converted.Begin | 
                    Should -BeExactly $Expected.P2.Converted.Begin
                    $Actual.P2.Converted.Middle | 
                    Should -BeExactly $Expected.P2.Converted.Middle
                    $Actual.P2.Converted.End | 
                    Should -BeExactly $Expected.P2.Converted.End
                }
            }
            Context 'do not replace value when' {
                $TestCases = @(
                    @{
                        TestName    = 'the begin value is not matching'
                        Permissions = @(
                            [PSCustomObject]@{P1 = 'x'; P2 = 'Manager' }
                            [PSCustomObject]@{P1 = 'x'; P2 = 'B' }
                            [PSCustomObject]@{P1 = 'x'; P2 = 'TOP' }
                        )
                        Expected    = @{
                            'P2' = @{
                                SamAccountName = 'TOP MIDDLE Manager'
                                Original       = @{
                                    Begin  = 'TOP'
                                    Middle = 'B'
                                    End    = 'Manager'
                                }
                                Converted      = @{
                                    Begin  = 'TOP'
                                    Middle = 'MIDDLE'
                                    End    = 'Manager'
                                }
                            } 
                        }
                    }
                    @{
                        TestName    = 'the middle value is not matching'
                        Permissions = @(
                            [PSCustomObject]@{P1 = 'x'; P2 = 'Manager' }
                            [PSCustomObject]@{P1 = 'x'; P2 = 'Consultant' }
                            [PSCustomObject]@{P1 = 'x'; P2 = 'A' }
                        )
                        Expected    = @{
                            'P2' = @{
                                SamAccountName = 'BEGIN Consultant Manager'
                                Original       = @{
                                    Begin  = 'A'
                                    Middle = 'Consultant'
                                    End    = 'Manager'
                                }
                                Converted      = @{
                                    Begin  = 'BEGIN'
                                    Middle = 'Consultant'
                                    End    = 'Manager'
                                }
                            } 
                        }
                    }
                    @{
                        TestName    = 'nothing is matching'
                        Permissions = @(
                            [PSCustomObject]@{P1 = 'x'; P2 = 'Manager' }
                            [PSCustomObject]@{P1 = 'x'; P2 = 'Consultant' }
                            [PSCustomObject]@{P1 = 'x'; P2 = '' }
                        )
                        Expected    = @{
                            'P2' = @{
                                SamAccountName = 'Consultant Manager'
                                Original       = @{
                                    Begin  = ''
                                    Middle = 'Consultant'
                                    End    = 'Manager'
                                }
                                Converted      = @{
                                    Begin  = ''
                                    Middle = 'Consultant'
                                    End    = 'Manager'
                                }
                            } 
                        }
                    }
                )

                It '<TestName>' -TestCases $TestCases {
                    Param (
                        $Permissions,
                        $Expected
                    )

                    $testParams = @{
                        ColumnHeaders = $Permissions
                        Begin         = 'BEGIN'
                        Middle        = 'MIDDLE'
                        BeginReplace  = 'A'
                        MiddleReplace = 'B'
                    }
                    $Actual = ConvertTo-MatrixADNamesHC @testParams

                    $Actual.SamAccountName | 
                    Should -BeExactly $Expected.SamAccountName

                    $Actual.P2.Original.Begin | 
                    Should -BeExactly $Expected.P2.Original.Begin
                    $Actual.P2.Original.Middle | 
                    Should -BeExactly $Expected.P2.Original.Middle
                    $Actual.P2.Original.End | 
                    Should -BeExactly $Expected.P2.Original.End

                    $Actual.P2.Converted.Begin | 
                    Should -BeExactly $Expected.P2.Converted.Begin
                    $Actual.P2.Converted.Middle | 
                    Should -BeExactly $Expected.P2.Converted.Middle
                    $Actual.P2.Converted.End | 
                    Should -BeExactly $Expected.P2.Converted.End
                }
            }
        }
    }
    Describe 'ConvertTo-MatrixAclHC' {
        Context 'an error is thrown when' {
            $TestCases = @(
                @{
                    TestName      = "duplicate SamAccountNames are given"
                    NonHeaderRows = @(
                        [PSCustomObject]@{ P1 = 'Path' ; P2 = 'L' ; P3 = 'R' }
                        [PSCustomObject]@{ P1 = 'F1'   ; P2 = 'W' ; P3 = 'C' }
                        [PSCustomObject]@{ P1 = 'F2'   ; P2 = 'W' ; P3 = 'C' }
                    )
                    ADObjects     = @{
                        'P2' = @{SamAccountName = 'bob' }
                        'P3' = @{SamAccountName = 'bob' }
                    }
                    Expected      = "*AD object name 'Bob' is not unique*"
                }
                @{
                    TestName      = "permissions are set but no SamAccountName is given"
                    NonHeaderRows = @(
                        [PSCustomObject]@{ P1 = 'Path' ; P2 = 'L' ; P3 = 'R' }
                        [PSCustomObject]@{ P1 = 'F1'   ; P2 = 'W' ; P3 = 'C' }
                        [PSCustomObject]@{ P1 = 'F2'   ; P2 = 'W' ; P3 = 'C' }
                    )
                    ADObjects     = @{
                        'P2' = @{SamAccountName = 'bob' }`
                    
                    }
                    Expected      = 'AD Object name is required'
                }
                @{
                    TestName      = "permissions are set and permission 'i' is set but no SamAccountName is given"
                    NonHeaderRows = @(
                        [PSCustomObject]@{ P1 = 'Path' ; P2 = 'L' ; P3 = 'R' }
                        [PSCustomObject]@{ P1 = 'F1'   ; P2 = 'W' ; P3 = 'i' }
                        [PSCustomObject]@{ P1 = 'F2'   ; P2 = 'W' ; P3 = 'C' }
                    )
                    ADObjects     = @{
                        'P2' = @{SamAccountName = 'bob' }
                    }
                    Expected      = 'AD Object name is required'
                }
            )

            It '<TestName>' -TestCases $TestCases {
                { 
                    $testParams = @{
                        NonHeaderRows = $NonHeaderRows 
                        ADObjects     = $ADObjects
                    }
                    ConvertTo-MatrixAclHC @testParams
                } |
                Should -Throw -PassThru | 
                Select-Object -ExpandProperty Exception |
                Should -BeLike "*$Expected*"
            }
        }
        Context 'an error is not thrown when' {
            $TestCases = @(
                @{
                    TestName      = "a column contains permission 'i', no SamAccountName, no other permissions"
                    NonHeaderRows = @(
                        [PSCustomObject]@{ P1 = 'Path' ; P2 = 'L' ; P3 = '' }
                        [PSCustomObject]@{ P1 = 'F1'   ; P2 = 'W' ; P3 = 'i' }
                        [PSCustomObject]@{ P1 = 'F2'   ; P2 = 'W' ; P3 = '' }
                    )
                    ADObjects     = @{
                        'P2' = @{SamAccountName = 'bob' }
                    }
                }
            )

            It '<TestName>' -TestCases $TestCases {
                { 
                    $testParams = @{
                        NonHeaderRows = $NonHeaderRows 
                        ADObjects     = $ADObjects
                    }
                    ConvertTo-MatrixAclHC @testParams
                } |
                Should -Not -Throw
            }
        }
        Context 'Path' {
            $TestCases = @(
                @{
                    TestName      = 'mark only first folder as path'
                    NonHeaderRows = @(
                        [PSCustomObject]@{P1 = 'F1'  ; P2 = 'L' }
                        [PSCustomObject]@{P1 = 'F2'  ; P2 = 'W' }
                    )
                    ADObjects     = @{
                        'P2' = @{SamAccountName = 'bob' }
                    }
                    Expected      = @(
                        [PSCustomObject]@{
                            Path   = 'F1'
                            Parent = $true
                            ACL    = @{'bob' = 'L' }
                            Ignore = $false
                        }
                        [PSCustomObject]@{
                            Path   = 'F2'
                            Parent = $false
                            ACL    = @{'bob' = 'W' }
                            Ignore = $false
                        }
                    )
                }

                @{
                    TestName      = "one row with 'Path' only returns one object"
                    NonHeaderRows = @(
                        [PSCustomObject]@{P1 = 'Path'; P2 = 'L' }
                    )
                    ADObjects     = @{
                        'P2' = @{SamAccountName = 'bob' }
                    }
                    Expected      = [PSCustomObject]@{
                        Path   = 'Path'
                        ACL    = @{'bob' = 'L' }
                        Parent = $true
                        Ignore = $false
                    }
                }
            )

            It '<TestName>' -TestCases $TestCases {
                $testParams = @{
                    NonHeaderRows = $NonHeaderRows 
                    ADObjects     = $ADObjects
                }
                $Actual = ConvertTo-MatrixAclHC @testParams

                Assert-Equivalent -Actual $Actual -Expected $Expected
            }
        }
        Context 'ACL' {
            $TestCases = @(
                @{
                    TestName      = 'empty when no permissions are set'
                    NonHeaderRows = @(
                        [PSCustomObject]@{P1 = 'Path' ; P2 = 'L' ; P3 = 'L' }
                        [PSCustomObject]@{P1 = 'F1'   ; P2 = ''  ; P3 = '' }
                    )
                    ADObjects     = @{
                        'P2' = @{SamAccountName = 'bob' }
                        'P3' = @{SamAccountName = 'mike' }
                    }
                    Expected      = @(
                        [PSCustomObject]@{
                            Path   = 'Path'
                            Parent = $true
                            Ignore = $false
                            ACL    = @{
                                'bob'  = 'L'
                                'mike' = 'L'
                            }
                        }
                        [PSCustomObject]@{
                            Path   = 'F1'
                            Parent = $false
                            Ignore = $false
                            ACL    = @{}
                        }
                    )
                }

                @{
                    TestName      = 'empty for blank cells'
                    NonHeaderRows = @(
                        [PSCustomObject]@{P1 = 'Path' ; P2 = '' }
                        [PSCustomObject]@{P1 = 'F1'   ; P2 = '' }
                    )
                    ADObjects     = @{
                        'P2' = @{SamAccountName = 'bob' }
                    }
                    Expected      = @(
                        [PSCustomObject]@{
                            Path   = 'Path'
                            ACL    = @{}
                            Parent = $true
                            Ignore = $false
                        }
                        [PSCustomObject]@{
                            Path   = 'F1'
                            ACL    = @{}
                            Parent = $false
                            Ignore = $false
                        }
                    )
                }
            )

            It '<TestName>' -TestCases $TestCases {
                $testParams = @{
                    NonHeaderRows = $NonHeaderRows 
                    ADObjects     = $ADObjects
                }
                $Actual = ConvertTo-MatrixAclHC @testParams

                Assert-Equivalent -Actual $Actual -Expected $Expected
            }
        } 
        Context 'ignore is TRUE and ACL is empty when' {
            $TestCases = @(
                @{
                    TestName      = "first column contains permission 'i'"
                    NonHeaderRows = @(
                        [PSCustomObject]@{ P1 = 'Path' ; P2 = 'L' ; P3 = 'L' }
                        [PSCustomObject]@{ P1 = 'F1'   ; P2 = 'i' ; P3 = 'C' }
                        [PSCustomObject]@{ P1 = 'F2'   ; P2 = 'R' ; P3 = 'C' }
                    )
                    ADObjects     = @{
                        'P2' = @{SamAccountName = 'mike' }
                        'P3' = @{SamAccountName = 'bob' }
                    }
                    Expected      = @(
                        [PSCustomObject]@{
                            Path   = 'Path'
                            Parent = $true
                            Ignore = $false
                            ACL    = @{
                                'mike' = 'L'
                                "bob"  = 'L'
                            }
                        }
                        [PSCustomObject]@{
                            Path   = 'F1'
                            Parent = $false
                            Ignore = $true
                            ACL    = @{}
                        }
                        [PSCustomObject]@{
                            Path   = 'F2'
                            Parent = $false
                            Ignore = $false
                            ACL    = @{
                                'mike' = 'R'
                                "bob"  = 'C'
                            }
                        }
                    )
                }

                @{
                    TestName      = "another column contains permission 'i'"
                    NonHeaderRows = @(
                        [PSCustomObject]@{ P1 = 'Path' ; P2 = 'L'  ; P3 = 'L' }
                        [PSCustomObject]@{ P1 = 'F1'   ; P2 = 'C'  ; P3 = 'i' }
                        [PSCustomObject]@{ P1 = 'F2'   ; P2 = 'R'  ; P3 = 'C' }
                    )
                    ADObjects     = @{
                        'P2' = @{SamAccountName = 'bob' }
                        'P3' = @{SamAccountName = 'mike' }
                    }
                    Expected      = @(
                        [PSCustomObject]@{
                            Path   = 'Path'
                            Parent = $true
                            Ignore = $false
                            ACL    = @{
                                'bob'  = 'L'
                                "mike" = 'L'
                            }
                        }
                        [PSCustomObject]@{
                            Path   = 'F1'
                            Parent = $false
                            Ignore = $true
                            ACL    = @{}
                        }
                        [PSCustomObject]@{
                            Path   = 'F2'
                            Parent = $false
                            Ignore = $false
                            ACL    = @{
                                'bob'  = 'R'
                                "mike" = 'C'
                            }
                        }
                    )
                }

                @{
                    TestName      = "a column contains permission 'i' and no SamAccountName is given"
                    NonHeaderRows = @(
                        [PSCustomObject]@{ P1 = 'Path' ; P2 = 'L'  ; P3 = '' }
                        [PSCustomObject]@{ P1 = 'F1'   ; P2 = ''   ; P3 = 'i' }
                        [PSCustomObject]@{ P1 = 'F2'   ; P2 = 'R'  ; P3 = '' }
                    )
                    ADObjects     = @{
                        'P2' = @{SamAccountName = 'bob' }
                    }
                    Expected      = @(
                        [PSCustomObject]@{
                            Path   = 'Path'
                            Parent = $true
                            Ignore = $false
                            ACL    = @{
                                'bob' = 'L'
                            }
                        }
                        [PSCustomObject]@{
                            Path   = 'F1'
                            Parent = $false
                            Ignore = $true
                            ACL    = @{}
                        }
                        [PSCustomObject]@{
                            Path   = 'F2'
                            Parent = $false
                            Ignore = $false
                            ACL    = @{
                                'bob' = 'R'
                            }
                        }
                    )
                }
            )

            It '<TestName>' -TestCases $TestCases {
                $testParams = @{
                    NonHeaderRows = $NonHeaderRows 
                    ADObjects     = $ADObjects
                }
                $Actual = ConvertTo-MatrixAclHC @testParams

                Assert-Equivalent -Actual $Actual -Expected $Expected
            }
        }
    }
    Describe 'Expand-MatrixHC' {
        Context "create a new matrix for each row in 'Settings'" {
            $TestCases = @(
                $TestName = 'same matrix for each row'
                $Permissions = @(
                    [PSCustomObject]@{
                        Path   = 'Path'  ; 
                        ACL    = @{'GroupName SiteCode Manager' = 'L' }; 
                        Ignore = $false; 
                        Parent = $true 
                    }
                    [PSCustomObject]@{
                        Path   = 'Folder'; 
                        ACL    = @{'GroupName SiteCode Manager' = 'R' }; 
                        Ignore = $false; 
                        Parent = $false 
                    }
                )
                @{
                    TestName    = $TestName
                    Permissions = @(
                        [PSCustomObject]@{P1 = $null      ; P2 = 'Manager' }
                        [PSCustomObject]@{P1 = 'SiteCode' ; P2 = 'SiteCode' }
                        [PSCustomObject]@{P1 = 'GroupName'; P2 = 'GroupName' }
                        [PSCustomObject]@{P1 = 'Path'     ; P2 = 'L' }
                        [PSCustomObject]@{P1 = 'Folder'   ; P2 = 'R' }
                    )
                    Settings    = @(
                        [PSCustomObject]@{
                            ComputerName = 'S1'; 
                            Path         = 'E:\Department'; 
                            Action       = 'Check' 
                        }
                        [PSCustomObject]@{
                            ComputerName = 'S2'; 
                            Path         = 'E:\Reporting' ; 
                            Action       = 'New' 
                        }
                    )
                    Expected    = @(
                        [PSCustomObject]@{
                            ComputerName = 'S1'; 
                            Path         = 'E:\Department'; 
                            Action       = 'Check'
                            Permissions  = $Permissions
                        }
                        [PSCustomObject]@{
                            ComputerName = 'S2'; 
                            Path         = 'E:\Reporting'; 
                            Action       = 'New'
                            Permissions  = $Permissions
                        }
                    )
                }

                $TestName = 'two matrixes the same and one different'
                $Permissions = @(
                    [PSCustomObject]@{
                        Path   = 'Path'  ; 
                        ACL    = @{'GroupName SiteCode Manager' = 'L' }; 
                        Ignore = $false; 
                        Parent = $true 
                    }
                    [PSCustomObject]@{
                        Path   = 'Folder'; 
                        ACL    = @{'GroupName SiteCode Manager' = 'R' }; 
                        Ignore = $false; 
                        Parent = $false 
                    }
                )
                @{
                    TestName    = $TestName
                    Permissions = @(
                        [PSCustomObject]@{P1 = $null      ; P2 = 'Manager' }
                        [PSCustomObject]@{P1 = 'SiteCode' ; P2 = 'SiteCode' }
                        [PSCustomObject]@{P1 = 'GroupName'; P2 = 'GroupName' }
                        [PSCustomObject]@{P1 = 'Path'     ; P2 = 'L' }
                        [PSCustomObject]@{P1 = 'Folder'   ; P2 = 'R' }
                    )
                    Settings    = @(
                        [PSCustomObject]@{
                            ComputerName = 'S1'; 
                            Path         = 'E:\Department'; 
                            Action       = 'Check' 
                        }
                        [PSCustomObject]@{
                            ComputerName = 'S2'; 
                            Path         = 'E:\Reporting' ; 
                            Action       = 'New' 
                        }
                        [PSCustomObject]@{
                            ComputerName = 'S3'; 
                            Path         = 'E:\Finance' ; 
                            Action       = 'Fix'; 
                            GroupName    = 'BEL'; 
                            SiteCode     = 'Bxl' 
                        }
                    )
                    Expected    = @(
                        [PSCustomObject]@{
                            ComputerName = 'S1'; 
                            Path         = 'E:\Department'; 
                            Action       = 'Check'
                            Permissions  = $Permissions
                        }
                        [PSCustomObject]@{
                            ComputerName = 'S2'; 
                            Path         = 'E:\Reporting'; 
                            Action       = 'New'
                            Permissions  = $Permissions
                        }
                        [PSCustomObject]@{
                            ComputerName = 'S3'; 
                            Path         = 'E:\Finance'; 
                            Action       = 'Fix'; 
                            GroupName    = 'BEL'; 
                            SiteCode     = 'Bxl'
                            Permissions  = @(
                                [PSCustomObject]@{
                                    Path   = 'Path'  ; 
                                    ACL    = @{'BEL Bxl Manager' = 'L' }; 
                                    Ignore = $false; 
                                    Parent = $true 
                                }
                                [PSCustomObject]@{
                                    Path   = 'Folder'; 
                                    ACL    = @{'BEL Bxl Manager' = 'R' }; 
                                    Ignore = $false; 
                                    Parent = $false 
                                }
                            )
                        }
                    )
                }

                $TestName = "with only property 'ComputerName', 'Path' and 'Action'"
                @{
                    TestName    = $TestName
                    Permissions = @(
                        [PSCustomObject]@{P1 = $null      ; P2 = 'Manager' }
                        [PSCustomObject]@{P1 = 'SiteCode' ; P2 = 'SiteCode' }
                        [PSCustomObject]@{P1 = 'GroupName'; P2 = 'GroupName' }
                        [PSCustomObject]@{P1 = 'Path'     ; P2 = 'L' }
                        [PSCustomObject]@{P1 = 'Folder'   ; P2 = 'R' }
                    )
                    Settings    = @(
                        [PSCustomObject]@{ComputerName = 'S1'; Path = 'E:\Department'; Action = 'Check' }
                        [PSCustomObject]@{ComputerName = 'S2'; Path = 'E:\Reporting' ; Action = 'Check' }
                        [PSCustomObject]@{ComputerName = 'S3'; Path = 'E:\Finance'   ; Action = 'Check' }
                    )
                    Expected    = @(
                        [PSCustomObject]@{
                            ComputerName = 'S1'; Path = 'E:\Department'; Action = 'Check'
                            Permissions = @(
                                [PSCustomObject]@{Path = 'Path'  ; ACL = @{'GroupName SiteCode Manager' = 'L' }; Ignore = $false; Parent = $true }
                                [PSCustomObject]@{Path = 'Folder'; ACL = @{'GroupName SiteCode Manager' = 'R' }; Ignore = $false; Parent = $false }
                            )
                        }
                        [PSCustomObject]@{
                            ComputerName = 'S2'; Path = 'E:\Reporting'; Action = 'Check'
                            Permissions = @(
                                [PSCustomObject]@{Path = 'Path'  ; ACL = @{'GroupName SiteCode Manager' = 'L' }; Ignore = $false; Parent = $true }
                                [PSCustomObject]@{Path = 'Folder'; ACL = @{'GroupName SiteCode Manager' = 'R' }; Ignore = $false; Parent = $false }
                            )
                        }
                        [PSCustomObject]@{
                            ComputerName = 'S3'; Path = 'E:\Finance'; Action = 'Check'
                            Permissions = @(
                                [PSCustomObject]@{Path = 'Path'  ; ACL = @{'GroupName SiteCode Manager' = 'L' }; Ignore = $false; Parent = $true }
                                [PSCustomObject]@{Path = 'Folder'; ACL = @{'GroupName SiteCode Manager' = 'R' }; Ignore = $false; Parent = $false }
                            )
                        }
                    )
                }

                $TestName = "with extra properties in the sheet 'Settings' that are kept and not removed"
                @{
                    TestName    = $TestName
                    Permissions = @(
                        [PSCustomObject]@{P1 = $null      ; P2 = 'Manager' }
                        [PSCustomObject]@{P1 = 'SiteCode' ; P2 = 'SiteCode' }
                        [PSCustomObject]@{P1 = 'GroupName'; P2 = 'GroupName' }
                        [PSCustomObject]@{P1 = 'Path'     ; P2 = 'L' }
                        [PSCustomObject]@{P1 = 'Folder'   ; P2 = 'R' }
                    )
                    Settings    = @(
                        [PSCustomObject]@{Prop1 = 10; Prop2 = 20; ComputerName = 'S1'; Path = 'E:\Department'; Action = 'Check' }
                        [PSCustomObject]@{Prop1 = 11; Prop2 = 21; ComputerName = 'S2'; Path = 'E:\Reporting' ; Action = 'Check' }
                        [PSCustomObject]@{Prop1 = 12; Prop2 = 22; ComputerName = 'S3'; Path = 'E:\Finance'   ; Action = 'Check' }
                    )
                    Expected    = @(
                        [PSCustomObject]@{
                            Prop1 = 10; Prop2 = 20; ComputerName = 'S1'; Path = 'E:\Department'; Action = 'Check'
                            Permissions = @(
                                [PSCustomObject]@{Path = 'Path'  ; ACL = @{'GroupName SiteCode Manager' = 'L' }; Ignore = $false; Parent = $true }
                                [PSCustomObject]@{Path = 'Folder'; ACL = @{'GroupName SiteCode Manager' = 'R' }; Ignore = $false; Parent = $false }
                            )
                        }
                        [PSCustomObject]@{
                            Prop1 = 11; Prop2 = 21; ComputerName = 'S2'; Path = 'E:\Reporting'; Action = 'Check'
                            Permissions = @(
                                [PSCustomObject]@{Path = 'Path'  ; ACL = @{'GroupName SiteCode Manager' = 'L' }; Ignore = $false; Parent = $true }
                                [PSCustomObject]@{Path = 'Folder'; ACL = @{'GroupName SiteCode Manager' = 'R' }; Ignore = $false; Parent = $false }
                            )
                        }
                        [PSCustomObject]@{
                            Prop1 = 12; Prop2 = 22; ComputerName = 'S3'; Path = 'E:\Finance'; Action = 'Check'
                            Permissions = @(
                                [PSCustomObject]@{Path = 'Path'  ; ACL = @{'GroupName SiteCode Manager' = 'L' }; Ignore = $false; Parent = $true }
                                [PSCustomObject]@{Path = 'Folder'; ACL = @{'GroupName SiteCode Manager' = 'R' }; Ignore = $false; Parent = $false }
                            )
                        }
                    )
                }

                $TestName = "even when 'Status' is not set to 'Enabled'"
                @{
                    TestName    = $TestName
                    Permissions = @(
                        [PSCustomObject]@{P1 = $null        ; P2 = 'Manager' }
                        [PSCustomObject]@{P1 = 'SiteCode'   ; P2 = 'SiteCode' }
                        [PSCustomObject]@{P1 = 'GroupName'  ; P2 = 'GroupName' }
                        [PSCustomObject]@{P1 = 'Path'; P2 = 'L' }
                        [PSCustomObject]@{P1 = 'Folder'     ; P2 = 'R' }
                    )
                    Settings    = @(
                        [PSCustomObject]@{Status = 'Enabled' ; ComputerName = 'S1'; Path = 'E:\Department'; GroupName = 'G1'; SiteName = 'S1'; SiteCode = 'C1'; Action = 'Check' }
                        [PSCustomObject]@{Status = 'Disabled'; ComputerName = 'S2'; Path = 'E:\Reporting' ; GroupName = 'G2'; SiteName = 'S2'; SiteCode = 'C2'; Action = 'Check' }
                        [PSCustomObject]@{Status = $null     ; ComputerName = 'S3'; Path = 'E:\Finance'   ; GroupName = 'G3'; SiteName = 'S3'; SiteCode = 'C3'; Action = 'Check' }
                    )
                    Expected    = @(
                        [PSCustomObject]@{
                            Status = 'Enabled' ; ComputerName = 'S1'; Path = 'E:\Department'; GroupName = 'G1'; SiteCode = 'C1'; SiteName = 'S1'; Action = 'Check'
                            Permissions = @(
                                [PSCustomObject]@{Path = 'Path'  ; ACL = @{'G1 C1 Manager' = 'L' }; Ignore = $false; Parent = $true }
                                [PSCustomObject]@{Path = 'Folder'; ACL = @{'G1 C1 Manager' = 'R' }; Ignore = $false; Parent = $false }
                            )
                        }
                        [PSCustomObject]@{
                            Status = 'Disabled'; ComputerName = 'S2'; Path = 'E:\Reporting'; GroupName = 'G2'; SiteCode = 'C2'; SiteName = 'S2'; Action = 'Check'
                            Permissions = @(
                                [PSCustomObject]@{Path = 'Path'  ; ACL = @{'G2 C2 Manager' = 'L' }; Ignore = $false; Parent = $true }
                                [PSCustomObject]@{Path = 'Folder'; ACL = @{'G2 C2 Manager' = 'R' }; Ignore = $false; Parent = $false }
                            )
                        }
                        [PSCustomObject]@{
                            Status = $null     ; ComputerName = 'S3'; Path = 'E:\Finance'; GroupName = 'G3'; SiteCode = 'C3'; SiteName = 'S3'; Action = 'Check'
                            Permissions = @(
                                [PSCustomObject]@{Path = 'Path'  ; ACL = @{'G3 C3 Manager' = 'L' }; Ignore = $false; Parent = $true }
                                [PSCustomObject]@{Path = 'Folder'; ACL = @{'G3 C3 Manager' = 'R' }; Ignore = $false; Parent = $false }
                            )
                        }
                    )
                }

                $TestName = 'parent folder is not replaced'
                $ParentFolder = 'Not replaced'
                @{
                    TestName    = $TestName
                    Permissions = @(
                        [PSCustomObject]@{P1 = $null        ; P2 = 'Manager' }
                        [PSCustomObject]@{P1 = 'SiteCode'   ; P2 = 'SiteCode' }
                        [PSCustomObject]@{P1 = 'GroupName'  ; P2 = 'GroupName' }
                        [PSCustomObject]@{P1 = $ParentFolder; P2 = 'L' }
                        [PSCustomObject]@{P1 = 'Folder'     ; P2 = 'R' }
                    )
                    Settings    = @(
                        [PSCustomObject]@{ComputerName = 'S1'; Path = 'E:\Department'; GroupName = 'G1'; SiteName = 'S1'; SiteCode = 'C1'; Action = 'Check' }
                        [PSCustomObject]@{ComputerName = 'S2'; Path = 'E:\Reporting'; GroupName = 'G2'; SiteName = 'S2'; SiteCode = 'C2'; Action = 'Check' }
                        [PSCustomObject]@{ComputerName = 'S3'; Path = 'E:\Finance'; GroupName = 'G3'; SiteName = 'S3'; SiteCode = 'C3'; Action = 'Check' }
                    )
                    Expected    = @(
                        [PSCustomObject]@{
                            ComputerName = 'S1'; Path = 'E:\Department'; GroupName = 'G1'; SiteCode = 'C1'; SiteName = 'S1'; Action = 'Check'
                            Permissions = @(
                                [PSCustomObject]@{Path = $ParentFolder; ACL = @{'G1 C1 Manager' = 'L' }; Ignore = $false; Parent = $true }
                                [PSCustomObject]@{Path = 'Folder'     ; ACL = @{'G1 C1 Manager' = 'R' }; Ignore = $false; Parent = $false }
                            )
                        }
                        [PSCustomObject]@{
                            ComputerName = 'S2'; Path = 'E:\Reporting'; GroupName = 'G2'; SiteCode = 'C2'; SiteName = 'S2'; Action = 'Check'
                            Permissions = @(
                                [PSCustomObject]@{Path = $ParentFolder; ACL = @{'G2 C2 Manager' = 'L' }; Ignore = $false; Parent = $true }
                                [PSCustomObject]@{Path = 'Folder'     ; ACL = @{'G2 C2 Manager' = 'R' }; Ignore = $false; Parent = $false }
                            )
                        }
                        [PSCustomObject]@{
                            ComputerName = 'S3'; Path = 'E:\Finance'; GroupName = 'G3'; SiteCode = 'C3'; SiteName = 'S3'; Action = 'Check'
                            Permissions = @(
                                [PSCustomObject]@{Path = $ParentFolder; ACL = @{'G3 C3 Manager' = 'L' }; Ignore = $false; Parent = $true }
                                [PSCustomObject]@{Path = 'Folder'     ; ACL = @{'G3 C3 Manager' = 'R' }; Ignore = $false; Parent = $false }
                            )
                        }
                    )
                }
            )

            It '<TestName>' -TestCases $TestCases {
                Param (
                    $Permissions,
                    $Settings,
                    $Expected
                )

                $Actual = Expand-MatrixHC -Permissions $Permissions -Settings $Settings

                Assert-Equivalent -Actual $Actual -Expected $Expected
            }
        }
        Context "replace AD names in 'Permissions' sheet" {
            $TestCases = @(
                @{
                    TestName    = 'A2 is NULL'
                    Permissions = @(
                        [PSCustomObject]@{P1 = $null      ; P2 = 'Manager' }
                        [PSCustomObject]@{P1 = $null      ; P2 = 'SiteCode' }
                        [PSCustomObject]@{P1 = 'GroupName'; P2 = 'GroupName' }
                        [PSCustomObject]@{P1 = 'Path'     ; P2 = 'L' }
                    )
                    Settings    = @(
                        [PSCustomObject]@{
                            ComputerName = 'S1';
                            Path         = 'E:\Department'; 
                            Action       = 'Check'; 
                            GroupName    = 'A'; 
                            SiteCode     = 'B' 
                        }
                    )
                    Expected    = [PSCustomObject]@{
                        ComputerName = 'S1'; 
                        Path         = 'E:\Department'; 
                        Action       = 'Check'; 
                        GroupName    = 'A'; 
                        SiteCode     = 'B'
                        Permissions  = [PSCustomObject]@{
                            Path   = 'Path'; 
                            Parent = $true; 
                            Ignore = $false;
                            ACL    = @{'A B Manager' = 'L' } 
                        }
                    }
                }
            )

            It '<TestName>' -TestCases $TestCases {
                $Actual = Expand-MatrixHC -Permissions $Permissions -Settings $Settings

                Assert-Equivalent -Actual $Actual -Expected $Expected
            }
        }
    }
    Describe 'Format-PermissionsStringsHC' {
        Context "manipulate strings in the sheet 'Permissions'" {
            It 'convert numbers to strings' {
                $Permissions = @(
                    [PSCustomObject]@{P1 = 1; P2 = 2 }
                )

                $Actual = Format-PermissionsStringsHC -Permissions $Permissions

                $Actual.P1 | Should -BeOfType [String]
                $Actual.P2 | Should -BeOfType [String]
            }

            $TestCases = @(
                $TestName = 'change lower case to upper case for ACE'
                @{
                    TestName    = $TestName
                    Permissions = @(
                        [PSCustomObject]@{P1 = $null    ; P2 = 'Bob'    ; P3 = 'Mike' }
                        [PSCustomObject]@{P1 = $null    ; P2 = 'Lee'    ; P3 = $null }
                        [PSCustomObject]@{P1 = $null    ; P2 = 'Swagger'; P3 = $null }
                        [PSCustomObject]@{P1 = 'Path'   ; P2 = 'l'      ; P3 = $null }
                        [PSCustomObject]@{P1 = 'Folder' ; P2 = 'r'      ; P3 = 'w' }
                        [PSCustomObject]@{P1 = 'F2'; P2 = $null    ; P3 = 'c*-i' }
                    )
                    Expected    = @(
                        [PSCustomObject]@{P1 = $null    ; P2 = 'Bob'    ; P3 = 'Mike' }
                        [PSCustomObject]@{P1 = $null    ; P2 = 'Lee'    ; P3 = $null }
                        [PSCustomObject]@{P1 = $null    ; P2 = 'Swagger'; P3 = $null }
                        [PSCustomObject]@{P1 = 'Path'   ; P2 = 'L'      ; P3 = $null }
                        [PSCustomObject]@{P1 = 'Folder' ; P2 = 'R'      ; P3 = 'W' }
                        [PSCustomObject]@{P1 = 'F2'; P2 = $null    ; P3 = 'C*-I' }
                    )
                }

                $TestName = 'remove leading and trailing spaces everywhere'
                @{
                    TestName    = $TestName
                    Permissions = @(
                        [PSCustomObject]@{P1 = $null      ; P2 = ' Bob ' }
                        [PSCustomObject]@{P1 = $null      ; P2 = ' Lee ' }
                        [PSCustomObject]@{P1 = $null      ; P2 = ' Swagger' }
                        [PSCustomObject]@{P1 = ' Path '   ; P2 = ' L ' }
                        [PSCustomObject]@{P1 = ' Folder ' ; P2 = ' R ' }
                    )
                    Expected    = @(
                        [PSCustomObject]@{P1 = $null    ; P2 = 'Bob' }
                        [PSCustomObject]@{P1 = $null    ; P2 = 'Lee' }
                        [PSCustomObject]@{P1 = $null    ; P2 = 'Swagger' }
                        [PSCustomObject]@{P1 = 'Path'   ; P2 = 'L' }
                        [PSCustomObject]@{P1 = 'Folder' ; P2 = 'R' }
                    )
                }

                $TestName = 'remove leading and trailing slashes from the folder names'
                @{
                    TestName    = $TestName
                    Permissions = @(
                        [PSCustomObject]@{P1 = $null      ; P2 = ' Bob ' }
                        [PSCustomObject]@{P1 = $null      ; P2 = ' Lee ' }
                        [PSCustomObject]@{P1 = $null      ; P2 = ' Swagger' }
                        [PSCustomObject]@{P1 = '\Path\'   ; P2 = 'L\' }
                        [PSCustomObject]@{P1 = '\Folder\' ; P2 = 'R' }
                    )
                    Expected    = @(
                        [PSCustomObject]@{P1 = $null    ; P2 = 'Bob' }
                        [PSCustomObject]@{P1 = $null    ; P2 = 'Lee' }
                        [PSCustomObject]@{P1 = $null    ; P2 = 'Swagger' }
                        [PSCustomObject]@{P1 = 'Path'   ; P2 = 'L\' }
                        [PSCustomObject]@{P1 = 'Folder' ; P2 = 'R' }
                    )
                }
            )

            Context 'with the arguments passed by a named parameter' {
                It '<TestName>' -TestCases $TestCases {
                    Param (
                        $Permissions,
                        $Expected
                    )

                    $Actual = Format-PermissionsStringsHC -Permissions $Permissions

                    for ($i = 0; $i -lt $Expected.length; $i++) {
                        $Actual[$i].P1 | Should -BeExactly $Expected[$i].P1
                        $Actual[$i].P2 | Should -BeExactly $Expected[$i].P2
                    }

                    $Actual.Count | Should -BeExactly $Expected.Count
                }
            }
            Context 'with the arguments passed through the pipeline' {
                It '<TestName>' -TestCases $TestCases {
                    Param (
                        $Permissions,
                        $Expected
                    )

                    $Actual = $Permissions | Format-PermissionsStringsHC

                    for ($i = 0; $i -lt $Expected.length; $i++) {
                        $Actual[$i].P1 | Should -BeExactly $Expected[$i].P1
                        $Actual[$i].P2 | Should -BeExactly $Expected[$i].P2
                    }

                    $Actual.Count | Should -BeExactly $Expected.Count
                }
            }
        }
    }
    Describe 'Format-SettingStringsHC' {
        Context "manipulate strings in the sheet 'Settings'" {
            $TestCases = @(
                $TestName = 'correct object, no changes'
                @{
                    TestName = $TestName
                    Settings = [PSCustomObject]@{
                        Status       = 'Enabled'
                        ComputerName = 'SERVER'
                        Path         = 'E:\DEPARTMENTS\Finance'
                        GroupName    = 'BEL'
                        SiteName     = 'BRUSSELS'
                        SiteCode     = 'BXL'
                        Action       = 'Fix'
                    }
                    Expected = [PSCustomObject]@{
                        Status       = 'Enabled'
                        ComputerName = 'SERVER'
                        Path         = 'E:\DEPARTMENTS\Finance'
                        GroupName    = 'BEL'
                        SiteName     = 'BRUSSELS'
                        SiteCode     = 'BXL'
                        Action       = 'Fix'
                    }
                }

                $TestName = 'leading and trailing spaces removed'
                @{
                    TestName = $TestName
                    Settings = [PSCustomObject]@{
                        Status       = ' ENABLED '
                        ComputerName = ' SERVER '
                        Path         = ' E:\DEPARTMENTS\Finance\ '
                        GroupName    = ' BEL '
                        SiteName     = ' BRUSSELS '
                        SiteCode     = ' BXL '
                        Action       = ' FIX '
                    }
                    Expected = [PSCustomObject]@{
                        Status       = 'Enabled'
                        ComputerName = 'SERVER'
                        Path         = 'E:\DEPARTMENTS\Finance'
                        GroupName    = 'BEL'
                        SiteName     = 'BRUSSELS'
                        SiteCode     = 'BXL'
                        Action       = 'Fix'
                    }
                }

                $TestName = 'ComputerName with domain name. domain name gets stripped'
                @{
                    TestName = $TestName
                    Settings = [PSCustomObject]@{
                        Status       = 'Enabled'
                        ComputerName = 'SERVER' + '.' + $env:USERDNSDOMAIN
                        Path         = 'E:\DEPARTMENTS\Finance'
                        GroupName    = 'BEL'
                        SiteName     = 'BRUSSELS'
                        SiteCode     = 'BXL'
                        Action       = 'Fix'
                    }
                    Expected = [PSCustomObject]@{
                        Status       = 'Enabled'
                        ComputerName = 'SERVER'
                        Path         = 'E:\DEPARTMENTS\Finance'
                        GroupName    = 'BEL'
                        SiteName     = 'BRUSSELS'
                        SiteCode     = 'BXL'
                        Action       = 'Fix'
                    }
                }

                $TestName = 'ComputerName with unknown domain name, no changes'
                @{
                    TestName = $TestName
                    Settings = [PSCustomObject]@{
                        Status       = 'Enabled'
                        ComputerName = 'SERVER.wrong.net'
                        Path         = 'E:\DEPARTMENTS\Finance'
                        GroupName    = 'BEL'
                        SiteName     = 'BRUSSELS'
                        SiteCode     = 'BXL'
                        Action       = 'Fix'
                    }
                    Expected = [PSCustomObject]@{
                        Status       = 'Enabled'
                        ComputerName = 'SERVER.wrong.net'
                        Path         = 'E:\DEPARTMENTS\Finance'
                        GroupName    = 'BEL'
                        SiteName     = 'BRUSSELS'
                        SiteCode     = 'BXL'
                        Action       = 'Fix'
                    }
                }

                $TestName = 'convert blanks to NULL'
                @{
                    TestName = $TestName
                    Settings = [PSCustomObject]@{
                        Status       = ' '
                        ComputerName = $null
                        Path         = ' '
                        GroupName    = 'BEL'
                        SiteName     = 'BRUSSELS'
                        SiteCode     = $null
                        Action       = ''
                    }
                    Expected = [PSCustomObject]@{
                        Status       = $null
                        ComputerName = $null
                        Path         = $null
                        GroupName    = 'BEL'
                        SiteName     = 'BRUSSELS'
                        SiteCode     = $null
                        Action       = $null
                    }
                }
            )

            Context 'with the arguments passed by a named parameter' {
                It '<TestName>' -TestCases $TestCases {
                    Param (
                        $Settings,
                        $Expected
                    )

                    $Actual = Format-SettingStringsHC -Settings $Settings
                    Assert-Equivalent -Actual $Actual -Expected $Expected
                }
            }
            Context 'with the arguments passed through the pipeline' {
                It '<TestName>' -TestCases $TestCases {
                    Param (
                        $Settings,
                        $Expected
                    )

                    $Actual = $Settings | Format-SettingStringsHC
                    Assert-Equivalent -Actual $Actual -Expected $Expected
                }
            }
        }
    }
    Describe 'Get-ADObjectDetailHC' {
        Context 'when the AD Object does not exist then' {
            It 'ADObject and Member are NULL' {
                Mock Get-ADObject

                $Expected = [PSCustomObject]@{
                    Name     = 'NotExisting'
                    ADObject = $null
                    Member   = $null
                }

                $Actual = Get-ADObjectDetailHC -Name NotExisting
                Assert-Equivalent -Actual $Actual -Expected $Expected
            }
        }
        Context 'when the AD object exist then' {
            # InModuleScope $moduleName {

            Context 'user' {
                It 'Member is NULL' {
                    $testADObject = New-Object Microsoft.ActiveDirectory.Management.ADObject Identity -Property @{
                        SamAccountName = 'Bob'
                        ObjectClass    = 'user'
                    }

                    Mock Get-ADObject {
                        $testADObject
                    }

                    $Expected = [PSCustomObject]@{
                        Name     = $testADObject.SamAccountName
                        ADObject = $testADObject
                        Member   = $null
                    }

                    $Actual = Get-ADObjectDetailHC -Name $testADObject.SamAccountName

                    $Actual.Name | Should -Be $Expected.Name
                    $Actual.Member | Should -Be $Expected.Member
                    $Actual.ADObject | Should -Be $Expected.ADObject
                    # Assert-Equivalent -Actual $Actual -Expected $Expected
                }
            }
            Context 'group' {
                It "Member is always True for 'Domain users'" {
                    $testADObject = New-Object Microsoft.ActiveDirectory.Management.ADGroup Identity -Property @{
                        SamAccountName = 'Domain users'
                        ObjectClass    = 'group'
                    }

                    Mock Get-ADObject {
                        $testADObject
                    }

                    $Expected = [PSCustomObject]@{
                        Name     = $testADObject.SamAccountName
                        ADObject = $testADObject
                        Member   = $true
                    }

                    $Actual = Get-ADObjectDetailHC -Name $testADObject.SamAccountName
                    Assert-Equivalent -Actual $Actual -Expected $Expected
                }
                It 'Member is True when there are user objects in the group' {
                    $testADObject = New-Object Microsoft.ActiveDirectory.Management.ADGroup Identity -Property @{
                        SamAccountName = 'BEL Managers'
                        ObjectClass    = 'group'
                    }

                    Mock Get-ADGroupMember {
                        New-Object Microsoft.ActiveDirectory.Management.ADUser Identity -Property @{
                            SamAccountName = 'Mike'
                            ObjectClass    = 'user'
                        }
                    }

                    Mock Get-ADObject {
                        $testADObject
                    }

                    $Expected = [PSCustomObject]@{
                        Name     = $testADObject.SamAccountName
                        ADObject = $testADObject
                        Member   = $true
                    }

                    $Actual = Get-ADObjectDetailHC -Name $testADObject.SamAccountName
                    Assert-Equivalent -Actual $Actual -Expected $Expected
                }
                It 'Member is True when there are user objects and a place holder account in the group' {
                    $testADObject = New-Object Microsoft.ActiveDirectory.Management.ADGroup Identity -Property @{
                        SamAccountName = 'BEL Managers'
                        ObjectClass    = 'group'
                    }

                    $testMember = @(
                        New-Object Microsoft.ActiveDirectory.Management.ADUser Identity -Property @{
                            SamAccountName = 'Mike'
                            ObjectClass    = 'user'
                        }
                        New-Object Microsoft.ActiveDirectory.Management.ADUser Identity -Property @{
                            SamAccountName = 'PlaceHolder'
                            ObjectClass    = 'user'
                        }
                    )

                    Mock Get-ADGroupMember {
                        $testMember
                    }

                    Mock Get-ADObject {
                        $testADObject
                    }

                    $Expected = [PSCustomObject]@{
                        Name     = $testADObject.SamAccountName
                        ADObject = $testADObject
                        Member   = $true
                    }

                    $Actual = Get-ADObjectDetailHC -Name $testADObject.SamAccountName -ExcludeMember $testMember[1].SamAccountName
                    Assert-Equivalent -Actual $Actual -Expected $Expected
                }
                It 'Member is False when there are no user objects in the group' {
                    $testADObject = New-Object Microsoft.ActiveDirectory.Management.ADGroup Identity -Property @{
                        SamAccountName = 'BEL Managers'
                        ObjectClass    = 'group'
                    }

                    Mock Get-ADGroupMember {
                        New-Object Microsoft.ActiveDirectory.Management.ADGroup Identity -Property @{
                            SamAccountName = 'Group 2'
                            ObjectClass    = 'group'
                        }
                    }

                    Mock Get-ADObject {
                        $testADObject
                    }

                    $Expected = [PSCustomObject]@{
                        Name     = $testADObject.SamAccountName
                        ADObject = $testADObject
                        Member   = $false
                    }

                    $Actual = Get-ADObjectDetailHC -Name $testADObject.SamAccountName
                    Assert-Equivalent -Actual $Actual -Expected $Expected
                }
                It 'Member is False when there is only a place holder account in the group' {
                    $testADObject = New-Object Microsoft.ActiveDirectory.Management.ADGroup Identity -Property @{
                        SamAccountName = 'BEL Managers'
                        ObjectClass    = 'group'
                    }
                    $testMember = New-Object Microsoft.ActiveDirectory.Management.ADUser Identity -Property @{
                        SamAccountName = 'PlaceHolder'
                        ObjectClass    = 'user'
                    }

                    Mock Get-ADGroupMember {
                        $testMember
                    }

                    Mock Get-ADObject {
                        $testADObject
                    }

                    $Expected = [PSCustomObject]@{
                        Name     = $testADObject.SamAccountName
                        ADObject = $testADObject
                        Member   = $false
                    }

                    $Actual = Get-ADObjectDetailHC -Name $testADObject.SamAccountName -ExcludeMember $testMember.SamAccountName
                    Assert-Equivalent -Actual $Actual -Expected $Expected
                }
            }
        }
        # }
    }
    Describe 'Get-DefaultAclHC' {
        Context 'an error is thrown' {
            $TestCases = @(
                $TaskName = "'Permission' given but no 'ADObjectName'"
                @{
                    TaskName     = $TaskName
                    DefaultsFile = @(
                        [PSCustomObject]@{MailTo = 'Bob@mail.com' ; ADObjectName = 'Manager'; Permission = 'L' }
                        [PSCustomObject]@{MailTo = 'Mike@mail.com'; ADObjectName = ''     ; Permission = 'R' }
                        [PSCustomObject]@{MailTo = 'Chuck@mail.com' }
                    )
                    Expected     = "Permission 'R' has no AD object name."
                }

                $TaskName = "'ADObjectName' given but no 'Permission'"
                @{
                    TaskName     = $TaskName
                    DefaultsFile = @(
                        [PSCustomObject]@{MailTo = 'Bob@mail.com' ; ADObjectName = 'Manager'; Permission = 'L' }
                        [PSCustomObject]@{MailTo = 'Mike@mail.com'; ADObjectName = 'Bob'     ; Permission = $null }
                        [PSCustomObject]@{MailTo = 'Chuck@mail.com' }
                    )
                    Expected     = "AD object name 'Bob' has no permission."
                }

                $TaskName = "unknown 'Permission' char"
                @{
                    TaskName     = $TaskName
                    DefaultsFile = @(
                        [PSCustomObject]@{MailTo = 'Bob@mail.com' ; ADObjectName = 'Manager'; Permission = 'L' }
                        [PSCustomObject]@{MailTo = 'Mike@mail.com'; ADObjectName = 'Bob'    ; Permission = 'Z' }
                        [PSCustomObject]@{MailTo = 'Chuck@mail.com' }
                    )
                    Expected     = "Permission character 'Z' unknown."
                }

                $TaskName = "duplicate 'ADObjectName'"
                @{
                    TaskName     = $TaskName
                    DefaultsFile = @(
                        [PSCustomObject]@{MailTo = 'Bob@mail.com' ; ADObjectName = 'Bob'; Permission = 'L' }
                        [PSCustomObject]@{MailTo = 'Mike@mail.com'; ADObjectName = 'Bob'; Permission = 'L' }
                        [PSCustomObject]@{MailTo = 'Chuck@mail.com' }
                    )
                    Expected     = "AD Object name 'Bob' is not unique."
                }
            )

            It "<TaskName>" -TestCases $TestCases {
                Param (
                    $DefaultsFile,
                    $Expected
                )

                { Get-DefaultAclHC -Sheet $DefaultsFile } |
                Should -Throw -PassThru | Select-Object -ExpandProperty Exception |
                Should -BeLike "*$Expected*"
            }
        }
        Context "combine 'ADObjectName' and 'Permission' in one hashtable" {
            $TestCases = @(
                $TaskName = "3 properties and 2 ACE's"
                @{
                    TaskName     = $TaskName
                    DefaultsFile = @(
                        [PSCustomObject]@{MailTo = 'Bob@mail.com' ; ADObjectName = 'Manager'; Permission = 'L' }
                        [PSCustomObject]@{MailTo = 'Mike@mail.com'; ADObjectName = 'SD'     ; Permission = 'R' }
                        [PSCustomObject]@{MailTo = 'Chuck@mail.com' }
                    )
                    Expected     = @{
                        'Manager' = 'L'
                        'SD'      = 'R'
                    }
                }

                $TaskName = "no 'ADObjectName' and no 'Permission', empty ACL"
                @{
                    TaskName     = $TaskName
                    DefaultsFile = @(
                        [PSCustomObject]@{MailTo = 'Bob@mail.com' }
                        [PSCustomObject]@{MailTo = 'Mike@mail.com' }
                        [PSCustomObject]@{MailTo = 'Chuck@mail.com' }
                    )
                    Expected     = @{}
                }

                $TaskName = "5 ACE's"
                @{
                    TaskName     = $TaskName
                    DefaultsFile = @(
                        [PSCustomObject]@{MailTo = 'Bob@mail.com'  ; ADObjectName = 'Manager'; Permission = 'C' }
                        [PSCustomObject]@{MailTo = 'Mike@mail.com' ; ADObjectName = 'User1'  ; Permission = 'R' }
                        [PSCustomObject]@{MailTo = 'Chuck@mail.com'; ADObjectName = 'User2'  ; Permission = 'F' }
                        [PSCustomObject]@{ADObjectName = 'User3'   ; Permission = 'L' }
                        [PSCustomObject]@{ADObjectName = 'User4'   ; Permission = 'W' }
                    )
                    Expected     = @{
                        'Manager' = 'C'
                        'User1'   = 'R'
                        'User2'   = 'F'
                        'User3'   = 'L'
                        'User4'   = 'W'
                    }
                }
            )

            It "<TaskName>" -TestCases $TestCases {
                Param (
                    $DefaultsFile,
                    $Expected
                )

                $Actual = Get-DefaultAclHC -Sheet $DefaultsFile
                Assert-Equivalent -Actual $Actual -Expected $Expected
            }
        }
    }
    Describe 'Get-ExecutableMatrixHC' {
        Context 'exclude the matrix when' {
            It 'the File.Check contains a FatalError' {
                $testFile = @(
                    [PSCustomObject]@{
                        File        = @{
                            Check = @([PSCustomObject]@{Type = 'FatalError' })
                        }
                        Settings    = @(
                            [PSCustomObject]@{
                                Check  = @()
                                Matrix = $true
                            }
                        )
                        Permissions = @{
                            Check = @()
                        }
                    }
                )

                Get-ExecutableMatrixHC -From $testFile | Should -BeNullOrEmpty
            }
            It 'the Settings.Check contains a FatalError' {
                $testFile = @(
                    [PSCustomObject]@{
                        File        = @{
                            Check = @()
                        }
                        Settings    = @(
                            [PSCustomObject]@{
                                Check  = @([PSCustomObject]@{Type = 'FatalError' })
                                Matrix = $true
                            }
                        )
                        Permissions = @{
                            Check = @()
                        }
                    }
                )

                Get-ExecutableMatrixHC -From $testFile | Should -BeNullOrEmpty
            }
            It 'the Permissions.Check contains a FatalError' {
                $testFile = @(
                    [PSCustomObject]@{
                        File        = @{
                            Check = @()
                        }
                        Settings    = @(
                            [PSCustomObject]@{
                                Check  = @()
                                Matrix = $true
                            }
                        )
                        Permissions = @{
                            Check = @([PSCustomObject]@{Type = 'FatalError' })
                        }
                    }
                )

                Get-ExecutableMatrixHC -From $testFile | Should -BeNullOrEmpty
            }
        }
        Context 'include the matrix when' {
            It 'no FatalError is detected' {
                $Expected = [PSCustomObject]@{
                    Check  = @()
                    Matrix = $true
                }
                $testFile = @(
                    [PSCustomObject]@{
                        File        = @{
                            Check = @()
                        }
                        Settings    = @(
                            $Expected
                        )
                        Permissions = @{
                            Check = @()
                        }
                    }
                )

                $Actual = Get-ExecutableMatrixHC -From $testFile
                Assert-Equivalent -Actual $Actual -Expected $Expected
            }
            It "when one matrix in the same file has a FatalError but the others don't" {
                $testFile = @(
                    [PSCustomObject]@{
                        File        = @{
                            Check = @()
                        }
                        Settings    = @(
                            [PSCustomObject]@{
                                Check  = @([PSCustomObject]@{Type = 'FatalError' })
                                Matrix = $true
                            }
                            [PSCustomObject]@{
                                Check  = @()
                                Matrix = $true
                            }
                            [PSCustomObject]@{
                                Check  = @()
                                Matrix = $true
                            }
                        )
                        Permissions = @{
                            Check = @()
                        }
                    }
                )

                $Actual = Get-ExecutableMatrixHC -From $testFile
                ($Actual | Measure-Object).Count | Should -BeExactly 2
            }
            It "when one file has a FatalError but the other files don't" {
                $testFile = @(
                    [PSCustomObject]@{
                        File        = @{
                            Check = @([PSCustomObject]@{Type = 'FatalError' })
                        }
                        Settings    = @(
                            [PSCustomObject]@{
                                Check  = @()
                                Matrix = 'ignore'
                            }
                            [PSCustomObject]@{
                                Check  = @()
                                Matrix = 'ignore'
                            }
                            [PSCustomObject]@{
                                Check  = @()
                                Matrix = 'ignore'
                            }
                        )
                        Permissions = @{
                            Check = @()
                        }
                    }
                    [PSCustomObject]@{
                        File        = @{
                            Check = @()
                        }
                        Settings    = @(
                            [PSCustomObject]@{
                                Check  = @()
                                Matrix = 'Ok'
                            }
                            [PSCustomObject]@{
                                Check  = @()
                                Matrix = 'Ok'
                            }
                            [PSCustomObject]@{
                                Check  = @()
                                Matrix = 'Ok'
                            }
                        )
                        Permissions = @{
                            Check = @()
                        }
                    }
                )

                $Actual = Get-ExecutableMatrixHC -From $testFile
                (@($Actual).Where( { $_.Matrix -eq 'Ok' }) | Measure-Object).Count | Should -BeExactly 3
                (@($Actual).Where( { $_.Matrix -eq 'Ignore' }) | Measure-Object).Count | Should -BeExactly 0
            }
        }
    }
    Describe 'Test-AclEqualHC' {
        BeforeAll {
            $A = New-Object System.Security.AccessControl.FileSystemAccessRule(
                'GROUPHC\gijbelsb',
                [System.Security.AccessControl.FileSystemRights]::Modify,
                [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $B = New-Object System.Security.AccessControl.FileSystemAccessRule(
                'GROUPHC\dverhuls',
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
        }
        Context 'returns true when' {
            It "both ACL's contain one object each and are the same" {
                $sourceAcl = New-Object System.Security.AccessControl.DirectorySecurity
                $sourceAcl.AddAccessRule($A)

                $destinationAcl = New-Object System.Security.AccessControl.DirectorySecurity
                $destinationAcl.AddAccessRule($A)

                Test-AclEqualHC -SourceAcl $sourceAcl -DestinationAcl $destinationAcl |
                Should -BeTrue
            }
            It "both ACL's contain multiple objects that are the same" {
                $sourceAcl = New-Object System.Security.AccessControl.DirectorySecurity
                $sourceAcl.AddAccessRule($B)
                $sourceAcl.AddAccessRule($A)

                $destinationAcl = New-Object System.Security.AccessControl.DirectorySecurity
                $destinationAcl.AddAccessRule($A)
                $destinationAcl.AddAccessRule($B)

                Test-AclEqualHC -SourceAcl $sourceAcl -DestinationAcl $destinationAcl |
                Should -BeTrue
            }
        }
        Context 'returns false when' {
            It "both ACL's are dfferent" {
                $sourceAcl = New-Object System.Security.AccessControl.DirectorySecurity
                $sourceAcl.AddAccessRule($A)

                $destinationAcl = New-Object System.Security.AccessControl.DirectorySecurity
                $destinationAcl.AddAccessRule($B)

                Test-AclEqualHC -SourceAcl $sourceAcl -DestinationAcl $destinationAcl |
                Should -BeFalse
            }
            It 'the source ACL contains more objects' {
                $sourceAcl = New-Object System.Security.AccessControl.DirectorySecurity
                $sourceAcl.AddAccessRule($A)
                $sourceAcl.AddAccessRule($B)

                $destinationAcl = New-Object System.Security.AccessControl.DirectorySecurity
                $destinationAcl.AddAccessRule($A)

                Test-AclEqualHC -SourceAcl $sourceAcl -DestinationAcl $destinationAcl |
                Should -BeFalse
            }
            It 'the destination ACL contains more objects' {
                $sourceAcl = New-Object System.Security.AccessControl.DirectorySecurity
                $sourceAcl.AddAccessRule($A)

                $destinationAcl = New-Object System.Security.AccessControl.DirectorySecurity
                $destinationAcl.AddAccessRule($A)
                $destinationAcl.AddAccessRule($B)

                Test-AclEqualHC -SourceAcl $sourceAcl -DestinationAcl $destinationAcl |
                Should -BeFalse
            }
            It "the source ACL is empty" {
                $sourceAcl = New-Object System.Security.AccessControl.DirectorySecurity

                $destinationAcl = New-Object System.Security.AccessControl.DirectorySecurity
                $destinationAcl.AddAccessRule($B)

                Test-AclEqualHC -SourceAcl $sourceAcl -DestinationAcl $destinationAcl |
                Should -BeFalse
            }
            It "the destination ACL is empty" {
                $sourceAcl = New-Object System.Security.AccessControl.DirectorySecurity
                $sourceAcl.AddAccessRule($A)

                $destinationAcl = New-Object System.Security.AccessControl.DirectorySecurity

                Test-AclEqualHC -SourceAcl $sourceAcl -DestinationAcl $destinationAcl |
                Should -BeFalse
            }
            Context 'there is a small difference in the field' {
                It 'InheritanceFlags' {
                    $sourceAcl = New-Object System.Security.AccessControl.DirectorySecurity
                    @(
                        $A
                        $B
                        New-Object System.Security.AccessControl.FileSystemAccessRule(
                            "GROUPHC\$env:USERNAME",
                            [System.Security.AccessControl.FileSystemRights]::Modify,
                            [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit",
                            [System.Security.AccessControl.PropagationFlags]::None,
                            [System.Security.AccessControl.AccessControlType]::Allow
                        )
                    ).ForEach( { $sourceAcl.AddAccessRule($_) })

                    $destinationAcl = New-Object System.Security.AccessControl.DirectorySecurity
                    @(
                        $A
                        New-Object System.Security.AccessControl.FileSystemAccessRule(
                            "GROUPHC\$env:USERNAME",
                            [System.Security.AccessControl.FileSystemRights]::Modify,
                            [System.Security.AccessControl.InheritanceFlags]"ContainerInherit",
                            [System.Security.AccessControl.PropagationFlags]::None,
                            [System.Security.AccessControl.AccessControlType]::Allow
                        )
                        $B
                    ).ForEach( { $destinationAcl.AddAccessRule($_) })

                    Test-AclEqualHC -SourceAcl $sourceAcl -DestinationAcl $destinationAcl |
                    Should -BeFalse
                }
                It 'FileSystemRights' {
                    $sourceAcl = New-Object System.Security.AccessControl.DirectorySecurity
                    @(
                        $A
                        $B
                        New-Object System.Security.AccessControl.FileSystemAccessRule(
                            "GROUPHC\$env:USERNAME",
                            [System.Security.AccessControl.FileSystemRights]::Read,
                            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
                            [System.Security.AccessControl.PropagationFlags]::None,
                            [System.Security.AccessControl.AccessControlType]::Allow
                        )
                    ).ForEach( { $sourceAcl.AddAccessRule($_) })

                    $destinationAcl = New-Object System.Security.AccessControl.DirectorySecurity
                    @(
                        $A
                        New-Object System.Security.AccessControl.FileSystemAccessRule(
                            "GROUPHC\$env:USERNAME",
                            [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
                            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
                            [System.Security.AccessControl.PropagationFlags]::None,
                            [System.Security.AccessControl.AccessControlType]::Allow
                        )
                        $B
                    ).ForEach( { $destinationAcl.AddAccessRule($_) })

                    Test-AclEqualHC -SourceAcl $sourceAcl -DestinationAcl $destinationAcl |
                    Should -BeFalse
                }
                It 'PropagationFlags' {
                    $sourceAcl = New-Object System.Security.AccessControl.DirectorySecurity
                    @(
                        $A
                        $B
                        New-Object System.Security.AccessControl.FileSystemAccessRule(
                            "GROUPHC\$env:USERNAME",
                            [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
                            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
                            [System.Security.AccessControl.PropagationFlags]::None,
                            [System.Security.AccessControl.AccessControlType]::Allow
                        )
                    ).ForEach( { $sourceAcl.AddAccessRule($_) })

                    $destinationAcl = New-Object System.Security.AccessControl.DirectorySecurity
                    @(
                        $A
                        New-Object System.Security.AccessControl.FileSystemAccessRule(
                            "GROUPHC\$env:USERNAME",
                            [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
                            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
                            [System.Security.AccessControl.PropagationFlags]::InheritOnly,
                            [System.Security.AccessControl.AccessControlType]::Allow
                        )
                        $B
                    ).ForEach( { $destinationAcl.AddAccessRule($_) })

                    Test-AclEqualHC -SourceAcl $sourceAcl -DestinationAcl $destinationAcl |
                    Should -BeFalse
                }
                It 'AccessControlType' {
                    $sourceAcl = New-Object System.Security.AccessControl.DirectorySecurity
                    @(
                        $A
                        $B
                        New-Object System.Security.AccessControl.FileSystemAccessRule(
                            "GROUPHC\$env:USERNAME",
                            [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
                            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
                            [System.Security.AccessControl.PropagationFlags]::None,
                            [System.Security.AccessControl.AccessControlType]::Deny
                        )
                    ).ForEach( { $sourceAcl.AddAccessRule($_) })

                    $destinationAcl = New-Object System.Security.AccessControl.DirectorySecurity
                    @(
                        $A
                        New-Object System.Security.AccessControl.FileSystemAccessRule(
                            "GROUPHC\$env:USERNAME",
                            [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
                            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
                            [System.Security.AccessControl.PropagationFlags]::None,
                            [System.Security.AccessControl.AccessControlType]::Allow
                        )
                        $B
                    ).ForEach( { $destinationAcl.AddAccessRule($_) })

                    Test-AclEqualHC -SourceAcl $sourceAcl -DestinationAcl $destinationAcl |
                    Should -BeFalse
                }
            }
        }
    }
    Describe 'Test-AclIsInheritedOnlyHC' {
        BeforeAll {
            $BuiltinAdmin = New-Object System.Security.AccessControl.FileSystemAccessRule(
                'BUILTIN\Administrators',
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $SystemNtAuthority = New-Object System.Security.AccessControl.FileSystemAccessRule(
                'NT AUTHORITY\SYSTEM',
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $A = New-Object System.Security.AccessControl.FileSystemAccessRule(
                'GROUPHC\gijbelsb',
                [System.Security.AccessControl.FileSystemRights]::Modify,
                [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $B = New-Object System.Security.AccessControl.FileSystemAccessRule(
                'GROUPHC\dverhuls',
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.InheritanceFlags]::ContainerInherit,
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
        }
        Context 'is returning true when' {
            It "there are only inherited ACE's in the ACL" {
                $testFileItem = New-Item -Path "TestDrive:/testFolder" -ItemType Directory -Force
                $testAcl = $testFileItem.GetAccessControl()

                Test-AclIsInheritedOnlyHC -Acl $testAcl | Should -BeTrue
            }
            It "there are only inherited ACE's and the group 'BUILTIN\Administrators' in the ACL" {
                $testFileItem = New-Item -Path "TestDrive:/testFolder" -ItemType Directory -Force
                $testAcl = $testFileItem.GetAccessControl()
                $testAcl.AddAccessRule($BuiltinAdmin)

                Test-AclIsInheritedOnlyHC -Acl $testAcl | Should -BeTrue
            }
            It "there are only inherited ACE's and the group 'NT AUTHORITY\SYSTEM' in the ACL" {
                $testFileItem = New-Item -Path "TestDrive:/testFolder" -ItemType Directory -Force
                $testAcl = $testFileItem.GetAccessControl()
                $testAcl.AddAccessRule($SystemNtAuthority)

                Test-AclIsInheritedOnlyHC -Acl $testAcl | Should -BeTrue
            }
        }
        Context 'is returning false when' {
            It "there is a non inherited ACE amongst the inherited ACE's" {
                $testFileItem = New-Item -Path "TestDrive:/testFolder" -ItemType Directory -Force
                $testAcl = $testFileItem.GetAccessControl()
                $testAcl.AddAccessRule($A)

                Test-AclIsInheritedOnlyHC -Acl $testAcl | Should -BeFalse
            }
            It "there are only non inherited ACE's in the ACL" {
                $testAcl = New-Object System.Security.AccessControl.DirectorySecurity
                $testAcl.AddAccessRule($A)

                Test-AclIsInheritedOnlyHC -Acl $testAcl | Should -BeFalse
            }
        }
    
    }
    Describe 'Test-ExpandedMatrixHC' {
        Context 'a terminating error is thrown when' {
            It 'the matrix contains an object that is unknown in ADObject' {
                $ADObjects = @(
                    @{
                        Name     = 'Group1'
                        ADObject = @{ObjectClass = 'group' }
                        Member   = $false
                    }
                )
                $Matrix = @(
                    [PSCustomObject]@{ACL = @{'Unknown1' = 'L'; 'Unknown2' = 'L' } }
                    [PSCustomObject]@{ACL = @{$ADObjects[0].Name = 'L' } }
                )

                { Test-ExpandedMatrixHC -Matrix $Matrix -ADObject $ADObjects } | Should -Throw
            }
        }
        Context 'Non existing AD Objects' {
            BeforeAll {
                $Expected = [PSCustomObject]@{
                    Type        = 'FatalError'
                    Name        = 'Unknown AD object'
                    Description = "Every AD object defined in the header row needs to exist before the matrix can be correctly executed."
                    Value       = $null
                } 
            }
            Context 'a FatalError object is registered when' {
                It 'a single AD object in the matrix is not found in the active directory' {
                    $ADObjects = @(
                        @{Name = 'UnknownUser1'; ADObject = $null }
                        @{Name = 'Bob'         ; ADObject = $true }
                    )

                    $Expected.Value = $ADObjects[0].Name

                    $Matrix = [PSCustomObject]@{ACL = @{$ADObjects[0].Name = 'L'; 'Bob' = 'R' } }

                    $Actual = Test-ExpandedMatrixHC -Matrix $Matrix -ADObject $ADObjects | Where-Object Name -EQ $Expected.Name
                    Assert-Equivalent -Actual $Actual -Expected $Expected
                }
                It 'multiple AD objects in the matrix are not found in the active directory' {
                    $ADObjects = @(
                        @{Name = 'UnknownUser1'; ADObject = $null }
                        @{Name = 'UnknownUser2'; ADObject = $null }
                        @{Name = 'Bob'         ; ADObject = @{ObjectClass = 'user' } }
                    )

                    $Expected.Value = $ADObjects[0].Name, $ADObjects[1].Name

                    $Matrix = @(
                        [PSCustomObject]@{Path = 'Folder1'; ACL = @{$ADObjects[0].Name = 'L'; $ADObjects[1].Name = 'L' } }
                        [PSCustomObject]@{Path = 'Folder2'; ACL = @{$ADObjects[0].Name = 'W'; $ADObjects[1].Name = 'R' } }
                        [PSCustomObject]@{Path = 'Folder3'; ACL = @{'Bob' = 'W'             ; $ADObjects[1].Name = 'R' } }
                    )

                    $Actual = Test-ExpandedMatrixHC -Matrix $Matrix -ADObject $ADObjects | Where-Object Name -EQ $Expected.Name
                    $Actual.Value = $Actual.Value | ConvertTo-ArrayHC
                    Assert-Equivalent -Actual $Actual -Expected $Expected
                }
            }
            Context 'no output is registered when' {
                It 'all AD objects exist in the active directory' {
                    $Matrix = [PSCustomObject]@{ACL = @{'Bob' = 'L'; 'Mike' = 'L' } }

                    $ADObjects = @(
                        @{Name = 'Bob' ; ADObject = $true }
                        @{Name = 'Mike'; ADObject = $true }
                    )

                    Test-ExpandedMatrixHC -Matrix $Matrix -ADObject $ADObjects | Where-Object Name -EQ $Expected.Name |
                    Should -BeNullOrEmpty
                }
            }
        }
        Context 'Empty AD groups' {
            BeforeAll {
                $Expected = [PSCustomObject]@{
                    Type        = 'Information'
                    Name        = 'Empty groups'
                    Description = 'Every active directory security group defined in the header row needs to have at least one user account as a member, excluding the place holder account.'
                    Value       = $null
                }
            }
            Context 'an Information object is registered when' {
                It "a matrix contains a single group that doesn't have a user account as member" {
                    $ADObjects = @(
                        @{
                            Name     = 'Group1'
                            ADObject = @{ObjectClass = 'group' }
                            Member   = $false
                        }
                    )

                    $Expected.Value = @($ADObjects[0].Name)

                    $Matrix = [PSCustomObject]@{ACL = @{$ADObjects[0].Name = 'L' } }

                    $Actual = Test-ExpandedMatrixHC -Matrix $Matrix -ADObject $ADObjects | Where-Object Name -EQ $Expected.Name

                    Assert-Equivalent -Actual $Actual -Expected $Expected
                }
                It 'a matrix contains multiple groups that have no user account as member' {
                    $ADObjects = @(
                        @{
                            Name     = 'Group1'
                            ADObject = @{ObjectClass = 'group' }
                            Member   = $false
                        }
                        @{
                            Name     = 'Group2'
                            ADObject = @{ObjectClass = 'group' }
                            Member   = $false
                        }
                    )

                    $Expected.Value = @($ADObjects[0].Name, $ADObjects[1].Name)

                    $Matrix = [PSCustomObject]@{ACL = @{$ADObjects[0].Name = 'L'; $ADObjects[1].Name = 'L' } }

                    $Actual = Test-ExpandedMatrixHC -Matrix $Matrix -ADObject $ADObjects | Where-Object Name -EQ $Expected.Name

                    $Actual.Value = $Actual.Value | ConvertTo-ArrayHC
                    Assert-Equivalent -Actual $Actual -Expected $Expected
                }
                It 'a matrix contains a mix of groups and users where two groups have no user account as member' {
                    $ADObjects = @(
                        @{
                            Name     = 'Group1'
                            ADObject = @{ObjectClass = 'group' }
                            Member   = $false
                        }
                        @{
                            Name     = 'Group2'
                            ADObject = @{ObjectClass = 'group' }
                            Member   = $false
                        }
                        @{
                            Name     = 'Bob'
                            ADObject = @{ObjectClass = 'user' }
                            Member   = $null
                        }
                        @{
                            Name     = 'Group3'
                            ADObject = @{ObjectClass = 'group' }
                            Member   = $true
                        }
                    )

                    $Expected.Value = @($ADObjects[0].Name, $ADObjects[1].Name)

                    $Matrix = [PSCustomObject]@{ACL = @{$ADObjects[0].Name = 'L'; $ADObjects[1].Name = 'L'; $ADObjects[2].Name = 'L'; $ADObjects[3].Name = 'L' } }

                    $Actual = Test-ExpandedMatrixHC -Matrix $Matrix -ADObject $ADObjects | Where-Object Name -EQ $Expected.Name

                    $Actual.Value = $Actual.Value | ConvertTo-ArrayHC
                    Assert-Equivalent -Actual $Actual -Expected $Expected
                }
            }
            Context 'no output is registered when' {
                It 'a matrix contains only a user account as member' {
                    $ADObjects = @(
                        @{
                            Name     = 'Bob'
                            ADObject = @{ObjectClass = 'user' }
                            Member   = $null
                        }
                    )
                    $Matrix = [PSCustomObject]@{ACL = @{$ADObjects[0].Name = 'L' } }

                    Test-ExpandedMatrixHC -Matrix $Matrix -ADObject $ADObjects | Where-Object Name -EQ $Expected.Name |
                    Should -BeNullOrEmpty
                }
                It 'a matrix contains a group that has a user account as member' {
                    $ADObjects = @(
                        @{
                            Name     = 'Group1'
                            ADObject = @{ObjectClass = 'group' }
                            Member   = $true
                        }
                    )
                    $Matrix = [PSCustomObject]@{ACL = @{$ADObjects[0].Name = 'L' } }

                    Test-ExpandedMatrixHC -Matrix $Matrix -ADObject $ADObjects | Where-Object Name -EQ $Expected.Name |
                    Should -BeNullOrEmpty
                }
                It "a matrix doesn't contain any of the empty groups defind in ADObjects" {
                    $ADObjects = @(
                        @{
                            Name     = 'Group1'
                            ADObject = @{ObjectClass = 'group' }
                            Member   = $false
                        }
                        @{
                            Name     = 'Group2'
                            ADObject = @{ObjectClass = 'group' }
                            Member   = $false
                        }
                        @{
                            Name     = 'Bob'
                            ADObject = @{ObjectClass = 'user' }
                            Member   = $null
                        }
                        @{
                            Name     = 'Group3'
                            ADObject = @{ObjectClass = 'group' }
                            Member   = $true
                        }
                    )
                    $Matrix = [PSCustomObject]@{ACL = @{$ADObjects[2].Name = 'L' } }

                    Test-ExpandedMatrixHC -Matrix $Matrix -ADObject $ADObjects | Where-Object Name -EQ $Expected.Name |
                    Should -BeNullOrEmpty
                }
                It 'a matrix contains no AD objects at all' {
                    $ADObjects = @(
                        @{
                            Name     = 'Group1'
                            ADObject = @{ObjectClass = 'group' }
                            Member   = $false
                        }
                        @{
                            Name     = 'Group2'
                            ADObject = @{ObjectClass = 'group' }
                            Member   = $false
                        }
                        @{
                            Name     = 'Bob'
                            ADObject = @{ObjectClass = 'user' }
                            Member   = $null
                        }
                        @{
                            Name     = 'Group3'
                            ADObject = @{ObjectClass = 'group' }
                            Member   = $true
                        }
                    )
                    $Matrix = [PSCustomObject]@{ACL = @{} }

                    Test-ExpandedMatrixHC -Matrix $Matrix -ADObject $ADObjects | Where-Object Name -EQ $Expected.Name |
                    Should -BeNullOrEmpty
                }
            }
        }
        Context 'Inaccessible folders' {
            BeforeAll {
                $Expected = [PSCustomObject]@{
                    Type        = 'Warning'
                    Name        = 'No folder access'
                    Description = "Every folder defined in the first column needs to have at least one user account that is able to access it. Group membership is checked to verify if groups granting access to the folder have at least one user account as a member that is not a place holder account."
                    Value       = $null
                }
            }
            Context 'a Warning object is registered when' {
                It 'a folder ACL contains a group without a user account as member' {
                    $ADObjects = @(
                        @{Name = 'Group1'; ADObject = @{ObjectClass = 'group' }; Member = $false }
                    )

                    $Matrix = [PSCustomObject]@{Path = 'Path'; ACL = @{$ADObjects[0].Name = 'L' } }

                    $Expected.Value = $Matrix[0].Path

                    $Actual = Test-ExpandedMatrixHC -Matrix $Matrix -ADObject $ADObjects | Where-Object Name -EQ $Expected.Name
                    Assert-Equivalent -Actual $Actual -Expected $Expected
                }
                It 'a folder ACL contains multiple groups where no user account is member' {
                    $ADObjects = @(
                        @{Name = 'Group1'; ADObject = @{ObjectClass = 'group' }; Member = $false }
                        @{Name = 'Group2'; ADObject = @{ObjectClass = 'group' }; Member = $false }
                    )

                    $Matrix = [PSCustomObject]@{Path = 'Path'; ACL = @{$ADObjects[0].Name = 'L'; $ADObjects[1].Name = 'L' } }

                    $Expected.Value = $Matrix[0].Path

                    $Actual = Test-ExpandedMatrixHC -Matrix $Matrix -ADObject $ADObjects | Where-Object Name -EQ $Expected.Name
                    $Actual.Value = $Actual.Value | ConvertTo-ArrayHC
                    Assert-Equivalent -Actual $Actual -Expected $Expected
                }
            }
            Context 'no output is registered when' {
                It 'a folder ACL contains a group with a user account as member' {
                    $ADObjects = @(
                        @{Name = 'Group1'; ADObject = @{ObjectClass = 'group' }; Member = $true }
                    )

                    $Matrix = [PSCustomObject]@{Path = 'Path'; ACL = @{$ADObjects[0].Name = 'L' } }

                    Test-ExpandedMatrixHC -Matrix $Matrix -ADObject $ADObjects | Where-Object Name -EQ $Expected.Name |
                    Should -BeNullOrEmpty
                }
                It 'a folder ACL contains a user account' {
                    $ADObjects = @(
                        @{Name = 'Bob'; ADObject = @{ObjectClass = 'user' }; Member = $null }
                    )

                    $Matrix = [PSCustomObject]@{Path = 'Path'; ACL = @{$ADObjects[0].Name = 'L' } }

                    Test-ExpandedMatrixHC -Matrix $Matrix -ADObject $ADObjects | Where-Object Name -EQ $Expected.Name |
                    Should -BeNullOrEmpty
                }
                It 'a folder ACL contains a mix of groups where one group has a user account as member' {
                    $ADObjects = @(
                        @{Name = 'Group1'; ADObject = @{ObjectClass = 'group' }; Member = $false }
                        @{Name = 'Group2'; ADObject = @{ObjectClass = 'group' }; Member = $false }
                        @{Name = 'Group3'; ADObject = @{ObjectClass = 'group' }; Member = $true }
                    )

                    $Matrix = [PSCustomObject]@{Path = 'Path'; ACL = @{$ADObjects[0].Name = 'L'; $ADObjects[1].Name = 'L'; $ADObjects[2].Name = 'L' } }

                    Test-ExpandedMatrixHC -Matrix $Matrix -ADObject $ADObjects | Where-Object Name -EQ $Expected.Name |
                    Should -BeNullOrEmpty
                }
                It 'a folder ACL contains a mix of empty groups with one user account' {
                    $ADObjects = @(
                        @{Name = 'Group1'; ADObject = @{ObjectClass = 'group' }; Member = $false }
                        @{Name = 'Group2'; ADObject = @{ObjectClass = 'group' }; Member = $false }
                        @{Name = 'Bob'   ; ADObject = @{ObjectClass = 'user' }; Member = $null }
                        @{Name = 'Group3'; ADObject = @{ObjectClass = 'group' }; Member = $false }
                    )

                    $Matrix = [PSCustomObject]@{Path = 'Path'; ACL = @{$ADObjects[0].Name = 'L'; $ADObjects[1].Name = 'L';
                            $ADObjects[2].Name = 'L'; $ADObjects[3].Name = 'L'
                        }
                    }

                    Test-ExpandedMatrixHC -Matrix $Matrix -ADObject $ADObjects | Where-Object Name -EQ $Expected.Name |
                    Should -BeNullOrEmpty
                }
                It 'a folder ACL is empty' {
                    $ADObjects = @(
                        @{Name = 'Group1'; ADObject = @{ObjectClass = 'group' }; Member = $true }
                    )

                    $Matrix = [PSCustomObject]@{Path = 'Path'; ACL = @{} }

                    Test-ExpandedMatrixHC -Matrix $Matrix -ADObject $ADObjects | Where-Object Name -EQ $Expected.Name |
                    Should -BeNullOrEmpty
                }
            }
        }
        Context 'Duplicate AD objects between matrix and default' {
            BeforeAll {
                $Expected = [PSCustomObject]@{
                    Type        = 'Information'
                    Name        = 'Conflichting AD Objects'
                    Description = "AD Objects defined in the matrix are duplicate with the ones defined in the default permissions. In such cases the AD objects in the matrix win over those in the default permissions. This to ensure a folder can be made completely private to those defined in the matrix. This can be desired for departments like 'Legal' or 'HR' where data might contian sensitive information that should not be visible to IT admins defined in the default permissions."
                    Value       = $null
                }
            }
            Context 'an Information object is registered when' {
                It 'a duplicate is found' {
                    $ADObjects = @(
                        @{Name = 'Group1'; ADObject = @{ObjectClass = 'group' } }
                        @{Name = 'Group2'; ADObject = @{ObjectClass = 'group' } }
                    )

                    $Matrix = @(
                        [PSCustomObject]@{Path = 'Path'; ACL = @{$ADObjects[0].Name = 'L'; $ADObjects[1].Name = 'L' } }
                    )

                    $Expected.Value = $ADObjects[0].Name

                    $testParams = @{
                        Matrix     = $Matrix
                        ADObject   = $ADObjects
                        DefaultAcl = @{$ADObjects[0].Name = 'L' }
                    }

                    $Actual = Test-ExpandedMatrixHC @testParams | Where-Object Name -EQ $Expected.Name
                    Assert-Equivalent -Actual $Actual -Expected $Expected
                }
                It 'multiple duplicates are found' {
                    $ADObjects = @(
                        @{Name = 'Group1'; ADObject = @{ObjectClass = 'group' } }
                        @{Name = 'Group2'; ADObject = @{ObjectClass = 'group' } }
                    )

                    $Matrix = @(
                        [PSCustomObject]@{Path = 'Path'; ACL = @{$ADObjects[0].Name = 'L'; $ADObjects[1].Name = 'L' } }
                    )

                    $Expected.Value = @($ADObjects[0].Name, $ADObjects[1].Name)

                    $testParams = @{
                        Matrix     = $Matrix
                        ADObject   = $ADObjects
                        DefaultAcl = @{$ADObjects[0].Name = 'L'; $ADObjects[1].Name = 'L' }
                    }

                    $Actual = Test-ExpandedMatrixHC @testParams | Where-Object Name -EQ $Expected.Name
                    $Actual.Value = $Actual.Value | ConvertTo-ArrayHC
                    Assert-Equivalent -Actual $Actual -Expected $Expected
                }
            }
            Context 'no output is registered when' {
                It 'there is no match between the matrix and the default ACL' {
                    $ADObjects = @(
                        @{Name = 'Group1'; ADObject = @{ObjectClass = 'group' } }
                        @{Name = 'Group2'; ADObject = @{ObjectClass = 'group' } }
                    )

                    $Matrix = @(
                        [PSCustomObject]@{Path = 'Path'; ACL = @{$ADObjects[0].Name = 'L'; $ADObjects[1].Name = 'L' } }
                    )

                    $testParams = @{
                        Matrix     = $Matrix
                        ADObject   = $ADObjects
                        DefaultAcl = @{'Bob' = 'L'; 'Mike' = 'L' }
                    }
                    Test-ExpandedMatrixHC @testParams | Where-Object Name -EQ $Expected.Name |
                    Should -BeNullOrEmpty
                }
                It 'the default ACL is empty' {
                    $ADObjects = @(
                        @{Name = 'Group1'; ADObject = @{ObjectClass = 'group' } }
                        @{Name = 'Group2'; ADObject = @{ObjectClass = 'group' } }
                    )

                    $Matrix = @(
                        [PSCustomObject]@{Path = 'Path'; ACL = @{$ADObjects[0].Name = 'L'; $ADObjects[1].Name = 'L' } }
                    )

                    $testParams = @{
                        Matrix     = $Matrix
                        ADObject   = $ADObjects
                        DefaultAcl = @{}
                    }
                    Test-ExpandedMatrixHC @testParams | Where-Object Name -EQ $Expected.Name |
                    Should -BeNullOrEmpty

                    $testParams = @{
                        Matrix     = $Matrix
                        ADObject   = $ADObjects
                        DefaultAcl = $null
                    }
                    Test-ExpandedMatrixHC @testParams | Where-Object Name -EQ $Expected.Name |
                    Should -BeNullOrEmpty

                    $testParams = @{
                        Matrix   = $Matrix
                        ADObject = $ADObjects
                        #DefaultAcl = @{}
                    }
                    Test-ExpandedMatrixHC @testParams | Where-Object Name -EQ $Expected.Name |
                    Should -BeNullOrEmpty
                }
            }
        }
    }
    Describe 'Test-MatrixPermissionsHC' {
        Context 'Deepest folder has only List permissions or none at all' {
            Context 'no Warning object is created when' {
                It 'the parent folder has list permissions and the the deepest folder has read/write permissions' {
                    $Permissions = @(
                        [PSCustomObject]@{P1 = $null                ; P2 = 'Bob' ; P3 = 'Mike' }
                        [PSCustomObject]@{P1 = 'SiteCode'           ; P2 = ''    ; P3 = '' }
                        [PSCustomObject]@{P1 = 'GroupName'          ; P2 = ''    ; P3 = '' }
                        [PSCustomObject]@{P1 = 'Path'               ; P2 = 'L'   ; P3 = 'L' }
                        [PSCustomObject]@{P1 = 'Vegetables'         ; P2 = 'R'   ; P3 = 'W' }
                    )

                    $Actual = Test-MatrixPermissionsHC -Permissions $Permissions | Where-Object Name -EQ 'Matrix design flaw' |
                    Should -BeNullOrEmpty
                }
                It 'the parent folder has no permissions and the the deepest folder has read/write permissions' {
                    $Permissions = @(
                        [PSCustomObject]@{P1 = $null                ; P2 = 'Bob' ; P3 = 'Mike' }
                        [PSCustomObject]@{P1 = 'SiteCode'           ; P2 = ''    ; P3 = '' }
                        [PSCustomObject]@{P1 = 'GroupName'          ; P2 = ''    ; P3 = '' }
                        [PSCustomObject]@{P1 = 'Path'               ; P2 = $null ; P3 = $null }
                        [PSCustomObject]@{P1 = 'Vegetables'         ; P2 = 'R'   ; P3 = 'W' }
                    )

                    $Actual = Test-MatrixPermissionsHC -Permissions $Permissions | Where-Object Name -EQ 'Matrix design flaw' |
                    Should -BeNullOrEmpty
                }
                It "the deepest folder has permission 'i' and is ignored" {
                    $Permissions = @(
                        [PSCustomObject]@{P1 = $null                ; P2 = 'Bob' ; P3 = 'Mike' }
                        [PSCustomObject]@{P1 = 'SiteCode'           ; P2 = ''    ; P3 = '' }
                        [PSCustomObject]@{P1 = 'GroupName'          ; P2 = ''    ; P3 = '' }
                        [PSCustomObject]@{P1 = 'Path'               ; P2 = 'L'   ; P3 = 'L' }
                        [PSCustomObject]@{P1 = 'Vegetables'         ; P2 = 'i'   ; P3 = 'L' }
                    )

                    $Actual = Test-MatrixPermissionsHC -Permissions $Permissions | Where-Object Name -EQ 'Matrix design flaw' |
                    Should -BeNullOrEmpty
                }
            }
            Context 'a Warning object is created for the deepest folder when' {
                $TestCases = @(
                    $TestName = 'the parent folder has no permissions and the deepest folder neither'
                    @{
                        TestName    = $TestName
                        Permissions = @(
                            [PSCustomObject]@{P1 = $null                ; P2 = 'Bob' ; P3 = 'Mike' }
                            [PSCustomObject]@{P1 = 'SiteCode'           ; P2 = ''    ; P3 = '' }
                            [PSCustomObject]@{P1 = 'GroupName'          ; P2 = ''    ; P3 = '' }
                            [PSCustomObject]@{P1 = 'Path'               ; P2 = $null ; P3 = $null }
                            [PSCustomObject]@{P1 = 'Vegetables'         ; P2 = $null ; P3 = $null }
                            [PSCustomObject]@{P1 = 'Fruit'              ; P2 = 'R'   ; P3 = $null }
                        )
                        Expected    = @{
                            Type        = 'Warning'
                            Description = "All folders need to be accessible by the end user. Please define at least (R)ead or (W)rite permissions on the deepest folder or use the permission (I)gnore."
                            Name        = 'Matrix design flaw'
                            Value       = 'Vegetables'
                        }
                    }

                    $TestName = 'the parent folder has list permissions and the deepest folder has none'
                    @{
                        TestName    = $TestName
                        Permissions = @(
                            [PSCustomObject]@{P1 = $null                ; P2 = 'Bob' ; P3 = 'Mike' }
                            [PSCustomObject]@{P1 = 'SiteCode'           ; P2 = ''    ; P3 = '' }
                            [PSCustomObject]@{P1 = 'GroupName'          ; P2 = ''    ; P3 = '' }
                            [PSCustomObject]@{P1 = 'Path'               ; P2 = 'L'   ; P3 = 'L' }
                            [PSCustomObject]@{P1 = 'Vegetables'         ; P2 = $null ; P3 = $null }
                            [PSCustomObject]@{P1 = 'Fruit'              ; P2 = 'R'   ; P3 = $null }
                        )
                        Expected    = @{
                            Type        = 'Warning'
                            Description = "All folders need to be accessible by the end user. Please define at least (R)ead or (W)rite permissions on the deepest folder or use the permission (I)gnore."
                            Name        = 'Matrix design flaw'
                            Value       = 'Vegetables'
                        }
                    }

                    $TestName = 'the parent folder has list permissions and the deepest folder list too'
                    @{
                        TestName    = $TestName
                        Permissions = @(
                            [PSCustomObject]@{P1 = $null                ; P2 = 'Bob' ; P3 = 'Mike' }
                            [PSCustomObject]@{P1 = 'SiteCode'           ; P2 = ''    ; P3 = '' }
                            [PSCustomObject]@{P1 = 'GroupName'          ; P2 = ''    ; P3 = '' }
                            [PSCustomObject]@{P1 = 'Path'               ; P2 = 'L'   ; P3 = 'L' }
                            [PSCustomObject]@{P1 = 'Vegetables'         ; P2 = 'L'   ; P3 = 'L' }
                            [PSCustomObject]@{P1 = 'Fruit'              ; P2 = 'R'   ; P3 = $null }
                        )
                        Expected    = @{
                            Type        = 'Warning'
                            Description = "All folders need to be accessible by the end user. Please define at least (R)ead or (W)rite permissions on the deepest folder or use the permission (I)gnore."
                            Name        = 'Matrix design flaw'
                            Value       = 'Vegetables'
                        }
                    }

                    $TestName = 'no read or write permissions are defined on the deepest folder'
                    @{
                        TestName    = $TestName
                        Permissions = @(
                            [PSCustomObject]@{P1 = $null                ; P2 = 'Bob' ; P3 = 'Mike' }
                            [PSCustomObject]@{P1 = 'SiteCode'           ; P2 = ''    ; P3 = '' }
                            [PSCustomObject]@{P1 = 'GroupName'          ; P2 = ''    ; P3 = '' }
                            [PSCustomObject]@{P1 = 'Path'               ; P2 = 'L'   ; P3 = $null } # ignored because parent folder
                            [PSCustomObject]@{P1 = 'Vegetables'         ; P2 = $null ; P3 = $null } # WRONG List inherited
                            [PSCustomObject]@{P1 = 'Fruit'              ; P2 = 'R'   ; P3 = 'W' }
                            [PSCustomObject]@{P1 = 'Fruit\Appel'        ; P2 = 'L'   ; P3 = 'L' } # WRONG
                            [PSCustomObject]@{P1 = 'Fruit\Banana'       ; P2 = 'R'   ; P3 = 'W' }
                            [PSCustomObject]@{P1 = 'Fruit\Banana\Yellow'; P2 = 'L'   ; P3 = $null } # WRONG
                            [PSCustomObject]@{P1 = 'Fruit\Kiwi'         ; P2 = 'L'   ; P3 = 'i' } # ignored because of 'i' perm
                            [PSCustomObject]@{P1 = 'Sports'             ; P2 = 'L'   ; P3 = 'L' }
                            [PSCustomObject]@{P1 = 'Color\Green'        ; P2 = 'L'   ; P3 = 'L' } # WRONG
                            [PSCustomObject]@{P1 = 'Animal\Dog'         ; P2 = $null ; P3 = $null } # WRONG
                            [PSCustomObject]@{P1 = 'Animal\Cat'         ; P2 = 'L'   ; P3 = 'R' }
                        )
                        Expected    = @{
                            Type        = 'Warning'
                            Description = "All folders need to be accessible by the end user. Please define at least (R)ead or (W)rite permissions on the deepest folder or use the permission (I)gnore."
                            Name        = 'Matrix design flaw'
                            Value       = @('Vegetables', 'Fruit\Appel', 'Fruit\Banana\Yellow',
                                'Sports', 'Color\Green', 'Animal\Dog')
                        }
                    }
                )
                It '<TestName>' -TestCases $TestCases {
                    Param (
                        $Permissions,
                        $Expected
                    )

                    $Actual = Test-MatrixPermissionsHC -Permissions $Permissions | Where-Object Name -EQ $Expected.Name

                    $Actual.Type | Should -Be $Expected.Type
                    $Actual.Description | Should -Be $Expected.Description
                    $Actual.Name | Should -Be $Expected.Name
                    $Actual.Value | Should -Be $Expected.Value
                }
            }
        }
        Context 'a FatalError object is created when' {
            $TestCases = @(
                $TestName = 'an ignore (i) permission is used for the parent folder'
                @{
                    TestName    = $TestName
                    Permissions = @(
                        [PSCustomObject]@{P1 = $null      ; P2 = 'Manager'  ; P3 = 'Bob'; P4 = 'Mike' }
                        [PSCustomObject]@{P1 = 'SiteCode' ; P2 = 'SiteCode' ; P3 = ''   ; P4 = '' }
                        [PSCustomObject]@{P1 = 'GroupName'; P2 = 'GroupName'; P3 = ''   ; P4 = '' }
                        [PSCustomObject]@{P1 = 'Parent'   ; P2 = $null      ; P3 = 'i'  ; P4 = '' }
                        [PSCustomObject]@{P1 = 'Folder'   ; P2 = 'R'        ; P3 = 'R'  ; P4 = 'W' }
                    )
                    Expected    = @{
                        Type        = 'FatalError'
                        Name        = 'Permissions missing on parent folder'
                        Description = "The permission ignore 'i' cannot be used on the parent folder."
                        Value       = $null
                    }
                }

                $TestName = 'there are less than 5 rows'
                @{
                    TestName    = $TestName
                    Permissions = @(
                        [PSCustomObject]@{P1 = $null      ; P2 = 'Manager'    ; P3 = $null }
                        [PSCustomObject]@{P1 = 'SiteCode' ; P2 = 'SiteCode'   ; P3 = $null }
                        [PSCustomObject]@{P1 = 'GroupName'; P2 = 'GroupName'  ; P3 = $null }
                        [PSCustomObject]@{P1 = 'Path'     ; P2 = 'L'          ; P3 = 'L' }
                    )
                    Expected    = @{
                        Type        = 'FatalError'
                        Description = 'At least 5 rows are required: 3 header rows. 1 row for the parent folder and at least 1 row for defining permissions on a sub folder.'
                        Name        = 'Missing rows'
                        Value       = '4 rows'
                    }
                }

                $TestName = 'there are less than 2 columns'
                @{
                    TestName    = $TestName
                    Permissions = @(
                        [PSCustomObject]@{P1 = $null }
                        [PSCustomObject]@{P1 = 'SiteCode' }
                        [PSCustomObject]@{P1 = 'GroupName' }
                        [PSCustomObject]@{P1 = 'F1' }
                        [PSCustomObject]@{P1 = 'F2' }
                    )
                    Expected    = @{
                        Type        = 'FatalError'
                        Description = 'At least 2 columns are required: 1 for the folder names and 1 where the permissions are defined.'
                        Name        = 'Missing columns'
                        Value       = '1 column'
                    }
                }

                $TestName = 'duplicate AD objects are found'
                @{
                    TestName    = $TestName
                    Permissions = @(
                        [PSCustomObject]@{P1 = $null      ; P2 = 'Bob' ; P3 = 'Bob'; P4 = 'Mike'  ; P5 = ''    ; P6 = 'Chuck' }
                        [PSCustomObject]@{P1 = 'SiteCode' ; P2 = ''    ; P3 = ''   ; P4 = ''      ; P5 = 'Mike'; P6 = '' }
                        [PSCustomObject]@{P1 = 'GroupName'; P2 = ''    ; P3 = ''   ; P4 = ''      ; P5 = ''    ; P6 = '' }
                        [PSCustomObject]@{P1 = 'Path'     ; P2 = 'L'   ; P3 = 'L'  ; P4 = 'L'     ; P5 = 'L'   ; P6 = 'L' }
                        [PSCustomObject]@{P1 = 'Folder'   ; P2 = 'R'   ; P3 = 'W'  ; P4 = 'R'     ; P5 = 'R'   ; P6 = 'R' }
                    )
                    Expected    = @{
                        Type        = 'FatalError'
                        Description = "All objects defined in the matrix need to be unique. Duplicate AD Objects can also be generated from the 'Settings' worksheet combined with the header rows in the 'Permissions' worksheet."
                        Name        = 'AD Object not unique'
                        Value       = @('Mike', 'Bob')
                    }
                }

                $TestName = 'an AD object name is missing in the header row'
                @{
                    TestName    = $TestName
                    Permissions = @(
                        [PSCustomObject]@{P1 = $null      ; P2 = $null }
                        [PSCustomObject]@{P1 = 'SiteCode' ; P2 = $null }
                        [PSCustomObject]@{P1 = 'GroupName'; P2 = $null }
                        [PSCustomObject]@{P1 = 'F1'  ; P2 = 'R' }
                        [PSCustomObject]@{P1 = 'F2'  ; P2 = 'R' }
                    )
                    Expected    = @{
                        Type        = 'FatalError'
                        Description = "Every column in the worksheet 'Permissions' needs to have an AD object name in the header row. The AD object name can not be blank."
                        Name        = 'AD Object name missing'
                        Value       = $null
                    }
                }

                $TestName = "incorrect permission character (not 'l', 'c', 'w', 'r', 'i' or ' ') is found"
                @{
                    TestName    = $TestName
                    Permissions = @(
                        [PSCustomObject]@{P1 = $null      ; P2 = 'Manager'  ; P3 = 'Bob'; P4 = '' }
                        [PSCustomObject]@{P1 = 'SiteCode' ; P2 = 'SiteCode' ; P3 = ''   ; P4 = 'Mike' }
                        [PSCustomObject]@{P1 = 'GroupName'; P2 = 'GroupName'; P3 = ''   ; P4 = 'L' }
                        [PSCustomObject]@{P1 = 'F1'  ; P2 = 'L'        ; P3 = '*'  ; P4 = 'R' }
                        [PSCustomObject]@{P1 = 'F2'  ; P2 = 'I'        ; P3 = ''   ; P4 = 'W' }
                        [PSCustomObject]@{P1 = 'FolderC'  ; P2 = 'C'        ; P3 = 'X'  ; P4 = '' }
                        [PSCustomObject]@{P1 = 'FolderD'  ; P2 = 'X'        ; P3 = ''   ; P4 = $null }
                    )
                    Expected    = @{
                        Type        = 'FatalError'
                        Description = "The only supported characters, to define permissions on a folder, are 'F' (FullControl), 'W' (Write/Modify), 'R' (Read), 'L' (List) or ' ' (blank)."
                        Name        = 'Permission character unknown'
                        Value       = @('*', 'X')
                    }
                }

                $TestName = 'no permissions are defined for the parent folder'
                @{
                    TestName    = $TestName
                    Permissions = @(
                        [PSCustomObject]@{P1 = $null      ; P2 = 'Manager'  ; P3 = 'Bob'; P4 = 'Mike' }
                        [PSCustomObject]@{P1 = 'SiteCode' ; P2 = 'SiteCode' ; P3 = ''   ; P4 = '' }
                        [PSCustomObject]@{P1 = 'GroupName'; P2 = 'GroupName'; P3 = ''   ; P4 = '' }
                        [PSCustomObject]@{P1 = 'Parent'   ; P2 = $null      ; P3 = ''   ; P4 = '' }
                        [PSCustomObject]@{P1 = 'Folder'   ; P2 = 'R'        ; P3 = 'R'  ; P4 = 'W' }
                    )
                    Expected    = @{
                        Type        = 'FatalError'
                        Description = 'Missing permissions on the parent folder. At least one permission character needs to be set.'
                        Name        = 'Permissions missing on parent folder'
                        Value       = $null
                    }
                }

                $TestName = 'a folder name is missing in the first column'
                @{
                    TestName    = $TestName
                    Permissions = @(
                        [PSCustomObject]@{P1 = $null      ; P2 = 'Manager' }
                        [PSCustomObject]@{P1 = 'SiteCode' ; P2 = 'SiteCode' }
                        [PSCustomObject]@{P1 = 'GroupName'; P2 = 'GroupName' }
                        [PSCustomObject]@{P1 = 'F1'  ; P2 = 'L' }
                        [PSCustomObject]@{P1 = $null      ; P2 = 'R' }
                        [PSCustomObject]@{P1 = 'FolderC'  ; P2 = 'L' }
                    )
                    Expected    = @{
                        Type        = 'FatalError'
                        Description = 'Missing folder name in the first column. A folder name is required to be able to set permissions on it.'
                        Name        = 'Folder name missing'
                        Value       = $null
                    }
                }

                $TestName = 'duplicate folder names are found in the first column'
                @{
                    TestName    = $TestName
                    Permissions = @(
                        [PSCustomObject]@{P1 = $null      ; P2 = 'Manager' }
                        [PSCustomObject]@{P1 = 'SiteCode' ; P2 = 'SiteCode' }
                        [PSCustomObject]@{P1 = 'GroupName'; P2 = 'GroupName' }
                        [PSCustomObject]@{P1 = 'Path'     ; P2 = 'L' }
                        [PSCustomObject]@{P1 = 'F1'  ; P2 = 'R' }
                        [PSCustomObject]@{P1 = 'F1'  ; P2 = 'W' }
                        [PSCustomObject]@{P1 = 'F2'  ; P2 = 'W' }
                    )
                    Expected    = @{
                        Type        = 'FatalError'
                        Description = 'Every folder name in the first column needs to be unique. This is required to be able to set the correct permissions.'
                        Name        = 'Folder name not unique'
                        Value       = 'F1'
                    }
                }
            )
            It '<TestName>' -TestCases $TestCases {
                Param (
                    $Permissions,
                    $Expected
                )

                $Actual = Test-MatrixPermissionsHC -Permissions $Permissions | Where-Object Name -EQ $Expected.Name

                $Actual.Type | Should -Be $Expected.Type
                $Actual.Description | Should -Be $Expected.Description
                $Actual.Name | Should -Be $Expected.Name
                $Actual.Value | Should -Be $Expected.Value
            }
        }
    }
    Describe 'Test-MatrixSettingHC' {
        Context 'a FatalError object is created when' {
            $TestCases = @(
                $TestName = 'the column header ComputerName is missing'
                @{
                    TestName = $TestName
                    Setting  = [PSCustomObject]@{
                        #ComputerName='S1'
                        Path   = 'E:\Department'
                        Action = 'Fix'
                    }
                    Expected = [PSCustomObject]@{
                        Type        = 'FatalError'
                        Name        = 'Missing column header'
                        Description = "The column headers 'ComputerName', Path' and 'Action' are mandatory."
                        Value       = 'ComputerName'
                    }
                }

                $TestName = 'the column header Path is missing'
                @{
                    TestName = $TestName
                    Setting  = [PSCustomObject]@{
                        ComputerName = 'S1'
                        #Path='E:\Department'
                        Action       = 'New'
                    }
                    Expected = [PSCustomObject]@{
                        Type        = 'FatalError'
                        Name        = 'Missing column header'
                        Description = "The column headers 'ComputerName', Path' and 'Action' are mandatory."
                        Value       = 'Path'
                    }
                }

                $TestName = 'the column header Action is missing'
                @{
                    TestName = $TestName
                    Setting  = [PSCustomObject]@{
                        ComputerName = 'S1'
                        Path         = 'E:\Department'
                        #Action='Check'
                    }
                    Expected = [PSCustomObject]@{
                        Type        = 'FatalError'
                        Name        = 'Missing column header'
                        Description = "The column headers 'ComputerName', Path' and 'Action' are mandatory."
                        Value       = 'Action'
                    }
                }

                $TestName = 'the column headers Action, ComputerName and Path are missing'
                @{
                    TestName = $TestName
                    Setting  = [PSCustomObject]@{
                        Name = 'thing'
                        #ComputerName='S1'
                        #Path='E:\Department'
                        #Action='Check'
                    }
                    Expected = [PSCustomObject]@{
                        Type        = 'FatalError'
                        Name        = 'Missing column header'
                        Description = "The column headers 'ComputerName', Path' and 'Action' are mandatory."
                        Value       = @('ComputerName', 'Path', 'Action')
                    }
                }

                $TestName = 'the value for ComputerName is blank'
                @{
                    TestName = $TestName
                    Setting  = [PSCustomObject]@{
                        ComputerName = $null
                        Path         = 'E:\Department'
                        Action       = 'Check'
                    }
                    Expected = [PSCustomObject]@{
                        Type        = 'FatalError'
                        Name        = 'Missing value'
                        Description = "Values for 'ComputerName', Path' and 'Action' are mandatory."
                        Value       = 'ComputerName'
                    }
                }

                $TestName = 'the values for Action, ComputerName and Path are blank'
                @{
                    TestName = $TestName
                    Setting  = [PSCustomObject]@{
                        ComputerName = $null
                        Path         = $null
                        Action       = $null
                    }
                    Expected = [PSCustomObject]@{
                        Type        = 'FatalError'
                        Name        = 'Missing value'
                        Description = "Values for 'ComputerName', Path' and 'Action' are mandatory."
                        Value       = @('ComputerName', 'Path', 'Action')
                    }
                }

                $TestName = 'the value for Action can only be New, Fix or Check'
                @{
                    TestName = $TestName
                    Setting  = [PSCustomObject]@{
                        ComputerName = 'S1'
                        Path         = 'E:\Department'
                        Action       = 'Unknown'
                    }
                    Expected = [PSCustomObject]@{
                        Type        = 'FatalError'
                        Name        = 'Action value incorrect'
                        Description = "Only the values 'New', 'Fix' or 'Check' are supported in the field 'Action'."
                        Value       = 'Unknown'
                    }
                }

                $TestName = 'the value for Path can only be a local path'
                @{
                    TestName = $TestName
                    Setting  = [PSCustomObject]@{
                        ComputerName = 'S1'
                        Path         = '\\contoso.com\Department'
                        Action       = 'Check'
                    }
                    Expected = [PSCustomObject]@{
                        Type        = 'FatalError'
                        Name        = 'Path value incorrect'
                        Description = "The 'Path' needs to be defined as a local folder (Ex. 'E:\Department\Finance')."
                        Value       = '\\contoso.com\Department'
                    }
                }
            )

            It '<TestName>' -TestCases $TestCases {
                Param (
                    $Setting,
                    $Expected
                )

                $Actual = Test-MatrixSettingHC -Setting $Setting | Where-Object Name -EQ $Expected.Name

                $Actual.Type | Should -Be $Expected.Type
                $Actual.Description | Should -Be $Expected.Description
                $Actual.Name | Should -Be $Expected.Name
                $Actual.Value | Should -Be $Expected.Value
            }
        }
    }
    Describe 'Get-JobErrorHC' {
        BeforeEach {
            Get-Job | Remove-Job -Force
        }
        Context 'no ouptut is generated when' {
            It 'the job executed flawlessly' {
                $testInvokeParams = @{
                    ScriptBlock  = { 1 }
                    ComputerName = 'localhost'
                    AsJob        = $true
                }

                $job = Invoke-Command  @testInvokeParams
                Wait-Job -Job $job

                Get-JobErrorHC -Job $job | Should -BeNullOrEmpty
            }
        }
        Context 'a FatalError object is created when' {
            It "the ComputerName is offline or doesn't exist" {
                $testInvokeParams = @{
                    ScriptBlock  = { 1 }
                    ComputerName = 'unknown'
                    AsJob        = $true
                }

                $job = Invoke-Command  @testInvokeParams
                Wait-Job -Job $job

                $Actual = Get-JobErrorHC -Job $job

                $Actual.Type | Should -Be 'FatalError'
                $Actual.Name | Should -Be 'Connection error'
            }
            It 'a terminating error occured in the job' {
                $testInvokeParams = @{
                    ScriptBlock  = { throw 'Shit' }
                    ComputerName = 'localhost'
                    AsJob        = $true
                }

                $job = Invoke-Command  @testInvokeParams
                Wait-Job -Job $job

                $Actual = Get-JobErrorHC -Job $job

                $Actual.Type | Should -Be 'FatalError'
                $Actual.Name | Should -Be 'Terminating error'
            }
            It 'a non terminating error in the job' {
                $testInvokeParams = @{
                    ScriptBlock  = { Write-Error 'Oops' }
                    ComputerName = 'localhost'
                    AsJob        = $true
                }

                $job = Invoke-Command  @testInvokeParams
                Wait-Job -Job $job

                $Actual = Get-JobErrorHC -Job $job

                $Actual.Type | Should -Be 'FatalError'
                $Actual.Name | Should -Be 'Non terminating error'
            }
        }
    }
}