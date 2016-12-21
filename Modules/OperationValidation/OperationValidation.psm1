#Region ObjectHelpers
function New-OperationValidationFailure
{
    param (
        [Parameter(Mandatory=$true)][string]$StackTrace,
        [Parameter(Mandatory=$true)][string]$FailureMessage
    )
    $o = [pscustomobject]@{
        StackTrace = $StackTrace
        FailureMessage = $FailureMessage
        }
    $o.psobject.Typenames.Insert(0,"OperationValidationFailure")
    $ToString = { return $this.StackTrace }
    Add-Member -inputobject $o -membertype ScriptMethod -Name ToString -Value $toString -Force
    $o
}
function New-OperationValidationResult
{
    param (
        [Parameter(Mandatory=$true)][string]$Module,
        [Parameter(Mandatory=$true)][string]$FileName,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Result,
        [Parameter()][object]$RawResult,
        [Parameter()][object]$Error
    )
    $o = new-object -TypeName pscustomobject
    Add-Member -InputObject $o -MemberType NoteProperty -Name Module -Value $Module
    Add-Member -InputObject $o -MemberType NoteProperty -Name FileName -Value $FileName
    Add-Member -InputObject $o -MemberType NoteProperty -Name ShortName -Value ([io.path]::GetFileName($FileName))
    Add-Member -InputObject $o -MemberType NoteProperty -Name Name -Value $Name
    Add-Member -InputObject $o -MemberType NoteProperty -Name Result -Value $Result
    Add-Member -InputObject $o -MemberType NoteProperty -Name Error -Value $Error
    Add-Member -InputObject $o -MemberType NoteProperty -Name RawResult -Value $RawResult
    $o.psobject.Typenames.Insert(0,"OperationValidationResult")
    $ToString = { return ("{0} ({1}): {2}" -f $this.Module, $this.FileName, $this.Name) }
    Add-Member -inputobject $o -membertype ScriptMethod -Name ToString -Value $toString -Force
    $o
}
function new-OperationValidationInfo
{
    param (
        [Parameter(Mandatory=$true)][string]$File,
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter(Mandatory=$true)][string[]]$Name,
        [Parameter()][string[]]$TestCases,
        [Parameter(Mandatory=$true)][ValidateSet("None","Simple","Comprehensive")][string]$Type,
        [Parameter()][string]$Modulename,
        [Parameter()][string[]]$Tags,
        [Parameter()][Version]$Version,
        [Parameter()][hashtable]$Parameters
        )
    $o = [pscustomobject]@{
        File = $File
        FilePath = $FilePath
        Name = $Name
        TestCases = $testCases
        Type = $type
        ModuleName = $Modulename
        Tags = $Tags
        Version = $Version
        ScriptParameters = $Parameters
    }
    $o.psobject.Typenames.Insert(0,"OperationValidationInfo")
    $ToString = { return ("{0} ({1}): {2}" -f $this.testFile, $this.Type, ($this.TestCases -join ",")) }
    Add-Member -inputobject $o -membertype ScriptMethod -Name ToString -Value $toString -Force
    $o
}
# endregion

function Get-TestFromScript
{
    param (
        [parameter(Mandatory)]
        [string]$ScriptPath
    )

    $text = Get-Content -Path $ScriptPath -Raw
    $tokens = $null
    $errors = $null
    $describes = [Management.Automation.Language.Parser]::ParseInput($text, [ref]$tokens, [ref]$errors).
       FindAll([Func[Management.Automation.Language.Ast,bool]]{
            param ($ast)
            $ast.CommandElements -and
            $ast.CommandElements[0].Value -eq 'describe'
        }, $true) |
        ForEach-Object {
            $CE = $_.CommandElements

            # This is the name of the 'describe' block
            $secondString = ($CE | where { $_.StaticType.name -eq 'string' })[1].SafeGetValue()

            $item = [PSCustomObject][ordered]@{
                Name = $secondString
                Tags = @()
            }

            # Get any tags defined
            $tagIdx = $CE.IndexOf(($CE | where ParameterName -eq 'Tag')) + 1
            if ($tagIdx -and $tagIdx -lt $CE.Count) {
                $tagExtent = $CE[$tagIdx].Extent

                $tagAST = [System.Management.Automation.Language.Parser]::ParseInput($tagExtent, [ref]$null, [ref]$null)

                # Try to get the tags as an array
                $tagElements = $tagAST.FindAll({$args[0] -is [System.Management.Automation.Language.ArrayLiteralAst]}, $true)
                if ($tagElements) {
                    $item.Tags = $tagElements.SafeGetValue()
                } else {
                    # Try to get the tag as a string
                    $tagElements = $tagAST.FindAll({$args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]}, $true)
                    if ($tagElements) {
                        $item.Tags = @($tagElements.SafeGetValue())
                    }
                }
            }
            $item
        }
    $describes
}
<#
.SYNOPSIS
Retrieve the operational tests from modules

.DESCRIPTION
Modules which include a Diagnostics directory are inspected for
Pester tests in either the "Simple" or "Comprehensive" directories.
If files are found in those directories, they will be inspected to determine
whether they are Pester tests. If Pester tests are found, the
test names in those files will be returned.

The module structure required is as follows:

ModuleBase\
    Diagnostics\
        Simple         # simple tests are held in this location
                         (e.g., ping, serviceendpoint checks)
        Comprehensive  # comprehensive scenario tests should be placed here

.PARAMETER ModuleName
By default this is * which will retrieve all modules in $env:psmodulepath
Additional module directories may be added. If you wish to check both
$env:psmodulepath and your own specific locations, use
*,<yourmodulepath>

.PARAMETER TestType
The type of tests to retrieve, this may be either "Simple", "Comprehensive"
or Both ("Simple,Comprehensive"). "Simple,Comprehensive" is the default.

.PARAMETER Version
The version of the module to retrieve. If the specified, the latest version
of the module will be retured.

.PARAMETER Tag
Executes tests with specified tag parameter values. Wildcard characters and tag values that include spaces
or whitespace characters are not supported.

When you specify multiple tag values, Get-OperationValidation executes tests that have any of the
listed tags. If you use both Tag and ExcludeTag, ExcludeTag takes precedence.

.PARAMETER ExcludeTag
Omits tests with the specified tag parameter values. Wildcard characters and tag values that include spaces
or whitespace characters are not supported.

When you specify multiple ExcludeTag values, Get-OperationValidation omits tests that have any
of the listed tags. If you use both Tag and ExcludeTag, ExcludeTag takes precedence.

.EXAMPLE
PS> Get-OperationValidation -ModuleName C:\temp\modules\AddNumbers

    Type:         Simple
    File:     addnum.tests.ps1
    FilePath: C:\temp\modules\AddNumbers\Diagnostics\Simple\addnum.tests.ps1
    Name:
        Add-Em
        Subtract em
        Add-Numbers
    Type:         Comprehensive
    File:     Comp.Adding.Tests.ps1
    FilePath: C:\temp\modules\AddNumbers\Diagnostics\Comprehensive\Comp.Adding.Tests.ps1
    Name:
        Comprehensive Adding Tests
        Comprehensive Subtracting Tests
        Comprehensive Examples

.LINK
Invoke-OperationValidation

#>
function Get-OperationValidation
{
[CmdletBinding()]
param (
    [Parameter(Position=0)][string[]]$ModuleName = "*",
    [Parameter()][ValidateSet("Simple","Comprehensive")][string[]]$TestType =  @("Simple","Comprehensive"),
    [Parameter()][Version]$Version,
    [Parameter()][string[]]$Tag,
    [Parameter()][string[]]$ExcludeTag
    )

    BEGIN
    {
        function Get-TestName ( $ast )
        {
            for($i = 1; $i -lt $ast.Parent.CommandElements.Count; $i++)
            {
                if ( $ast.Parent.CommandElements[$i] -is "System.Management.Automation.Language.CommandParameterAst") { $i++; continue }
                if ( $ast.Parent.CommandElements[$i] -is "System.Management.Automation.Language.ScriptBlockExpressionAst" ) { continue }
                if ( $ast.Parent.CommandElements[$i] -is "System.Management.Automation.Language.StringConstantExpressionAst" ) { return $ast.Parent.CommandElements[$i].Value }
            }
            throw "Could not determine test name"
        }
        function Get-TestFromAst ( $ast )
        {
            $eb = $ast.EndBlock
            foreach($statement in $eb.Statements)
            {
                if ( $statement -isnot "System.Management.Automation.Language.PipelineAst" )
                {
                    continue
                }
                $CommandAst = $statement.PipelineElements[0].CommandElements[0]

                if (  $CommandAst.Value -eq "Describe" )
                {
                    Get-TestName $CommandAst
                }
            }
        }
        function Get-TestCaseNamesFromAst ( $ast )
        {
            $eb = $ast.EndBlock
            foreach($statement in $eb.Statements)
            {
                if ( $statement -isnot "System.Management.Automation.Language.PipelineAst" )
                {
                    continue
                }
                $CommandAst = $statement.PipelineElements[0].CommandElements[0]

                if (  $CommandAst.Value -eq "It" )
                {
                    Get-TestName $CommandAst
                }
            }
        }
        function Get-ModuleList
        {
            param (
                [string[]]$Name,
                [version]$Version
            )
            foreach($p in $env:psmodulepath.split(";"))
            {
                if ( test-path -path $p )
                {
                    foreach($modDir in get-childitem -path $p -directory)
                    {
                        foreach ($n in $name )
                        {
                            if ( $modDir.Name -like $n )
                            {
                                # now determine if there's a diagnostics directory, or a version
                                if ( test-path -path ($modDir.FullName + "\Diagnostics"))
                                {
                                    # Did we specify a specific version to find?
                                    if ($PSBoundParameters.ContainsKey('Version'))
                                    {
                                        $manifestFile = Get-ChildItem -Path $modDir.FullName -Filter "$modDir.psd1" | Select-Object -First 1
                                        $manifest = Test-ModuleManifest -Path $manifestFile.FullName
                                        if ($manifest.Version -eq $Version)
                                        {
                                            $modDir.FullName
                                            break
                                        }
                                    }
                                    else
                                    {
                                        $modDir.FullName
                                        break
                                    }
                                }

                                # Get latest version if no specific version specified
                                if ($PSBoundParameters.ContainsKey('Version'))
                                {
                                    $versionDirectories = Get-Childitem -Path $modDir.FullName -Directory |
                                        where-object { $_.name -as [version] -and $_.Name -eq $Version }
                                }
                                else
                                {
                                    $versionDirectories = Get-Childitem -Path $modDir.FullName -Directory |
                                        where-object { $_.name -as [version] }
                                }

                                $potentialDiagnostics = $versionDirectories | Where-Object {
                                    test-path ($_.fullname + "\Diagnostics")
                                    }
                                # now select the most recent module path which has diagnostics
                                $DiagnosticDir = $potentialDiagnostics |
                                    sort-object {$_.name -as [version]} |
                                    Select-Object -Last 1
                                if ( $DiagnosticDir )
                                {
                                    $DiagnosticDir.FullName
                                    break
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    PROCESS
    {
        Write-Progress -Activity 'Inspecting Modules' -Status ' '
        if ($PSBoundParameters.ContainsKey('Version'))
        {
            $moduleCollection = Get-ModuleList -Name $ModuleName -Version $Version
        }
        else
        {
            $moduleCollection = Get-ModuleList -Name $ModuleName
        }

        $count = 1
        $moduleCount = @($moduleCollection).Count
        foreach($modulePath in $moduleCollection)
        {
            Write-Progress -Activity ("Searching for Diagnostics in $modulePath") -PercentComplete ($count++/$moduleCount*100) -status ' '

            # Get the module manifest so we can pull out the version
            $modName = Split-Path -Path $modulePath -Leaf
            $versionedMod = $false
            if ($modName -as [version]) {
                $versionedMod = $true
                # We may be in a 'version' directory so get the actual module name from the parent directory
                $parentPath = Split-Path -Path $modulePath -Parent
                write-verbose "looking in parent path $parentPath"
                $modName = Split-Path -Path $parentPath -Leaf
            }

            Write-Verbose $modName

            $manifestFile = Get-ChildItem -Path $modulePath -Filter "$modName.psd1"
            $manifest = $null
            if ($manifestFile)
            {
                $manifest = Test-ModuleManifest -Path $manifestFile.FullName -Verbose:$false
            }
            # else
            # {

            #     # We may be in a 'version' directory so get the actual module name from the parent directory
            #     $parentPath = Split-Path -Path $modulePath -Parent
            #     write-verbose "looking in parent path $parentPath"
            #     $modName = Split-Path -Path $parentPath -Leaf
            #     $manifestFile = Get-ChildItem -Path $parentPath -Filter "$modName.psd1"
            #     if ($manifestFile)
            #     {
            #         $manifest = Test-ModuleManifest -Path $manifestFile.FullName -Verbose:$false
            #     }
            #     else {
            #         write-warning "couldn't file manifest $parentPath\$modName.psd1)"
            #     }
            # }

            $diagnosticsDir = Join-Path -Path $modulePath -ChildPath 'Diagnostics'
            if ( Test-Path -Path $diagnosticsDir )
            {
                foreach($dir in $testType)
                {
                    $testDir = Join-Path -Path $diagnosticsDir -ChildPath $dir
                    Write-Verbose -Message "TEST DIR: $testDir"
                    if ( -not (Test-Path -path $testDir) )
                    {
                        continue
                    }
                    foreach($file in Get-ChildItem -Path $testDir -Filter *.tests.ps1)
                    {
                        Write-Verbose -Message "PESTER TEST: $($file.fullname)"

                        # Pull out parameters to Pester script if they exist
                        $script = Get-Command -Name $file.fullname
                        $parameters = $script.Parameters
                        if ($parameters.Keys.Count -gt 0)
                        {
                            Write-Debug -Message 'Test script has overrideable parameters'
                            Write-Debug -Message "`n$($parameters.Keys | Out-String)"
                        }

                        $tests = @(Get-TestFromScript -ScriptPath $file.FullName)
                        foreach ($test in $tests)
                        {
                            # Only return tests that match the tag filter(s)
                            if ($Tag -and @(Compare-Object -ReferenceObject $Tag -DifferenceObject $test.Tags -IncludeEqual -ExcludeDifferent).count -eq 0) { continue }
                            if ($ExcludeTag -and @(Compare-Object -ReferenceObject $ExcludeTag -DifferenceObject $test.Tags -IncludeEqual -ExcludeDifferent).count -gt 0) { continue }

                            $modInfoParams = @{
                                FilePath = $file.Fullname
                                File = $file.Name
                                Type = $dir
                                Name = $test.Name
                                ModuleName =  $modulePath
                                Tags = $test.Tags
                                Version = if ($manifest) { [version]$manifest.Version } else { $null }
                                Parameters = $parameters
                            }
                            New-OperationValidationInfo @modInfoParams
                        }
                    }
                }
            }
        }
    }
}

<#
.SYNOPSIS
Invoke the operational tests from modules

.DESCRIPTION
Modules which include Diagnostics tests are executed via this cmdlet

.PARAMETER TestFilePath
The path to a diagnostic test to execute. By default all discoverable diagnostics will be invoked

.PARAMETER TestInfo
The type of tests to invoke, this may be either "Simple", "Comprehensive"
or Both ("Simple,Comprehensive"). "Simple,Comprehensive" is the default.

.PARAMETER ModuleName
By default this is * which will retrieve and execute all OVF modules in $env:psmodulepath
Additional module directories may be added. If you wish to check both
$env:psmodulepath and your own specific locations, use
*,<yourmodulepath>

.PARAMETER TestType
The type of tests to execute, this may be either "Simple", "Comprehensive"
or Both ("Simple,Comprehensive"). "Simple,Comprehensive" is the default.

.PARAMETER IncludePesterOutput
Include the Pester output when execute the tests.

.PARAMETER Version
The version of the module to retrieve. If the specified, the latest version
of the module will be retured.

.PARAMETER Overrides
If the Pester test(s) include script parameters, those parameters can be overridden by
specifying a hashtable of values. The key(s) in the hashtable must match the parameter
names in the Pester test.

For example, if the Pester test includes a parameter block like the following, one or more of
these parameters can be overriden using values from the hashtable passed to the -Overrides parameter.

Pester test script:
param(
    [int]$SomeValue = 100
    [bool]$ExtraChecks = $false
)

Overrides the default parameter values:
Invoke-OperationValidation -ModuleName MyModule -Overrides @{ SomeValue = 500; ExtraChecks = $true }

.PARAMETER Tag
Executes tests with specified tag parameter values. Wildcard characters and tag values that include spaces
or whitespace characters are not supported.

When you specify multiple tag values, Invoke-OperationValidation executes tests that have any of the
listed tags. If you use both Tag and ExcludeTag, ExcludeTag takes precedence.

.PARAMETER ExcludeTag
Omits tests with the specified tag parameter values. Wildcard characters and tag values that include spaces
or whitespace characters are not supported.

When you specify multiple ExcludeTag values, Get-OperationValidation omits tests that have any
of the listed tags. If you use both Tag and ExcludeTag, ExcludeTag takes precedence.

.EXAMPLE
PS> Get-OperationValidation -ModuleName OperationValidation | Invoke-OperationValidation -IncludePesterOutput
Describing Simple Test Suite
 [+] first Operational test 20ms
 [+] second Operational test 19ms
 [+] third Operational test 9ms
Tests completed in 48ms
Passed: 3 Failed: 0 Skipped: 0 Pending: 0
Describing Scenario targeted tests
   Context The RemoteAccess service
    [+] The service is running 37ms
   Context The Firewall Rules
    [+] A rule for TCP port 3389 is enabled 1.19s
    [+] A rule for UDP port 3389 is enabled 11ms
Tests completed in 1.24s
Passed: 3 Failed: 0 Skipped: 0 Pending: 0


   Module: OperationValidation

Result  Name
------- --------
Passed  Simple Test Suite::first Operational test
Passed  Simple Test Suite::second Operational test
Passed  Simple Test Suite::third Operational test
Passed  Scenario targeted tests:The RemoteAccess service:The service is running
Passed  Scenario targeted tests:The Firewall Rules:A rule for TCP port 3389 is enabled
Passed  Scenario targeted tests:The Firewall Rules:A rule for UDP port 3389 is enabled

.LINK
Get-OperationValidation
#>
function Invoke-OperationValidation
{
    [CmdletBinding(SupportsShouldProcess=$true,DefaultParameterSetName="FileAndTest")]
    param (
        [Parameter(ParameterSetName="Path",ValueFromPipelineByPropertyName=$true)][string[]]$TestFilePath,
        [Parameter(ParameterSetName="FileAndTest",ValueFromPipeline=$true)][pscustomobject[]]$TestInfo,
        [Parameter(ParameterSetName="UseGetOperationTest")][string[]]$ModuleName = "*",
        [Parameter(ParameterSetName="UseGetOperationTest")]
        [ValidateSet("Simple","Comprehensive")][string[]]$TestType = @("Simple","Comprehensive"),
        [Parameter()][switch]$IncludePesterOutput,
        [Parameter(ParameterSetName="UseGetOperationTest")]
        [Parameter()][Version]$Version,
        [Parameter(ParameterSetName="FileAndTest")]
        [Parameter(ParameterSetName="UseGetOperationTest")]
        [Parameter()][hashtable]$Overrides,
        [Parameter()][string[]]$Tag,
        [Parameter()][string[]]$ExcludeTag
        )
    BEGIN
    {
        $quiet = ! $IncludePesterOutput
        if ( ! (get-module -Name Pester))
        {
            if ( get-module -list Pester )
            {
                import-module -Name Pester
            }
            else
            {
                Throw "Cannot load Pester module"
            }
        }
    }
    PROCESS
    {
        if ( $PSCmdlet.ParameterSetName -eq "UseGetOperationTest" )
        {
            if ($PSBoundParameters.ContainsKey('Version'))
            {
                $TestInfo = Get-OperationValidation -ModuleName $ModuleName -TestType $TestType -Version $Version
            }
            else
            {
                $TestInfo = Get-OperationValidation -ModuleName $ModuleName -TestType $TestType
            }
        }

        if ( $null -ne $testInfo )
        {
            # first check to be sure all of the TestInfos are sane
            foreach($ti in $testinfo)
            {
                if ( ! ($ti.FilePath -and $ti.Name))
                {
                    throw "TestInfo must contain the path and the list of tests"
                }
            }

            # first check to be sure all of the TestInfos are sane
            foreach($ti in $testinfo)
            {
                if ( ! ($ti.FilePath -and $ti.Name))
                {
                    throw "TestInfo must contain the path and the list of tests"
                }
            }

            Write-Verbose -Message ("EXECUTING: {0} [{1}]" -f $ti.FilePath,($ti.Name -join ","))
            foreach($ti in $testinfo)
            {
                $pesterParams = @{
                    TestName = $ti.Name
                    Quiet = $quiet
                    PassThru = $true
                    Verbose = $false
                }

                if ($ti.ScriptParameters)
                {
                    Write-Verbose -Message 'Test has script parameters'
                    if ($PSBoundParameters.ContainsKey('Overrides'))
                    {
                        Write-Verbose -Message "Overriding with parameters:`n$($Overrides | Format-Table -Property Key, Value | Out-String)"
                        $pesterParams.Script = @{
                            Path = $ti.FilePath
                            Parameters = $Overrides
                        }
                    }
                    else
                    {
                        Write-Verbose -Message 'Using default parameters for test'
                        $pesterParams.Path = $ti.FilePath
                    }
                }
                else
                {
                    $pesterParams.Path = $ti.FilePath
                }

                if ($PSBoundParameters.ContainsKey('Tag'))
                {
                    $pesterParams.Tag = $Tag
                }

                if ($PSBoundParameters.ContainsKey('ExcludeTag'))
                {
                    $pesterParams.ExcludeTag = $ExcludeTag
                }

                if ( $PSCmdlet.ShouldProcess("$($ti.Name) [$($ti.FilePath)]"))
                {
                    $testResult = Invoke-Pester @pesterParams
                    if ($testResult)
                    {
                        Add-member -InputObject $testResult -MemberType NoteProperty -Name Path -Value $ti.FilePath
                        Convert-TestResult $testResult
                    }
                }
            }
            return
        }

        if ($TestFilePath)
        {
            foreach($filePath in $TestFilePath) {
                write-progress -Activity "Invoking tests in $filePath"
                if ( $PSCmdlet.ShouldProcess($filePath)) {
                    $testResult = Invoke-Pester $filePath -passthru -quiet:$quiet
                    Add-Member -InputObject $testResult -MemberType NoteProperty -Name Path -Value $filePath
                    Convert-TestResult $testResult
                }
            }
        }
    }
}

# emit an object which can be used in reporting
Function Convert-TestResult
{
    param ( $result )
    foreach ( $testResult in $result.TestResult )
    {
        $testError = $null
        if ( $testResult.Result -eq "Failed" )
        {
            Write-Verbose -message "Creating error object"
            $testError = new-OperationValidationFailure -Stacktrace $testResult.StackTrace -FailureMessage $testResult.FailureMessage
        }
        $Module = $result.Path.split([io.path]::DirectorySeparatorChar)[-4]
        $TestName = "{0}:{1}:{2}" -f $testResult.Describe,$testResult.Context,$testResult.Name
        New-OperationValidationResult -Module $Module -Name $TestName -FileName $result.path -Result $testresult.result -RawResult $testResult -Error $TestError
    }

}
