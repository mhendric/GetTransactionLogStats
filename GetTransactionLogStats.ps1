<#PSScriptInfo

.VERSION 3.0

.GUID e511b38d-e70e-453d-93a1-9bfbda10f263

.AUTHOR Mike Hendrickson

#>

<#
.NAME:
 GetTransactionLogStats.ps1

.SYNOPSIS
 Used to collect and analyze Exchange transaction log generation statistics.
 Designed to be run as an hourly scheduled task, on the top of each hour.
 Can be run against one or more servers and databases.

.PARAMETER Gather
 Switch specifying we want to capture current log generations.
 If this switch is omitted, the -Analyze switch must be used.

.PARAMETER Analyze
 Switch specifying we want to analyze already captured data.
 If this switch is omitted, the -Gather switch must be used.

.PARAMETER ResetStats
 Switch indicating that the output file, LogStats.csv, should
 be cleared and reset. Only works if combined with –Gather.

.PARAMETER WorkingDirectory
 The directory containing TargetServers.txt and LogStats.csv.
 If omitted, the working directory will be the current working
 directory of PowerShell (not necessarily the directory the
 script is in).

.PARAMETER LogDirectoryOut
 The directory to send the output log files from running in
 Analyze mode to. If omitted, logs will be sent to WorkingDirectory.

.EXAMPLE
PS> .\GetTransactionLogStats.ps1 -Gather

.EXAMPLE
PS> .\GetTransactionLogStats.ps1 -Gather -WorkingDirectory "C:\GetTransactionLogStats" -ResetStats

.EXAMPLE
PS> .\GetTransactionLogStats.ps1 -Analyze

.EXAMPLE
PS> .\GetTransactionLogStats.ps1 -Analyze -DontAnalyzeInactiveDatabases `$true

.EXAMPLE
PS> .\GetTransactionLogStats.ps1 -Analyze -LogDirectoryOut "C:\GetTransactionLogStats\LogsOut"

#>

[CmdletBinding()]
param(
	[Switch]
    $Gather,

	[Switch]
    $Analyze,

	[Switch]
    $ResetStats,

	[String]
    $WorkingDirectory = "",

	[String]
    $LogDirectoryOut = ""
)

#Function used to take a snapshot of the current log generation on all configured databases locally on the server.
#This function is intended to be used with Invoke-Command and executed on remote systems.
function Get-LogGenerationsLocal
{
	[CmdletBinding()]
	[OutputType([Object[]])]
    param
    (
        [String[]]
        $Databases
    )

	#Return value contains an array of PSObjects containing log gen stats
    $logGenStats = New-Object System.Collections.Generic.List[System.Object]

    #First determine what the Exchange Version that is being monitored
    $exVersion = 0

    if ($null -ne (Get-Item REGISTRY::HKLM\Software\Microsoft\ExchangeServer\v15 -ErrorAction SilentlyContinue))
    {
        $exVersion = 2013
    }
    elseif ($null -ne (Get-Item REGISTRY::HKLM\Software\Microsoft\ExchangeServer\v14 -ErrorAction SilentlyContinue))
    {
        $exVersion = 2010
    }

    if ($exVersion -lt 2010)
    {
        throw "Exchange Server running an unsupported version. This script requires Exchange 2010 or higher."
    }

    #Get the list of counters for the server. Try 2013 first, if configured.
    if ($exVersion -ge 2013)
    {
        $targetCounterCommand = "(Get-Counter -ListSet `"MSExchangeIS HA Active Database`" -ErrorAction SilentlyContinue).PathsWithInstances | where {`$_ -like '*Current Log Generation Number*' -and `$_ -notlike '*_total*'}"
    }
    else
    {
        $targetCounterCommand = "(Get-Counter -ListSet `"MSExchange Database ==> Instances`" -ErrorAction SilentlyContinue).PathsWithInstances | where {`$_ -like '*Information Store*Log File Current Generation*' -and `$_ -notlike '*Information Store/_Total*' -and `$_ -notlike '*Information Store/Base instance to*'}"
    }
                
    #DB's were specified for this server. Filter on them
    if ($Databases.Count -gt 0)
    {
        $dbFilterString = " -and (`$_ -like '*$($Databases[0])*'"  
                    
        for ($i = 1; $i -lt $Databases.Count; $i++)
        {
            $dbFilterString += " -or `$_ -like '*$($Databases[$i])*'"                                
        }
                    
        $targetCounterCommand = $targetCounterCommand.Replace("}", $dbFilterString + ")}")
    }
   
    #Invoke the command and get the counter names of databases we want
    $targetCounters = Invoke-Command -ScriptBlock ([ScriptBlock]::Create($targetCounterCommand))

    if ($null -ne $targetCounters)
    {
        #Process each counter in the list
        foreach ($counterName in $targetCounters)
        {
            #Parse out the database name from the current counter
            if ($exVersion -ge 2013)
            {
                $dbNameStartIndex = $counterName.IndexOf("MSExchangeIS HA Active Database(") + "MSExchangeIS HA Active Database(".Length                            
            }
            else 
            {
                $dbNameStartIndex = $counterName.IndexOf("Instances(Information Store/") + "Instances(Information Store/".Length
            }
                        
            $dbNameEndIndex =  $counterName.IndexOf(")", $dbNameStartIndex)
            $dbName = $counterName.SubString($dbNameStartIndex, $dbNameEndIndex - $dbNameStartIndex)
                
            #Get the counter's value
            $counter = Get-Counter "$($counterName)" -ErrorAction SilentlyContinue
                        
            if ($null -ne $counter)
            {
                $logGenStats.Add((New-Object PSObject -Property @{DatabaseName=$dbName;ServerName=$env:COMPUTERNAME;LogGeneration=$counter.CounterSamples[0].RawValue;TimeCollected=[DateTime]::Now}))
            }
            else
            {
                Write-Error "[$([DateTime]::Now)] Failed to read perfmon counter from server $($serverName)"
            }
        }
    }
    else
    {
        Write-Error "[$([DateTime]::Now)] Failed to get perfmon counters from server $($serverName)"
    }
    
    return $logGenStats
}

#Function used to remotely initiate a local stat collection on all configured servers and databases.
function Get-LogGenerationsRemote
{
	[CmdletBinding()]
	param
    (
        [parameter(Mandatory = $true)]
        [Object[]]
        $CollectionTargets,

        [parameter(Mandatory = $true)]
        [String]
        $WorkingDirectory
    )

    #Used to store all remote collection jobs that have been initiated
    [System.Management.Automation.Job[]]$allJobs = @()

    Write-Verbose "[$([DateTime]::Now)] Sending log generation collection job to $($CollectionTargets.Count) servers."

    foreach ($target in $CollectionTargets)
    {
        $wsManTest = $null
        $wsManTest = Test-WSMan -ComputerName $target.Server -ErrorAction SilentlyContinue

        if ($null -eq $wsManTest)
        {
            Write-Warning "[$([DateTime]::Now)] Failed to establish Remote PowerShell session to computer '$($target.Server)'. To enable PowerShell Remoting, use Enable-PSRemoting, or 'winrm quickconfig' on the server to be configured. No databases on this server will be processed."
            continue
        }

        $job = Invoke-Command -ComputerName $target.Server -ScriptBlock ${function:Get-LogGenerationsLocal} -ArgumentList $target.Databases -AsJob
        $allJobs += $job
    }
        
    if ($allJobs.Count -gt 0)
    {          
        Write-Verbose "[$([DateTime]::Now)] Waiting for remote collections to finish."

        Wait-Job $allJobs | Out-Null
        $logGenerations = Receive-Job $allJobs

        if ($null -ne $logGenerations)
        {
            Write-Verbose "[$([DateTime]::Now)] Saving results to disk."

            $logPath = Join-Path $WorkingDirectory "LogStats.csv"
            
            #The log file hasn't been created yet, or a reset was request, so add a header first
            if ($ResetStats -eq $true -or !(Test-Path -LiteralPath $logPath))
            {
                $logGenerations | Select-Object -Property DatabaseName, ServerName, LogGeneration, TimeCollected | Sort-Object -Property DatabaseName, ServerName | Export-Csv -Path $logPath -NoTypeInformation
            }
            else
            {
                if ((Get-Command Export-Csv).Parameters.Keys.Contains("Append"))
                {
                    $logGenerations | Select-Object -Property DatabaseName, ServerName, LogGeneration, TimeCollected | Sort-Object -Property DatabaseName, ServerName | Export-Csv -Path $logPath -NoTypeInformation -Append 
                }
                else #Maintain support for PowerShell 2, which doesn't have -Append
                {
                    "DatabaseName,ServerName,LogGeneration,TimeCollected" | Out-File -FilePath $logPath -Encoding ASCII

                    foreach ($sample in $logGenerations)
                    {
                        "$($sample.Database),$($sample.Server),$($sample.LogGeneration),$($sample.TimeCollected)" | Out-File -FilePath $logPath -Append -Encoding ASCII
                    }
                }
            }                

            Write-Verbose "[$([DateTime]::Now)] Finished saving results to disk."    
        }
        else
        {
            Write-Warning "[$([DateTime]::Now)] No log generations collected."
        }
    }
    else
    {
        Write-Error "[$([DateTime]::Now)] No servers in TargetServers.txt were reachable via Remote PowerShell. No logs will be processed."
    }
}

#Checks whether a string contains a character that is not allowed in a database or server name.
function Test-BadCharactersInString
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
	param
    (
        [String]
        $TestString
    )

    foreach ($char in @("~","``","!","@","#","$","%","^","&","*","(",")","_","+","=","{","}","|","[","]","\",":","`"",";","'","<",">",",",".","?","/","}"))
    {
        if ($TestString.Contains($char))
        {
            return $true
        }
    }

    return $false
}

#Reads TargetServers.txt, and returns an array of Servers, plus their Databases (if specified)
function Get-TargetsForCollection
{
	[CmdletBinding()]
    [OutputType([System.Object[]])]
	param
    (
        [String]
        $WorkingDirectory
    )
    
    $collectionTargets = @()

    #Read our input file of servers and databases
    $targetServersPath = Join-Path $WorkingDirectory "TargetServers.txt"
    
    [String[]]$targetServers = Get-Content -Path $targetServersPath -ErrorAction SilentlyContinue | Where-Object {$_.Trim().Length -gt 0 -and (Test-BadCharactersInString -TestString $_) -eq $false}

    if ($null -ne $targetServers -and $targetServers.Count -gt 0)
    {
        foreach ($serverDBPair in $targetServers)
        {
            $databases = @()

            if (($serverDBPair.Contains(",")) -eq $false)
            {
                $server = $serverDBPair
            }
            else
            {
                [String[]]$serverDBParts = $serverDBPair.Split(",").Trim()

                $server = $serverDBParts[0]

                for ($i = 1; $i -lt $serverDBParts.Count; $i++)
                {
                    $databases += $serverDBParts[$i]
                }
            }

            $collectionTargets += (New-Object PSObject -Property @{Server=$server;Databases=$databases})
        }
    }

    return $collectionTargets
}

#Function used to Analyze log files which were captured in Gather mode
function Get-LogAnalysis
{
	[CmdletBinding()]
	param
    (
	    [String]
        $LogDirectoryOut
    )

    #Get the UI culture for proper DateTime parsing (credit Thomas Stensitzki)
    $uiCulture = Get-UICulture

    $inputLogPath = Join-Path $WorkingDirectory "LogStats.csv"

    Write-Verbose "[$([DateTime]::Now)] Attempting to read: $inputLogPath"

    $logStats = Import-Csv -Path "$($inputLogPath)"

    if ($null -eq $logStats)
    {
        Write-Error "[$([DateTime]::Now)] Failed to read LogStats.csv at: $inputLogPath. Exiting script."
        return
    }
    
    Write-Verbose "[$([DateTime]::Now)] Grouping $($logStats.Count) samples by database."

    $groupedByDB = $logStats | Group-Object -Property DatabaseName
    $databases = New-Object System.Collections.Generic.List[System.String]
    $dbCount = $groupedByDB.Count

    Write-Verbose "[$([DateTime]::Now)] Processing samples from $dbCount databases."

    #Setup hashtables for keeping track of various totals
    [UInt64]$totalLogsGenerated = 0
    $totalLogsGeneratedByDB = @{}
    $totalHoursByDB = @{}
    $totalLogsGeneratedByHour = @{[Int32]0=[UInt64]0;[Int32]1=[UInt64]0;[Int32]2=[UInt64]0;[Int32]3=[UInt64]0;[Int32]4=[UInt64]0;[Int32]5=[UInt64]0;[Int32]6=[UInt64]0;[Int32]7=[UInt64]0;[Int32]8=[UInt64]0;[Int32]9=[UInt64]0;[Int32]10=[UInt64]0;[Int32]11=[UInt64]0;[Int32]12=[UInt64]0;[Int32]13=[UInt64]0;[Int32]14=[UInt64]0;[Int32]15=[UInt64]0;[Int32]16=[UInt64]0;[Int32]17=[UInt64]0;[Int32]18=[UInt64]0;[Int32]19=[UInt64]0;[Int32]20=[UInt64]0;[Int32]21=[UInt64]0;[Int32]22=[UInt64]0;[Int32]23=[UInt64]0}
    $totalSamplesByHour = @{[Int32]0=[UInt64]0;[Int32]1=[UInt64]0;[Int32]2=[UInt64]0;[Int32]3=[UInt64]0;[Int32]4=[UInt64]0;[Int32]5=[UInt64]0;[Int32]6=[UInt64]0;[Int32]7=[UInt64]0;[Int32]8=[UInt64]0;[Int32]9=[UInt64]0;[Int32]10=[UInt64]0;[Int32]11=[UInt64]0;[Int32]12=[UInt64]0;[Int32]13=[UInt64]0;[Int32]14=[UInt64]0;[Int32]15=[UInt64]0;[Int32]16=[UInt64]0;[Int32]17=[UInt64]0;[Int32]18=[UInt64]0;[Int32]19=[UInt64]0;[Int32]20=[UInt64]0;[Int32]21=[UInt64]0;[Int32]22=[UInt64]0;[Int32]23=[UInt64]0}

    #Lists to store the output variables
    $logGenByHour = New-Object System.Collections.Generic.List[System.Object]
    $logGenByDB = New-Object System.Collections.Generic.List[System.Object]
    $logGenByDBByHour = New-Object System.Collections.Generic.List[System.Object]

    #Loop through all copies in each unique database.
    foreach ($dbGroup in $groupedByDB)
    {   
        $database = $dbGroup.Group[0].DatabaseName
        $databases.Add($database)

        $rawSamples = $dbGroup.Group | Select-Object -Property ServerName, DatabaseName, @{Label="LogGeneration";Expression={[UInt64]::Parse($_.LogGeneration)}}, @{Label="TimeCollected";Expression={[DateTime]::Parse($_.TimeCollected, $uiCulture)}}
        
        #Group samples by exact date down to the hour.
        $groupedByHour = $rawSamples | Group-Object -Property @{Expression={$_.TimeCollected.Year}},@{Expression={$_.TimeCollected.Month}},@{Expression={$_.TimeCollected.Day}},@{Expression={$_.TimeCollected.Hour}}
        $parsedSamples = @{}

        #Setup variables to get totals for this DB
        [UInt64]$thisDBLogsGenerated = 0
        [UInt64]$thisDBHours = 0
        $thisLogsGeneratedByHour = @{[Int32]0=[UInt64]0;[Int32]1=[UInt64]0;[Int32]2=[UInt64]0;[Int32]3=[UInt64]0;[Int32]4=[UInt64]0;[Int32]5=[UInt64]0;[Int32]6=[UInt64]0;[Int32]7=[UInt64]0;[Int32]8=[UInt64]0;[Int32]9=[UInt64]0;[Int32]10=[UInt64]0;[Int32]11=[UInt64]0;[Int32]12=[UInt64]0;[Int32]13=[UInt64]0;[Int32]14=[UInt64]0;[Int32]15=[UInt64]0;[Int32]16=[UInt64]0;[Int32]17=[UInt64]0;[Int32]18=[UInt64]0;[Int32]19=[UInt64]0;[Int32]20=[UInt64]0;[Int32]21=[UInt64]0;[Int32]22=[UInt64]0;[Int32]23=[UInt64]0}
        $thisSamplesByHour = @{[Int32]0=[UInt64]0;[Int32]1=[UInt64]0;[Int32]2=[UInt64]0;[Int32]3=[UInt64]0;[Int32]4=[UInt64]0;[Int32]5=[UInt64]0;[Int32]6=[UInt64]0;[Int32]7=[UInt64]0;[Int32]8=[UInt64]0;[Int32]9=[UInt64]0;[Int32]10=[UInt64]0;[Int32]11=[UInt64]0;[Int32]12=[UInt64]0;[Int32]13=[UInt64]0;[Int32]14=[UInt64]0;[Int32]15=[UInt64]0;[Int32]16=[UInt64]0;[Int32]17=[UInt64]0;[Int32]18=[UInt64]0;[Int32]19=[UInt64]0;[Int32]20=[UInt64]0;[Int32]21=[UInt64]0;[Int32]22=[UInt64]0;[Int32]23=[UInt64]0}

        #Take the largest log generation for that this hour group. The largest should belong to the Active DB copy.
        foreach ($hourGroup in $groupedByHour)
        {
            $groupTime = New-Object DateTime($hourGroup.Group[0].TimeCollected.Year, $hourGroup.Group[0].TimeCollected.Month, $hourGroup.Group[0].TimeCollected.Day, $hourGroup.Group[0].TimeCollected.Hour, 0, 0)

            $logGen = $hourGroup.Group | Sort-Object -Property LogGeneration -Descending | Select-Object -Property LogGeneration -First 1

            $parsedSamples.Add($groupTime, $logGen)
        }

        #Calculate log differences if we have 2 or more samples
        if ($parsedSamples.Count -ge 2)
        {
            $sortedByTime = $parsedSamples.GetEnumerator() | Sort-Object -Property Name

            for ($i = 0; $i -lt $sortedByTime.Count - 1; $i++)
            {
                $currentSample = $sortedByTime[$i]
                $nextSample = $sortedByTime[$i + 1]

                if ($nextSample.Value.LogGeneration -ge $currentSample.Value.LogGeneration -and $nextSample.Name -gt $currentSample.Name)
                {
                    [Int32]$currentHour = $currentSample.Name.Hour
                    $hourDiff = ($nextSample.Name - $currentSample.Name).TotalHours
                    [UInt64]$logGenDiff = $nextSample.Value.LogGeneration - $currentSample.Value.LogGeneration

                    $thisDBLogsGenerated += $logGenDiff
                    $thisDBHours += $hourDiff

                    #Split the logs found across however many hours this sample spanned
                    for ($j = 0; $j -lt $hourDiff; $j++)
                    {
                        $logGenPerHour = $logGenDiff / $hourDiff

                        $totalLogsGeneratedByHour[$currentHour + $j] += $logGenPerHour
                        $totalSamplesByHour[$currentHour + $j]++

                        $thisLogsGeneratedByHour[$currentHour + $j] += $logGenPerHour
                        $thisSamplesByHour[$currentHour + $j]++
                    }
                }
            }
        }
        else
        {
            Write-Warning "[$([DateTime]::Now)] Found only $($parsedSamples.Count) samples for database $database. Unable to calculate differences."
        }

        #Do the hourly comparisons for this database
        for ([Int32]$i = 0; $i -lt 24; $i++)
        {
            [Decimal]$logGenToTotalRatioForDB = 0

            if ($thisDBLogsGenerated -ne 0)
            {
                [Decimal]$logGenToTotalRatioForDB = $thisLogsGeneratedByHour[$i] / $thisDBLogsGenerated
            }

            $logGenByDBByHour.Add(((New-Object PSObject -Property @{DatabaseName=$database;Hour=$i;LogsGenerated=$thisLogsGeneratedByHour[$i];HourToDailyLogGenRatioForDB=$logGenToTotalRatioForDB}) | Select-Object -Property DatabaseName, Hour, LogsGenerated, HourToDailyLogGenRatioForDB))
        }

        #Add this database stats to totals
        $totalLogsGenerated += $thisDBLogsGenerated
        $totalLogsGeneratedByDB.Add($database, $thisDBLogsGenerated)
        $totalHoursByDB.Add($database, $thisDBHours)
    }

    if ($totalLogsGenerated -le 0)
    {
        Write-Warning "[$([DateTime]::Now)] Found no meaningful samples. Exiting script."
        return
    }    

    Write-Verbose "[$([DateTime]::Now)] Calculating total per hour log generation rates."

    for ([Int32]$i = 0; $i -lt 24; $i++)
    {
        [Decimal]$hourlyGenerationRate = $totalLogsGeneratedByHour[$i] / $totalLogsGenerated

        [Decimal]$averageSampleSize = 0

        if ($totalLogsGeneratedByHour[$i] -ne 0)
        {
            [Decimal]$averageSampleSize = $totalLogsGeneratedByHour[$i] / $totalSamplesByHour[$i]
        }

        $logGenByHour.Add(((New-Object PSObject -Property @{Hour=$i;LogsGenerated=$totalLogsGeneratedByHour[$i];HourToDailyLogGenRatio=$hourlyGenerationRate;NumberOfHourlySamples=$totalSamplesByHour[$i];AvgLogGenPerHour=$averageSampleSize}) | Select-Object -Property Hour, LogsGenerated, HourToDailyLogGenRatio, NumberOfHourlySamples, AvgLogGenPerHour))
    }    

    Write-Verbose "[$([DateTime]::Now)] Calculating database totals relative to all databases."

    foreach ($database in $databases)
    {
        $thisDBLogsGenerated = $totalLogsGeneratedByDB[$database]
        $thisDBHours = $totalHoursByDB[$database]

        [Decimal]$logGenToTotalRatio = 0
        [Decimal]$logsGeneratedPerHour = 0

        if ($totalLogsGenerated -gt 0)
        {
            [Decimal]$logGenToTotalRatio = $thisDBLogsGenerated / $totalLogsGenerated
        }
        
        if ($thisDBHours -ne 0)
        {
            [Decimal]$logsGeneratedPerHour = $thisDBLogsGenerated / $thisDBHours
        }

        $logGenByDB.Add(((New-Object PSObject -Property @{DatabaseName=$database;LogsGenerated=$totalLogsGeneratedByDB[$database];LogGenToTotalRatio=$logGenToTotalRatio;NumberOfHours=$thisDBHours;LogsGeneratedPerHour=$logsGeneratedPerHour}) | Select-Object -Property DatabaseName, LogsGenerated, LogGenToTotalRatio, NumberOfHours, LogsGeneratedPerHour))
    }

    Write-Verbose "[$([DateTime]::Now)] Saving results to CSV."

    $logGenByHour | Export-Csv -Path (Join-Path $LogDirectoryOut "LogGenByHour.csv") -NoTypeInformation
    $logGenByDB | Sort-Object -Property @{Expression="LogsGenerated";Descending=$true},@{Expression="DatabaseName";Descending=$false} | Export-Csv -Path (Join-Path $LogDirectoryOut "LogGenByDB.csv") -NoTypeInformation
    $logGenByDBByHour | Export-Csv -Path (Join-Path $LogDirectoryOut "LogGenByDBByHour.csv") -NoTypeInformation

    Write-Verbose "[$([DateTime]::Now)] Finished analyzing log stats."
}

####################################################################################################
# Script starts here
####################################################################################################

#Do input validation before proceeding
if (($Gather -eq $false -and $Analyze -eq $false) -or ($Gather -eq $true -and $Analyze -eq $true))
{
    Write-Error "[$([DateTime]::Now)] Either the Gather or Analyze switch must be specified, but not both."
}
else #Made it past input validation
{
    #Massage the log directory string so they're in an expected format when we need them
	if (([String]::IsNullOrEmpty($LogDirectoryOut)))
	{
		$LogDirectoryOut = (Resolve-Path .\).Path
	}

	if (([String]::IsNullOrEmpty($WorkingDirectory)))
	{
		$WorkingDirectory = (Resolve-Path .\).Path
	}

	if (!([String]::IsNullOrEmpty($LogDirectoryOut)) -and !(Test-Path -LiteralPath $LogDirectoryOut))
	{
		mkdir -Path $LogDirectoryOut -ErrorAction Stop
	}

	if (!([String]::IsNullOrEmpty($WorkingDirectory)) -and !(Test-Path -LiteralPath $WorkingDirectory))
	{
		mkdir -Path $WorkingDirectory -ErrorAction Stop
	}

    #Now do the real work
    if ($Gather -eq $true)
    {
        $collectionTargets = Get-TargetsForCollection -WorkingDirectory $WorkingDirectory

        if ($collectionTargets.Count -gt 0)
        {
            Get-LogGenerationsRemote -CollectionTargets $collectionTargets -WorkingDirectory $WorkingDirectory
        }
        else
        {
            Write-Error "[$([DateTime]::Now)] Failed to find, or find any valid servers or databases in, TargetServers.csv."
        }
    }
    else #(Analyze -eq $true)
    {
        Get-LogAnalysis -LogDirectoryOut $LogDirectoryOut
    }
}