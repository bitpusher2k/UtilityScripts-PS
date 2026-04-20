function ConvertTo-CsvOnDoubleNewline {
    <#
    .SYNOPSIS
        Converts a text file to CSV format by splitting on double newlines.
    
    .DESCRIPTION
        This function reads a text file and splits it into rows whenever two consecutive 
        newlines (blank lines) are encountered. Each group of lines between double newlines 
        becomes a row in the output CSV. The CSV is saved with the same name and location 
        as the input file with a .csv extension.
    
    .PARAMETER InputPath
        The path to the input text file to process.
    
    .PARAMETER OutputPath
        Optional. The path where the CSV file will be saved. If not specified, 
        the output will be saved in the same directory as the input file with a .csv extension.
    
    .PARAMETER Force
        If specified, overwrites the output file if it already exists.
    
    .EXAMPLE
        ConvertTo-CsvOnDoubleNewline -InputPath "C:\data\input.txt"
        
        Reads C:\data\input.txt and creates C:\data\input.csv
    
    .EXAMPLE
        ConvertTo-CsvOnDoubleNewline -InputPath ".\data.txt" -OutputPath ".\output.csv" -Force
        
        Reads data.txt and creates output.csv, overwriting if it exists.
    
    .EXAMPLE
        Get-ChildItem *.txt | ForEach-Object { ConvertTo-CsvOnDoubleNewline -InputPath $_.FullName }
        
        Processes all .txt files in the current directory.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("FullName", "Path")]
        [ValidateScript({
            if (Test-Path $_ -PathType Leaf) {
                $true
            } else {
                throw "File '$_' does not exist."
            }
        })]
        [string]$InputPath,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$false)]
        [switch]$Force
    )
    
    Process {
        try {
            # Resolve the full path
            $inputFile = Get-Item -Path $InputPath -ErrorAction Stop
            
            # Determine output path
            if ([string]::IsNullOrWhiteSpace($OutputPath)) {
                $outputFile = Join-Path -Path $inputFile.DirectoryName -ChildPath "$($inputFile.BaseName).csv"
            } else {
                $outputFile = $OutputPath
            }
            
            Write-Verbose "Reading input file: $($inputFile.FullName)"
            
            # Read the entire file content
            $content = Get-Content -Path $inputFile.FullName -Raw
            
            # Split on double newlines (handles both Windows \r\n and Unix \n)
            # This regex matches two or more consecutive newlines
            $records = $content -split "(\r?\n){2,}" | Where-Object { $_.Trim() -ne "" }
            
            Write-Verbose "Found $($records.Count) records"
            
            if ($records.Count -eq 0) {
                Write-Warning "No records found in the input file."
                return
            }
            
            # Process each record into an object
            $csvData = @()
            $maxFields = 0
            
            foreach ($record in $records) {
                # Split each record into lines
                $lines = $record -split "\r?\n" | Where-Object { $_.Trim() -ne "" }
                
                # Track the maximum number of fields
                if ($lines.Count -gt $maxFields) {
                    $maxFields = $lines.Count
                }
                
                $csvData += ,$lines
            }
            
            Write-Verbose "Maximum fields per record: $maxFields"
            
            # Create objects with consistent property names
            $objects = @()
            for ($i = 0; $i -lt $csvData.Count; $i++) {
                $obj = New-Object PSCustomObject
                
                for ($j = 0; $j -lt $maxFields; $j++) {
                    $fieldName = "Field$($j + 1)"
                    $fieldValue = if ($j -lt $csvData[$i].Count) { $csvData[$i][$j] } else { "" }
                    $obj | Add-Member -MemberType NoteProperty -Name $fieldName -Value $fieldValue
                }
                
                $objects += $obj
            }
            
            # Check if output file exists
            if ((Test-Path $outputFile) -and -not $Force) {
                throw "Output file '$outputFile' already exists. Use -Force to overwrite."
            }
            
            # Export to CSV
            $objects | Export-Csv -Path $outputFile -NoTypeInformation -Force:$Force
            
            Write-Host "Successfully created CSV: $outputFile" -ForegroundColor Green
            Write-Verbose "Exported $($objects.Count) rows with $maxFields columns"
            
            # Return the output file info
            Get-Item -Path $outputFile
        }
        catch {
            Write-Error "Error processing file: $_"
            throw
        }
    }
}