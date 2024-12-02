#Author João Furlan & Keiron Mcdonnel
#Desktop engineering team
#joao.furlan@cat.com

$csvname = Read-Host "Please input the (filename).csv "
$vulrem = Read-Host "Provide the Vulnerabality remediation"
$date = Get-Date -Format "yyMMdd"

function BlankMatchingRows {
    param (
        [string]$textFilePath,
        [string]$csvFilePath,
        [string]$csvExcludedPath
    )

    # Read the lines from the text file
    $exclusions = Get-Content $textFilePath

    # Read the CSV file
    $csvData = Import-Csv $csvFilePath

    Write-Host "PCs in $csvFilePath that match exclusion list, and have been removed:"

    $excludedPath = "C:\exclusions\reassign $csvname $date.csv"

    if (Test-Path $excludedPath) {
        Remove-Item -Path $excludedPath -Recurse
    }

    if (!(Test-Path $excludedPath)) {
        New-Item -ItemType File -Path $excludedPath
    }

    $excludedcsv = @()

    foreach ($exclusion in $exclusions) {
        # Iterate through each row in the CSV file
        foreach ($row in $csvData) {
            # Check if the value in Column D matches the line from the text file
            if ($row.'cmdb_ci' -eq $exclusion) {
                
                #Write the required information in the exluded CSV
                $excludedcsv += [PSCustomObject]@{
                    'Asset' = $row.'cmdb_ci'
                    'VIT' = $row.'number'
                    'QID' = $row.'vulnerability'
                    'Support Group' = $row.'cmdb_ci.support_group'
                    'Required solution' = $vulrem
                }
                $row.'cmdb_ci' = 'EXCLUDED'
                Write-Host $exclusion
            }
        }
    }

    $excludedcsv | Export-Csv -Path $excludedPath -NoTypeInformation

     # Save the updated CSV file
    $csvData | Export-Csv $csvFilePath -NoTypeInformation

    # Append the excluded CSV to the reassign folder with the new name
    $reassignPath = "C:\exclusions\reassign\machines to reassign.csv"
    if (Test-Path $reassignPath) {
        $excludedcsv | Export-Csv -Path $reassignPath -NoTypeInformation -Append
        Write-Host "Machines appended to the ressign file"
    } else {
        $excludedcsv | Export-Csv -Path $reassignPath -NoTypeInformation
        Write-Host "New file created"
    }

    Write-Host "Done"
}



#--------------------------------------------------change this path to your downloads folder-----------------------------#

#Set your TXT with the excluded items              #2nd CSV file to compare

BlankMatchingRows "C:\exclusions\exclusions.txt" "C:\Users\furlajp\Downloads\$csvname.csv" 


