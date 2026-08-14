<#
.SYNOPSIS
    CVE Prediction Audit. For each CVE in README.md, finds the earliest
    prediction file where it was RATED (not just mentioned) and quotes that
    exact line.

    A CVE is only credited with a prediction date once it has an
    "actionable" rating (warm/hot/fire/neutral) -- appearing in a file rated
    cold, or with a blank rating, doesn't count as a prediction. Files with
    no rating column at all (e.g. reduction.txt) are treated as implicitly
    actionable, since those are pre-filtered exports of already-notable
    CVEs.

    This is the PowerShell port of audit.py; keep the two in sync.

.PARAMETER UseGitHubDates
    Query the GitHub API for the first-commit date of each prediction file
    (following renames back through history) and use those dates (instead
    of the hardcoded estimates) to sort and report on the file list.
    Requires internet access; unauthenticated GitHub API allows 60
    requests/hour. Pass -GitHubToken to raise the limit.

.PARAMETER GitHubToken
    Optional GitHub personal access token for higher API rate limits. The
    script also supports unauthenticated GitHub API use.

.OUTPUTS
    audit-results.csv  - machine-readable
    audit-results.txt  - human-readable report
#>

param(
    [string]$Root          = $(if ($PSScriptRoot) { $PSScriptRoot } else { $PWD.Path }),
    [string]$DataRoot      = '',
    [string]$JournalPath   = '',
    [string]$OutCsv        = '',
    [string]$OutTxt        = '',
    [switch]$UseGitHubDates,
    [string]$GitHubToken   = $env:GITHUB_TOKEN,
    [double]$GitHubDelaySeconds = 1.0,
    [string]$GitHubRepo    = 'opendr-io/causality'
)

if (-not $DataRoot) {
    $rootLeaf = Split-Path -Path $Root -Leaf
    if ($rootLeaf -ieq 'auditor') {
        $DataRoot = Split-Path -Path $Root -Parent
    } else {
        $DataRoot = $Root
    }
}

if (-not $JournalPath) { $JournalPath = Join-Path $DataRoot 'README.md' }
if (-not $OutCsv)      { $OutCsv      = Join-Path $Root 'audit-results.csv' }
if (-not $OutTxt)      { $OutTxt      = Join-Path $Root 'audit-results.txt' }
if (-not (Test-Path -LiteralPath $JournalPath)) { throw "Source file not found: $JournalPath" }

# Prediction files; hardcoded dates are fallback estimates used only for
# ordering when -UseGitHubDates is not set (or a file isn't on GitHub yet).
# Add new runs here. Keep this list in sync with PREDICTION_FILES in audit.py.
$Files = @(
    [PSCustomObject]@{ Date = '2025-01-03'; Label = 'Jan 3 2025 run (2024 CVEs)';       RelPath = '2024\2024-predictions.txt' }
    [PSCustomObject]@{ Date = '2025-01-07'; Label = 'Jan 7 2025 run (2024 CVEs)';       RelPath = '2024\predictions-jan-7-run.txt' }
    [PSCustomObject]@{ Date = '2025-01-17'; Label = 'Jan 17 2025 run (2024 CVEs)';      RelPath = '2024\2024-predictions-jan-17-run.txt' }
    [PSCustomObject]@{ Date = '2025-04-08'; Label = 'April 2025 reduction (2024 CVEs)'; RelPath = '2024\reduction.txt' }
    [PSCustomObject]@{ Date = '2026-02-08'; Label = 'May 24 2025 run (2024 CVEs)';      RelPath = '2024\2024-output-may-24.txt' }

    [PSCustomObject]@{ Date = '2025-01-08'; Label = 'Jan 8 2025 run (2025 CVEs)';       RelPath = '2025\output-jan-8.txt' }
    [PSCustomObject]@{ Date = '2025-01-15'; Label = 'Jan 15 2025 run';                  RelPath = '2025\jan-15-run.txt' }
    [PSCustomObject]@{ Date = '2025-01-17'; Label = 'Jan 17 2025 run (2025 CVEs)';      RelPath = '2025\jan-17-run.txt' }
    [PSCustomObject]@{ Date = '2025-02-17'; Label = 'Feb 2025 run';                     RelPath = '2025\feb-15-run.txt' }
    [PSCustomObject]@{ Date = '2025-05-08'; Label = 'May 2025 run';                     RelPath = '2025\may-8-run.txt' }
    [PSCustomObject]@{ Date = '2025-08-31'; Label = 'August 2025 run';                  RelPath = '2025\August\august-2025-combined-ratings.txt' }
    [PSCustomObject]@{ Date = '2025-12-02'; Label = 'December 2025 run';                RelPath = '2025\November\december-2-ratings.txt' }
    [PSCustomObject]@{ Date = '2026-01-31'; Label = '2025 ratings final (Jan 31 run)';  RelPath = '2025\Final run Jan 2026\2025-ratings-final.txt' }
    [PSCustomObject]@{ Date = '2026-02-08'; Label = '2025 ratings final';               RelPath = '2025\2025-ratings-final.txt' }
    [PSCustomObject]@{ Date = '2026-03-21'; Label = '2025 processed-clean';             RelPath = 'HEAD\2025-processed-clean.txt' }

    [PSCustomObject]@{ Date = '2026-04-25'; Label = 'April 2026 run';                   RelPath = '2026\2026-april-1-for-sharing.txt' }
    [PSCustomObject]@{ Date = '2026-06-01'; Label = 'June 2026 run';                    RelPath = '2026\2026-june-1.txt' }
    [PSCustomObject]@{ Date = '2026-08-07'; Label = 'August 2026 run';                  RelPath = 'HEAD\2026-august.txt' }
)
foreach ($f in $Files) {
    $f | Add-Member -NotePropertyName EstimatedDate -NotePropertyValue $f.Date
    $f | Add-Member -NotePropertyName DateStatus     -NotePropertyValue ''
}

# Rating-column name aliases used across the pipeline's various export
# schemas, and the token values that count as an actual rating (as opposed
# to header noise or free text that happens to match).
$RatingCols       = @('rating', 'label', 'prediction', 'predicted_label')
$RatingValues     = @('hot', 'cold', 'warm', 'fire', 'neutral')
$ActionableValues = $RatingValues | Where-Object { $_ -ne 'cold' }

$CveRe        = '(?i)\bCVE\s*[-–— ]\s*(\d{4})\s*[-–— ]\s*(\d{3,})\b'
$CveFullRe    = '(?i)^CVE\s*[-–— ]\s*(\d{4})\s*[-–— ]\s*(\d{3,})$'
$BareCveRe    = '\b(20\d{2})-(\d{3,})\b'

function Get-CveIdsFromLine {
    param([string]$Line)

    $ids = [System.Collections.Generic.List[string]]::new()
    foreach ($m in [regex]::Matches($Line, $CveRe)) {
        $ids.Add("CVE-$($m.Groups[1].Value)-$($m.Groups[2].Value)")
    }

    if ($Line -match '(?i)\bCVEs?\b') {
        foreach ($m in [regex]::Matches($Line, $BareCveRe)) {
            $start = $m.Index
            $prefixStart = [Math]::Max(0, $start - 10)
            $prefix = $Line.Substring($prefixStart, $start - $prefixStart).ToUpperInvariant()
            if ($prefix -match '(?i)(CVE|GHSL)\s*[-–— ]\s*$') { continue }
            $ids.Add("CVE-$($m.Groups[1].Value)-$($m.Groups[2].Value)")
        }
    }

    return $ids | Select-Object -Unique
}

function Get-CveIdsFromText {
    param([string]$Text)

    $ids = [System.Collections.Generic.List[string]]::new()
    foreach ($line in ($Text -split "`r?`n")) {
        foreach ($id in (Get-CveIdsFromLine -Line $line)) {
            $ids.Add($id)
        }
    }
    return $ids
}

# Return the CVE ID from this row's own field only (a full-string match),
# not from anywhere in the line -- prediction rows are TSV/CSV where one
# field is the CVE ID and another is free-text description that can
# incidentally mention unrelated CVE IDs (e.g. "see also CVE-2020-6950").
function Get-RowCve {
    param([string[]]$Fields)

    foreach ($field in $Fields) {
        $trimmed = ($field -as [string]).Trim().Trim('"')
        if ($trimmed -match $CveFullRe) {
            return "CVE-$($Matches[1])-$($Matches[2])"
        }
    }
    return $null
}

function Get-Delimiter {
    param([string]$Path)

    $header = Get-Content -LiteralPath $Path -TotalCount 1 -Encoding UTF8
    if (-not $header) { return "`t" }
    $tabCount   = ([regex]::Matches($header, "`t")).Count
    $commaCount = ([regex]::Matches($header, ',')).Count
    if ($tabCount -ge $commaCount) { return "`t" } else { return ',' }
}

function Get-RatingColumnIndices {
    param([string[]]$Header)

    $indices = [System.Collections.Generic.List[int]]::new()
    for ($i = 0; $i -lt $Header.Count; $i++) {
        $h = ($Header[$i] -as [string])
        if ($h -and ($RatingCols -contains $h.Trim().ToLowerInvariant())) {
            $indices.Add($i)
        }
    }
    return $indices
}

# Return this row's rating token, or $null if it can't be determined.
# Checks the known rating column(s) first; if that comes up empty (a
# handful of rows have broken multi-line descriptions that aren't properly
# quoted, throwing off column alignment for that row specifically -- a
# source-data defect, not something safely auto-repairable here) falls back
# to scanning every field for a literal rating token.
function Get-RowRating {
    param([string[]]$Fields, [int[]]$RatingIdx)

    foreach ($idx in $RatingIdx) {
        if ($idx -lt $Fields.Count) {
            $v = ($Fields[$idx] -as [string]).Trim().ToLowerInvariant()
            if ($RatingValues -contains $v) { return $v }
        }
    }
    foreach ($field in $Fields) {
        $vv = ($field -as [string]).Trim().ToLowerInvariant()
        if ($RatingValues -contains $vv) { return $vv }
    }
    return $null
}

# Parse an entire delimited text blob into rows of fields, RFC4180-style: a
# quote only opens a quoted field when it's the first character of that
# field (a quote appearing mid-field is literal), doubled quotes inside a
# quoted field are a literal quote, and a quoted field may contain embedded
# delimiters/newlines. This intentionally mirrors Python's csv module
# semantics rather than Microsoft.VisualBasic.FileIO.TextFieldParser, which
# has catastrophic (multi-minute) performance on some of these prediction
# files -- large exports with many mostly-empty trailing rows.
function ConvertFrom-DelimitedText {
    param([string]$Text, [string]$Delimiter)

    $d = $Delimiter[0]
    $chars = $Text.ToCharArray()
    $len = $chars.Length
    $rows = [System.Collections.Generic.List[string[]]]::new()
    $fields = [System.Collections.Generic.List[string]]::new()
    $sb = [System.Text.StringBuilder]::new(256)
    $inQuotes = $false
    $fieldStart = $true
    $i = 0

    while ($i -lt $len) {
        $c = $chars[$i]
        if ($inQuotes) {
            if ($c -eq '"') {
                if ($i + 1 -lt $len -and $chars[$i + 1] -eq '"') {
                    [void]$sb.Append('"'); $i += 2; continue
                } else { $inQuotes = $false; $i++; continue }
            } else { [void]$sb.Append($c); $i++; continue }
        } elseif ($fieldStart -and $c -eq '"') {
            $inQuotes = $true; $fieldStart = $false; $i++; continue
        } elseif ($c -eq $d) {
            $fields.Add($sb.ToString()); [void]$sb.Clear(); $fieldStart = $true; $i++; continue
        } elseif ($c -eq "`r") { $i++; continue }
        elseif ($c -eq "`n") {
            $fields.Add($sb.ToString()); [void]$sb.Clear()
            $rows.Add($fields.ToArray()); $fields.Clear()
            $fieldStart = $true; $i++; continue
        } else { [void]$sb.Append($c); $fieldStart = $false; $i++; continue }
    }
    if ($sb.Length -gt 0 -or $fields.Count -gt 0) {
        $fields.Add($sb.ToString()); $rows.Add($fields.ToArray())
    }
    return $rows
}

# Parse source: map each CVE to the earliest date it was confirmed.
# Journal is reverse-chronological so we overwrite on every hit; the last
# write for any CVE is therefore the earliest (oldest) KEV addition date.
function Get-JournalDates {
    param([string]$Path)

    $monthMap = @{
        January='01'; February='02'; March='03';    April='04'
        May='05';     June='06';     July='07';     August='08'
        September='09'; October='10'; November='11'; December='12'
        Jan='01'; Feb='02'; Mar='03'; Apr='04'
        Jun='06'; Jul='07'; Aug='08'; Sep='09'; Oct='10'; Nov='11'; Dec='12'
    }

    $cveDates    = @{}
    $currentYear = ''
    $currentDate = ''

    foreach ($line in (Get-Content $Path -Encoding UTF8)) {
        if ($line -match '^\s*#{0,3}\s*(\d{4})\s*:?\s*$') {
            $currentYear = $Matches[1]
            continue
        }

        if ($line -match '^\s*(January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\w*\s+(\d{1,2})\s*:') {
            $month = $monthMap[$Matches[1]]
            $day   = $Matches[2].PadLeft(2, '0')
            if ($currentYear -and $month) { $currentDate = "$currentYear-$month-$day" }
        }

        if ($line -match '^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)(\d{1,2})\s') {
            $month = $monthMap[$Matches[1]]
            $day   = $Matches[2].PadLeft(2, '0')
            if ($currentYear -and $month) { $currentDate = "$currentYear-$month-$day" }
        }

        if ($currentDate) {
            foreach ($cve in (Get-CveIdsFromLine -Line $line)) {
                $cveDates[$cve] = $currentDate   # overwrite keeps earliest
            }
        }
    }

    return $cveDates
}

# ---------------------------------------------------------------------------
# GitHub date lookup, following renames back through history (like
# `git log --follow`): the commits?path= API stops at whichever commit
# introduced the file under its *current* path, so a plain query understates
# the true first-commit date whenever the file was renamed after creation.
# ---------------------------------------------------------------------------

function Get-GitHubApiErrorMessage {
    param($ErrorRecord, [string]$Context)

    $statusCode = $null
    $remaining  = 'unknown'
    $reset      = 'unknown'
    if ($ErrorRecord.Exception.Response) {
        $statusCode = [int]$ErrorRecord.Exception.Response.StatusCode
        try { $remainingValues = $ErrorRecord.Exception.Response.Headers.GetValues('X-RateLimit-Remaining') } catch { $remainingValues = $null }
        try { $resetValues     = $ErrorRecord.Exception.Response.Headers.GetValues('X-RateLimit-Reset') }     catch { $resetValues = $null }
        if ($remainingValues) { $remaining = ($remainingValues | Select-Object -First 1) }
        if ($resetValues)     { $reset     = ($resetValues | Select-Object -First 1) }
    }

    if ($statusCode) {
        $msg = "GitHub API $statusCode for $Context; rate-limit remaining=$remaining, reset=$reset."
        if ($remaining -eq '0') {
            $msg += ' Rate limit exhausted; retry after reset or pass a -GitHubToken.'
        } else {
            $msg += ' Unauthenticated GitHub API use is supported but limited; retry after reset, omit -UseGitHubDates, or optionally pass a token.'
        }
        return $msg
    }
    return "GitHub API error for $Context`: $ErrorRecord"
}

function Get-OldestCommitForPath {
    param([string]$Repo, [string]$FilePath, [hashtable]$Headers, [double]$DelaySeconds)

    $apiPath = (($FilePath -replace '\\', '/') -split '/' | ForEach-Object { [System.Uri]::EscapeDataString($_) }) -join '/'
    $page = 1
    $oldest = $null

    do {
        $url = "https://api.github.com/repos/$Repo/commits?path=$apiPath&per_page=100&page=$page"
        try {
            $batch = Invoke-RestMethod -Uri $url -Headers $Headers -ErrorAction Stop
        } catch {
            throw (Get-GitHubApiErrorMessage -ErrorRecord $_ -Context "$FilePath (page $page)")
        }

        if (-not $batch -or $batch.Count -eq 0) { break }

        $oldest = $batch[-1]   # last item on this page is older than all previous
        $page++
        if ($DelaySeconds -gt 0 -and $batch.Count -eq 100) {
            Start-Sleep -Seconds $DelaySeconds
        }
    } while ($batch.Count -eq 100)   # if < 100 returned we're on the last page

    return $oldest
}

function Get-RenamedFrom {
    param([string]$Repo, [string]$Sha, [string]$FilePath, [hashtable]$Headers)

    $url = "https://api.github.com/repos/$Repo/commits/$Sha"
    try {
        $detail = Invoke-RestMethod -Uri $url -Headers $Headers -ErrorAction Stop
    } catch {
        throw (Get-GitHubApiErrorMessage -ErrorRecord $_ -Context "commit $Sha")
    }

    $normPath = $FilePath -replace '\\', '/'
    foreach ($entry in $detail.files) {
        if ($entry.filename -eq $normPath -and $entry.status -eq 'renamed') {
            return $entry.previous_filename
        }
    }
    return $null
}

function Get-FirstCommitDate {
    param([string]$Repo, [string]$FilePath, [hashtable]$Headers, [double]$DelaySeconds = 1.0)

    $currentPath = $FilePath
    $visited     = [System.Collections.Generic.HashSet[string]]::new()
    $oldest      = $null

    while ($visited.Add($currentPath)) {
        $found = Get-OldestCommitForPath -Repo $Repo -FilePath $currentPath -Headers $Headers -DelaySeconds $DelaySeconds
        if (-not $found) { break }
        $oldest = $found
        if ($DelaySeconds -gt 0) { Start-Sleep -Seconds $DelaySeconds }

        $prevPath = Get-RenamedFrom -Repo $Repo -Sha $oldest.sha -FilePath $currentPath -Headers $Headers
        if ($DelaySeconds -gt 0) { Start-Sleep -Seconds $DelaySeconds }
        if (-not $prevPath -or $visited.Contains($prevPath)) { break }
        $currentPath = $prevPath
    }

    if ($oldest) { return $oldest.commit.committer.date.Substring(0, 10) }
    return $null
}

if ($UseGitHubDates) {
    $apiHeaders = @{ 'User-Agent' = 'cve-audit-script' }
    if ($GitHubToken) { $apiHeaders['Authorization'] = "Bearer $GitHubToken" }

    Write-Host "Fetching first-commit dates from github.com/$GitHubRepo ..."
    Write-Host "GitHub API delay: $GitHubDelaySeconds seconds"
    Write-Host "GitHub auth: $(if ($GitHubToken) { 'token' } else { 'none' })"

    $rateLimited = $false
    $apiErrors   = [System.Collections.Generic.List[string]]::new()

    foreach ($f in $Files) {
        if ($rateLimited) {
            # Every further call would fail the same way -- don't burn time
            # re-proving that. Keep whatever we already fetched and mark the
            # rest unverified rather than losing all prior progress.
            $f.Date = ''
            $f.DateStatus = 'UNVERIFIED (skipped -- rate limit hit earlier this run)'
            continue
        }
        try {
            $date = Get-FirstCommitDate -Repo $GitHubRepo -FilePath $f.RelPath -Headers $apiHeaders -DelaySeconds $GitHubDelaySeconds
        } catch {
            $errMsg = $_.ToString()
            Write-Host "  $($f.RelPath) -> ERROR: $errMsg"
            $f.Date = ''
            $f.DateStatus = "UNVERIFIED (GitHub API error: $errMsg)"
            $apiErrors.Add($f.RelPath)
            if ($errMsg -like '*remaining=0*') {
                $rateLimited = $true
                Write-Host '  Rate limit exhausted -- keeping dates already fetched, marking remaining files unverified, and finishing the report.'
            }
            continue
        }

        if ($date) {
            $f.Date = $date
            $f.DateStatus = 'verified'
            Write-Host "  $($f.RelPath) -> $date"
        } else {
            # Not yet pushed to GitHub -- this script exists to show provable,
            # third-party-verifiable dates, so we do NOT fall back to the
            # hardcoded estimate here. Leave it unverified rather than crash.
            $f.Date = ''
            $f.DateStatus = 'NOT ON GITHUB YET (no provable first-commit date)'
            Write-Host "  $($f.RelPath) -> NOT ON GITHUB YET (no provable first-commit date)"
        }
        if ($GitHubDelaySeconds -gt 0) { Start-Sleep -Seconds $GitHubDelaySeconds }
    }

    # Sort by the verified date when we have one; fall back to the hardcoded
    # estimate only to keep unverified files in a sensible position, never as
    # a stand-in for the (unproven) date itself.
    $Files = $Files | Sort-Object { if ($_.Date) { $_.Date } else { $_.EstimatedDate } }

    if ($apiErrors.Count -gt 0) {
        Write-Host ''
        Write-Host "WARNING: $($apiErrors.Count) file(s) could not be verified via the GitHub API this run (see ERROR lines above). They're marked UNVERIFIED in the report below -- rerun -UseGitHubDates later (after the rate limit resets, or with -GitHubToken) to fill them in."
    }
    Write-Host ''
}

# Extract unique CVE IDs from source
$journalText  = Get-Content $JournalPath -Raw -Encoding UTF8
$cveMentions  = Get-CveIdsFromText -Text $journalText
$cveIds       = $cveMentions | Sort-Object -Unique
$journalDates = Get-JournalDates -Path $JournalPath

Write-Host "Source   : $JournalPath"
Write-Host "Data root: $DataRoot"
Write-Host "CVEs     : $($cveMentions.Count) mentions, $($cveIds.Count) unique IDs extracted"
Write-Host ''

foreach ($f in $Files) {
    $fullPath = Join-Path $DataRoot $f.RelPath
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "Prediction data file not found: $fullPath"
    }
}

# Search prediction files once, in chronological order. Each CVE is
# attributed to the first file where it has an ACTIONABLE rating
# (warm/hot/fire/neutral) -- a cold or blank rating doesn't count as a
# prediction, even though the CVE ID is technically present. We also track
# the first appearance under any rating, so a CVE that's cold everywhere is
# still reported (flagged, not silently dropped) rather than vanishing from
# the audit.
$target          = [System.Collections.Generic.HashSet[string]]::new([string[]]$cveIds)
$firstActionable = @{}
$firstAny        = @{}

foreach ($f in $Files) {
    $fullPath  = Join-Path $DataRoot $f.RelPath
    $delimiter = Get-Delimiter -Path $fullPath

    try {
        $text = Get-Content -LiteralPath $fullPath -Raw -Encoding UTF8
        $rows = ConvertFrom-DelimitedText -Text $text -Delimiter $delimiter
    } catch {
        throw "Could not read prediction data file $fullPath`: $_"
    }
    if ($rows.Count -eq 0) { continue }

    $header = $rows[0]
    $ratingIdx          = Get-RatingColumnIndices -Header $header
    $implicitActionable = ($ratingIdx.Count -eq 0)   # e.g. reduction.txt

    for ($ri = 1; $ri -lt $rows.Count; $ri++) {
        $row = $rows[$ri]
        if (-not $row -or $row.Count -eq 0) { continue }

        $cve = Get-RowCve -Fields $row
        if (-not $cve -or -not $target.Contains($cve)) { continue }

        $lineText = $row -join $delimiter
        if ($implicitActionable) {
            $rating = 'n/a (no rating column)'
        } else {
            $rating = Get-RowRating -Fields $row -RatingIdx $ratingIdx
        }

        if (-not $firstAny.ContainsKey($cve)) {
            $firstAny[$cve] = [PSCustomObject]@{
                CVE = $cve; Rating = $(if ($rating) { $rating } else { 'unrated' })
                'Github Timestamp' = $f.Date; 'Date Status' = $f.DateStatus
                RunLabel = $f.Label; File = $f.RelPath; Line = $lineText
            }
        }
        if (-not $firstActionable.ContainsKey($cve)) {
            $isActionable = $implicitActionable -or ($rating -and ($ActionableValues -contains $rating))
            if ($isActionable) {
                $firstActionable[$cve] = [PSCustomObject]@{
                    CVE = $cve; Rating = $(if ($rating) { $rating } else { 'unrated' })
                    'Github Timestamp' = $f.Date; 'Date Status' = $f.DateStatus
                    RunLabel = $f.Label; File = $f.RelPath; Line = $lineText
                }
            }
        }
    }
}

$results               = [System.Collections.Generic.List[PSCustomObject]]::new()
$notFoundCves          = [System.Collections.Generic.List[string]]::new()
$neverActionableCves   = [System.Collections.Generic.List[string]]::new()
$predictedAfterKevCves = [System.Collections.Generic.List[string]]::new()

foreach ($cve in $cveIds) {
    $kevDate = $journalDates[$cve]
    $hit = $firstActionable[$cve]
    $status = 'OK'

    if (-not $hit) {
        $hit = $firstAny[$cve]
        if ($hit) {
            $status = 'MISS (never rated non-cold in any tracked file)'
            $neverActionableCves.Add($cve)
        }
    }

    if (-not $hit) {
        $results.Add([PSCustomObject]@{
            CVE = $cve; 'KEV Date' = $kevDate; Rating = ''
            'Github Timestamp' = ''; 'Date Status' = ''
            RunLabel = 'NOT FOUND'; File = ''; Line = ''; Status = 'NOT FOUND'
        })
        $notFoundCves.Add($cve)
        continue
    }

    $predDate = if ($hit.'Github Timestamp') { $hit.'Github Timestamp' } else { $hit.'Date Status' }
    if ($status -eq 'OK' -and $kevDate -and $predDate -and ($predDate -match '^\d{4}-\d{2}-\d{2}$') -and ($predDate -ge $kevDate)) {
        $status = 'MISS (rated non-cold only on/after the KEV date -- not a valid lead-time example)'
        $predictedAfterKevCves.Add($cve)
    }

    $results.Add([PSCustomObject]@{
        CVE = $cve; 'KEV Date' = $kevDate; Rating = $hit.Rating
        'Github Timestamp' = $hit.'Github Timestamp'; 'Date Status' = $hit.'Date Status'
        RunLabel = $hit.RunLabel; File = $hit.File; Line = $hit.Line; Status = $status
    })
}

$notFound      = $notFoundCves.Count
$found         = $results.Count - $notFound
$genuineMisses = $neverActionableCves.Count + $predictedAfterKevCves.Count

Write-Host "Found: $found  |  Not found: $notFound  |  Flagged as non-predictions: $genuineMisses"
if ($notFoundCves.Count -gt 0) {
    Write-Host 'Not found:'
    foreach ($cve in $notFoundCves) { Write-Host "  $cve" }
}
if ($neverActionableCves.Count -gt 0) {
    Write-Host ''
    Write-Host "Never rated non-cold ($($neverActionableCves.Count)):"
    foreach ($cve in $neverActionableCves) { Write-Host "  $cve" }
}
if ($predictedAfterKevCves.Count -gt 0) {
    Write-Host ''
    Write-Host "Rated non-cold only after KEV date ($($predictedAfterKevCves.Count)):"
    foreach ($cve in $predictedAfterKevCves) { Write-Host "  $cve" }
}

# CSV output
$results | Select-Object CVE, 'KEV Date', Rating, 'Github Timestamp', 'Date Status', RunLabel, File, Line, Status |
    Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
Write-Host ''
Write-Host "CSV  -> $OutCsv"

# Plain-text output
$sep = '-' * 80
$txt = [System.Text.StringBuilder]::new()

$dateSource = if ($UseGitHubDates) { "from GitHub commit history ($GitHubRepo)" } else { 'hardcoded estimates (use -UseGitHubDates for authoritative dates)' }

[void]$txt.AppendLine('CVE PREDICTION AUDIT REPORT')
[void]$txt.AppendLine("Generated  : $(Get-Date -Format 'yyyy-MM-dd HH:mm')")
[void]$txt.AppendLine("Source     : $JournalPath")
[void]$txt.AppendLine("Data root  : $DataRoot")
[void]$txt.AppendLine("Dates      : $dateSource")
[void]$txt.AppendLine("Total CVEs : $($results.Count)  |  Found: $found  |  Not found: $notFound  |  Flagged as non-predictions: $genuineMisses")
[void]$txt.AppendLine($sep)

foreach ($r in $results) {
    [void]$txt.AppendLine('')
    [void]$txt.AppendLine("CVE              : $($r.CVE)")
    [void]$txt.AppendLine("KEV Date         : $($r.'KEV Date')")
    if ($r.RunLabel -eq 'NOT FOUND') {
        [void]$txt.AppendLine('Github Timestamp : NOT FOUND in any prediction file')
    } else {
        $ghTs = $r.'Github Timestamp'
        if (-not $ghTs) { $ghTs = $r.'Date Status' }
        if (-not $ghTs) { $ghTs = 'NOT ON GITHUB YET (no provable first-commit date)' }
        [void]$txt.AppendLine("Github Timestamp : $ghTs  ($($r.RunLabel))")
        [void]$txt.AppendLine("Rating           : $($r.Rating)")
        [void]$txt.AppendLine("File             : $($r.File)")
        [void]$txt.AppendLine("Line             : $($r.Line)")
        if ($r.Status -ne 'OK') {
            [void]$txt.AppendLine("STATUS           : $($r.Status)")
        }
    }
}

$txt.ToString() | Out-File -FilePath $OutTxt -Encoding UTF8
Write-Host "Text -> $OutTxt"
Write-Host ''
Write-Host "Done. $found / $($results.Count) CVEs matched to a prediction file ($genuineMisses flagged as non-predictions, not valid lead-time examples)."
