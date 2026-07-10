<#
.SYNOPSIS
    Audits CVE predictions: for each CVE in journal.md, finds the earliest
    prediction file where it was rated and quotes that exact line.

.PARAMETER UseGitHubDates
    Query the GitHub API for the first-commit date of each prediction file
    and use those dates (instead of the hardcoded estimates) to sort the
    file list before searching. Requires internet access; unauthenticated
    GitHub API allows 60 requests/hour. Pass -GitHubToken to raise the limit.

.PARAMETER GitHubToken
    Optional GitHub personal access token for higher API rate limits.

.OUTPUTS
    audit-results.csv  — machine-readable
    audit-results.txt  — human-readable report
#>

param(
    [string]$Root          = $(if ($PSScriptRoot) { $PSScriptRoot } else { $PWD.Path }),
    [string]$JournalPath   = '',
    [string]$OutCsv        = '',
    [string]$OutTxt        = '',
    [switch]$UseGitHubDates,
    [string]$GitHubToken   = '',
    [string]$GitHubRepo    = 'cyberdyne-ventures/predictions'
)

if (-not $JournalPath) { $JournalPath = Join-Path $Root 'journal.md' }
if (-not $OutCsv)      { $OutCsv      = Join-Path $Root 'audit-results.csv' }
if (-not $OutTxt)      { $OutTxt      = Join-Path $Root 'audit-results.txt' }

# ── Prediction files — hardcoded dates are fallback estimates ─────────────────
# Add new runs here. When -UseGitHubDates is set the Date field is replaced
# with the actual first-commit timestamp from the repo.
# NOTE: a "January 31 2025" run is referenced in the journal but no matching
#       file was found in this repo — may exist in a newer version of the data.
$Files = @(
    [PSCustomObject]@{ Date = '2025-01-03'; Label = 'Jan 3 2025 run (2024 CVEs)';  RelPath = '2024\2024-predictions.txt' }
    [PSCustomObject]@{ Date = '2025-01-07'; Label = 'Jan 7 2025 run (2024 CVEs)';  RelPath = '2024\predictions-jan-7-run.txt' }
    [PSCustomObject]@{ Date = '2025-01-08'; Label = 'Jan 8 2025 run (2025 CVEs)';  RelPath = '2025\output-jan-8.txt' }
    [PSCustomObject]@{ Date = '2025-01-15'; Label = 'Jan 15 2025 run';             RelPath = '2025\jan-15-run.txt' }
    [PSCustomObject]@{ Date = '2025-01-17'; Label = 'Jan 17 2025 run (2024 CVEs)'; RelPath = '2024\2024-predictions-jan-17-run.txt' }
    [PSCustomObject]@{ Date = '2025-01-17'; Label = 'Jan 17 2025 run (2025 CVEs)'; RelPath = '2025\jan-17-run.txt' }
    [PSCustomObject]@{ Date = '2025-02-15'; Label = 'Feb 15 2025 run';             RelPath = '2025\feb-15-run.txt' }
    [PSCustomObject]@{ Date = '2025-05-08'; Label = 'May 8 2025 run';              RelPath = '2025\may-8-run.txt' }
    [PSCustomObject]@{ Date = '2025-05-13'; Label = 'May 13 2025 run';             RelPath = '2025\may-13-o4.txt' }
    [PSCustomObject]@{ Date = '2025-05-24'; Label = 'May 24 2025 run (2024 CVEs)'; RelPath = '2024\2024-output-may-24.txt' }
    [PSCustomObject]@{ Date = '2025-08-01'; Label = 'August 2025 run';             RelPath = '2025\August\august-2025-combined-ratings.txt' }
    [PSCustomObject]@{ Date = '2025-09-14'; Label = 'Sep 14 2025 run';             RelPath = '2025\September\2025-ratings-sep-14.txt' }
    [PSCustomObject]@{ Date = '2025-12-02'; Label = 'Dec 2 2025 run';              RelPath = '2025\November\december-2-ratings.txt' }
    [PSCustomObject]@{ Date = '2026-01-01'; Label = 'Jan 2026 run';                RelPath = '2025\Final run Jan 2026\2025-ratings-final.txt' }
    [PSCustomObject]@{ Date = '2026-01-15'; Label = '2025 processed-clean (HEAD)'; RelPath = 'HEAD\2025-processed-clean.txt' }
    [PSCustomObject]@{ Date = '2026-03-01'; Label = 'March 2026 run';              RelPath = 'HEAD\2026-MARCH-RUN.csv' }
    [PSCustomObject]@{ Date = '2026-04-01'; Label = 'April 2026 run';              RelPath = 'HEAD\2026-april-run.csv' }
    [PSCustomObject]@{ Date = '2026-06-01'; Label = 'June 1 2026 run';             RelPath = 'HEAD\2026-june-1.txt' }
)

# ── Optionally fetch first-commit dates from GitHub ───────────────────────────
function Get-FirstCommitDate {
    param([string]$Repo, [string]$FilePath, [hashtable]$Headers)

    # GitHub returns commits newest-first; we paginate to find the oldest.
    $apiPath = $FilePath -replace '\\', '/'
    $page = 1
    $oldest = $null

    do {
        $url = "https://api.github.com/repos/$Repo/commits?path=$apiPath&per_page=100&page=$page"
        try {
            $batch = Invoke-RestMethod -Uri $url -Headers $Headers -ErrorAction Stop
        } catch {
            Write-Warning "GitHub API error for $FilePath (page $page): $_"
            break
        }

        if (-not $batch -or $batch.Count -eq 0) { break }

        $oldest = $batch[-1]   # last item on this page is older than all previous
        $page++
    } while ($batch.Count -eq 100)   # if < 100 returned we're on the last page

    if ($oldest) {
        return $oldest.commit.committer.date   # ISO 8601 string
    }
    return $null
}

if ($UseGitHubDates) {
    $apiHeaders = @{ 'User-Agent' = 'cve-audit-script' }
    if ($GitHubToken) {
        $apiHeaders['Authorization'] = "Bearer $GitHubToken"
    }

    Write-Host "Fetching first-commit dates from github.com/$GitHubRepo ..."
    foreach ($f in $Files) {
        $date = Get-FirstCommitDate -Repo $GitHubRepo -FilePath $f.RelPath -Headers $apiHeaders
        if ($date) {
            $f.Date = $date.Substring(0, 10)   # keep YYYY-MM-DD portion
            Write-Host "  $($f.RelPath) -> $($f.Date)"
        } else {
            Write-Warning "  $($f.RelPath) -> could not fetch date, keeping estimate ($($f.Date))"
        }
    }

    # Re-sort by the now-accurate dates
    $Files = $Files | Sort-Object { [datetime]$_.Date }
    Write-Host ''
}

# ── Parse journal: map each CVE to the earliest date it was confirmed ─────────
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
        # Year section header — e.g. "2026:" or "2025:"
        if ($line -match '^\s*(\d{4})\s*:?\s*$') {
            $currentYear = $Matches[1]
            continue
        }

        # Standard date line — "March 20:", "Feb 23:", " January 27:", etc.
        if ($line -match '^\s*(January|February|March|April|May|June|July|August|September|October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\w*\s+(\d{1,2})\s*:') {
            $month = $monthMap[$Matches[1]]
            $day   = $Matches[2].PadLeft(2, '0')
            if ($currentYear -and $month) { $currentDate = "$currentYear-$month-$day" }
        }

        # Compact "Jan22" style entries at the bottom of the journal
        if ($line -match '^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)(\d{1,2})\s') {
            $month = $monthMap[$Matches[1]]
            $day   = $Matches[2].PadLeft(2, '0')
            if ($currentYear -and $month) { $currentDate = "$currentYear-$month-$day" }
        }

        if ($currentDate) {
            foreach ($m in [regex]::Matches($line, 'CVE-\d{4}-\d+')) {
                $cveDates[$m.Value] = $currentDate   # overwrite keeps earliest date
            }
        }
    }

    return $cveDates
}

# ── Extract unique CVE IDs from journal ──────────────────────────────────────
$journalText = Get-Content $JournalPath -Raw -Encoding UTF8
$cveIds = [regex]::Matches($journalText, 'CVE-\d{4}-\d+') |
    ForEach-Object { $_.Value } |
    Sort-Object -Unique

$journalDates = Get-JournalDates -Path $JournalPath

Write-Host "Journal  : $JournalPath"
Write-Host "CVEs     : $($cveIds.Count) unique IDs extracted"
Write-Host ''

# ── Search prediction files in order ─────────────────────────────────────────
$results = [System.Collections.Generic.List[PSCustomObject]]::new()
$notFound = 0

foreach ($cve in $cveIds) {
    $hit = $null

    foreach ($f in $Files) {
        $fullPath = Join-Path $Root $f.RelPath
        if (-not (Test-Path $fullPath)) { continue }

        $match = Select-String -LiteralPath $fullPath `
                               -Pattern ([regex]::Escape($cve)) `
                               -SimpleMatch |
                 Select-Object -First 1

        if ($match) {
            $hit = [PSCustomObject]@{
                CVE                = $cve
                'KEV Date'         = $journalDates[$cve]
                'Github Timestamp' = $f.Date
                RunLabel           = $f.Label
                File               = $f.RelPath
                Line               = $match.Line.Trim()
            }
            break
        }
    }

    if ($hit) {
        Write-Host "  [FOUND]     $cve  ->  $($hit.RunLabel)"
    } else {
        $hit = [PSCustomObject]@{
            CVE                = $cve
            'KEV Date'         = $journalDates[$cve]
            'Github Timestamp' = ''
            RunLabel           = 'NOT FOUND'
            File               = ''
            Line               = ''
        }
        Write-Warning "  [NOT FOUND] $cve"
        $notFound++
    }

    $results.Add($hit)
}

$found = $results.Count - $notFound

# ── CSV output ────────────────────────────────────────────────────────────────
$results | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
Write-Host ''
Write-Host "CSV  -> $OutCsv"

# ── Plain-text output ─────────────────────────────────────────────────────────
$sep = '-' * 80
$txt = [System.Text.StringBuilder]::new()

[void]$txt.AppendLine('CVE PREDICTION AUDIT REPORT')
[void]$txt.AppendLine("Generated  : $(Get-Date -Format 'yyyy-MM-dd HH:mm')")
[void]$txt.AppendLine("Journal    : $JournalPath")
[void]$txt.AppendLine("Dates      : $(if ($UseGitHubDates) { "from GitHub commit history ($GitHubRepo)" } else { 'hardcoded estimates (use -UseGitHubDates for authoritative dates)' })")
[void]$txt.AppendLine("Total CVEs : $($results.Count)  |  Found: $found  |  Not found: $notFound")
[void]$txt.AppendLine($sep)

foreach ($r in $results) {
    [void]$txt.AppendLine('')
    [void]$txt.AppendLine("CVE    : $($r.CVE)")
    [void]$txt.AppendLine("KEV Date         : $($r.'KEV Date')")
    if ($r.RunLabel -eq 'NOT FOUND') {
        [void]$txt.AppendLine('Github Timestamp : NOT FOUND in any prediction file')
    } else {
        [void]$txt.AppendLine("Github Timestamp : $($r.'Github Timestamp')  ($($r.RunLabel))")
        [void]$txt.AppendLine("File             : $($r.File)")
        [void]$txt.AppendLine("Line             : $($r.Line)")
    }
}

$txt.ToString() | Out-File -FilePath $OutTxt -Encoding UTF8
Write-Host "Text -> $OutTxt"
Write-Host ''
Write-Host "Done. $found / $($results.Count) CVEs matched to a prediction file."
