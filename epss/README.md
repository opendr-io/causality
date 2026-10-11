# Introduction
The [Exploit Prediction Scoring System](https://www.first.org/epss/) (EPSS) is a data-driven 
effort for estimating the likelihood (probability) that a software vulnerability will be exploited 
in the wild. 

This is the official repository for current and historical EPSS Scores. Scores are also available
for [direct download](https://www.first.org/epss/data_stats), or scores for individual 
vulenrabilities can be retrieved throug the [FIRST API](https://api.first.org/epss/).

# EPSS Data

The current fields in the available data are:

- `cve` : The CVE identifier as specified by MITRE's CVE List
- `epss` : the EPSS score representing the probability \[0-1\] of
  exploitation in the wild in the next 30 days (following score
  publication)
- `percentile` : the percentile of the current score, the proportion of
  all scored vulnerabilities with the same or a lower EPSS score

Each of the comma-separated values (CSV) file contain the CVE Identifier, the EPSS
score and ranking percentile as of the date the data was generated. That date is in the filename. 

# Important 

If you do historical analysis, keep in mind the following dates:

- No scores are available before 2021-04-14
- EPSS v2 (v2022.01.01) started publishing on 2022-02-04, you will see a
  major shift in most scores on that day, and the files now include a
  comment at the start with `#` stating the model version and publish
  date.
- EPSS v3 (v2023.03.01) started publishing on 2023-03-07, you will see a
  shift in scores on that day.
- EPSS v4 (v2025.03.14) started publishing on 2025-03-17, you will see a
  shift in scores on that day.
