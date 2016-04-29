# pythreatgrid-search

<strong>Dependencies</strong>:
<ul>
  <li>pythreatgrid - https://github.com/hosom/pythreatgrid</li>
</ul>

<h3>Summary</h3>
Searches ThreatGrid for samples based on a supplied IOC. The search will find related IOCs (IP,md5,sha1,sha256) from the returned sample(s) and recursively search off those IOCs to find more related samples. If not specified, default recursion depth is 3. Outputs discovered Sample ID's into current working directory 

<h3>Example Usage</h3>
<code>python threatgrid_search.py <API_KEY> --checksum <(MD5,SHA1,SHA256)> --after \<DATETIME\> --depth \<DEPTH\> --limit \<LIMIT\></code>
