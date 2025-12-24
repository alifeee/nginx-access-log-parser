"""parse nginx access logs
turns
  access.log
into
  access.csv
  access.json
  access.html
they must be of the format (or similar enough) to
log_format upstream_time '$remote_addr - $remote_user [$time_local] '
    '"$request" $status $body_bytes_sent '
    '"$http_referer" "$http_user_agent" '
    '$host '
    'rt="$request_time" uct="$upstream_connect_time" uht="$upstream_header_time" urt="$upstream_response_time"';
usage:
  python3 parse.py /var/log/nginx/access.log
usage (multiple log files):
  ls /var/log/nginx/access.log* | sort -rV | xargs python3 parse.py
"""

import sys
import csv
import hashlib
import json
import datetime
import gzip

if len(sys.argv) < 2:
    raise ValueError(
        "need to include file(s), e.g.,: python3 parse.py /var/log/nginx/access.log.1 /var/log/nginx/access.log"
    )
access_logs = sys.argv[1:]
N_LOG_FILES = len(access_logs)

NGINX_DATE_FORMAT = "[%d/%b/%Y:%H:%M:%S %z]"
GOOD_RESPONSE_CODES = ["200", "304", "206"]
IGNORE_RESPONSE_CODES = ["301", "101"]
# log locations of items
i_IP = 0
i_TIMEPT1 = 3
i_TIMEPT2 = 4
i_REQUEST = 5
i_RESPONSE = 6
i_BYTES = 7
i_REFERER = 8
i_USERAGENT = 9
i_DOMAIN = 10
with open("http_codes.json", "r", encoding="utf-8") as file:
    http_codes = json.load(file)

parsed = []
last_dt = 0
for access_log in access_logs:
    print(f"parsing {access_log}...")

    if access_log.endswith(".gz"):
        # open gzip file
        with gzip.open(access_log, "rt", encoding="utf-8") as file:
            reader = csv.reader(file, delimiter=" ")
            logs = list(reader)
    else:
        # open normal file
        with open(access_log, "r", encoding="utf-8") as file:
            reader = csv.reader(file, delimiter=" ")
            logs = list(reader)

    for j, log in enumerate(logs):
        # hash IP+useragent to make "user"
        ipandua = f"{log[i_IP]}+{log[i_USERAGENT]}"
        userhash = hashlib.md5(ipandua.encode("utf-8")).hexdigest()[:16]

        # get request type and location
        request = log[i_REQUEST]
        try:
            request_method, request_path, request_version = request.split(" ")
        except ValueError:
            continue

        # get time as unix timestamp
        #   (we ignore timept2, assume UTC)
        dt = datetime.datetime.strptime(
            f"{log[i_TIMEPT1]} {log[i_TIMEPT2]}", NGINX_DATE_FORMAT
        )
        # check this log file is newer than the last one
        ts = dt.timestamp()
        if j == 1:
            if ts < last_dt:
                raise ValueError(
                    "log files do not seem to be in date order. oldest should be first"
                )
            last_dt = ts

        # line of parsed
        parsed.append(
            {
                "userhash": userhash,
                "ip": log[i_IP],
                "datetime": ts,
                "useragent": log[i_USERAGENT],
                "domain": log[i_DOMAIN],
                "request_method": request_method,
                "request_path": request_path,
                "referer": log[i_REFERER],
                "response": log[i_RESPONSE],
                "bytes": log[i_BYTES],
            }
        )

print("  saving to access.csv")
with open("access.csv", "w", encoding="utf-8") as file:
    writer = csv.DictWriter(file, parsed[0].keys(), delimiter="\t")
    writer.writeheader()
    writer.writerows(parsed)

users = {}
for log in parsed:
    u = log["userhash"]
    d = log["domain"]
    if u not in users:
        users[u] = {
            "user": u,
            "ip": log["ip"],
            "useragent": log["useragent"],
            "ts_start": log["datetime"],
            "ts_end": log["datetime"],
            "total_requests": 0,
            "total_bytes": 0,
            "domains": {},
        }
    users[u]["total_requests"] += 1
    users[u]["total_bytes"] += int(log["bytes"])
    users[u]["ts_end"] = log["datetime"]

    if d not in users[u]["domains"]:
        users[u]["domains"][d] = {
            "total_requests": 0,
            "total_bytes": 0,
            "requests": {},
            "paths": {},
            "referers": {},
            "responses": {},
        }
    users[u]["domains"][d]["total_requests"] += 1
    users[u]["domains"][d]["total_bytes"] += int(log["bytes"])

    request_method = log["request_method"]
    if request_method not in users[u]["domains"][d]["requests"]:
        users[u]["domains"][d]["requests"][request_method] = 1
    else:
        users[u]["domains"][d]["requests"][request_method] += 1

    request_path = log["request_path"]
    if request_path not in users[u]["domains"][d]["paths"]:
        users[u]["domains"][d]["paths"][request_path] = 1
    else:
        users[u]["domains"][d]["paths"][request_path] += 1
    referer = log["referer"]
    if referer not in users[u]["domains"][d]["referers"]:
        users[u]["domains"][d]["referers"][referer] = 1
    else:
        users[u]["domains"][d]["referers"][referer] += 1
    response = log["response"]
    if response not in users[u]["domains"][d]["responses"]:
        users[u]["domains"][d]["responses"][response] = 1
    else:
        users[u]["domains"][d]["responses"][response] += 1

users = sorted(
    list(users.values()),
    key=lambda usr: usr["total_requests"],
    reverse=True,
)

print("  saving to access.json")
with open("access.json", "w", encoding="utf-8") as file:
    json.dump(users, file, indent="  ")

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<link rel=stylesheet href=style.css>
<script src="script.js"></script>
</head>
<body>
<header>
  <h1>nginx access logs</h1>
  <p>
    <a href="access.json">see json</a>
    <button onclick="toggleFirst()">toggle unfold</button>
  </p>
</header>
<main>
<section class="users">
"""

for u in users:
    HTML += "<pre>"
    HTML += "<details class=user><summary>"
    HTML += f"<span class=name>{u['user']}</span> "
    HTML += f"·&nbsp;{u['total_requests']:>4} total "
    total_req = u["total_requests"]
    total_good = sum(
        u["domains"][d]["responses"][r]
        for d in u["domains"]
        for r in u["domains"][d]["responses"]
        if r in GOOD_RESPONSE_CODES
    )
    total_ignore = sum(
        u["domains"][d]["responses"][r]
        for d in u["domains"]
        for r in u["domains"][d]["responses"]
        if r in IGNORE_RESPONSE_CODES
    )
    if total_req == total_ignore:
        # full bar if only ignored requests
        total_req = 1
        total_ignore = 0
        total_good = 1
    HTML += (
        f"<progress min=0 max={total_req - total_ignore} value={total_good}></progress>"
    )
    HTML += f"&nbsp;{u['total_bytes']/1024:>8.2f} kB"

    time_start = datetime.datetime.fromtimestamp(u["ts_start"])
    time_end = datetime.datetime.fromtimestamp(u["ts_end"])
    time_diff = round((time_end - time_start).total_seconds())  # s
    time_diff_unit = "s"
    if time_diff > 120:
        time_diff = round(time_diff / 60)
        time_diff_unit = "min"
    if time_diff > 120:
        time_diff = round(time_diff / 60)
        time_diff_unit = "hr"
    HTML += f" · "
    time_diff_str = f"({time_diff} {time_diff_unit})"
    HTML += f"{time_diff_str:<10}"
    HTML += f" {time_start.strftime('%Y-%m-%d %H:%M:%S')}"
    if time_diff > 0:
        if (
            (time_start.year == time_end.year)
            and (time_start.month == time_end.month)
            and (time_start.day == time_end.day)
        ):
            HTML += f" - {time_end.strftime('%H:%M:%S')}"
        else:
            HTML += f" - {time_end.strftime('%Y-%m-%d %H:%M:%S')}"
    HTML += "</summary>"
    HTML += (
        f"<div class=ua><span class=ip tabindex=0>{u['ip']}</span>"
        f"·<span>{u['useragent']}</span></div>"
    )
    for d in u["domains"]:
        HTML += "<details><summary>"
        total_req = u["domains"][d]["total_requests"]
        total_good = sum(
            u["domains"][d]["responses"][r]
            for r in u["domains"][d]["responses"]
            if r in GOOD_RESPONSE_CODES
        )
        total_ignore = sum(
            u["domains"][d]["responses"][r]
            for r in u["domains"][d]["responses"]
            if r in IGNORE_RESPONSE_CODES
        )
        if total_req == total_ignore:
            # full bar if only ignored requests
            total_req = 1
            total_ignore = 0
            total_good = 1
        HTML += f"<progress min=0 max={total_req - total_ignore} value={total_good}></progress> "
        HTML += f"{d}"
        HTML += f" ·&nbsp;{u['domains'][d]['total_requests']:>5} total "
        HTML += f"&nbsp;{u['domains'][d]['total_bytes']/1024:>8.2f} kB"
        HTML += "</summary>"

        HTML += "<details open><summary>REQUESTS</summary><ul>"
        for request in sorted(u["domains"][d]["requests"]):
            HTML += (
                f"<li><span>{u['domains'][d]['requests'][request]}</span> "
                f"· <span>{request}</span></li>"
            )
        HTML += "</ul></details>"
        HTML += "<details open><summary>PATHS</summary><ul>"
        for path in sorted(u["domains"][d]["paths"]):
            HTML += (
                f"<li><span>{u['domains'][d]['paths'][path]}</span> "
                f"· <span><a target=_blank href='http://{d}{path}'>{path}</a></span></li>"
            )
        HTML += "</ul></details>"
        HTML += "<details open><summary>RESPONSES</summary><ul>"
        for response in sorted(u["domains"][d]["responses"]):
            if c := http_codes.get(response):
                http_code = f"{response} {c['message']}"
            else:
                http_code = response
            HTML += (
                f"<li><span>{u['domains'][d]['responses'][response]}</span> "
                f"· <span>{http_code}</span></li>"
            )
        HTML += "</ul></details>"
        HTML += "<details open><summary>REFERERS</summary><ul>"
        for referer in sorted(u["domains"][d]["referers"]):
            HTML += (
                f"<li><span>{u['domains'][d]['referers'][referer]}</span> "
                f"· <span><a target=_blank href='{referer}'>{referer}</a></span></li>"
            )
        HTML += "</ul></details>"

        HTML += "</details>"
    HTML += "</details>"
    HTML += "</pre>"
    HTML += "\n"

HTML += """
</section>
</main>
</body>
</html>
"""

print("  saving to access.html")
with open("access.html", "w", encoding="utf-8") as file:
    file.write(HTML)

print("done :]")
