#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ipsourcebypass.py
# Author             : Podalirius (@podalirius_)
# Date created       : 10 Oct 2021

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
import requests
from rich.console import Console
from rich import box
from rich.table import Table
import json
from http.cookies import SimpleCookie

banner = "[~] IP source bypass using HTTP headers, v1.1\n"

BYPASS_HEADERS = [
    'Access-Control-Allow-Origin', 'Client-IP', 'Forwarded', 'Forwarded-For', 'Forwarded-For-IP', 'Origin',
    'X-Client-IP', 'X-Custom-IP-Authorization', 'X-Forwarded', 'X-Forwarded-By', 'X-Forwarded-For',
    'X-Forwarded-For-Original', 'X-Forwarded-Host', 'X-Forwarder-For', 'X-Originating-IP', 'X-Remote-Addr',
    'X-Remote-IP'
]


def test_bypass(options, proxies, results, header_name, header_value):
    try:
        r = requests.get(
            url=options.url,
            verify=options.verify,  # this is to set the client to accept insecure servers
            proxies=proxies,
            allow_redirects=options.redirect,
            stream=True,  # this is to prevent the download of huge files, focus on the request, not on the data,
            headers={header_name: header_value}
        )
    except requests.exceptions.ProxyError:
        print("[!] Invalid proxy specified")
        raise SystemExit
    if options.verbose == True:
        print("[!] Obtained results: [%d] length : %d bytes" %(r.status_code, len(r.content)))

    results[header_name] = {"status_code": r.status_code, "length": len(r.text), "header": "%s: %s" % (header_name, header_value)}

def print_results(console, results):
    if options.verbose == True:
        print("[>] Parsing & printing results")
    table = Table(show_header=True, header_style="bold blue", border_style="blue", box=box.SIMPLE)
    table.add_column("Length")
    table.add_column("Status code")
    table.add_column("Header")

    # Choose colors for uncommon lengths
    lengths = [result[1]["length"] for result in results.items()]
    lengths = [(len([1 for result in results.items() if result[1]["length"]==l]), l) for l in list(set(lengths))]

    if len(lengths) == 2:
        for result in results.items():
            if result[1]["length"] == min(lengths)[1]:
                style = "green"
            elif result[1]["length"] == max(lengths)[1]:
                style = "red"
            table.add_row(str(result[1]["length"]), str(result[1]["status_code"]), result[1]["header"], style=style)
    elif len(lengths) == 3:
        scale = ["red", "orange3", "green"]
        colors = {str(sorted(lengths, reverse=True)[k][1]):scale[k] for k in range(len(lengths))}
        for result in results.items():
            style = colors[str(result[1]["length"])]
            table.add_row(str(result[1]["length"]), str(result[1]["status_code"]), result[1]["header"], style=style)
    elif len(lengths) == 4:
        scale = ["red", "orange3", "yellow3", "green"]
        colors = {str(sorted(lengths, reverse=True)[k][1]):scale[k] for k in range(len(lengths))}
        for result in results.items():
            style = colors[str(result[1]["length"])]
            table.add_row(str(result[1]["length"]), str(result[1]["status_code"]), result[1]["header"], style=style)
    else:
        for result in results.items():
            style = "orange3"
            table.add_row(str(result[1]["length"]), str(result[1]["status_code"]), result[1]["header"], style=style)
    console.print(table)


def parseArgs():
    description = "This Python script can be used to test for IP source bypass using HTTP headers"
    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "url",
        help="e.g. https://example.com:port/path"
    )
    parser.add_argument("-v", "--verbose", default=None, action="store_true", help='arg1 help message')
    parser.add_argument("-i", "--ip", dest="ip", required=True, help="IP to spoof.")
    parser.add_argument("-t", "--threads", dest="threads", action="store", type=int, default=5, required=False, help="Number of threads (default: 5)")
    parser.add_argument('-x', '--proxy', action="store", default=None, dest='proxy', help="Specify a proxy to use for requests (e.g., http://localhost:8080)")
    parser.add_argument("-k", "--insecure", dest="verify", action="store_false", default=True, required=False, help="Allow insecure server connections when using SSL (default: False)")
    parser.add_argument("-L", "--location", dest="redirect", action="store_true", default=False, required=False, help="Follow redirects (default: False)")
    parser.add_argument("-j", "--jsonfile", dest="jsonfile", default=None, required=False, help="Save results to specified JSON file.")
    return parser.parse_args()


if __name__ == '__main__':
    print(banner)

    options = parseArgs()
    try:
        console = Console()
        # Verifying the proxy option
        if options.proxy:
            try:
                proxies = {
                    "http": "http://" + options.proxy.split('//')[1],
                    "https": "http://" + options.proxy.split('//')[1]
                }
                if options.verbose == True:
                    print("[debug] Setting proxies to %s" % str(proxies))
            except (IndexError, ValueError):
                print("[!] Invalid proxy specified.")
                sys.exit(1)
        else:
            if options.verbose == True:
                print("[debug] Setting proxies to 'None'")
            proxies = None

        if not options.verify:
            # Disable warings of insecure connection for invalid cerificates
            requests.packages.urllib3.disable_warnings()
            # Allow use of deprecated and weak cipher methods
            requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
            try:
                requests.packages.urllib3.contrib.pyopenssl.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
            except AttributeError:
                pass

        results = {}
        # Waits for all the threads to be completed
        with ThreadPoolExecutor(max_workers=min(options.threads, len(BYPASS_HEADERS))) as tp:
            for bph in BYPASS_HEADERS:
                tp.submit(test_bypass, options, proxies, results, bph, options.ip)

        # Sorting the results by method name
        results = {key: results[key] for key in sorted(results, key=lambda key:results[key]["length"])}

        # Parsing and print results
        print_results(console, results)

        # Export to JSON if specified
        if options.jsonfile is not None:
            f = open(options.jsonfile, "w")
            f.write(json.dumps(results, indent=4) + "\n")
            f.close()

    except KeyboardInterrupt:
        print("[+] Terminating script...")
        raise SystemExit