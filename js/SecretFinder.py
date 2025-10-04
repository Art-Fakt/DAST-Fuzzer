#!/usr/bin/env python
# SecretFinder - Tool for discover apikeys/accesstokens and sensitive data in js file
# based to LinkFinder - github.com/GerbenJavado
# edited by 4rt3f4kt


import os
import sys
import re
import glob
import argparse
import jsbeautifier
import webbrowser
import subprocess
import base64
import requests
import string
import random
from html import escape
import urllib3
import xml.etree.ElementTree

# for read local file with file:// protocol
from requests_file import FileAdapter
from lxml import html
from urllib.parse import urlparse

if not sys.version_info.major >= 3:
    print("[ + ] Run this tool with python version 3.+")
    sys.exit(0)
os.environ["BROWSER"] = "open"

# disable warning

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# regex
_regex = {
    "google_api": r"AIza[0-9A-Za-z-_]{35}",
    "firebase": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "google_captcha": r"6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$",
    "google_oauth": r"ya29\.[0-9A-Za-z\-_]+",
    "amazon_aws_access_key_id": r"AKIA[0-9A-Z]{16}",
    "amazon_mws_auth_toke": r"amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "amazon_aws_url": r"s3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com",
    "amazon_aws_url2": r"("
    r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com"
    r"|s3://[a-zA-Z0-9-\.\_]+"
    r"|s3-[a-zA-Z0-9-\.\_\/]+"
    r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+"
    r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
    "facebook_access_token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "authorization_basic": r"basic [a-zA-Z0-9=:_\+\/-]{5,100}",
    "authorization_bearer": r"bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}",
    "authorization_api": r"api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}",
    "mailgun_api_key": r"key-[0-9a-zA-Z]{32}",
    "twilio_api_key": r"SK[0-9a-fA-F]{32}",
    "twilio_account_sid": r"AC[a-zA-Z0-9_\-]{32}",
    "twilio_app_sid": r"AP[a-zA-Z0-9_\-]{32}",
    "paypal_braintree_access_token": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    "square_oauth_secret": r"sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}",
    "square_access_token": r"sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}",
    "stripe_standard_api": r"sk_live_[0-9a-zA-Z]{24}",
    "stripe_restricted_api": r"rk_live_[0-9a-zA-Z]{24}",
    "github_access_token": r"[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*",
    "rsa_private_key": r"-----BEGIN RSA PRIVATE KEY-----",
    "ssh_dsa_private_key": r"-----BEGIN DSA PRIVATE KEY-----",
    "ssh_dc_private_key": r"-----BEGIN EC PRIVATE KEY-----",
    "pgp_private_block": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "json_web_token": r"ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$",
    "slack_token": r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
    "SSH_privKey": r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    "Heroku API KEY": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "possible_Creds": r"(?i)("
    r"password\s*[`=:\"]+\s*[^\s]+|"
    r"password is\s*[`=:\"]*\s*[^\s]+|"
    r"pwd\s*[`=:\"]*\s*[^\s]+|"
    r"passwd\s*[`=:\"]+\s*[^\s]+)",
    
    # Additional API Keys and Tokens
    "discord_token": r"[MN][A-Za-z\d]{23}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27}",
    "discord_webhook": r"https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
    "telegram_bot_token": r"[0-9]+:AA[A-Za-z0-9_-]{33}",
    "telegram_bot_url": r"api.telegram.org",
    "instagram_access_token": r"IGQV[A-Za-z0-9_-]{100,}",
    "linkedin_access_token": r"AQ[A-Za-z0-9_-]{100,}",
    "youtube_api_key": r"AIza[0-9A-Za-z\\-_]{35}",
    "microsoft_teams_webhook": r"https://[a-zA-Z0-9]+\.webhook\.office\.com/webhookb2/[a-zA-Z0-9-]+",
    
    # Database Connection Strings
    "mongodb_connection": r"mongodb(\+srv)?://[^\s\"']+",
    "mysql_connection": r"mysql://[^\s\"']+",
    "postgresql_connection": r"postgres(ql)?://[^\s\"']+",
    "redis_connection": r"redis://[^\s\"']+",
    "sqlserver_connection": r"mssql://[^\s\"']+",
    
    # Cloud Provider Keys
    "azure_storage_key": r"(?:DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=)[A-Za-z0-9+/]{88}==",
    # "azure_client_secret": r"[A-Za-z0-9~._-]{34}(?=\s*[;,\n\r]|$)",
    "gcp_service_account": r"\"type\":\s*\"service_account\",\s*\"project_id\"",
    "digitalocean_token": r"dop_v1_[a-f0-9]{64}",
    "linode_token": r"(?:token|key)\s*[=:]\s*['\"][a-f0-9]{64}['\"]",
    "vultr_api_key": r"(?:vultr|VULTR)[_-]?(?:api[_-]?key|key)\s*[=:]\s*['\"][A-Z0-9]{36}['\"]",
    
    # Payment and Financial APIs
    "paypal_client_id": r"(?:client[_-]?id|clientId)\s*[=:]\s*['\"]A[A-Za-z0-9_-]{79}['\"]",
    "coinbase_api_key": r"(?:coinbase|COINBASE)[_-]?(?:api[_-]?key|key)\s*[=:]\s*['\"][a-f0-9]{32}['\"]",
    "binance_api_key": r"(?:binance|BINANCE)[_-]?(?:api[_-]?key|key)\s*[=:]\s*['\"][A-Za-z0-9]{64}['\"]",
    "razorpay_key": r"rzp_(test|live)_[A-Za-z0-9]{14}",
    
    # Communication Services
    "sendgrid_api_key": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    "mailchimp_api_key": r"[a-f0-9]{32}-us[0-9]{1,2}",
    "pusher_key": r"(?:pusher|PUSHER)[_-]?(?:app[_-]?key|key)\s*[=:]\s*['\"][a-f0-9]{20}['\"]",
    "pusher_secret": r"(?:pusher|PUSHER)[_-]?(?:secret|app[_-]?secret)\s*[=:]\s*['\"][a-f0-9]{40}['\"]",
    "twilio_auth_token": r"(?:twilio|TWILIO)[_-]?(?:auth[_-]?token|token)\s*[=:]\s*['\"][a-f0-9]{32}['\"]",
    
    # Analytics and Tracking
    # "google_analytics": r"UA-[0-9]+-[0-9]+",
    # "google_tag_manager": r"GTM-[A-Z0-9]+",
    "mixpanel_token": r"(?:mixpanel|MIXPANEL)[_-]?(?:token|project[_-]?token)\s*[=:]\s*['\"][a-f0-9]{32}['\"]",
    "segment_write_key": r"(?:segment|SEGMENT)[_-]?(?:write[_-]?key|key)\s*[=:]\s*['\"][A-Za-z0-9]{32}['\"]",
    "amplitude_api_key": r"(?:amplitude|AMPLITUDE)[_-]?(?:api[_-]?key|key)\s*[=:]\s*['\"][a-f0-9]{32}['\"]",
    
    # Content Delivery Networks
    "cloudflare_api_key": r"(?:cloudflare|CLOUDFLARE)[_-]?(?:api[_-]?key|key)\s*[=:]\s*['\"][a-f0-9]{37}['\"]",
    "fastly_api_token": r"(?:fastly|FASTLY)[_-]?(?:api[_-]?token|token)\s*[=:]\s*['\"][A-Za-z0-9_-]{32}['\"]",
    
    # Development and CI/CD
    "npm_token": r"npm_[A-Za-z0-9]{36}",
    "docker_auth": r"\"auths\":\s*{[^}]*}",
    "jenkins_api_token": r"(?:jenkins|JENKINS)[_-]?(?:api[_-]?token|token)\s*[=:]\s*['\"][a-f0-9]{34}['\"]",
    "travis_token": r"(?:travis|TRAVIS)[_-]?(?:token|api[_-]?token)\s*[=:]\s*['\"][A-Za-z0-9_-]{22}['\"]",
    "circleci_token": r"(?:circleci|CIRCLECI)[_-]?(?:token|api[_-]?token)\s*[=:]\s*['\"][a-f0-9]{40}['\"]",
    
    # Monitoring and Logging
    "datadog_api_key": r"(?:datadog|DATADOG)[_-]?(?:api[_-]?key|key)\s*[=:]\s*['\"][a-f0-9]{32}['\"]",
    "new_relic_license": r"(?:new[_-]?relic|NEW[_-]?RELIC)[_-]?(?:license|key)\s*[=:]\s*['\"][a-f0-9]{40}['\"]",
    "bugsnag_api_key": r"(?:bugsnag|BUGSNAG)[_-]?(?:api[_-]?key|key)\s*[=:]\s*['\"][a-f0-9]{32}['\"]",
    "sentry_dsn": r"https://[a-f0-9]{32}@[a-z0-9.-]+/[0-9]+",
    
    # Generic Patterns
    "api_key_generic": r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][a-zA-Z0-9_-]{10,}['\"]",
    "secret_key_generic": r"(?i)(secret[_-]?key|secretkey)\s*[=:]\s*['\"][a-zA-Z0-9_-]{10,}['\"]",
    "access_token_generic": r"(?i)(access[_-]?token|accesstoken)\s*[=:]\s*['\"][a-zA-Z0-9_.-]{10,}['\"]",
    "client_secret_generic": r"(?i)(client[_-]?secret|clientsecret)\s*[=:]\s*['\"][a-zA-Z0-9_-]{10,}['\"]",
    "auth_token_generic": r"(?i)(auth[_-]?token|authtoken)\s*[=:]\s*['\"][a-zA-Z0-9_.-]{10,}['\"]",
    
    # URLs with embedded credentials
    "url_with_credentials": r"https?://[a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+",
    
    # Environment variables (often leaked in frontend builds)
    "env_var_secrets": r"(?i)(REACT_APP_|VUE_APP_|VITE_|NEXT_PUBLIC_)[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD)['\"]?\s*[=:]\s*['\"][^'\"]{10,}['\"]",
    
    # Cryptocurrency wallets
    # "bitcoin_address": r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}",
    # "ethereum_address": r"0x[a-fA-F0-9]{40}",
    # "litecoin_address": r"[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}",
    
    # Certificates and Keys (additional formats)
    "pkcs8_private_key": r"-----BEGIN PRIVATE KEY-----",
    "openssh_private_key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "certificate": r"-----BEGIN CERTIFICATE-----",
    
    # Phone numbers and sensitive data
    # "phone_number": r"(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}",
    # "credit_card": r"(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})",
    
    # Additional social media tokens
    "twitter_bearer_token": r"AAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{80,}",
    "twitter_access_token": r"[0-9]+-[A-Za-z0-9]{40}",
    # "facebook_app_secret": r"[a-f0-9]{32}",
}

_template = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <style>
       h1 {
          font-family: sans-serif;
       }
       a {
          color: #000;
       }
       .text {
          font-size: 16px;
          font-family: Helvetica, sans-serif;
          color: #323232;
          background-color: white;
       }
       .container {
          background-color: #e9e9e9;
          padding: 10px;
          margin: 10px 0;
          font-family: helvetica;
          font-size: 13px;
          border-width: 1px;
          border-style: solid;
          border-color: #8a8a8a;
          color: #323232;
          margin-bottom: 15px;
       }
       .button {
          padding: 17px 60px;
          margin: 10px 10px 10px 0;
          display: inline-block;
          background-color: #f4f4f4;
          border-radius: .25rem;
          text-decoration: none;
          -webkit-transition: .15s ease-in-out;
          transition: .15s ease-in-out;
          color: #333;
          position: relative;
       }
       .button:hover {
          background-color: #eee;
          text-decoration: none;
       }
       .github-icon {
          line-height: 0;
          position: absolute;
          top: 14px;
          left: 24px;
          opacity: 0.7;
       }
  </style>
  <title>SecretFinder Output</title>
</head>
<body contenteditable="true">
  $$content$$

  <a class='button' contenteditable='false' href='https://github.com/Art-Fakt' \
rel='nofollow noopener noreferrer' target='_blank'><span class='github-icon'><svg height="24" viewbox="0 \
0 24 24" width="24" xmlns="http://www.w3.org/2000/svg">
<path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 \
6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 \
5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 \
18.13V22" fill="none" stroke="#000" stroke-linecap="round" stroke-linejoin="round" stroke-width="2">\
</path></svg></span> Check 4rt3f4kt's Github.</a>
</body>
</html>
"""


def parser_error(msg):
    print("Usage: python %s [OPTIONS] use -h for help" % sys.argv[0])
    print("Error: %s" % msg)
    sys.exit(0)


def getContext(matches, content, name, rex=".+?"):
    """ get context """
    items = []
    matches2 = []
    for i in [x[0] for x in matches]:
        if i not in matches2:
            matches2.append(i)
    for m in matches2:
        context = re.findall("%s%s%s" % (rex, m, rex), content, re.IGNORECASE)

        item = {
            "matched": m,
            "name": name,
            "context": context,
            "multi_context": True if len(context) > 1 else False,
        }
        items.append(item)
    return items


def parser_file(content, mode=1, more_regex=None, no_dup=1):
    """ parser file """
    if mode == 1:
        if len(content) > 1000000:
            content = content.replace(";", ";\r\n").replace(",", ",\r\n")
        else:
            content = jsbeautifier.beautify(content)
    all_items = []
    for regex in _regex.items():
        r = re.compile(regex[1], re.VERBOSE)
        if mode == 1:
            all_matches = [
                (m.group(0), m.start(0), m.end(0)) for m in re.finditer(r, content)
            ]
            items = getContext(all_matches, content, regex[0])
            if items != []:
                all_items.append(items)
        else:
            items = [
                {
                    "matched": m.group(0),
                    "context": [],
                    "name": regex[0],
                    "multi_context": False,
                }
                for m in re.finditer(r, content)
            ]
        if items != []:
            all_items.append(items)
    if all_items != []:
        k = []
        for i in range(len(all_items)):
            for ii in all_items[i]:
                if ii not in k:
                    k.append(ii)
        if k != []:
            all_items = k

    if no_dup:
        all_matched = set()
        no_dup_items = []
        for item in all_items:
            if item != [] and type(item) is dict:
                if item["matched"] not in all_matched:
                    all_matched.add(item["matched"])
                    no_dup_items.append(item)
        all_items = no_dup_items

    filtered_items = []
    if all_items != []:
        for item in all_items:
            if more_regex:
                if re.search(more_regex, item["matched"]):
                    filtered_items.append(item)
            else:
                filtered_items.append(item)
    return filtered_items


def parser_input(input):
    """ Parser Input """
    # method 1 - url
    schemes = ("http://", "https://", "ftp://", "file://", "ftps://")
    if input.startswith(schemes):
        return [input]
    # method 2 - url inpector firefox/chrome
    if input.startswith("view-source:"):
        return [input[12:]]
    # method 3 - Burp file
    if args.burp:
        jsfiles = []
        items = []

        try:
            items = xml.etree.ElementTree.fromstring(open(args.input, "r").read())
        except Exception as err:
            print(err)
            sys.exit()
        for item in items:
            jsfiles.append(
                {
                    "js": base64.b64decode(item.find("response").text).decode(
                        "utf-8", "replace"
                    ),
                    "url": item.find("url").text,
                }
            )
        return jsfiles
    # method 4 - folder with a wildcard
    if "*" in input:
        paths = glob.glob(os.path.abspath(input))
        for index, path in enumerate(paths):
            paths[index] = "file://%s" % path
        return (
            paths
            if len(paths) > 0
            else parser_error("Input with wildcard does not match any files.")
        )

    # method 5 - local file
    path = "file://%s" % os.path.abspath(input)
    return [
        path
        if os.path.exists(input)
        else parser_error(
            "file could not be found (maybe you forgot to add http/https)."
        )
    ]


def html_save(output):
    """ html output """
    hide = os.dup(1)
    os.close(1)
    os.open(os.devnull, os.O_RDWR)
    try:
        text_file = open(args.output, "wb")
        text_file.write(_template.replace("$$content$$", output).encode("utf-8"))
        text_file.close()

        print("HTML report saved to: %s" % os.path.abspath(args.output))
        print("URL to access output: file://%s" % os.path.abspath(args.output))
        # Removed automatic browser opening
        # file = "file:///%s" % (os.path.abspath(args.output))
        # if sys.platform == "linux" or sys.platform == "linux2":
        #     subprocess.call(["xdg-open", file])
        # else:
        #     webbrowser.open(file)
    except Exception as err:
        print("Output can't be saved in %s due to exception: %s" % (args.output, err))
    finally:
        os.dup2(hide, 1)


def cli_output(matched):
    """ cli output """
    for match in matched:
        print(
            match.get("name")
            + "\t->\t"
            + match.get("matched").encode("ascii", "ignore").decode("utf-8")
        )


def urlParser(url):
    """ urlParser """
    parse = urlparse(url)
    urlParser.this_root = parse.scheme + "://" + parse.netloc
    urlParser.this_path = parse.scheme + "://" + parse.netloc + "/" + parse.path


def extractjsurl(content, base_url):
    """ JS url extract from html page """
    soup = html.fromstring(content)
    all_src = []
    urlParser(base_url)
    for src in soup.xpath("//script"):
        src = src.xpath("@src")[0] if src.xpath("@src") != [] else []
        if src != []:
            if src.startswith(("http://", "https://", "ftp://", "ftps://")):
                if src not in all_src:
                    all_src.append(src)
            elif src.startswith("//"):
                src = "http://" + src[2:]
                if src not in all_src:
                    all_src.append(src)
            elif src.startswith("/"):
                src = urlParser.this_root + src
                if src not in all_src:
                    all_src.append(src)
            else:
                src = urlParser.this_path + src
                if src not in all_src:
                    all_src.append(src)
    if args.ignore and all_src != []:
        temp = all_src
        ignore = []
        for i in args.ignore.split(";"):
            for src in all_src:
                if i in src:
                    ignore.append(src)
        if ignore:
            for i in ignore:
                temp.pop(int(temp.index(i)))
        return temp
    if args.only:
        temp = all_src
        only = []
        for i in args.only.split(";"):
            for src in all_src:
                if i in src:
                    only.append(src)
        return only
    return all_src


def send_request(url):
    """ Send Request """
    # read local file
    # https://github.com/dashea/requests-file
    if "file://" in url:
        s = requests.Session()
        s.mount("file://", FileAdapter())
        return s.get(url).content.decode("utf-8", "replace")
    # set headers and cookies
    headers = {}
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
Chrome/58.0.3029.110 Safari/537.36",
        "Accept": "text/html, application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.8",
        "Accept-Encoding": "gzip",
    }
    if args.headers:
        for i in args.header.split("\\n"):
            # replace space and split
            name, value = i.replace(" ", "").split(":")
            headers[name] = value
    # add cookies
    if args.cookie:
        headers["Cookie"] = args.cookie

    headers.update(default_headers)
    # proxy
    proxies = {}
    if args.proxy:
        proxies.update(
            {
                "http": args.proxy,
                "https": args.proxy,
                # ftp
            }
        )
    try:
        resp = requests.get(url=url, verify=False, headers=headers, proxies=proxies)
        return resp.content.decode("utf-8", "replace")
    except Exception as err:
        print(err)
        sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-e",
        "--extract",
        help="Extract all javascript links located in a page and process it",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-i",
        "--input",
        help="Input a: URL, file or folder",
        required="True",
        action="store",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Where to save the file, including file name. Default: output.html",
        action="store",
        default="output.html",
    )
    parser.add_argument(
        "-r",
        "--regex",
        help="RegEx for filtering purposes against found endpoint (e.g: ^/api/)",
        action="store",
    )
    parser.add_argument(
        "-b", "--burp", help="Support burp exported file", action="store_true"
    )
    parser.add_argument(
        "-c",
        "--cookie",
        help="Add cookies for authenticated JS files",
        action="store",
        default="",
    )
    parser.add_argument(
        "-g",
        "--ignore",
        help="Ignore js url, if it contain the provided string (string;string2..)",
        action="store",
        default="",
    )
    parser.add_argument(
        "-n",
        "--only",
        help="Process js url, if it contain the provided string (string;string2..)",
        action="store",
        default="",
    )
    parser.add_argument(
        "-H",
        "--headers",
        help='Set headers ("Name:Value\\nName:Value")',
        action="store",
        default="",
    )
    parser.add_argument(
        "-p", "--proxy", help="Set proxy (host:port)", action="store", default=""
    )
    args = parser.parse_args()

    if args.input[-1:] == "/":
        # /aa/ -> /aa
        args.input = args.input[:-1]

    mode = 1
    if args.output == "cli":
        mode = 0
    # add args
    if args.regex:
        # validate regular exp
        try:
            r = re.search(
                args.regex,
                "".join(
                    random.choice(string.ascii_uppercase + string.digits)
                    for _ in range(random.randint(10, 50))
                ),
            )
        except Exception:
            print("your python regex isn't valid")
            sys.exit()

        _regex.update({"custom_regex": args.regex})

    if args.extract:
        content = send_request(args.input)
        urls = extractjsurl(content, args.input)
    else:
        # convert input to URLs or JS files
        urls = parser_input(args.input)
    # conver URLs to js file
    output = ""
    for url in urls:
        print("[ + ] URL: " + url)
        if not args.burp:
            file = send_request(url)
        else:
            file = url.get("js")
            url = url.get("url")

        matched = parser_file(file, mode)
        if len(matched) > 0:
            if args.output == "cli":
                cli_output(matched)
            else:
                output += (
                    '<h1>File: <a href="%s" target="_blank" rel="nofollow noopener noreferrer">%s</a></h1>'
                    % (escape(url), escape(url))
                )
                for match in matched:
                    _matched = match.get("matched")
                    _named = match.get("name")
                    header = '<div class="text">%s</div>' % (_named.replace("_", " "))
                    body = ""
                    # find same thing in multiple context
                    if match.get("multi_context"):
                        # remove duplicate
                        no_dup = []
                        for context in match.get("context"):
                            if context not in no_dup:
                                escaped_context = escape(str(context))
                                body += '<div class="container">%s</div>' % escaped_context
                                body = body.replace(
                                    escape(str(context)),
                                    '<span style="background-color:yellow">%s</span>' % escape(str(context)),
                                )
                                no_dup.append(context)
                    else:
                        if match.get("context") and len(match.get("context")) > 0:
                            context = match.get("context")[0] if isinstance(match.get("context"), list) else match.get("context")
                            escaped_context = escape(str(context))
                            body += '<div class="container">%s</div>' % escaped_context
                            body = body.replace(
                                escape(str(_matched)),
                                '<span style="background-color:yellow">%s</span>' % escape(str(_matched)),
                            )
                        else:
                            # If no context, just show the matched string
                            escaped_matched = escape(str(_matched))
                            body += '<div class="container">%s</div>' % escaped_matched
                            body = body.replace(
                                escaped_matched,
                                '<span style="background-color:yellow">%s</span>' % escaped_matched,
                            )
                    output += header + body
            if args.output != "cli":
                html_save(output)
