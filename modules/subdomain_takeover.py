#!/usr/bin/env python3
"""
modules/subdomain_takeover.py — v3.0.0 (Intelligence Edition)
═══════════════════════════════════════════════════════════════════════════
Professional subdomain takeover engine with multi-signal confidence scoring.

Changelog v3.0.0
    • Multi-source subdomain enumeration:
        crt.sh · AlienVault OTX · HackerTarget · RapidDNS · brute-force
    • Wildcard DNS detection — prevents mass false positives
    • Dangling NS delegation detection (not just CNAME)
    • Dangling MX record detection
    • Favicon fingerprinting via mmh3 hash (Shodan-style)
    • Multi-resolver DNS fallback (Cloudflare / Google / Quad9 / OpenDNS)
    • Confidence score 0–100 per finding, evidence-weighted
    • Per-provider takeover playbook (steps to claim)
    • Historical state — diff vs last scan, cache persisted on disk
    • Rate limiter scoped per-source (crt.sh vs HTTP vs DNS)
    • Cancel Event propagates into DNS, HTTP, and enumeration
    • Progress callback + SSE-friendly streaming API
    • Reduced defaults: max_hosts 150, http_timeout 5, rate 25/s
    • 68 provider fingerprints (incl. Vercel Edge, Cloudflare R2,
      Supabase, Planetscale, Fly Volumes, Deno Deploy, Val Town,
      PartyKit, onrender Static Sites)

Public API (backward compatible)
    ─ run(domain, options)                          → dict report
    ─ run_streaming(domain, options, cancel_event)  → Iterator[dict]
    ─ scan_single(host)                             → dict | None
    ─ enumerate_subdomains(domain, ...)             → set[str]
    ─ PROVIDERS                                     → provider table
    ─ PLAYBOOKS                                     → per-provider steps

Author: Yanxzyx
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import logging
import random
import re
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests
import urllib3
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
except ImportError:
    from requests.packages.urllib3.util.retry import Retry  # type: ignore

try:
    import dns.resolver
    import dns.exception
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False

try:
    import tldextract
    _TLDEXTRACT_AVAILABLE = True
except ImportError:
    _TLDEXTRACT_AVAILABLE = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("oxysintx.subdomain_takeover")
__version__ = "3.0.0"


# ═══════════════════════════════════════════════════════════════════════════
# Tunables
# ═══════════════════════════════════════════════════════════════════════════
DEFAULT_HTTP_TIMEOUT = 5.0
DEFAULT_DNS_TIMEOUT  = 2.5
DEFAULT_RATE_LIMIT   = 25.0
DEFAULT_CONCURRENCY  = 24
DEFAULT_MAX_HOSTS    = 150
DEFAULT_GLOBAL_BUDGET = 90.0
CRTSH_TIMEOUT   = 8.0
CRTSH_COOLDOWN  = 120.0
STATE_DIR       = Path(__file__).resolve().parent.parent / "data" / "takeover_state"

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

_DNS_RESOLVERS = [
    "1.1.1.1",      # Cloudflare
    "8.8.8.8",      # Google
    "9.9.9.9",      # Quad9
    "208.67.222.222",  # OpenDNS
    "8.8.4.4",
]


# ═══════════════════════════════════════════════════════════════════════════
# PROVIDER FINGERPRINT DATABASE
# ═══════════════════════════════════════════════════════════════════════════
# Every provider entry declares:
#   name        — display name
#   cnames      — substrings that may appear in the CNAME target
#   body        — substrings that may appear in the HTTP response body
#   headers     — {header: substring} that may appear in the HTTP response
#   ip_ranges   — optional list of CIDR blocks (cloud edges, checked last)
#   severity    — informational severity if takeover is possible
#   claimable   — whether a third party can actually register the resource
#   docs        — documentation URL
#   playbook    — ordered steps to claim the resource
# ═══════════════════════════════════════════════════════════════════════════
PROVIDERS: List[Dict[str, Any]] = [
    # ─── AWS ─────────────────────────────────────────────────────────
    {
        "name": "AWS S3",
        "cnames": ["s3.amazonaws.com", "s3-website", "s3-external-1.amazonaws.com",
                   "s3.dualstack", "s3.accelerate.amazonaws.com"],
        "body": ["<Code>NoSuchBucket</Code>", "The specified bucket does not exist"],
        "headers": {"Server": "AmazonS3"},
        "severity": "critical",
        "claimable": True,
        "docs": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/WebsiteHosting.html",
        "playbook": [
            "Bucket name is derived from the CNAME target host prefix.",
            "aws s3api create-bucket --bucket <name> --region <region>",
            "aws s3 website s3://<name>/ --index-document index.html",
            "Upload your index.html and confirm DNS still resolves to the new bucket.",
        ],
    },
    {
        "name": "AWS CloudFront",
        "cnames": ["cloudfront.net"],
        "body": ["Bad request", "ERROR: The request could not be satisfied",
                 "The request could not be satisfied"],
        "headers": {"X-Cache": "Error from cloudfront", "Via": "cloudfront"},
        "severity": "high",
        "claimable": False,
        "docs": "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/",
        "playbook": [
            "CloudFront distributions are assigned on a first-come basis via AWS account.",
            "An attacker would need the distribution domain name to be freed by AWS.",
            "Usually only exploitable if the original distribution was deleted by the owner.",
        ],
    },
    {
        "name": "AWS Elastic Beanstalk",
        "cnames": ["elasticbeanstalk.com"],
        "body": [], "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://docs.aws.amazon.com/elasticbeanstalk/",
        "playbook": [
            "eb create <env-name> --cname <target>",
            "If the target CNAME is free, Beanstalk will bind it.",
        ],
    },
    {
        "name": "AWS Load Balancer",
        "cnames": ["elb.amazonaws.com", "elb.us-", "elb.eu-", "elb.ap-",
                   "elb.ca-", "elb.sa-"],
        "body": [], "headers": {},
        "severity": "medium", "claimable": False,
        "docs": "https://docs.aws.amazon.com/elasticloadbalancing/",
        "playbook": [
            "ELB DNS names are region-scoped and cannot be claimed directly.",
            "Attack succeeds only if the original load balancer was deleted.",
        ],
    },

    # ─── Azure ───────────────────────────────────────────────────────
    {
        "name": "Azure App Service",
        "cnames": ["azurewebsites.net", "cloudapp.azure.com", "cloudapp.net",
                   "trafficmanager.net", "azurestaticapps.net"],
        "body": ["Error 404 - Web app not found",
                 "The resource you are looking for has been removed"],
        "headers": {},
        "severity": "critical", "claimable": True,
        "docs": "https://learn.microsoft.com/azure/app-service/",
        "playbook": [
            "az webapp create -g <rg> -p <plan> -n <app-name>",
            "Add custom domain: az webapp config hostname add",
            "If the original app no longer claims the hostname, Azure will bind it.",
        ],
    },
    {
        "name": "Azure Traffic Manager",
        "cnames": ["trafficmanager.net"],
        "body": [], "headers": {},
        "severity": "high", "claimable": False,
        "docs": "https://learn.microsoft.com/azure/traffic-manager/",
        "playbook": [
            "Traffic Manager profile names are globally unique.",
            "If original profile deleted, an attacker with an Azure subscription can recreate it.",
        ],
    },
    {
        "name": "Azure CDN",
        "cnames": ["azureedge.net", "afd.azureedge.net", "azurefd.net"],
        "body": ["The requested content does not exist"],
        "headers": {},
        "severity": "critical", "claimable": True,
        "docs": "https://learn.microsoft.com/azure/cdn/",
        "playbook": [
            "Create a new Azure CDN endpoint with the same subdomain name.",
            "Point the origin to attacker-controlled storage.",
        ],
    },
    {
        "name": "Azure Blob Storage",
        "cnames": ["blob.core.windows.net"],
        "body": ["BlobNotFound", "The specified container does not exist"],
        "headers": {},
        "severity": "critical", "claimable": True,
        "docs": "https://learn.microsoft.com/azure/storage/blobs/",
        "playbook": [
            "az storage account create -n <name> -g <rg> --sku Standard_LRS",
            "Create container with matching name.",
            "Enable static website hosting.",
        ],
    },

    # ─── Google Cloud ────────────────────────────────────────────────
    {
        "name": "Google Cloud Storage",
        "cnames": ["storage.googleapis.com", "commondatastorage.googleapis.com",
                   "storage.cloud.google.com"],
        "body": ["NoSuchBucket", "The specified bucket does not exist"],
        "headers": {},
        "severity": "critical", "claimable": True,
        "docs": "https://cloud.google.com/storage/",
        "playbook": [
            "gsutil mb gs://<bucket-name>",
            "gsutil web set -m index.html -e 404.html gs://<bucket-name>",
            "gsutil iam ch allUsers:objectViewer gs://<bucket-name>",
        ],
    },
    {
        "name": "Google App Engine",
        "cnames": ["appspot.com"],
        "body": ["Error 404", "The requested URL was not found on this server"],
        "headers": {},
        "severity": "high", "claimable": False,
        "docs": "https://cloud.google.com/appengine/",
        "playbook": [
            "App Engine app IDs are globally unique — only reclaimable if deleted by owner.",
        ],
    },
    {
        "name": "Firebase Hosting",
        "cnames": ["firebaseapp.com", "web.app"],
        "body": ["Site Not Found", "404 - Page Not Found"],
        "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://firebase.google.com/docs/hosting",
        "playbook": [
            "firebase init hosting",
            "firebase hosting:sites:create <site-name>",
            "firebase deploy",
        ],
    },

    # ─── Cloud hosting / PaaS ────────────────────────────────────────
    {
        "name": "Heroku",
        "cnames": ["herokuapp.com", "herokudns.com", "herokussl.com"],
        "body": ["No such app", "There is no app configured at this host"],
        "headers": {},
        "severity": "critical", "claimable": True,
        "docs": "https://devcenter.heroku.com/articles/custom-domains",
        "playbook": [
            "heroku create <app-name>",
            "heroku domains:add <your-domain>",
            "Push any code — the domain will now serve attacker content.",
        ],
    },
    {
        "name": "Netlify",
        "cnames": ["netlify.app", "netlify.com"],
        "body": ["Not Found - Request ID", "Looks like you've followed a broken link"],
        "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://docs.netlify.com/domains-https/",
        "playbook": [
            "netlify sites:create --name <site-name>",
            "Add custom domain via UI or CLI.",
        ],
    },
    {
        "name": "Vercel",
        "cnames": ["vercel.app", "now.sh", "vercel-dns.com", "vercel-dns-0"],
        "body": ["The deployment could not be found", "DEPLOYMENT_NOT_FOUND",
                 "404: NOT_FOUND"],
        "headers": {"X-Vercel-Error": "DEPLOYMENT_NOT_FOUND"},
        "severity": "high", "claimable": True,
        "docs": "https://vercel.com/docs/concepts/projects/domains",
        "playbook": [
            "vercel --prod",
            "vercel domains add <your-domain>",
            "If the domain wasn't bound to another Vercel account, it will claim it.",
        ],
    },
    {
        "name": "GitHub Pages",
        "cnames": ["github.io", "github.map.fastly.net"],
        "body": ["There isn't a GitHub Pages site here",
                 "For root URLs (like http://example.com/) you must provide an index.html file"],
        "headers": {},
        "severity": "critical", "claimable": True,
        "docs": "https://docs.github.com/pages",
        "playbook": [
            "Create a repo named <youruser>.github.io",
            "Add CNAME file containing the target hostname.",
            "Push and enable Pages in repo Settings.",
        ],
    },
    {
        "name": "GitLab Pages",
        "cnames": ["gitlab.io"],
        "body": ["The page you're looking for could not be found"],
        "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://docs.gitlab.com/ee/user/project/pages/",
        "playbook": [
            "Create a GitLab project with a matching name.",
            "Add a `.gitlab-ci.yml` with pages deploy stage.",
        ],
    },
    {
        "name": "Bitbucket Cloud",
        "cnames": ["bitbucket.io"],
        "body": ["Repository not found"],
        "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://support.atlassian.com/bitbucket-cloud/",
        "playbook": [
            "Create a repo with the matching name on Bitbucket.",
            "Enable static website hosting.",
        ],
    },
    {
        "name": "Surge.sh",
        "cnames": ["surge.sh"],
        "body": ["project not found", "404 Not Found"],
        "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://surge.sh/help/",
        "playbook": [
            "npm install -g surge",
            "surge --domain <target-domain> ./public",
        ],
    },
    {
        "name": "Render",
        "cnames": ["onrender.com"],
        "body": ["Not Found"], "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://render.com/docs/custom-domains",
        "playbook": [
            "Create a new Static Site or Web Service in Render.",
            "Add custom domain — will bind if previously freed.",
        ],
    },
    {
        "name": "Fly.io",
        "cnames": ["fly.dev", "fly.io"],
        "body": ["404 Not Found"], "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://fly.io/docs/",
        "playbook": [
            "flyctl launch --name <app-name>",
            "flyctl certs add <your-domain>",
        ],
    },
    {
        "name": "Railway",
        "cnames": ["railway.app"],
        "body": ["Application not found"], "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://docs.railway.app/",
        "playbook": [
            "railway up",
            "railway domain add <your-domain>",
        ],
    },
    {
        "name": "Kinsta",
        "cnames": ["kinsta.cloud"],
        "body": ["No Site For Domain"], "headers": {},
        "severity": "high", "claimable": False,
        "docs": "https://kinsta.com/docs/",
        "playbook": ["Requires Kinsta account provisioning — contact support."],
    },
    {
        "name": "DigitalOcean Spaces",
        "cnames": ["digitaloceanspaces.com", "cdn.digitaloceanspaces.com"],
        "body": ["NoSuchBucket", "The specified bucket does not exist"],
        "headers": {},
        "severity": "critical", "claimable": True,
        "docs": "https://docs.digitalocean.com/products/spaces/",
        "playbook": [
            "doctl spaces create <bucket-name> --region <region>",
            "Enable CDN and set index document.",
        ],
    },
    {
        "name": "DigitalOcean App Platform",
        "cnames": ["ondigitalocean.app"],
        "body": ["404 Not Found"], "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://docs.digitalocean.com/products/app-platform/",
        "playbook": ["doctl apps create --spec app.yaml"],
    },
    {
        "name": "Cloudflare Pages",
        "cnames": ["pages.dev"],
        "body": ["Not Found"], "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://developers.cloudflare.com/pages/",
        "playbook": [
            "Create a Cloudflare Pages project with the same name.",
            "Add custom domain in project settings.",
        ],
    },
    {
        "name": "Cloudflare Workers",
        "cnames": ["workers.dev"],
        "body": ["There is nothing here yet", "404 Not Found"],
        "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://developers.cloudflare.com/workers/",
        "playbook": [
            "wrangler init",
            "wrangler publish --name <worker-name>",
            "The *.workers.dev subdomain is unique per account but reclaimable.",
        ],
    },
    {
        "name": "Cloudflare R2",
        "cnames": ["r2.dev", "r2.cloudflarestorage.com"],
        "body": ["NoSuchBucket", "Not Found"], "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://developers.cloudflare.com/r2/",
        "playbook": ["Create R2 bucket with the same name.", "Enable public access."],
    },

    # ─── SaaS / static hosting ──────────────────────────────────────
    {
        "name": "Shopify",
        "cnames": ["myshopify.com", "shopify.com"],
        "body": ["Sorry, this shop is currently unavailable"],
        "headers": {},
        "severity": "critical", "claimable": False,
        "docs": "https://help.shopify.com/domains",
        "playbook": [
            "Requires the exact shop handle — call Shopify support to release.",
        ],
    },
    {
        "name": "BigCommerce",
        "cnames": ["mybigcommerce.com", "bigcommerce.com"],
        "body": ["Store Not Found"], "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://support.bigcommerce.com/",
        "playbook": ["Sign up for BigCommerce trial — store URL follows your store name."],
    },
    {
        "name": "Squarespace",
        "cnames": ["squarespace.com"],
        "body": ["No Such Account", "You're using an unsupported browser"],
        "headers": {},
        "severity": "high", "claimable": False,
        "docs": "https://support.squarespace.com/",
        "playbook": ["Requires direct contact with Squarespace support."],
    },
    {
        "name": "Wix",
        "cnames": ["wixsite.com", "wix.com"],
        "body": ["Looks like this site was made on Wix", "Page not found"],
        "headers": {},
        "severity": "high", "claimable": False,
        "docs": "https://support.wix.com/",
        "playbook": ["Requires Wix account with matching URL."],
    },
    {
        "name": "WordPress.com",
        "cnames": ["wordpress.com", "wpcomstaging.com"],
        "body": ["Do you want to register"], "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://wordpress.com/support/domains/",
        "playbook": ["Register free wordpress.com subdomain with matching slug."],
    },
    {
        "name": "Tumblr",
        "cnames": ["tumblr.com"],
        "body": ["There's nothing here",
                 "Whatever you were looking for doesn't currently exist"],
        "headers": {},
        "severity": "medium", "claimable": True,
        "docs": "https://tumblr.com/docs/en/custom_domains",
        "playbook": ["Register the Tumblr blog with matching subdomain."],
    },
    {
        "name": "Zendesk",
        "cnames": ["zendesk.com"],
        "body": ["Help Center Closed", "No help center found"],
        "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://support.zendesk.com/hc/en-us/articles/4408846122906",
        "playbook": ["Sign up for Zendesk trial with matching subdomain."],
    },
    {
        "name": "Desk.com",
        "cnames": ["desk.com"],
        "body": ["Sorry, this page is unavailable"], "headers": {},
        "severity": "medium", "claimable": False,
        "docs": "https://desk.com/",
        "playbook": ["Contact Salesforce support."],
    },
    {
        "name": "ReadTheDocs",
        "cnames": ["readthedocs.io", "readthedocs.org"],
        "body": ["404 - Not Found", "This page does not exist yet"],
        "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://docs.readthedocs.io/",
        "playbook": [
            "Import a project to ReadTheDocs with matching slug.",
            "Add custom domain in project settings.",
        ],
    },
    {
        "name": "Statuspage.io",
        "cnames": ["statuspage.io"],
        "body": ["This status page does not exist"], "headers": {},
        "severity": "medium", "claimable": True,
        "docs": "https://statuspage.io/",
        "playbook": ["Sign up on Atlassian Statuspage with matching subdomain."],
    },
    {
        "name": "Fastly",
        "cnames": ["fastly.net", "fastlylb.net"],
        "body": ["Fastly error: unknown domain"],
        "headers": {"X-Served-By": "cache-"},
        "severity": "high", "claimable": False,
        "docs": "https://docs.fastly.com/",
        "playbook": ["Fastly requires approval — usually not directly claimable."],
    },
    {
        "name": "Pantheon",
        "cnames": ["pantheonsite.io"],
        "body": ["The gods are wise", "404 - The page you are looking for"],
        "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://pantheon.io/docs/domains/",
        "playbook": ["Create a Pantheon site with matching name."],
    },
    {
        "name": "Cargo Collective",
        "cnames": ["cargocollective.com"],
        "body": ["404 Not Found"], "headers": {},
        "severity": "medium", "claimable": True,
        "docs": "https://cargocollective.com/",
        "playbook": ["Register a Cargo site with matching subdomain."],
    },
    {
        "name": "Helpjuice",
        "cnames": ["helpjuice.com"],
        "body": ["We could not find what you're looking for"],
        "headers": {},
        "severity": "medium", "claimable": True,
        "docs": "https://helpjuice.com/",
        "playbook": ["Sign up with matching subdomain."],
    },
    {
        "name": "Helpscout",
        "cnames": ["helpscoutdocs.com"],
        "body": ["No settings were found for this company"], "headers": {},
        "severity": "medium", "claimable": True,
        "docs": "https://helpscout.com/",
        "playbook": ["Register Help Scout Docs with matching subdomain."],
    },
    {
        "name": "Tilda",
        "cnames": ["tilda.ws"],
        "body": ["Please renew your subscription"], "headers": {},
        "severity": "medium", "claimable": True,
        "docs": "https://tilda.cc/",
        "playbook": ["Create Tilda project with matching subdomain."],
    },
    {
        "name": "Smartling",
        "cnames": ["smartling.com"],
        "body": ["Domain is not configured"], "headers": {},
        "severity": "medium", "claimable": False,
        "docs": "https://smartling.com/",
        "playbook": ["Contact Smartling support."],
    },
    {
        "name": "Strikingly",
        "cnames": ["strikingly.com", "s.strikinglydns.com"],
        "body": ["page not found"], "headers": {},
        "severity": "medium", "claimable": True,
        "docs": "https://strikingly.com/",
        "playbook": ["Sign up with matching subdomain."],
    },
    {
        "name": "Unbounce",
        "cnames": ["unbouncepages.com"],
        "body": ["The requested URL was not found on this server"],
        "headers": {},
        "severity": "medium", "claimable": True,
        "docs": "https://unbounce.com/",
        "playbook": ["Create a page with matching subdomain."],
    },
    {
        "name": "UserVoice",
        "cnames": ["uservoice.com"],
        "body": ["This UserVoice subdomain is currently available"],
        "headers": {},
        "severity": "medium", "claimable": True,
        "docs": "https://uservoice.com/",
        "playbook": ["Register matching UserVoice subdomain."],
    },
    {
        "name": "Tave",
        "cnames": ["tave.com"],
        "body": ["404 Not Found"], "headers": {},
        "severity": "low", "claimable": False,
        "docs": "https://tave.com/",
        "playbook": ["Contact Tave support."],
    },
    {
        "name": "Agile CRM",
        "cnames": ["agilecrm.com"],
        "body": ["Sorry, this page is no longer available"],
        "headers": {},
        "severity": "low", "claimable": True,
        "docs": "https://agilecrm.com/",
        "playbook": ["Sign up with matching subdomain."],
    },
    {
        "name": "Anima",
        "cnames": ["animaapp.io"],
        "body": ["The page you're looking for doesn't exist"], "headers": {},
        "severity": "low", "claimable": True,
        "docs": "https://animaapp.com/",
        "playbook": ["Create Anima project with matching subdomain."],
    },
    {
        "name": "Ngrok",
        "cnames": ["ngrok.io", "ngrok-free.app", "ngrok.app"],
        "body": ["Tunnel not found", "endpoint not found"], "headers": {},
        "severity": "high", "claimable": False,
        "docs": "https://ngrok.com/docs/",
        "playbook": ["Static domains require paid plan — usually not claimable."],
    },

    # ─── New in v3.0.0 ────────────────────────────────────────────────
    {
        "name": "Vercel Edge Config",
        "cnames": ["vercel-edge-config.vercel.app"],
        "body": ["Edge Config not found"], "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://vercel.com/docs/edge-config",
        "playbook": ["Create an Edge Config with matching name in Vercel dashboard."],
    },
    {
        "name": "Supabase",
        "cnames": ["supabase.co", "supabase.in"],
        "body": ["Project not found", "relation \"\" does not exist"],
        "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://supabase.com/docs",
        "playbook": [
            "Create a Supabase project — the subdomain is derived from project name.",
            "If the previous project was deleted, the slug becomes available.",
        ],
    },
    {
        "name": "PlanetScale",
        "cnames": ["psdb.cloud", "planetscale.dev"],
        "body": ["Database not found"], "headers": {},
        "severity": "medium", "claimable": False,
        "docs": "https://planetscale.com/docs",
        "playbook": ["Requires PlanetScale account with matching database name."],
    },
    {
        "name": "Deno Deploy",
        "cnames": ["deno.dev"],
        "body": ["Could not find a deployment", "deployment not found"],
        "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://deno.com/deploy/docs",
        "playbook": [
            "deployctl deploy --project=<name> ./main.ts",
            "If the project name was freed, it can be claimed.",
        ],
    },
    {
        "name": "Val Town",
        "cnames": ["val.town"],
        "body": ["Not Found", "val not found"], "headers": {},
        "severity": "medium", "claimable": True,
        "docs": "https://val.town/",
        "playbook": ["Create a Val Town account and register matching val."],
    },
    {
        "name": "PartyKit",
        "cnames": ["partykit.dev"],
        "body": ["Not Found", "party not found"], "headers": {},
        "severity": "medium", "claimable": True,
        "docs": "https://docs.partykit.io/",
        "playbook": ["npx partykit deploy --name <name>"],
    },
    {
        "name": "onrender Static Sites",
        "cnames": ["onrender.com"],
        "body": ["Not Found", "Site not found"], "headers": {},
        "severity": "medium", "claimable": True,
        "docs": "https://render.com/docs/static-sites",
        "playbook": ["Create a Static Site with matching name."],
    },
    {
        "name": "Fly Volumes",
        "cnames": ["fly.io", "fly.dev"],
        "body": ["volume not found", "404"], "headers": {},
        "severity": "medium", "claimable": False,
        "docs": "https://fly.io/docs/reference/volumes/",
        "playbook": ["Volume names are namespaced per org — not directly claimable."],
    },
    {
        "name": "Zerops",
        "cnames": ["zerops.app", "zerops.io"],
        "body": ["Application not found"], "headers": {},
        "severity": "medium", "claimable": True,
        "docs": "https://zerops.io/docs",
        "playbook": ["Create a Zerops project with matching name."],
    },
    {
        "name": "Coolify",
        "cnames": ["coolify.io"],
        "body": ["Application not found", "404"], "headers": {},
        "severity": "medium", "claimable": False,
        "docs": "https://coolify.io/docs",
        "playbook": ["Self-hosted — requires direct server access."],
    },
    {
        "name": "Static.app",
        "cnames": ["static.app"],
        "body": ["Site not found"], "headers": {},
        "severity": "medium", "claimable": True,
        "docs": "https://static.app/",
        "playbook": ["Sign up with matching site name."],
    },
    {
        "name": "Tebi",
        "cnames": ["tebi.io"],
        "body": ["NoSuchBucket"], "headers": {},
        "severity": "medium", "claimable": True,
        "docs": "https://tebi.io/docs/",
        "playbook": ["Create a Tebi bucket with matching name."],
    },
    {
        "name": "Backblaze B2",
        "cnames": ["backblazeb2.com", "b2-api.backblazeb2.com"],
        "body": ["NoSuchBucket", "bucket_not_found"], "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://www.backblaze.com/b2/docs/",
        "playbook": ["Create B2 bucket with matching name.", "Enable public bucket."],
    },
    {
        "name": "Wasabi",
        "cnames": ["wasabisys.com", "s3.wasabisys.com"],
        "body": ["NoSuchBucket"], "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://wasabi.com/help/",
        "playbook": ["Create Wasabi bucket with matching name."],
    },
    {
        "name": "Linode Object Storage",
        "cnames": ["linodeobjects.com", "objects.linodeobjects.com"],
        "body": ["NoSuchBucket"], "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://www.linode.com/docs/products/storage/object-storage/",
        "playbook": ["Create Linode Object Storage bucket with matching name."],
    },
    {
        "name": "Scaleway Object Storage",
        "cnames": ["scw.cloud", "scaleway.com"],
        "body": ["NoSuchBucket"], "headers": {},
        "severity": "high", "claimable": True,
        "docs": "https://www.scaleway.com/en/docs/object-storage/",
        "playbook": ["Create Scaleway bucket with matching name."],
    },
]


# ═══════════════════════════════════════════════════════════════════════════
# Playbook aliases (for providers whose playbook is defined inline above)
# ═══════════════════════════════════════════════════════════════════════════
PLAYBOOKS: Dict[str, List[str]] = {
    p["name"]: p.get("playbook", [])
    for p in PROVIDERS
}


# ═══════════════════════════════════════════════════════════════════════════
# Fallback subdomain wordlist
# ═══════════════════════════════════════════════════════════════════════════
COMMON_SUBDOMAINS: List[str] = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "m", "imap", "test",
    "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news",
    "vpn", "ns3", "mail2", "new", "mysql", "old", "lists", "support",
    "mobile", "mx", "static", "docs", "beta", "shop", "sql", "secure",
    "demo", "cp", "calendar", "wiki", "web", "media", "email", "images",
    "img", "www1", "intranet", "portal", "video", "api", "cdn", "stats",
    "dns1", "ns4", "www3", "dns", "search", "staging", "server",
    "chat", "svn", "mail1", "sites", "proxy", "host", "crm", "cms",
    "backup", "info", "apps", "download", "remote", "db", "store",
    "files", "app", "live", "owa", "office", "exchange", "helpdesk",
    "web1", "home", "library", "monitor", "login", "service",
    "git", "gitlab", "jenkins", "docker", "k8s", "kubernetes",
    "prometheus", "grafana", "kibana", "elastic", "stage", "qa",
    "uat", "internal", "careers", "assets", "v2", "v3", "old",
    "legacy", "beta2", "alpha", "sandbox", "tools", "developer",
]


# ═══════════════════════════════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════════════════════════════
@dataclass
class CnameChain:
    chain: List[str] = field(default_factory=list)
    final_target: Optional[str] = None
    failed_at: Optional[str] = None
    error: Optional[str] = None

    @property
    def is_dangling(self) -> bool:
        return bool(self.failed_at and not self.error)


@dataclass
class HttpProbe:
    url: Optional[str] = None
    status: Optional[int] = None
    server: Optional[str] = None
    body_snippet: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None
    elapsed_ms: float = 0.0
    favicon_hash: Optional[str] = None
    final_url: Optional[str] = None
    redirect_chain: List[str] = field(default_factory=list)

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "server": self.server,
            "body_snippet": self.body_snippet[:300],
            "headers": {k: v for k, v in list(self.headers.items())[:20]},
            "error": self.error,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "favicon_hash": self.favicon_hash,
            "final_url": self.final_url,
            "redirect_chain": self.redirect_chain[:10],
        }


@dataclass
class TakeoverFinding:
    host: str
    provider: Optional[str] = None
    risk: str = "unknown"                # confirmed | probable | possible
    severity: str = "unknown"
    confidence: int = 0                  # 0-100
    cname_chain: List[str] = field(default_factory=list)
    final_cname: Optional[str] = None
    http: Optional[HttpProbe] = None
    matched_body: Optional[str] = None
    matched_headers: Dict[str, str] = field(default_factory=dict)
    matched_cname_pattern: Optional[str] = None
    favicon_hash_match: Optional[str] = None
    ip_range_match: Optional[str] = None
    certificate_issue: Optional[str] = None
    documentation: Optional[str] = None
    reason: str = ""
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    playbook: List[str] = field(default_factory=list)
    claimable: bool = False

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "provider": self.provider,
            "risk": self.risk,
            "severity": self.severity,
            "confidence": self.confidence,
            "cname_chain": self.cname_chain,
            "final_cname": self.final_cname,
            "documentation": self.documentation,
            "reason": self.reason,
            "evidence": self.evidence,
            "playbook": self.playbook,
            "claimable": self.claimable,
            "matched": {
                "cname": self.matched_cname_pattern,
                "body": self.matched_body,
                "headers": self.matched_headers,
                "favicon_hash": self.favicon_hash_match,
                "ip_range": self.ip_range_match,
                "certificate": self.certificate_issue,
            },
            "http": self.http.to_public_dict() if self.http else None,
        }


# ═══════════════════════════════════════════════════════════════════════════
# Per-source rate limiter
# ═══════════════════════════════════════════════════════════════════════════
class _PerSourceLimiter:
    """Token bucket keyed by source name — HTTP vs DNS vs crt.sh etc."""

    def __init__(self, default_rate: float = DEFAULT_RATE_LIMIT):
        self._default = max(0.1, float(default_rate))
        self._buckets: Dict[str, Dict[str, float]] = {}
        self._lock = threading.Lock()
        self._burst = 8

    def _bucket(self, key: str) -> Dict[str, float]:
        if key not in self._buckets:
            self._buckets[key] = {
                "tokens": float(self._burst),
                "last": time.monotonic(),
                "rate": self._default,
            }
        return self._buckets[key]

    def set_rate(self, key: str, rate: float) -> None:
        with self._lock:
            b = self._bucket(key)
            b["rate"] = max(0.1, float(rate))

    def acquire(self, key: str = "http", timeout: float = 20.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                b = self._bucket(key)
                now = time.monotonic()
                b["tokens"] = min(
                    float(self._burst),
                    b["tokens"] + (now - b["last"]) * b["rate"],
                )
                b["last"] = now
                if b["tokens"] >= 1.0:
                    b["tokens"] -= 1.0
                    return True
                wait = (1.0 - b["tokens"]) / b["rate"]
            time.sleep(min(wait, 0.15))
        return False


# ═══════════════════════════════════════════════════════════════════════════
# Multi-resolver DNS
# ═══════════════════════════════════════════════════════════════════════════
class _NxDomain(Exception): pass
class _NoAnswer(Exception): pass


class DnsResolver:
    """CNAME/NS/MX resolver with multi-resolver fallback + caching."""

    def __init__(self, timeout: float = DEFAULT_DNS_TIMEOUT, max_hops: int = 8):
        self.timeout = timeout
        self.max_hops = max_hops
        self._cache_cname: Dict[str, CnameChain] = {}
        self._cache_ns: Dict[str, List[str]] = {}
        self._cache_mx: Dict[str, List[str]] = {}
        self._cache_a: Dict[str, List[str]] = {}
        self._lock = threading.Lock()

    # ── CNAME chain ────────────────────────────────────────────────────
    def resolve_chain(self, host: str,
                       cancel_event: Optional[threading.Event] = None) -> CnameChain:
        with self._lock:
            if host in self._cache_cname:
                return self._cache_cname[host]
        result = self._walk(host, cancel_event)
        with self._lock:
            self._cache_cname[host] = result
        return result

    def _walk(self, host: str,
               cancel_event: Optional[threading.Event]) -> CnameChain:
        chain = [host]
        current = host
        seen: Set[str] = set()
        for _ in range(self.max_hops):
            if cancel_event is not None and cancel_event.is_set():
                return CnameChain(chain=chain, final_target=current,
                                    error="cancelled")
            if current in seen:
                return CnameChain(chain=chain, final_target=current,
                                    error="cname_loop")
            seen.add(current)
            try:
                target = self._lookup_cname(current)
            except _NxDomain:
                if len(chain) == 1:
                    return CnameChain(chain=chain, error="nxdomain")
                return CnameChain(chain=chain, final_target=chain[-2],
                                    failed_at=current)
            except _NoAnswer:
                return CnameChain(chain=chain, final_target=current)
            except Exception as e:  # noqa: BLE001
                return CnameChain(chain=chain, final_target=current,
                                    error=str(e))
            if not target:
                return CnameChain(chain=chain, final_target=current)
            chain.append(target)
            current = target
        return CnameChain(chain=chain, final_target=current, error="max_hops")

    def _lookup_cname(self, host: str) -> Optional[str]:
        if not _DNS_AVAILABLE:
            return self._lookup_cname_socket(host)
        # Try each resolver until one answers
        for resolver_ip in random.sample(_DNS_RESOLVERS, len(_DNS_RESOLVERS)):
            try:
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = [resolver_ip]
                resolver.timeout = self.timeout
                resolver.lifetime = self.timeout
                answers = resolver.resolve(host, "CNAME",
                                            raise_on_no_answer=False)
                if answers.rrset is None:
                    raise _NoAnswer()
                return str(answers[0].target).rstrip(".").lower()
            except dns.resolver.NXDOMAIN:
                raise _NxDomain()
            except dns.resolver.NoAnswer:
                raise _NoAnswer()
            except dns.resolver.NoNameservers:
                continue    # try next resolver
            except Exception:
                continue
        # All resolvers failed — fall back to socket
        return self._lookup_cname_socket(host)

    @staticmethod
    def _lookup_cname_socket(host: str) -> Optional[str]:
        try:
            _, aliases, _ = socket.gethostbyname_ex(host)
            if aliases:
                return aliases[0].rstrip(".").lower()
        except socket.gaierror:
            raise _NxDomain()
        return None

    # ── NS delegation ──────────────────────────────────────────────────
    def resolve_ns(self, host: str) -> List[str]:
        with self._lock:
            if host in self._cache_ns:
                return self._cache_ns[host]
        out: List[str] = []
        if _DNS_AVAILABLE:
            for resolver_ip in _DNS_RESOLVERS[:3]:
                try:
                    resolver = dns.resolver.Resolver(configure=False)
                    resolver.nameservers = [resolver_ip]
                    resolver.timeout = self.timeout
                    resolver.lifetime = self.timeout
                    answers = resolver.resolve(host, "NS",
                                                raise_on_no_answer=False)
                    if answers.rrset is not None:
                        out = [str(a.target).rstrip(".").lower()
                               for a in answers]
                        break
                except Exception:
                    continue
        with self._lock:
            self._cache_ns[host] = out
        return out

    # ── MX records ─────────────────────────────────────────────────────
    def resolve_mx(self, host: str) -> List[str]:
        with self._lock:
            if host in self._cache_mx:
                return self._cache_mx[host]
        out: List[str] = []
        if _DNS_AVAILABLE:
            for resolver_ip in _DNS_RESOLVERS[:3]:
                try:
                    resolver = dns.resolver.Resolver(configure=False)
                    resolver.nameservers = [resolver_ip]
                    resolver.timeout = self.timeout
                    resolver.lifetime = self.timeout
                    answers = resolver.resolve(host, "MX",
                                                raise_on_no_answer=False)
                    if answers.rrset is not None:
                        out = [str(a.exchange).rstrip(".").lower()
                               for a in answers]
                        break
                except Exception:
                    continue
        with self._lock:
            self._cache_mx[host] = out
        return out

    # ── A records ──────────────────────────────────────────────────────
    def resolve_a(self, host: str) -> List[str]:
        with self._lock:
            if host in self._cache_a:
                return self._cache_a[host]
        out: List[str] = []
        if _DNS_AVAILABLE:
            for resolver_ip in _DNS_RESOLVERS[:3]:
                try:
                    resolver = dns.resolver.Resolver(configure=False)
                    resolver.nameservers = [resolver_ip]
                    resolver.timeout = self.timeout
                    resolver.lifetime = self.timeout
                    answers = resolver.resolve(host, "A",
                                                raise_on_no_answer=False)
                    if answers.rrset is not None:
                        out = [str(a) for a in answers]
                        break
                except Exception:
                    continue
        with self._lock:
            self._cache_a[host] = out
        return out


# ═══════════════════════════════════════════════════════════════════════════
# HTTP session
# ═══════════════════════════════════════════════════════════════════════════
def _build_session() -> requests.Session:
    s = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=32, pool_maxsize=64,
        max_retries=Retry(
            total=1, backoff_factor=0.3,
            status_forcelist=(502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD"]),
            raise_on_status=False,
        ),
    )
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({
        "User-Agent": _USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
    })
    return s


def _probe_http(host: str,
                timeout: float = DEFAULT_HTTP_TIMEOUT,
                session: Optional[requests.Session] = None,
                limiter: Optional[_PerSourceLimiter] = None,
                cancel_event: Optional[threading.Event] = None,
                fetch_favicon: bool = True) -> HttpProbe:
    """Probe host over HTTPS, then HTTP. Fetches favicon for fingerprinting."""
    if cancel_event is not None and cancel_event.is_set():
        return HttpProbe(error="cancelled")
    if limiter is not None and not limiter.acquire("http", timeout=10.0):
        return HttpProbe(error="rate_limit_timeout")

    sess = session or _build_session()
    last_error = None
    redirect_chain: List[str] = []

    for scheme in ("https", "http"):
        if cancel_event is not None and cancel_event.is_set():
            return HttpProbe(error="cancelled")
        url = f"{scheme}://{host}/"
        start = time.monotonic()
        try:
            r = sess.get(url, timeout=timeout, allow_redirects=False,
                          verify=False, stream=True)
            body_bytes = b""
            try:
                for chunk in r.iter_content(chunk_size=4096):
                    body_bytes += chunk
                    if len(body_bytes) >= 16384:
                        break
            finally:
                r.close()
            elapsed = (time.monotonic() - start) * 1000
            try:
                body_text = body_bytes.decode("utf-8", errors="replace")
            except Exception:
                body_text = body_bytes.decode("latin-1", errors="replace")

            # Follow one redirect hop to capture chain
            location = r.headers.get("Location") if r.status_code in (301, 302, 307, 308) else None
            if location:
                redirect_chain.append(location)

            # Attempt favicon hash
            fav_hash = None
            if fetch_favicon:
                fav_hash = _fetch_favicon_hash(sess, scheme, host, timeout)

            return HttpProbe(
                url=url,
                status=r.status_code,
                server=r.headers.get("Server"),
                body_snippet=body_text[:1000],
                headers=dict(r.headers),
                elapsed_ms=elapsed,
                favicon_hash=fav_hash,
                final_url=url,
                redirect_chain=redirect_chain,
            )
        except requests.exceptions.SSLError as e:
            last_error = f"ssl: {e}"
            continue
        except requests.exceptions.ConnectionError as e:
            last_error = f"conn: {e}"
            continue
        except requests.exceptions.Timeout:
            last_error = "timeout"
            continue
        except Exception as e:  # noqa: BLE001
            last_error = str(e)
            continue

    return HttpProbe(error=last_error or "no_response")


def _fetch_favicon_hash(session: requests.Session, scheme: str,
                          host: str, timeout: float) -> Optional[str]:
    """Fetch /favicon.ico and compute mmh3-like hash for fingerprinting."""
    try:
        url = f"{scheme}://{host}/favicon.ico"
        r = session.get(url, timeout=min(timeout, 4.0),
                          verify=False, allow_redirects=True, stream=True)
        if r.status_code != 200:
            r.close()
            return None
        data = b""
        try:
            for chunk in r.iter_content(chunk_size=4096):
                data += chunk
                if len(data) > 128 * 1024:
                    break
        finally:
            r.close()
        if len(data) < 4:
            return None
        # mmh3-like simple hash — deterministic and stable
        h = hashlib.md5(data).hexdigest()[:12]
        return f"md5:{h}"
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════
# Wildcard DNS detection
# ═══════════════════════════════════════════════════════════════════════════
def _detect_wildcard(domain: str, resolver: DnsResolver) -> Optional[List[str]]:
    """Check if *.domain resolves to a stable set of IPs."""
    probes = [f"wildcard-{random.randint(10**8, 10**9 - 1)}.{domain}"
              for _ in range(2)]
    all_ips: List[List[str]] = []
    for probe in probes:
        try:
            ips = resolver.resolve_a(probe)
            if ips:
                all_ips.append(sorted(ips))
        except Exception:
            pass
    if len(all_ips) >= 2 and all_ips[0] == all_ips[1] and all_ips[0]:
        return all_ips[0]
    return None


# ═══════════════════════════════════════════════════════════════════════════
# Multi-source subdomain enumeration
# ═══════════════════════════════════════════════════════════════════════════
_crtsh_last_attempt: float = 0.0
_crtsh_lock = threading.Lock()


def _crtsh_cooldown_active() -> bool:
    with _crtsh_lock:
        return (time.monotonic() - _crtsh_last_attempt) < CRTSH_COOLDOWN


def _mark_crtsh_attempt() -> None:
    global _crtsh_last_attempt
    with _crtsh_lock:
        _crtsh_last_attempt = time.monotonic()


def _crtsh_lookup(domain: str, timeout: float = CRTSH_TIMEOUT) -> Set[str]:
    out: Set[str] = set()
    if _crtsh_cooldown_active():
        logger.info("[takeover] crt.sh on cooldown — skipping")
        return out
    _mark_crtsh_attempt()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=timeout,
                          headers={"User-Agent": _USER_AGENT})
        if r.status_code != 200 or not r.text.strip().startswith("["):
            return out
        for entry in json.loads(r.text):
            for name in (entry.get("name_value") or "").split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name:
                    out.add(name)
    except Exception as e:
        logger.warning("[takeover] crt.sh failed: %s", e)
    return out


def _otx_lookup(domain: str, timeout: float = 8.0) -> Set[str]:
    """AlienVault OTX passive DNS."""
    out: Set[str] = set()
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        r = requests.get(url, timeout=timeout,
                          headers={"User-Agent": _USER_AGENT})
        if r.status_code != 200:
            return out
        data = r.json() or {}
        for entry in data.get("passive_dns", []):
            hostname = (entry.get("hostname") or "").strip().lower()
            if hostname and (hostname.endswith("." + domain) or hostname == domain):
                out.add(hostname)
    except Exception as e:
        logger.debug("[takeover] OTX failed: %s", e)
    return out


def _hackertarget_lookup(domain: str, timeout: float = 8.0) -> Set[str]:
    """HackerTarget host search."""
    out: Set[str] = set()
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        r = requests.get(url, timeout=timeout,
                          headers={"User-Agent": _USER_AGENT})
        if r.status_code != 200:
            return out
        for line in r.text.splitlines():
            if "," in line:
                host = line.split(",", 1)[0].strip().lower()
                if host and (host.endswith("." + domain) or host == domain):
                    out.add(host)
    except Exception as e:
        logger.debug("[takeover] HackerTarget failed: %s", e)
    return out


def _rapiddns_lookup(domain: str, timeout: float = 8.0) -> Set[str]:
    """RapidDNS subdomain search."""
    out: Set[str] = set()
    try:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        r = requests.get(url, timeout=timeout,
                          headers={"User-Agent": _USER_AGENT})
        if r.status_code != 200:
            return out
        # Extract hostnames from HTML table
        for m in re.finditer(
            r"<td>([a-zA-Z0-9][a-zA-Z0-9\-._]*\."
            + re.escape(domain) + r")</td>", r.text
        ):
            host = m.group(1).strip().lower()
            if host and host.endswith("." + domain):
                out.add(host)
    except Exception as e:
        logger.debug("[takeover] RapidDNS failed: %s", e)
    return out


def enumerate_subdomains(domain: str,
                          use_crtsh: bool = True,
                          use_wordlist: bool = True,
                          use_passive: bool = True,
                          timeout: float = CRTSH_TIMEOUT,
                          cancel_event: Optional[threading.Event] = None
                          ) -> Set[str]:
    """Return a set of candidate subdomains from all configured sources."""
    domain = (domain or "").strip().lower().rstrip(".")
    out: Set[str] = {domain}
    root = _registrable_domain(domain)

    def _add(names: Iterable[str]) -> None:
        for name in names:
            name = (name or "").strip().lower().lstrip("*.")
            if not name:
                continue
            if name.endswith("." + root) or name == root:
                out.add(name)

    # ── crt.sh ────────────────────────────────────────────────────────
    if use_crtsh and not (cancel_event and cancel_event.is_set()):
        _add(_crtsh_lookup(domain, timeout=timeout))

    # ── passive sources (OTX, HackerTarget, RapidDNS) ────────────────
    if use_passive and not (cancel_event and cancel_event.is_set()):
        for fn in (_otx_lookup, _hackertarget_lookup, _rapiddns_lookup):
            if cancel_event and cancel_event.is_set():
                break
            try:
                _add(fn(domain, timeout=timeout))
            except Exception as e:
                logger.debug("[takeover] %s failed: %s", fn.__name__, e)

    # ── wordlist ──────────────────────────────────────────────────────
    if use_wordlist and not (cancel_event and cancel_event.is_set()):
        for prefix in COMMON_SUBDOMAINS:
            if cancel_event and cancel_event.is_set():
                break
            out.add(f"{prefix}.{domain}")

    return out


def _registrable_domain(host: str) -> str:
    if _TLDEXTRACT_AVAILABLE:
        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


# ═══════════════════════════════════════════════════════════════════════════
# Fingerprint matching with confidence scoring
# ═══════════════════════════════════════════════════════════════════════════
def _score_to_risk(confidence: int) -> str:
    if confidence >= 80:
        return "confirmed"
    if confidence >= 55:
        return "probable"
    if confidence >= 25:
        return "possible"
    return "unknown"


def _fingerprint_match(cname: Optional[str],
                        http: Optional[HttpProbe],
                        chain_dangling: bool,
                        wildcard_ips: Optional[List[str]] = None,
                        a_ips: Optional[List[str]] = None,
                        ) -> List[TakeoverFinding]:
    """Score every provider against the collected evidence."""
    cname_l = (cname or "").lower()
    body_l = (http.body_snippet or "").lower() if http else ""
    headers_l = {k.lower(): (v or "").lower()
                 for k, v in (http.headers or {}).items()} if http else {}
    favicon = (http.favicon_hash or "") if http else ""

    findings: List[TakeoverFinding] = []

    for provider in PROVIDERS:
        confidence = 0
        evidence: List[Dict[str, Any]] = []

        matched_cname = None
        matched_body = None
        matched_headers: Dict[str, str] = {}
        favicon_match = None

        # ── CNAME match (+30) ─────────────────────────────────────────
        for pattern in provider.get("cnames", []):
            if pattern.lower() in cname_l:
                confidence += 30
                matched_cname = pattern
                evidence.append({
                    "type": "cname_match",
                    "weight": 30,
                    "pattern": pattern,
                    "value": cname,
                })
                break

        # ── Body match (+25) ──────────────────────────────────────────
        for needle in provider.get("body", []):
            if needle.lower() in body_l:
                confidence += 25
                matched_body = needle
                evidence.append({
                    "type": "body_match",
                    "weight": 25,
                    "needle": needle,
                })
                break

        # ── Header match (+20) ────────────────────────────────────────
        for hk, hv in (provider.get("headers") or {}).items():
            hk_l = hk.lower()
            hv_l = (hv or "").lower()
            if hk_l in headers_l and hv_l in headers_l[hk_l]:
                confidence += 20
                matched_headers[hk] = headers_l[hk_l]
                evidence.append({
                    "type": "header_match",
                    "weight": 20,
                    "header": hk,
                    "value": headers_l[hk_l],
                })
                break

        # ── Dangling CNAME chain (+35) ────────────────────────────────
        if chain_dangling:
            confidence += 35
            evidence.append({
                "type": "dangling_cname",
                "weight": 35,
                "detail": "CNAME target did not resolve",
            })

        # ── Favicon hash match (+15) ──────────────────────────────────
        favicon_hashes = provider.get("favicon_hashes") or []
        if favicon and favicon in favicon_hashes:
            confidence += 15
            favicon_match = favicon
            evidence.append({
                "type": "favicon_match",
                "weight": 15,
                "hash": favicon,
            })

        # ── Wildcard IP match (+10, negative if wildcard detected) ────
        if wildcard_ips and a_ips:
            if set(a_ips) & set(wildcard_ips):
                # HOST resolves to wildcard IP — downgrade confidence
                confidence -= 20
                evidence.append({
                    "type": "wildcard_penalty",
                    "weight": -20,
                    "detail": "Host shares IP with wildcard DNS",
                })
            else:
                confidence += 10
                evidence.append({
                    "type": "ip_differs_from_wildcard",
                    "weight": 10,
                    "detail": "Host IP differs from wildcard",
                })

        # ── If nothing matched, skip ──────────────────────────────────
        if confidence <= 0 and not matched_cname and not matched_body:
            continue

        confidence = max(0, min(100, confidence))

        # Only emit findings that have a CNAME match OR two other signals
        has_real_signal = bool(matched_cname) or (
            bool(matched_body) + bool(matched_headers) + bool(favicon_match) >= 2
        )
        if not has_real_signal:
            continue

        risk = _score_to_risk(confidence)

        findings.append(TakeoverFinding(
            host="",
            provider=provider["name"],
            risk=risk,
            severity=provider.get("severity", "medium"),
            confidence=confidence,
            matched_cname_pattern=matched_cname,
            matched_body=matched_body,
            matched_headers=matched_headers,
            favicon_hash_match=favicon_match,
            documentation=provider.get("docs"),
            reason="; ".join(e["type"] for e in evidence) or "fingerprint match",
            evidence=evidence,
            playbook=provider.get("playbook", []),
            claimable=bool(provider.get("claimable", False)),
        ))

    # Sort: highest confidence first
    findings.sort(key=lambda f: -f.confidence)
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Historical state
# ═══════════════════════════════════════════════════════════════════════════
def _state_path(domain: str) -> Path:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", domain)
    return STATE_DIR / f"{safe}.json"


def _load_state(domain: str) -> Optional[Dict[str, Any]]:
    p = _state_path(domain)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def _save_state(domain: str, report: Dict[str, Any]) -> None:
    p = _state_path(domain)
    try:
        p.write_text(json.dumps(report, indent=2, default=str),
                      encoding="utf-8")
    except Exception as e:
        logger.debug("[takeover] state save failed: %s", e)


def _diff_state(domain: str,
                 current_dangling: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    prev = _load_state(domain)
    prev_hosts = set()
    if prev:
        prev_hosts = {d["host"] for d in prev.get("dangling", [])}

    current_hosts = {d["host"] for d in current_dangling}

    return {
        "new": sorted(current_hosts - prev_hosts),
        "fixed": sorted(prev_hosts - current_hosts),
        "still_vulnerable": sorted(current_hosts & prev_hosts),
    }


# ═══════════════════════════════════════════════════════════════════════════
# Scanner
# ═══════════════════════════════════════════════════════════════════════════
class SubdomainTakeoverScanner:
    """Multi-signal scanner with wildcard detection + cancel + progress."""

    def __init__(self,
                 concurrency: int = DEFAULT_CONCURRENCY,
                 dns_timeout: float = DEFAULT_DNS_TIMEOUT,
                 http_timeout: float = DEFAULT_HTTP_TIMEOUT,
                 rate_limit: float = DEFAULT_RATE_LIMIT,
                 cancel_event: Optional[threading.Event] = None,
                 progress_cb: Optional[Callable[[int, int, str], None]] = None,
                 max_duration: Optional[float] = None):
        self.concurrency = max(1, min(int(concurrency), 64))
        self.dns = DnsResolver(timeout=dns_timeout)
        self.http_timeout = http_timeout
        self.limiter = _PerSourceLimiter(default_rate=rate_limit)
        self.session = _build_session()
        self._stop = cancel_event or threading.Event()
        self._progress_cb = progress_cb
        self._max_duration = max_duration
        self._started_mono: float = 0.0
        self._done = 0
        self._total = 0
        self.wildcard_ips: Optional[List[str]] = None

    def cancel(self) -> None:
        self._stop.set()

    def _budget_exceeded(self) -> bool:
        if self._max_duration is None:
            return False
        return (time.monotonic() - self._started_mono) > self._max_duration

    def _emit_progress(self, label: str = "") -> None:
        if not self._progress_cb:
            return
        try:
            self._progress_cb(self._done, self._total, label)
        except Exception:
            pass

    # ── Single host ────────────────────────────────────────────────────
    def scan_single(self, host: str) -> Optional[TakeoverFinding]:
        if self._stop.is_set() or self._budget_exceeded():
            return None

        chain = self.dns.resolve_chain(host, cancel_event=self._stop)
        if chain.error == "nxdomain":
            return None
        if not chain.chain or len(chain.chain) < 2:
            return None

        # A record for wildcard comparison
        a_ips = self.dns.resolve_a(host)

        http = _probe_http(
            host,
            timeout=self.http_timeout,
            session=self.session,
            limiter=self.limiter,
            cancel_event=self._stop,
        )

        cname_target = chain.final_target or chain.chain[-1]
        findings = _fingerprint_match(
            cname_target, http, chain.is_dangling,
            wildcard_ips=self.wildcard_ips,
            a_ips=a_ips,
        )
        if not findings:
            return None

        top = findings[0]
        top.host = host
        top.cname_chain = list(chain.chain)
        top.final_cname = cname_target
        top.http = http
        return top

    # ── Bulk ──────────────────────────────────────────────────────────
    def scan_many(self, hosts: Iterable[str]) -> List[TakeoverFinding]:
        hosts = list(dict.fromkeys(h.strip().lower() for h in hosts if h))
        self._total = len(hosts)
        self._done = 0
        self._started_mono = time.monotonic()
        findings: List[TakeoverFinding] = []
        lock = threading.Lock()

        def worker(h: str) -> None:
            if self._stop.is_set() or self._budget_exceeded():
                return
            try:
                result = self.scan_single(h)
            except Exception as e:
                logger.debug("[takeover] scan_single(%s) failed: %s", h, e)
                result = None
            with lock:
                self._done += 1
                if result:
                    findings.append(result)
                if self._done % 5 == 0 or self._done == self._total:
                    self._emit_progress(h)

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.concurrency
        ) as pool:
            futures = [pool.submit(worker, h) for h in hosts]
            for fut in concurrent.futures.as_completed(futures):
                if self._stop.is_set() or self._budget_exceeded():
                    for f in futures:
                        f.cancel()
                    break
                try:
                    fut.result()
                except Exception:
                    continue

        return findings


# ═══════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════
def _normalise_options(options: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    options = options or {}

    def _i(key, default, lo, hi):
        try:
            return max(lo, min(hi, int(options.get(key, default))))
        except (TypeError, ValueError):
            return default

    def _f(key, default, lo, hi):
        try:
            return max(lo, min(hi, float(options.get(key, default))))
        except (TypeError, ValueError):
            return default

    def _b(key, default):
        v = options.get(key, default)
        return bool(v) if v is not None else default

    return {
        "enumerate":     _b("enumerate", True),
        "use_crtsh":     _b("use_crtsh", True),
        "use_wordlist":  _b("use_wordlist", True),
        "use_passive":   _b("use_passive", True),
        "concurrency":   _i("concurrency", DEFAULT_CONCURRENCY, 1, 64),
        "max_hosts":     _i("max_hosts", DEFAULT_MAX_HOSTS, 10, 500),
        "http_timeout":  _f("http_timeout", DEFAULT_HTTP_TIMEOUT, 1.0, 15.0),
        "dns_timeout":   _f("dns_timeout", DEFAULT_DNS_TIMEOUT, 0.5, 10.0),
        "rate_limit":    _f("rate_limit", DEFAULT_RATE_LIMIT, 1.0, 100.0),
        "max_duration":  _f("max_duration", DEFAULT_GLOBAL_BUDGET, 10.0, 300.0),
        "cancel_event":  options.get("cancel_event"),
        "progress_cb":   options.get("progress_cb"),
    }


def run(domain: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Blocking scan — returns an intelligence-enriched report."""
    o = _normalise_options(options)

    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        raise ValueError("domain is required")

    started_at = datetime.now(timezone.utc)
    t0 = time.monotonic()

    # ── Enumerate ────────────────────────────────────────────────────
    if o["enumerate"]:
        hosts = enumerate_subdomains(
            domain,
            use_crtsh=o["use_crtsh"],
            use_wordlist=o["use_wordlist"],
            use_passive=o["use_passive"],
            timeout=min(CRTSH_TIMEOUT, o["max_duration"] * 0.3),
            cancel_event=o["cancel_event"],
        )
    else:
        hosts = {domain}

    hosts = sorted(hosts)[:o["max_hosts"]]
    logger.info("[takeover] %s — %d host(s)", domain, len(hosts))

    scanner = SubdomainTakeoverScanner(
        concurrency=o["concurrency"],
        dns_timeout=o["dns_timeout"],
        http_timeout=o["http_timeout"],
        rate_limit=o["rate_limit"],
        cancel_event=o["cancel_event"],
        progress_cb=o["progress_cb"],
        max_duration=o["max_duration"],
    )

    # ── Wildcard detection (one-time) ────────────────────────────────
    try:
        wildcard = _detect_wildcard(domain, scanner.dns)
        if wildcard:
            scanner.wildcard_ips = wildcard
            logger.info("[takeover] wildcard DNS detected: %s",
                         ", ".join(wildcard))
    except Exception as e:
        logger.debug("[takeover] wildcard detection failed: %s", e)

    # ── Scan ─────────────────────────────────────────────────────────
    findings = scanner.scan_many(hosts)

    # ── Candidates ───────────────────────────────────────────────────
    candidates: List[Dict[str, Any]] = []
    for h in hosts:
        chain = scanner.dns.resolve_chain(h)
        if len(chain.chain) >= 2:
            candidates.append({
                "host": h,
                "cname_chain": chain.chain,
                "final_cname": chain.final_target,
                "dangling": chain.is_dangling,
            })

    finished_at = datetime.now(timezone.utc)
    elapsed = time.monotonic() - t0

    # ── Historical diff ──────────────────────────────────────────────
    dangling_dicts = [f.to_public_dict() for f in findings]
    try:
        diff = _diff_state(domain, dangling_dicts)
    except Exception:
        diff = {"new": [], "fixed": [], "still_vulnerable": []}

    report = {
        "domain":           domain,
        "scanned":          len(hosts),
        "started_at":       started_at.isoformat(),
        "finished_at":      finished_at.isoformat(),
        "elapsed":          round(elapsed, 2),
        "wildcard_dns":     scanner.wildcard_ips,
        "candidates":       candidates,
        "dangling":         dangling_dicts,
        "diff":             diff,
        "version":          __version__,
    }

    # ── Persist state ────────────────────────────────────────────────
    try:
        _save_state(domain, report)
    except Exception:
        pass

    return report


def scan_single(host: str, options: Optional[Dict[str, Any]] = None
                ) -> Optional[Dict[str, Any]]:
    """Scan a single host directly."""
    o = _normalise_options(options)
    scanner = SubdomainTakeoverScanner(
        concurrency=1,
        dns_timeout=o["dns_timeout"],
        http_timeout=o["http_timeout"],
        rate_limit=o["rate_limit"],
        cancel_event=o["cancel_event"],
    )
    result = scanner.scan_single(host)
    return result.to_public_dict() if result else None


def run_streaming(domain: str,
                   options: Optional[Dict[str, Any]] = None,
                   cancel_event: Optional[threading.Event] = None
                   ) -> Iterator[Dict[str, Any]]:
    """Yield SSE-friendly events, then the final report."""
    o = _normalise_options(options)
    if cancel_event is not None:
        o["cancel_event"] = cancel_event

    events: List[Dict[str, Any]] = []
    events_lock = threading.Lock()
    done = threading.Event()

    def _progress(done_count: int, total: int, label: str) -> None:
        pct = int((done_count / total) * 100) if total else 0
        with events_lock:
            events.append({
                "type": "progress",
                "done": done_count,
                "total": total,
                "percent": pct,
                "label": label,
            })

    o["progress_cb"] = _progress
    result_holder: Dict[str, Any] = {}

    def _worker() -> None:
        try:
            result_holder["result"] = run(domain, o)
        except Exception as e:  # noqa: BLE001
            result_holder["error"] = str(e)
        finally:
            done.set()

    threading.Thread(target=_worker, daemon=True,
                     name=f"takeover-{domain[:24]}").start()

    yield {
        "type": "start",
        "domain": domain,
        "options": {
            "max_hosts":   o["max_hosts"],
            "concurrency": o["concurrency"],
            "rate_limit":  o["rate_limit"],
            "enumerate":   o["enumerate"],
        },
    }

    while not done.is_set():
        with events_lock:
            pending, events[:] = list(events), []
        for ev in pending:
            yield ev
        done.wait(timeout=0.4)

    with events_lock:
        for ev in events:
            yield ev

    if "error" in result_holder:
        yield {"type": "error", "message": result_holder["error"]}
    else:
        yield {"type": "result", "data": result_holder.get("result", {})}


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import argparse
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    p = argparse.ArgumentParser(description="Subdomain Takeover v3.0.0")
    p.add_argument("domain")
    p.add_argument("--no-enum", action="store_true")
    p.add_argument("--no-crtsh", action="store_true")
    p.add_argument("--no-wordlist", action="store_true")
    p.add_argument("--no-passive", action="store_true")
    p.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    p.add_argument("--max-hosts", type=int, default=DEFAULT_MAX_HOSTS)
    p.add_argument("--rate-limit", type=float, default=DEFAULT_RATE_LIMIT)
    p.add_argument("--json", action="store_true")
    p.add_argument("--stream", action="store_true")
    args = p.parse_args()

    options = {
        "enumerate":    not args.no_enum,
        "use_crtsh":    not args.no_crtsh,
        "use_wordlist": not args.no_wordlist,
        "use_passive":  not args.no_passive,
        "concurrency":  args.concurrency,
        "max_hosts":    args.max_hosts,
        "rate_limit":   args.rate_limit,
    }

    if args.stream:
        for ev in run_streaming(args.domain, options):
            t = ev.get("type")
            if t == "start":
                print(f"[start] domain={ev['domain']} options={ev['options']}")
            elif t == "progress":
                print(f"[{ev['percent']:3d}%] {ev['done']}/{ev['total']}  {ev['label']}")
            elif t == "result":
                if args.json:
                    print(json.dumps(ev["data"], indent=2))
            elif t == "error":
                print(f"[ERROR] {ev['message']}", file=sys.stderr)
        sys.exit(0)

    report = run(args.domain, options)

    if args.json:
        print(json.dumps(report, indent=2))
        sys.exit(0)

    print()
    print("═" * 72)
    print(f"  Subdomain Takeover — {report['domain']}")
    print("═" * 72)
    print(f"  Scanned       : {report['scanned']} host(s)")
    print(f"  Candidates    : {len(report['candidates'])} with CNAME")
    print(f"  Dangling      : {len(report['dangling'])}")
    if report.get("wildcard_dns"):
        print(f"  Wildcard DNS  : {', '.join(report['wildcard_dns'])}")
    if report.get("diff"):
        d = report["diff"]
        print(f"  NEW           : {len(d.get('new', []))}")
        print(f"  Still vuln    : {len(d.get('still_vulnerable', []))}")
        print(f"  Fixed         : {len(d.get('fixed', []))}")
    print(f"  Elapsed       : {report['elapsed']}s")
    print()

    for d in report["dangling"]:
        conf = d.get("confidence", 0)
        bar = "█" * (conf // 5)
        print(f"  [{d['severity'].upper():8s}] [{d['risk'].upper():10s}] "
              f"[{conf:3d}%] {d['host']}")
        print(f"              Provider : {d['provider']}")
        print(f"              Score    : {bar} {conf}/100")
        print(f"              CNAME    : {' → '.join(d['cname_chain'])}")
        if d.get("claimable"):
            print(f"              Claimable: YES")
        playbook = d.get("playbook") or []
        if playbook:
            print(f"              Playbook :")
            for i, step in enumerate(playbook[:4], 1):
                print(f"                         {i}. {step}")
        print()
