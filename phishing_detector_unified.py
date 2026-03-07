#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║              UNIFIED PHISHING WEBSITE DETECTOR v2.0                  ║
╠══════════════════════════════════════════════════════════════════════╣
║  Module 01 · SSL/TLS Certificate Analyzer                            ║
║  Module 02 · URL Feature Scorer (16-feature weighted model)          ║
║  Module 03 · TLD / Token Checker                                     ║
║  Module 04 · Unicode / Suspicious Character Checker                  ║
║  Module 05 · IP / WHOIS / ASN Analyzer                               ║
║  Module 06 · Permission API Scanner (static)                         ║
║  Module 07 · CAPTCHA / Login Content Checker (Playwright)            ║
║  Module 08 · Autofill / Hidden Form Field Scanner                    ║
║  Module 09 · Fake CAPTCHA Validator (Selenium)                       ║
║  Module 10 · OTP Security Checker (seleniumwire)                     ║
║  Module 11 · URL Scheme Checker                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  Core deps  : pip install requests beautifulsoup4 cryptography       ║
║               ipwhois lxml                                           ║
║  Browser    : pip install selenium seleniumwire playwright           ║
║               python -m playwright install                           ║
║  ChromeDriver must be on PATH for Selenium modules (8, 9, 10)        ║
╚══════════════════════════════════════════════════════════════════════╝
"""

# ── stdlib ──────────────────────────────────────────────────────────
import re, sys, ssl, math, socket, datetime, ipaddress
import importlib, subprocess, fnmatch, json, time, random
from urllib.parse  import urlparse, unquote, urljoin
from urllib.error  import URLError, HTTPError
import urllib.request
from difflib       import SequenceMatcher

# ════════════════════════════════════════════════════════════════════
# ANSI COLORS
# ════════════════════════════════════════════════════════════════════
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def c(text, col):   return f"{col}{text}{RESET}"
def ok(msg):        return c(f"✔  {msg}", GREEN)
def warn(msg):      return c(f"⚠  {msg}", YELLOW)
def bad(msg):       return c(f"✖  {msg}", RED)
def info(msg):      return c(f"ℹ  {msg}", CYAN)

def section(title):
    print(f"\n{BOLD}{'─'*68}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'─'*68}{RESET}")

def progress(msg):
    print(c(f"  ⟳ {msg} …", DIM), flush=True)

# ════════════════════════════════════════════════════════════════════
# SHARED UTILITIES
# ════════════════════════════════════════════════════════════════════
def normalize_url(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    return url

def extract_hostname(url: str) -> str:
    return (urlparse(normalize_url(url)).hostname or "").lower()

def ensure_pkg(name, pip_name=None):
    try:
        return importlib.import_module(name)
    except ImportError:
        pkg = pip_name or name
        print(info(f"Installing {pkg} …"))
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return importlib.import_module(name)


# ════════════════════════════════════════════════════════════════════
# MODULE 11 · URL SCHEME CHECKER  (fastest — run first as gate)
# ════════════════════════════════════════════════════════════════════
def run_scheme_module(url: str) -> dict:
    """Flag any non-HTTPS scheme as an immediate risk signal."""
    result = {"module": "URL Scheme Checker", "score": 0, "flags": [], "info": {}}
    parsed = urlparse(normalize_url(url))
    original_parsed = urlparse(url)
    scheme = (original_parsed.scheme or "http").lower()

    result["info"]["scheme"]   = scheme
    result["info"]["hostname"] = parsed.hostname or ""

    if scheme == "https":
        result["score"] = 0
        result["flags"].append((ok("HTTPS scheme — encrypted transport"), GREEN))
    elif scheme == "http":
        result["score"] = 35
        result["flags"].append((bad("Plain HTTP — no encryption, easily intercepted"), RED))
    else:
        result["score"] = 50
        result["flags"].append((bad(f"Non-standard scheme '{scheme}' — highly suspicious"), RED))
    return result


# ════════════════════════════════════════════════════════════════════
# MODULE 03 · TLD / TOKEN CHECKER
# ════════════════════════════════════════════════════════════════════
SUSPICIOUS_TLDS = {
    "tk","ml","ga","cf","gq","pw","xyz","top","club","online","site","website",
    "win","work","loan","review","trade","click","info","biz","tech","store",
    "space","vip","press","party","download","host","live","ru","cn","cc","su",
    "me","io","ly","to","im","fm","tv","pro","link","fun","one","ooo","news",
    "social","support","account","security","bank","email","login","update",
    "verify","cloud","icu","men","country","kim","buzz","fit","date","faith",
    "racing","science","bid","zip","mov","rest","love","cam","bet","monster",
    "surf","uno","cyou","tk","ml","ga","cf","gq","pw","xyz","top","club","online","site",
"website","win","work","loan","review","trade","click","info","biz",
"tech","store","space","vip","press","party","download","host","live",
"ru","cn","cc","su","me","io","ly","to","im","fm","tv","pro",
"name","mobi","asia","tel","link","fun","one","ooo","news",
"social","support","account","security","bank","email","login",
"update","verify","cloud","guru","today","digital","center",
"company","solutions","services","group","world","network","systems",
"media","life","city","academy","shop","cash","icu","men","country",
"kim","buzz","fit","date","faith","racing","science","bid",
"accountants","accountant","zip","mov","rest","love","beauty","hair",
"makeup","pics","guide","cam","bet","monster","surf","uno","cyou"
}

def run_tld_module(hostname: str) -> dict:
    result = {"module": "TLD / Token Checker", "score": 0, "flags": [], "info": {}}
    try:
        decoded = hostname.encode("ascii").decode("idna")
    except Exception:
        decoded = hostname

    labels  = [l for l in decoded.split(".") if l]
    matches = []
    for lbl in labels:
        if lbl in SUSPICIOUS_TLDS:
            matches.append((lbl, lbl, "exact"))
        else:
            for tok in SUSPICIOUS_TLDS:
                if tok and tok in lbl:
                    matches.append((lbl, tok, "substring")); break

    if matches:
        result["score"] = min(20 * len(matches), 60)
        for lbl, tok, mtype in matches:
            result["flags"].append((f"Label '{lbl}' matches suspicious token '{tok}' ({mtype})", YELLOW))
    else:
        result["flags"].append(("No suspicious TLD/token patterns detected", GREEN))
    result["info"] = {"decoded_hostname": decoded, "matches": matches}
    return result


# ════════════════════════════════════════════════════════════════════
# MODULE 04 · UNICODE / SUSPICIOUS CHARACTER CHECKER
# ════════════════════════════════════════════════════════════════════
_RAW = """ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩαβγδεζηθικλμνξοπρσςτυφχψω
¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿×÷•…–—―′″''""\u2039\u203a‣․‥‐‒€₹₿₩₪₫₭₱
√∞≈≠≤≥∑∏∂∆∇∫∴∵∩∪⊂⊃⊆⊇⊕⊗"""
_SUSP_CHARS = set(_RAW.replace("\n",""))

def run_char_module(hostname: str) -> dict:
    result = {"module": "Unicode / Char Checker", "score": 0, "flags": [], "info": {}}
    try:
        decoded = hostname.encode("utf-8").decode("idna")
    except Exception:
        decoded = hostname

    bad_labels = []
    for label in decoded.split("."):
        if not label: continue
        reasons = []
        if re.search(r"\d", label):
            reasons.append("contains digit(s)")
        hits = [ch for ch in label if ch in _SUSP_CHARS]
        for ch in hits:
            reasons.append(f"lookalike/special char '{ch}' (U+{ord(ch):04X})")
        if reasons:
            bad_labels.append({"label": label, "reasons": reasons})

    if bad_labels:
        result["score"] = min(20 * len(bad_labels), 50)
        for item in bad_labels:
            result["flags"].append((
                f"Label '{item['label']}': {'; '.join(item['reasons'][:3])}", YELLOW))
    else:
        result["flags"].append(("No suspicious Unicode or special characters found", GREEN))
    result["info"] = {"decoded_hostname": decoded, "suspicious_labels": bad_labels}
    return result


# ════════════════════════════════════════════════════════════════════
# MODULE 05 · IP / WHOIS / ASN ANALYZER
# ════════════════════════════════════════════════════════════════════
def run_ip_module(hostname: str) -> dict:
    result = {"module": "IP / WHOIS Analyzer", "score": 0, "flags": [], "info": {}}
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror as e:
        result["error"] = f"DNS resolution failed: {e}"; return result

    result["info"]["ip"] = ip
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            result["score"] = 40
            result["flags"].append(("Private/local IP — spoofed or internal", RED)); return result
        if ip_obj.is_reserved:
            result["score"] = 30
            result["flags"].append(("Reserved IP address", RED)); return result
    except Exception:
        pass

    try:
        rev, _, _ = socket.gethostbyaddr(ip)
    except Exception:
        rev = None
    result["info"]["reverse_dns"] = rev or "None"

    asn = country = desc = "Unknown"
    try:
        from ipwhois import IPWhois
        data    = IPWhois(ip).lookup_rdap(asn_methods=["whois"])
        asn     = data.get("asn","Unknown")
        country = data.get("asn_country_code","Unknown")
        desc    = data.get("asn_description","Unknown")
    except Exception:
        pass
    result["info"].update({"asn": asn, "country": country, "asn_desc": desc})

    score = 0
    if any(t in desc.lower() for t in ["hosting","vpn","vps","cloud","colo","reseller"]):
        score += 2
    high_abuse = {"RU","CN","KP","IR","VN","TR","BR"}
    if country in high_abuse:
        score += 2; result["flags"].append((f"High-abuse-rate country: {country}", YELLOW))
    if any(t in (rev or "").lower() for t in ["vps","cloud","dedicated","dynamic","host","server"]):
        score += 2; result["flags"].append(("Suspicious reverse-DNS pattern", YELLOW))
    elif not rev:
        score += 1; result["flags"].append(("No reverse DNS (PTR) record", YELLOW))
    if score == 0:
        result["flags"].append(("IP/ASN profile looks normal", GREEN))
    result["score"] = min(score * 15, 60)
    return result


# ════════════════════════════════════════════════════════════════════
# MODULE 02 · URL FEATURE SCORER
# ════════════════════════════════════════════════════════════════════
URL_SHORTENERS = {
    "bit.ly","t.co","tinyurl.com","goo.gl","ow.ly","buff.ly","adf.ly","bit.do",
    "mcaf.ee","is.gd","soo.gd","s.id","lc.chat","cutt.ly","shorte.st","po.st",
    "rebrand.ly","t.ly","v.gd","qr.ae","trib.al","shorturl.at","lnkd.in","tiny.cc",
    "urlz.fr","clck.ru","u.to","ift.tt","rb.gy","chilp.it","ouo.io","t2m.io",
    "clk.im","1url.com","fb.me","j.mp","ity.im","zi.ma","x.co","prn.to","tiny.pl",
    "short.cm","short.io","sharelink.to","cur.lv","lnk.co","haz.gd","shorturl.com",
    "lnk.to","snip.ly","snipr.com","shrlink.net","smarturl.it","go.shr.lc","adfoc.us",
    "bl.ink","bc.vc","fy.gg","yourls.org","su.pr","viid.me","fur.ly","vzturl.com",
    "moourl.com","zpr.io","lnks.gd","lnkfi.re","t2m.cc","q.gs","shrtco.de",
    "short.gy","urlzs.com","shortcm.li","cut.ly","4url.cc","ziplink.us","xurl.es",
    "safe.mn","sk.gy","virl.ws","surl.li","jump.link","miniurl.io","shorti.io",
    "shorten.sh","tiny.ie","short.am","shortest.link","linktr.ee","bitly.is",
    "shrten.link","tiny.one","go2l.ink","tlink.io","miniurl.tk","adcrun.ch",
    "dft.ba","t9y.me","v.gy","dai.ly","tiny.bz","tco.la","url.ie","lnk.bio",
    "tlnk.io","tinycat.net",
}
PORT_TUNNELS = {
    "ngrok.io","tcp.ngrok.io","trycloudflare.com","cfargotunnel.com","serveo.net",
    "localhost.run","localtunnel.me","pagekite.me","pagekite.co","nip.io","xip.io",
    "ssh.localhost.run","localxpose.io","inlets.dev","gradio.live","railway.app",
    "loca.lt","vps.me","herokuapp.com","repl.co","vercel.app","fly.dev",
    "tunnel.us","sb-ssl",
}
SUSP_WORDS = {
    "login","signin","secure","update","verify","account","bank","ebay","paypal",
    "confirm","password","wp-admin","admin","user","webscr","credentials","auth",
    "accounts","log-in","sign-in","sign_in","authenticate","authentication",
    "verification","validate","validation","confirm-account","confirm-email",
    "update-account","update-info","upgrade","upgrade-account","secure-login",
    "secure-account","secureverify","alert","alerts","notice","important","urgent",
    "action-required","actionrequired","attention","locked","account-locked",
    "suspended","suspend","restricted","reset-password","reset","change-password",
    "changepassword","pwd","recover","recovery","otp","one-time","2fa","twofactor",
    "two-factor","mfa","authcode","auth-code","verification-code","code","pin",
    "passcode","token","security-code","billing","bill","invoice","invoices",
    "payment","payments","payment-info","billing-info","due","overdue","refund",
    "reimburse","reimbursement","charge","charged","unauthorized-charge",
    "account-statement","statement","bank-statement","account-summary",
    "banking-alert","card","creditcard","credit-card","ccnum","cvv","cvv2",
    "payment-method","appleid","apple-id","google-account","microsoft","msaccount",
    "amazon-account","verify-identity","identity","id-verification","kyc",
    "know-your-customer","ssn","social-security","tax","irs","vat","tax-refund",
    "delivery","shipment","shipping","tracking","track","parcel","order",
    "order-confirmation","order-update","attachment","download","doc","docs","pdf",
    "claim","claims","payout","withdraw","withdrawal","remit","wire","transfer",
    "reward","rewards","bonus","gift","gift-card","voucher","coupon","promo",
    "promotion","support","helpdesk","help","customer-service","customerservice",
    "service-center","support-ticket","ticket","verify-email","email-update",
    "mailbox","mail-update","authenticate-device","new-login","new-signin",
    "unusual-activity","suspicious-activity","security-alert","fix","resolve",
    "resolve-issue","remedy","confirm-now","verify-now","validate-now",
    "securelink","secure-link","secure_access","safe","safenow","click-here",
    "clickhere","click-now","open","open-document","open-file","administrator",
    "webmaster","chargeback","dispute","disputed","report","reported","partner",
    "vendor","supplier","payroll","salary","hr","human-resources","subscription",
    "auto-renew","renewal","cancel-subscription","cancel-now","expired",
    "expiration","expire","renew","reauthorize","lookup","verify-account-info",
    "accountinfo","account-info","profile-update","secureverification",
    "accountverification","emailverification","phoneverification","secureportal",
    "portal","webportal","user-portal","mbank","onlinebanking","intuit","stripe",
    "square","quickbooks",
}
KNOWN_BRANDS = [
    "paypal","apple","google","facebook","amazon","bankofamerica","microsoft",
    "netflix","linkedin","instagram","twitter","ebay","chase","wellsfargo","dropbox",
]
_W = {
    "has_ip":12,"url_length":8,"host_length":6,"num_digits_ratio":8,
    "num_special_chars":6,"has_at":10,"has_double_slash_in_path":6,
    "num_subdomains":8,"suspicious_words":10,"is_shortener":10,
    "suspicious_tld":6,"has_port":4,"query_params":4,"entropy":8,
    "modified_brands":10,"tunnel_specialchars":14,
}

def _clamp(x,a=0.,b=1.): return max(a,min(b,x))
def _lin(v,lo,hi):
    if v<=lo: return 0.
    if v>=hi: return 1.
    return (v-lo)/(hi-lo)
def _ent(s):
    if not s: return 0.
    freq={}
    for c_ in s: freq[c_]=freq.get(c_,0)+1
    H,L=0.,len(s)
    for v in freq.values():
        p=v/L; H-=p*math.log2(p)
    u=len(freq)
    return 0. if u<=1 else H/math.log2(u)
def _brands(host):
    host=(host or "").lower()
    joined="".join(re.split(r"[.\-]+",host))
    out=[]
    for b in KNOWN_BRANDS:
        if b in host: out.append({"brand":b,"ratio":1.0}); continue
        r=SequenceMatcher(None,b,joined).ratio()
        if r>=0.75: out.append({"brand":b,"ratio":round(r,2)})
    return out
def _redirects(url,max_r=5,timeout=5):
    chain=[url]; cur=url
    hdrs={"User-Agent":"PhishDetector/1.0"}
    for _ in range(max_r):
        try:
            req=urllib.request.Request(cur,headers=hdrs,method="HEAD")
            with urllib.request.urlopen(req,timeout=timeout) as r:
                fin=r.geturl()
        except HTTPError as he:
            if he.code in(405,501):
                try:
                    req2=urllib.request.Request(cur,headers=hdrs,method="GET")
                    with urllib.request.urlopen(req2,timeout=timeout) as r2: fin=r2.geturl()
                except Exception: break
            else: break
        except Exception: break
        if not fin or fin==cur: break
        chain.append(fin); cur=fin
    return cur,chain

def run_url_module(original_url: str) -> dict:
    result = {"module": "URL Feature Scorer", "score": 0, "flags": [], "info": {}}
    pcheck = urlparse(normalize_url(original_url))
    hcheck = (pcheck.hostname or "").lower()
    if hcheck in URL_SHORTENERS:
        resolved, chain = _redirects(original_url)
    else:
        resolved, chain = original_url, [original_url]

    probe  = normalize_url(resolved)
    parsed = urlparse(probe)
    host   = (parsed.hostname or "").lower()
    path   = unquote(parsed.path or "")
    query  = unquote(parsed.query or "")
    port   = parsed.port

    has_ip = False
    try: ipaddress.ip_address(host); has_ip=True
    except Exception: pass

    noscheme  = probe.split("://",1)[1] if "://" in probe else probe
    drat      = sum(c_.isdigit() for c_ in noscheme)/max(len(noscheme),1)
    special   = sum(1 for c_ in noscheme if not c_.isalnum() and c_ not in "./-_%?=&:")
    url_len   = len(original_url)
    hlen      = len(host)
    has_at    = "@" in noscheme
    has_dbl   = "//" in path
    subd      = max(0,len(host.split("."))-2) if host and not has_ip else 0
    lowered   = (host+" "+path+" "+query).lower()
    sw        = sorted({w for w in SUSP_WORDS if w in lowered})
    is_short  = host in URL_SHORTENERS
    tld_      = host.split(".")[-1] if "." in host else ""
    is_stld   = tld_ in SUSPICIOUS_TLDS
    qcount    = query.count("&")+1 if query else 0
    eh,ep     = _ent(host),_ent(path)
    bmatches  = _brands(host)
    bscore    = _clamp(len(bmatches)/2.)
    sih       = bool(re.search(r"[^a-z0-9.\-]",host))
    usetun    = any(s in host for s in PORT_TUNNELS)

    sc={
        "has_ip":1. if has_ip else 0.,
        "url_length":_lin(url_len,70,200),"host_length":_lin(hlen,30,60),
        "num_digits_ratio":_lin(drat,.05,.35),"num_special_chars":_lin(special,2,8),
        "has_at":1. if has_at else 0.,"has_double_slash_in_path":1. if has_dbl else 0.,
        "num_subdomains":_lin(subd,0,3),"suspicious_words":_clamp(len(sw)/5.),
        "is_shortener":1. if is_short else 0.,"suspicious_tld":1. if is_stld else 0.,
        "has_port":1. if port else 0.,"query_params":_lin(qcount,1,4),
        "entropy":_lin(max(eh,ep),.4,.95),"modified_brands":bscore,
        "tunnel_specialchars":1. if (sih and usetun) else 0.,
    }
    tw   = sum(_W.values())
    raw  = sum(sc[f]*w for f,w in _W.items())/tw*100
    final= round(_clamp(raw,0,100),2)

    flags=[]
    if bmatches: flags.append((f"Brand impersonation: {', '.join(b['brand'] for b in bmatches)}", RED))
    if has_ip:   flags.append(("Bare IP address as host", RED))
    if is_short: flags.append(("URL shortener — destination hidden", YELLOW))
    if sw:       flags.append((f"Suspicious keywords: {', '.join(sw[:5])}", YELLOW))
    if has_at:   flags.append(("'@' in URL — redirection trick", RED))
    if subd>1:   flags.append((f"{subd} subdomains — brand spoofing risk", YELLOW))
    if is_stld:  flags.append((f"Suspicious TLD: .{tld_}", YELLOW))
    if usetun:   flags.append(("Tunnel/port-forwarding service in host", YELLOW))
    if len(chain)>1: flags.append((f"Redirects through {len(chain)} URLs", YELLOW))
    if not flags: flags.append(("No high-risk URL patterns detected", GREEN))

    # Per-feature score breakdown (from original module)
    total_contrib = sum(sc[f]*w for f,w in _W.items())
    breakdown = {}
    for feat, w in _W.items():
        s_val = sc.get(feat, 0.)
        contrib = s_val * w
        rel_pct = (contrib / total_contrib * 100) if total_contrib > 0 else 0.
        breakdown[feat] = {"score_0_1": round(s_val,4), "weight": w,
                           "contribution": round(contrib,4), "relative_pct": round(rel_pct,2)}

    result["score"]=final
    result["flags"]=flags
    result["info"]={
        "host":host,"tld":tld_,"resolved_url":resolved,
        "redirect_hops":len(chain)-1,"suspicious_keywords":sw,
        "brand_matches":[b["brand"] for b in bmatches],
        "uses_tunnel":usetun,
        "score_breakdown": breakdown,
    }
    return result


# ════════════════════════════════════════════════════════════════════
# MODULE 01 · SSL / TLS CERTIFICATE ANALYZER
# ════════════════════════════════════════════════════════════════════
def run_ssl_module(hostname: str) -> dict:
    result = {"module": "SSL/TLS Certificate", "score": 0, "flags": [], "info": {}}
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa,ec,dsa,ed25519,ed448
    except ImportError:
        ensure_pkg("cryptography")
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa,ec,dsa,ed25519,ed448

    def fetch(host,port=443):
        ctx=ssl.create_default_context(); ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        with socket.create_connection((host,port),timeout=10) as sk:
            with ctx.wrap_socket(sk,server_hostname=host) as ss:
                return ss.getpeercert(binary_form=True),ss.version(),ss.cipher()

    try:
        der,tls_ver,cipher=fetch(hostname)
    except Exception as e:
        result["error"]=str(e); result["score"]=30
        result["flags"].append((f"Could not retrieve certificate: {e}", RED)); return result

    cert=x509.load_der_x509_certificate(der,default_backend())
    subj={a.oid._name:a.value for a in cert.subject}
    issr={a.oid._name:a.value for a in cert.issuer}
    sig =cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "Unknown"
    org =cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
    ctype="OV/EV" if org else "DV"

    try:
        san=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)\
            .value.get_values_for_type(x509.DNSName)
    except Exception: san=[]

    try:    nb,na=cert.not_valid_before_utc,cert.not_valid_after_utc
    except: nb=cert.not_valid_before.replace(tzinfo=datetime.timezone.utc);\
            na=cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

    now=datetime.datetime.now(datetime.timezone.utc)
    vdays=(na-nb).days; exp=now>na; nyv=now<nb

    pub=cert.public_key()
    if   isinstance(pub,rsa.RSAPublicKey):           ka,ks="RSA",pub.key_size
    elif isinstance(pub,ec.EllipticCurvePublicKey):  ka,ks="ECC",pub.key_size
    elif isinstance(pub,dsa.DSAPublicKey):            ka,ks="DSA",pub.key_size
    elif isinstance(pub,ed25519.Ed25519PublicKey):    ka,ks="Ed25519",256
    elif isinstance(pub,ed448.Ed448PublicKey):        ka,ks="Ed448",456
    else:                                             ka,ks="Unknown",0

    def verify(host):
        ctx=ssl.create_default_context(); ctx.check_hostname=True
        ctx.verify_mode=ssl.CERT_REQUIRED; ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        try:
            with socket.create_connection((host,443),timeout=5) as sk:
                with ctx.wrap_socket(sk,server_hostname=host): pass
            return True
        except Exception: return False

    trusted=verify(hostname)
    score=0; flags=[]
    if not trusted:         score+=40; flags.append(("Untrusted CA / certificate chain", RED))
    if exp:                 score+=30; flags.append(("Certificate is EXPIRED", RED))
    if nyv:
        score+=10; flags.append(("Certificate not yet valid", YELLOW))
        # future_validity_flag: valid-from > 30 days in future
        future_days = (nb - now).days if nb > now else 0
        if future_days > 30:
            score+=20; flags.append((f"Valid-from date is {future_days} days in the future (suspicious)", YELLOW))
    cn=subj.get("commonName")
    if not any(e and fnmatch.fnmatch(hostname,e) for e in [cn,*san]):
        score+=15; flags.append(("CN/SAN mismatch", YELLOW))
    if vdays<30:            score+=5;  flags.append(("Short validity period (<30 days)", YELLOW))
    if tls_ver in ["TLSv1","TLSv1.1","SSLv3"]:
        score+=20; flags.append((f"Weak TLS version: {tls_ver}", RED))
    cname=(cipher[0] or "").upper(); klen=cipher[2] if cipher and len(cipher)>2 else 0
    if any(w in cname for w in ["RC4","DES","3DES","MD5","NULL","EXPORT"]) or klen<128:
        score+=20; flags.append((f"Weak cipher: {cname} ({klen}-bit)", RED))
    if any(w in sig.upper() for w in ["SHA1","MD5"]):
        score+=20; flags.append((f"Weak signature algorithm: {sig}", RED))
    if ctype=="DV":         score+=30; flags.append(("DV cert — domain-only validation", RED))
    elif ctype=="OV/EV":    score+=10; flags.append(("OV/EV cert — org validated", YELLOW))
    if ka=="RSA" and ks<2048: score+=25; flags.append((f"Weak RSA key: {ks}-bit", RED))
    elif ka=="ECC" and ks<256: score+=20; flags.append((f"Weak ECC key: {ks}-bit", RED))
    elif ka=="DSA":            score+=15; flags.append(("Deprecated DSA algorithm", YELLOW))

    # Tunneling/temporary domain heuristics (from original Module 1)
    _ssl_tunnel_indicators = [
        "trycloudflare.com","ngrok.io","localtunnel.me","serveo.net","localhost.run",
        "pagekite.me","localtunnel","loca.lt","vps.me","herokuapp.com","repl.co",
        "vercel.app","railway.app","fly.dev","tunnel.us","sb-ssl","gradio.live",
    ]
    _ssl_sensitive_kw = ["login","signin","verify","account","secure","bank",
                         "update","confirm","password","auth","credential","payment"]
    hn_lower = hostname.lower()
    is_tunnel = any(t in hn_lower for t in _ssl_tunnel_indicators)
    has_sensitive = any(k in hn_lower for k in _ssl_sensitive_kw)
    if is_tunnel:
        if ctype=="DV" and has_sensitive:
            score+=30; flags.append(("Tunneling domain + DV cert + sensitive keyword (High Risk)", RED))
        elif ctype=="DV":
            score+=15; flags.append(("Tunneling domain + DV certificate (Medium Risk)", YELLOW))
        elif has_sensitive:
            score+=20; flags.append(("Tunneling domain + sensitive keyword (High Risk)", RED))
        else:
            score+=5;  flags.append(("Tunneling/temporary domain detected (may be dev use)", YELLOW))

    cdn=["Cloudflare","Amazon","CloudFront","Akamai","Fastly"]
    icn=issr.get("commonName","") or ""
    if any(n in icn for n in cdn): flags.append((f"CDN-protected (issuer: {icn})", GREEN))
    if not flags: flags.append(("Certificate profile looks healthy", GREEN))

    result["score"]=min(score,100); result["flags"]=flags
    result["info"]={
        "issuer":icn,"subject_cn":cn,"tls_version":tls_ver,
        "cert_type":ctype,"days_until_expiry":(na-now).days,
        "public_key":f"{ka} {ks}-bit","trusted":trusted,
    }
    return result


# ════════════════════════════════════════════════════════════════════
# MODULE 06 · PERMISSION API SCANNER (static + optional Playwright)
# ════════════════════════════════════════════════════════════════════
_PERM_PATS = {
    "camera/microphone": [
        r"getUserMedia\s*\(", r"navigator\.mediaDevices",
        r"webkitGetUserMedia\s*\(", r"mozGetUserMedia\s*\(",
    ],
    "camera/microphone (permissions API)": [
        r"permissions\.query\s*\(\s*\{\s*['\"]name['\"]\s*:\s*['\"](?:camera|microphone)['\"]\s*\}\s*\)",
    ],
    "geolocation": [
        r"geolocation\.getCurrentPosition", r"navigator\.geolocation",
    ],
    "notifications": [
        r"Notification\.requestPermission", r"Notification\.permission",
    ],
    "clipboard": [
        r"navigator\.clipboard\.read", r"navigator\.clipboard\.write",
        r"document\.execCommand\s*\(\s*['\"]copy['\"]",
    ],
    "midi": [
        r"requestMIDIAccess", r"navigator\.requestMIDIAccess",
    ],
    "device-motion-orientation": [
        r"deviceorientation", r"devicemotion",
        r"DeviceOrientationEvent", r"DeviceMotionEvent",
    ],
    "payment": [
        r"PaymentRequest\s*\(", r"navigator\.credentials",
    ],
    "push/subscriptions": [
        r"pushManager", r"serviceWorker\.register",
        r"subscribe\(\s*{?\s*userVisibleOnly",
    ],
    "permission header / policy": [
        r"camera", r"microphone", r"geolocation",
        r"clipboard-read", r"clipboard-write",
    ],
}
MAX_EXTERNAL_SCRIPTS = 8

# Runtime-editable pattern store (can be modified by tune_permission_patterns())
_ACTIVE_PERM_PATS = dict(_PERM_PATS)

def _compile_perm_patterns(pats_dict):
    compiled = []
    for cat, pats in pats_dict.items():
        for pat in pats:
            try:   cr = re.compile(pat, re.IGNORECASE)
            except re.error: cr = re.compile(re.escape(pat), re.IGNORECASE)
            compiled.append((cat, cr))
    return compiled

def _scan_text(text, compiled):
    findings = []
    if not text: return findings
    for cat, regex in compiled:
        m = regex.search(text)
        if m:
            ctx = text[max(0,m.start()-80):m.end()+80].replace("\n"," ")
            findings.append((cat, m.group(0), ctx.strip()))
    return findings

def _scan_perm_headers(headers):
    findings = []
    for key in headers.keys():
        if key.lower() in ("permissions-policy","feature-policy"):
            val = headers.get(key,"")
            if val and any(t in val.lower() for t in
                           ("camera","microphone","geolocation","clipboard-read","clipboard-write")):
                findings.append(("header", key, val))
    return findings

_PLAYWRIGHT_INJECTION = r"""
window.__permission_requests = window.__permission_requests || [];
function _rec(k,d){ try{ window.__permission_requests.push({kind:k,details:d||null,ts:Date.now()}); }catch(e){} }
try{ if(navigator.mediaDevices&&navigator.mediaDevices.getUserMedia){
  const o=navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
  navigator.mediaDevices.getUserMedia=function(c){ _rec('getUserMedia',JSON.stringify(c)); return o(c); };
}}catch(e){}
try{ if(window.Notification&&window.Notification.requestPermission){
  const o=window.Notification.requestPermission.bind(window.Notification);
  window.Notification.requestPermission=function(){ _rec('Notification.requestPermission',null); return o.apply(this,arguments); };
}}catch(e){}
try{ if(navigator.geolocation){
  const g=navigator.geolocation, og=g.getCurrentPosition.bind(g);
  g.getCurrentPosition=function(){ _rec('geolocation.getCurrentPosition',null); return og.apply(this,arguments); };
}}catch(e){}
try{ if(navigator.requestMIDIAccess){
  const o=navigator.requestMIDIAccess.bind(navigator);
  navigator.requestMIDIAccess=function(){ _rec('requestMIDIAccess',null); return o.apply(this,arguments); };
}}catch(e){}
try{ const oa=EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener=function(type){
    try{ if(type&&(type.toLowerCase().includes('deviceorientation')||type.toLowerCase().includes('devicemotion')))
      _rec('device-motion-orientation-listener',type); }catch(e){}
    return oa.apply(this,arguments); };
}catch(e){}
"""

def tune_permission_patterns():
    """Interactive runtime tuner for permission patterns (from original Module 5)."""
    global _ACTIVE_PERM_PATS
    while True:
        print("\n  Permission Pattern Tuner:")
        print("  1) List categories & patterns")
        print("  2) Add a pattern")
        print("  3) Remove a pattern")
        print("  4) Save to patterns.json")
        print("  5) Load from patterns.json")
        print("  0) Back")
        ch = input("  Choice: ").strip()
        if ch == "1":
            for cat, pats in _ACTIVE_PERM_PATS.items():
                print(f"\n  {cat}:")
                for i,p in enumerate(pats,1): print(f"    {i}. {p}")
        elif ch == "2":
            cat = input("  Category name: ").strip()
            pat = input("  Regex pattern : ").strip()
            if cat and pat:
                _ACTIVE_PERM_PATS.setdefault(cat,[]).append(pat)
                print("  Pattern added.")
        elif ch == "3":
            cat = input("  Category to remove from: ").strip()
            if cat not in _ACTIVE_PERM_PATS: print("  Not found."); continue
            for i,p in enumerate(_ACTIVE_PERM_PATS[cat],1): print(f"  {i}. {p}")
            idx = input("  Pattern number: ").strip()
            try:
                _ACTIVE_PERM_PATS[cat].pop(int(idx)-1)
                if not _ACTIVE_PERM_PATS[cat]: del _ACTIVE_PERM_PATS[cat]
                print("  Removed.")
            except Exception: print("  Invalid.")
        elif ch == "4":
            with open("patterns.json","w") as f: json.dump(_ACTIVE_PERM_PATS,f,indent=2)
            print("  Saved to patterns.json")
        elif ch == "5":
            try:
                with open("patterns.json") as f: _ACTIVE_PERM_PATS = json.load(f)
                print("  Loaded.")
            except Exception as e: print(f"  Failed: {e}")
        elif ch == "0":
            break

def run_permission_module(url: str, use_playwright: bool = False) -> dict:
    result = {"module": "Permission API Scanner", "score": 0, "flags": [], "info": {}}
    try:
        import requests
        from bs4 import BeautifulSoup
    except ImportError:
        ensure_pkg("requests"); ensure_pkg("beautifulsoup4")
        import requests
        from bs4 import BeautifulSoup

    compiled = _compile_perm_patterns(_ACTIVE_PERM_PATS)
    static_evidence = []

    # ── Static scan ──
    try:
        resp = requests.get(url, headers={"User-Agent":"Mozilla/5.0"},
                            timeout=12, allow_redirects=True)
        # Header scan
        for h in _scan_perm_headers(resp.headers):
            static_evidence.append((h[1], h[2], "response header"))

        soup = BeautifulSoup(resp.text, "html.parser")

        # Meta permissions-policy
        for meta in soup.find_all("meta"):
            he = meta.get("http-equiv","")
            if "permissions-policy" in he.lower() or "feature-policy" in he.lower():
                content = meta.get("content","")
                static_evidence.append(("meta-permissions-policy", content,
                                        f"<meta http-equiv='{he}'>"))

        # iframe allow attribute
        for iframe in soup.find_all("iframe"):
            allow = iframe.get("allow","")
            if allow and any(t in allow.lower() for t in
                             ("camera","microphone","geolocation","clipboard")):
                static_evidence.append(("iframe-allow", allow, str(iframe)[:200]))

        # Inline scripts
        inline_js = "\n".join(s.string or "" for s in soup.find_all("script", src=False))
        static_evidence += _scan_text(inline_js, compiled)

        # External scripts (up to MAX_EXTERNAL_SCRIPTS)
        ext_scripts = [s.get("src") for s in soup.find_all("script", src=True)]
        fetched = 0
        for src in ext_scripts:
            if not src or fetched >= MAX_EXTERNAL_SCRIPTS: break
            full = urljoin(url, src)
            try:
                r = requests.get(full, headers={"User-Agent":"Mozilla/5.0"}, timeout=10)
                if r.status_code == 200:
                    for (cat, span, ctx) in _scan_text(r.text, compiled):
                        static_evidence.append((f"{cat} (ext script)", span, ctx[:200]))
                fetched += 1
            except Exception:
                pass

        # Body text scan
        static_evidence += _scan_text(soup.get_text(separator="\n"), compiled)

    except Exception as e:
        result["info"]["static_error"] = str(e)

    # ── Optional Playwright dynamic scan ──
    dynamic_records = []
    if use_playwright:
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                ctx_pw  = browser.new_context(user_agent="Mozilla/5.0")
                page    = ctx_pw.new_page()
                page.add_init_script(_PLAYWRIGHT_INJECTION)
                try: page.goto(url, timeout=15000, wait_until="load")
                except Exception: pass
                time.sleep(4)
                try: page.wait_for_load_state("networkidle", timeout=3000)
                except Exception: pass
                try:
                    recs = page.evaluate("() => window.__permission_requests || []")
                    dynamic_records = recs or []
                except Exception:
                    pass
                ctx_pw.close(); browser.close()
        except ImportError:
            result["info"]["playwright_note"] = "Playwright not installed; dynamic scan skipped"
        except Exception as e:
            result["info"]["playwright_error"] = str(e)

    # ── Deduplicate & score ──
    seen = set(); combined = []
    for item in static_evidence:
        key = (item[0], item[1])
        if key not in seen: seen.add(key); combined.append(item)
    for rec in dynamic_records:
        kind    = rec.get("kind","unknown") if isinstance(rec,dict) else str(rec)
        details = rec.get("details","")    if isinstance(rec,dict) else ""
        key = (kind, details)
        if key not in seen: seen.add(key); combined.append((kind, details, "runtime"))

    cats_found = list({item[0] for item in combined})
    if combined:
        result["score"] = min(20*len(cats_found), 60)
        for cat in cats_found:
            col = RED if "camera" in cat or "microphone" in cat or "getUserMedia" in cat else YELLOW
            result["flags"].append((f"Sensitive browser API/policy detected: {cat}", col))
        susp_terms = ("getUserMedia","mediaDevices","camera","microphone")
        if any(any(t.lower() in (str(i[0])+" "+str(i[1])).lower() for t in susp_terms)
               for i in combined):
            result["score"] = max(result["score"], 50)
    else:
        result["flags"].append(("No sensitive permission APIs found", GREEN))

    result["info"].update({
        "apis_detected": cats_found,
        "total_indicators": len(combined),
        "dynamic_runtime_calls": len(dynamic_records),
    })
    return result


# ════════════════════════════════════════════════════════════════════
# MODULE 07 · CAPTCHA / PROTECTED CONTENT CHECK (Playwright)
# ════════════════════════════════════════════════════════════════════
_CAP_SUCCESS_KW = [r"thank you",r"success",r"welcome",r"logged in",
                   r"verification complete",r"access granted"]
_CAP_FAILURE_KW = [r"incorrect",r"invalid",r"try again",r"captcha",
                   r"verification failed",r"not match",r"are you human"]
_CAP_PROTECTED_KW = [r"\blogout\b",r"\bsign out\b",r"\bmy account\b",
                     r"\bdashboard\b",r"\border history\b",r"\bprofile\b",
                     r"\bwelcome back\b",r"\bwelcome,\b"]

def _cap_contains(text, patterns):
    if not text: return False
    txt = text.lower()
    return any(re.search(p, txt) for p in patterns)

def _find_captcha_indicators(page):
    indicators = {}
    for i, fr in enumerate(page.query_selector_all("iframe")):
        src = fr.get_attribute("src") or ""
        if "recaptcha" in src or "google.com/recaptcha" in src or re.search(r"gstatic.*recaptcha",src):
            indicators.setdefault("recaptcha_iframe",[]).append(fr)
        if "hcaptcha" in src or "hcaptcha.com" in src:
            indicators.setdefault("hcaptcha_iframe",[]).append(fr)
        if "challenges.cloudflare.com" in src or "turnstile" in src:
            indicators.setdefault("turnstile_iframe",[]).append(fr)
    # DOM-based markers
    if (page.query_selector("div.g-recaptcha") or
        page.query_selector("script[src*='recaptcha']") or
        page.query_selector("[data-sitekey]")):
        indicators.setdefault("recaptcha_dom",[]).append("g-recaptcha found")
    if (page.query_selector("div.h-captcha") or
        page.query_selector("script[src*='hcaptcha']")):
        indicators.setdefault("hcaptcha_dom",[]).append("h-captcha found")
    if page.query_selector("[id*='captcha'],[name*='captcha'],[class*='captcha']"):
        indicators.setdefault("captcha_field",[]).append("captcha input found")
    content_lower = page.content().lower()
    if "checking your browser" in content_lower or "please enable javascript" in content_lower:
        indicators.setdefault("browser_check_text",[]).append("browser check text")
    return indicators

def _try_submit_wrong_captcha(page, url, timeout_ms=15000):
    """Submit a form with an invalid CAPTCHA value and observe outcome."""
    from playwright.sync_api import TimeoutError as PWTimeout
    result = {"tested": False, "vulnerable": None, "reason": ""}
    try:
        candidate_selectors = [
            "input[name*='captcha']","input[id*='captcha']",
            "textarea[name*='captcha']","input[name='g-recaptcha-response']",
            "textarea[name='g-recaptcha-response']","input[name*='verification']",
            "input[name*='code']","input[name*='pin']",
        ]
        filled = False
        for sel in candidate_selectors:
            elems = page.query_selector_all(sel)
            for e in elems:
                try:
                    e.evaluate("(el)=>{ el.value='INVALID_TEST_VALUE'; "
                               "el.dispatchEvent(new Event('input',{bubbles:true})); }")
                    filled = True; break
                except Exception: pass
            if filled: break

        if not filled:
            # Inject fake g-recaptcha-response into first form
            page.evaluate("""()=>{
                let t=document.createElement('textarea');
                t.name='g-recaptcha-response'; t.style.display='none';
                t.value='INVALID_TEST_VALUE';
                document.forms[0]&&document.forms[0].appendChild(t);
            }""")

        form = page.query_selector("form")
        if not form:
            result["reason"] = "No form found"; return result

        btn = form.query_selector("button[type='submit'],input[type='submit'],button")
        if btn:
            try:
                with page.expect_navigation(timeout=5000): btn.click()
            except PWTimeout:
                try: btn.click()
                except Exception: pass
        else:
            try: form.evaluate("f=>f.submit()")
            except Exception: pass

        time.sleep(2.5)
        new_content = page.content().lower()
        new_url     = page.url

        if _cap_contains(new_content, _CAP_FAILURE_KW):
            result.update({"tested":True,"vulnerable":False,
                           "reason":"Site rejected invalid captcha (expected behaviour)"})
        elif _cap_contains(new_content, _CAP_SUCCESS_KW):
            result.update({"tested":True,"vulnerable":True,
                           "reason":"Site accepted invalid captcha — possible bypass"})
        elif new_url.rstrip("/") != url.rstrip("/"):
            result.update({"tested":True,"vulnerable":True,
                           "reason":f"URL changed to {new_url} after invalid captcha (heuristic)"})
        else:
            result.update({"tested":True,"vulnerable":None,
                           "reason":"No clear success/failure detected — inconclusive"})
    except Exception as e:
        result["reason"] = f"Exception: {e}"
    return result

def _detect_protected_content(page):
    body  = page.content().lower()
    found = []
    for kw in _CAP_PROTECTED_KW:
        if re.search(kw, body): found.append(kw)
    PROT_SEL = ["a[href*='logout']","a[href*='signout']",
                "button:has-text('Logout')","a:has-text('My Account')","a:has-text('Dashboard')"]
    for sel in PROT_SEL:
        try:
            els = page.query_selector_all(sel)
            if els: found.append(f"selector:{sel}")
        except Exception: pass
    return found

def run_captcha_playwright_module(url: str) -> dict:
    result = {"module": "CAPTCHA / Login Check (Playwright)", "score": 0, "flags": [], "info": {}}
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        result["info"]["skipped"] = "Playwright not installed"
        result["flags"].append(("Module skipped — install playwright", YELLOW))
        return result

    detected_indicators = {}
    submit_test         = {}
    before_protected    = []
    after_protected     = []

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)

            # ── Before: detect protected content ──
            page = browser.new_context().new_page()
            try: page.goto(url, timeout=15000)
            except Exception: pass
            before_protected = _detect_protected_content(page)
            detected_indicators = _find_captcha_indicators(page)

            # ── Attempt wrong-captcha submission ──
            submit_test = _try_submit_wrong_captcha(page, url)

            # ── After: fresh visit, detect protected content again ──
            page2 = browser.new_context().new_page()
            try: page2.goto(url, timeout=15000)
            except Exception: pass
            after_protected = _detect_protected_content(page2)

            browser.close()
    except Exception as e:
        result["error"] = str(e); return result

    # ── Score & flags ──
    score = 0
    if detected_indicators:
        types = list(detected_indicators.keys())
        result["flags"].append((f"CAPTCHA detected: {', '.join(types)}", YELLOW))
        score = max(score, 10)

    if submit_test.get("vulnerable") is True:
        score = max(score, 50)
        result["flags"].append((f"Invalid CAPTCHA ACCEPTED — {submit_test['reason']}", RED))
    elif submit_test.get("vulnerable") is False:
        result["flags"].append(("CAPTCHA correctly rejected invalid input", GREEN))
    elif submit_test.get("tested"):
        result["flags"].append((f"CAPTCHA test inconclusive: {submit_test.get('reason','')}", YELLOW))

    # Protected content comparison
    if not before_protected and after_protected:
        score = max(score, 40)
        result["flags"].append(("Protected/login content appeared AFTER test — suspicious", RED))
    elif before_protected and after_protected:
        result["flags"].append(("Login-style content present on page (may be normal)", YELLOW))
        score = max(score, 15)
    elif not before_protected and not after_protected:
        if not detected_indicators:
            result["flags"].append(("No CAPTCHA or login indicators detected", GREEN))

    result["score"] = score
    result["info"]  = {
        "captcha_types": list(detected_indicators.keys()),
        "submit_test_result": submit_test.get("reason","n/a"),
        "submit_vulnerable": submit_test.get("vulnerable"),
        "before_protected_matches": len(before_protected),
        "after_protected_matches":  len(after_protected),
    }
    return result


# ════════════════════════════════════════════════════════════════════
# MODULE 08 · AUTOFILL / HIDDEN FORM FIELD SCANNER
# ════════════════════════════════════════════════════════════════════
def run_autofill_module(url: str) -> dict:
    result = {"module": "Autofill / Hidden Field Scanner", "score": 0, "flags": [], "info": {}}
    SENSITIVE_KW = ["name","email","phone","address","password","card","otp","dob"]

    # ── Static scan (BeautifulSoup) ──
    bs_autofill=False; bs_hidden=False; form_count=0
    try:
        import requests
        from bs4 import BeautifulSoup
        resp=requests.get(url,headers={"User-Agent":"Mozilla/5.0"},timeout=10)
        soup=BeautifulSoup(resp.text,"html.parser")
        forms=soup.find_all("form"); form_count=len(forms)
        for form in forms:
            for inp in form.find_all("input"):
                if inp.get("autocomplete")=="on":   bs_autofill=True
                fname=(inp.get("name") or inp.get("id") or "").lower()
                if any(k in fname for k in SENSITIVE_KW): bs_autofill=True
                if inp.get("type")=="hidden":        bs_hidden=True
    except Exception as e:
        result["info"]["static_error"]=str(e)

    # ── Dynamic scan (Selenium) ──
    js_hidden=0; js_autofill=0
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
        opts=Options(); opts.add_argument("--headless"); opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        driver=webdriver.Chrome(options=opts)
        driver.get(url); time.sleep(3)
        js_hidden = len(driver.find_elements("xpath","//input[@type='hidden']"))
        xpath_kw  = " or ".join(
            [f"contains(@name,'{k}') or contains(@id,'{k}')" for k in SENSITIVE_KW]
        )
        js_autofill=len(driver.find_elements("xpath",f"//input[{xpath_kw}]"))
        driver.quit()
    except Exception as e:
        result["info"]["selenium_error"]=str(e)

    # ── Verdict ──
    is_risky=(bs_hidden or js_hidden>0) and (bs_autofill or js_autofill>0)
    if is_risky:
        result["score"]=45
        result["flags"].append(("Hidden + sensitive autofill fields detected — phishing risk", RED))
    elif bs_autofill or js_autofill>0:
        result["score"]=20
        result["flags"].append(("Sensitive autofill fields found (no hidden fields)", YELLOW))
    elif bs_hidden or js_hidden>0:
        result["score"]=15
        result["flags"].append(("Hidden form fields detected", YELLOW))
    else:
        result["flags"].append(("No suspicious autofill or hidden fields found", GREEN))

    result["info"].update({
        "forms_found": form_count,
        "html_autofill": bs_autofill, "html_hidden": bs_hidden,
        "js_hidden_count": js_hidden, "js_autofill_count": js_autofill,
    })
    return result


# ════════════════════════════════════════════════════════════════════
# MODULE 09 · FAKE CAPTCHA VALIDATOR (Selenium)
# ════════════════════════════════════════════════════════════════════
def run_fake_captcha_module(url: str) -> dict:
    result = {"module": "Fake CAPTCHA Validator", "score": 0, "flags": [], "info": {}}
    try:
        from selenium import webdriver
        from selenium.webdriver.common.by import By
        from selenium.webdriver.chrome.options import Options
    except ImportError:
        result["info"]["skipped"]="Selenium not installed (pip install selenium)"
        result["flags"].append(("Module skipped — install selenium", YELLOW))
        return result

    try:
        opts=Options(); opts.add_argument("--headless"); opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        driver=webdriver.Chrome(options=opts)
        driver.get(url); time.sleep(4)

        # Fill username
        for xp in ["//input[contains(@name,'user')]","//input[contains(@name,'email')]",
                   "//input[contains(@placeholder,'email')]"]:
            els=driver.find_elements(By.XPATH,xp)
            if els: els[0].send_keys("test@example.com"); break

        # Fill password
        for xp in ["//input[@type='password']","//input[contains(@name,'pass')]"]:
            els=driver.find_elements(By.XPATH,xp)
            if els: els[0].send_keys("fakepassword123"); break

        # Fill CAPTCHA with wrong value
        captcha_el=None
        for xp in ["//input[contains(@name,'captcha')]","//input[contains(@id,'captcha')]",
                   "//input[contains(@placeholder,'captcha')]"]:
            els=driver.find_elements(By.XPATH,xp)
            if els: captcha_el=els[0]; captcha_el.send_keys(str(random.randint(1000,9999))); break

        if not captcha_el:
            driver.quit()
            result["info"]["note"]="No CAPTCHA field found — skipping fake CAPTCHA test"
            result["flags"].append(("No CAPTCHA input detected on page", YELLOW))
            return result

        # Click submit
        btns=driver.find_elements(By.XPATH,
            "//button[contains(text(),'Login') or contains(text(),'Sign') or "
            "contains(text(),'Submit') or contains(text(),'Verify') or contains(text(),'Continue')]")
        if btns:
            btns[0].click(); time.sleep(4)
        else:
            driver.quit()
            result["flags"].append(("CAPTCHA found but no submit button detected", YELLOW))
            return result

        start_url=url.rstrip("/")
        final_url=driver.current_url.rstrip("/")
        page_src =driver.page_source.lower()
        driver.quit()

        # Verdict
        captcha_still_present="captcha" in page_src
        redirected = (final_url != start_url and final_url != start_url.replace("https://","http://"))
        if redirected and not captcha_still_present:
            result["score"]=60
            result["flags"].append(("Invalid CAPTCHA accepted → page navigated — PHISHING INDICATOR", RED))
        else:
            result["score"]=0
            result["flags"].append(("CAPTCHA correctly rejected invalid input", GREEN))

        result["info"]={"captcha_found":True,"redirected":redirected,"final_url":final_url}

    except Exception as e:
        result["error"]=str(e)
        result["flags"].append((f"Selenium error: {e}", YELLOW))
    return result


# ════════════════════════════════════════════════════════════════════
# MODULE 10 · OTP SECURITY CHECKER (seleniumwire)
# ════════════════════════════════════════════════════════════════════
def run_otp_module(url: str) -> dict:
    result = {"module": "OTP Security Checker", "score": 0, "flags": [], "info": {}}
    try:
        from seleniumwire import webdriver as wire_driver
        from selenium.webdriver.common.by import By
        from selenium.webdriver.common.keys import Keys
        from selenium.webdriver.chrome.options import Options
        from bs4 import BeautifulSoup
    except ImportError:
        result["info"]["skipped"]="seleniumwire not installed (pip install seleniumwire)"
        result["flags"].append(("Module skipped — install seleniumwire", YELLOW))
        return result

    OTP_KW = r"(otp|o\.t\.p|pin|code|verification|verify|auth|2fa|two.?factor)"
    SUCCESS_KW = ["success","verified","welcome","logged"]
    FAIL_KW    = ["invalid","wrong","incorrect","try again","failed"]

    def _find_otp_fields(driver):
        soup=BeautifulSoup(driver.page_source,"html.parser")
        fields=[]
        for inp in soup.find_all("input"):
            attrs=" ".join(str(inp.get(a,"")).lower() for a in ["id","name","placeholder","type","class"])
            if re.search(OTP_KW,attrs): fields.append(inp)
        for inp in soup.find_all("input"):
            t=inp.get("type","").lower()
            if t in["tel","number","text"] and inp.get("maxlength") in["4","5","6","7","8"]: fields.append(inp)
        seg=soup.find_all("input",{"maxlength":"1"})
        if len(seg)>=4: fields+=seg
        return list(set(fields))

    def _submit(driver,otp):
        driver.requests.clear()
        for inp in driver.find_elements(By.XPATH,"//input"):
            try: inp.clear(); inp.send_keys(otp)
            except: pass
        try:
            btn=driver.find_element(By.XPATH,
                "//button[contains(text(),'Verify') or contains(text(),'Submit') "
                "or contains(text(),'Continue') or contains(text(),'Login')]")
            btn.click()
        except:
            try: driver.find_elements(By.XPATH,"//input")[0].send_keys(Keys.ENTER)
            except: pass
        time.sleep(4)
        page=driver.page_source.lower()
        calls=[r.url for r in driver.requests if r.response
               and any(k in r.url for k in ["verify","otp","auth","login","code"])]
        return page,calls

    try:
        opts=Options(); opts.add_argument("--headless"); opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-dev-shm-usage")
        driver=wire_driver.Chrome(options=opts)
        driver.get(url); time.sleep(4)

        otp_fields=_find_otp_fields(driver)
        if not otp_fields:
            driver.quit()
            result["info"]["note"]="No OTP field detected"
            result["flags"].append(("No OTP input detected — skipping OTP test", YELLOW))
            return result

        result["info"]["otp_fields_found"]=len(otp_fields)

        invalid_page,invalid_calls=_submit(driver,"000000")
        valid_page,valid_calls=_submit(driver,"123456")
        driver.quit()

        invalid_accepted=any(k in invalid_page for k in SUCCESS_KW) and not any(k in invalid_page for k in FAIL_KW)
        backend_missing=(len(invalid_calls)==0 and len(valid_calls)==0)
        all_calls=list(set(valid_calls+invalid_calls))

        if invalid_accepted:
            result["score"]=70
            result["flags"].append(("Invalid OTP was accepted — HIGH phishing indicator", RED))
        elif backend_missing:
            result["score"]=40
            result["flags"].append(("No backend API call during OTP submit — suspicious", YELLOW))
        else:
            result["score"]=0
            result["flags"].append(("OTP mechanism rejected invalid input — appears legitimate", GREEN))
            if all_calls:
                result["flags"].append((f"Backend verification endpoint: {all_calls[0]}", GREEN))

        result["info"]["backend_api_calls"]=all_calls

    except Exception as e:
        result["error"]=str(e)
        result["flags"].append((f"OTP module error: {e}", YELLOW))
    return result


# ════════════════════════════════════════════════════════════════════
# SCORE AGGREGATOR
# ════════════════════════════════════════════════════════════════════
MODULE_WEIGHTS = {
    "URL Scheme Checker":                 0.05,
    "URL Feature Scorer":                 0.20,
    "SSL/TLS Certificate":                0.20,
    "TLD / Token Checker":                0.08,
    "Unicode / Char Checker":             0.07,
    "IP / WHOIS Analyzer":                0.10,
    "Permission API Scanner":             0.08,
    "CAPTCHA / Login Check (Playwright)": 0.05,
    "Autofill / Hidden Field Scanner":    0.08,
    "Fake CAPTCHA Validator":             0.05,
    "OTP Security Checker":               0.04,
}

def aggregate(results: list) -> tuple:
    total=0.; wsum=0.
    for r in results:
        name=r["module"]
        if "error" in r and r.get("score",0)==0 and not r.get("flags"): continue
        w=MODULE_WEIGHTS.get(name,0.05)
        total+=r.get("score",0)*w; wsum+=w
    final=round(total/wsum,1) if wsum>0 else 0.
    if   final<25: verdict,col="Likely Benign",          GREEN
    elif final<55: verdict,col="Suspicious — Use Caution",YELLOW
    else:          verdict,col="HIGH RISK — Likely Phishing",RED
    return final,verdict,col


# ════════════════════════════════════════════════════════════════════
# REPORT PRINTER
# ════════════════════════════════════════════════════════════════════
def bar(score, width=20):
    filled=int(score//5)
    col=RED if score>=55 else (YELLOW if score>=25 else GREEN)
    return c("█"*filled + "░"*(width-filled), col)

def print_report(url, results, final_score, verdict, risk_col):
    print(f"\n{'═'*68}")
    print(c(f"  UNIFIED PHISHING DETECTION REPORT", BOLD))
    print(f"  Target : {url}")
    print(f"  Scanned: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'═'*68}")

    for r in results:
        section(f"[{r['module']}]")
        if "error" in r:
            print(f"    {warn('Error: ' + str(r['error']))}")

        # Print key info items
        skip_keys={"skipped","static_error","selenium_error","note"}
        if r.get("info"):
            for k,v in r["info"].items():
                if k in skip_keys or not v and v!=0: continue
                if isinstance(v,list): v=", ".join(str(i) for i in v) or "—"
                print(f"    {c(k+':','') :<28} {v}")

        if r.get("flags"):
            print()
            for flag,col in r["flags"]:
                print(f"    {c('• ', col)}{flag}")

        s=r.get("score",0)
        sc=RED if s>=55 else (YELLOW if s>=25 else GREEN)
        print(f"\n    Module Risk:  {c(f'{s:.0f}/100',sc)}  {bar(s)}")

    # ── FINAL SUMMARY ────────────────────────────────────────────
    print(f"\n{'═'*68}")
    print(c(f"  FINAL PHISHING RISK SCORE", BOLD))
    print(f"  {c(f'{final_score:.1f}/100', risk_col)}   {bar(final_score)}")
    print(f"  {BOLD}VERDICT: {c(verdict, risk_col)}{RESET}")
    print(f"{'═'*68}")

    # ── Score breakdown table ─────────────────────────────────────
    print(f"\n  {'Module':<42} {'Score':>6}  {'Weight':>7}  Contribution")
    print(f"  {'─'*64}")
    for r in results:
        name=r["module"]; s=r.get("score",0)
        w=MODULE_WEIGHTS.get(name,0.05)
        contrib=s*w
        sc=RED if s>=55 else (YELLOW if s>=25 else GREEN)
        print(f"  {name:<42} {c(f'{s:5.0f}',sc)}   {w:5.0%}    {contrib:6.2f}")
    print(f"  {'─'*64}")
    print(f"  {'WEIGHTED TOTAL':<42} {c(f'{final_score:5.1f}',risk_col)}")

    # ── Recommendations ───────────────────────────────────────────
    print(f"\n  {BOLD}RECOMMENDATIONS:{RESET}")
    if final_score>=55:
        print(f"  {bad('DO NOT visit or enter any credentials on this site.')}")
        print(f"  {bad('Report this URL to Google Safe Browsing / your security team.')}")
        print(f"  {bad('If credentials were entered, change passwords immediately + enable MFA.')}")
    elif final_score>=25:
        print(f"  {warn('Treat with caution. Verify domain via WHOIS before proceeding.')}")
        print(f"  {warn('Do NOT enter personal data unless you have fully verified the site.')}")
        print(f"  {warn('Check the URL against VirusTotal or Google Safe Browsing.')}")
    else:
        print(f"  {ok('Appears low-risk based on all checks.')}")
        print(f"  {ok('Always confirm you navigated here intentionally.')}")
    print()


# ════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ════════════════════════════════════════════════════════════════════
def scan(url: str, enable_browser: bool = True):
    """
    Run all 11 modules against the given URL.
    Set enable_browser=False to skip Selenium/Playwright modules (faster, offline).
    """
    hostname = extract_hostname(url)

    modules = [
        ("Module 11 · URL Scheme",          lambda: run_scheme_module(url)),
        ("Module 03 · TLD/Token",           lambda: run_tld_module(hostname)),
        ("Module 04 · Unicode Chars",       lambda: run_char_module(hostname)),
        ("Module 02 · URL Features",        lambda: run_url_module(url)),
        ("Module 05 · IP/WHOIS",            lambda: run_ip_module(hostname)),
        ("Module 01 · SSL/TLS",             lambda: run_ssl_module(hostname)),
        ("Module 06 · Permissions",         lambda: run_permission_module(normalize_url(url), use_playwright=enable_browser)),
        ("Module 07 · CAPTCHA (Playwright)",lambda: run_captcha_playwright_module(normalize_url(url))),
        ("Module 08 · Autofill/Forms",      lambda: run_autofill_module(normalize_url(url))),
        ("Module 09 · Fake CAPTCHA",        lambda: run_fake_captcha_module(normalize_url(url))),
        ("Module 10 · OTP Security",        lambda: run_otp_module(normalize_url(url))),
    ]

    browser_modules = {
        "Module 07 · CAPTCHA (Playwright)",
        "Module 08 · Autofill/Forms",
        "Module 09 · Fake CAPTCHA",
        "Module 10 · OTP Security",
    }

    results = []
    for label, fn in modules:
        if not enable_browser and label in browser_modules:
            print(c(f"  ⟳ {label} … SKIPPED (browser disabled)", DIM))
            results.append({"module": label.split("·")[1].strip(), "score": 0,
                            "flags": [("Skipped (browser mode off)", YELLOW)], "info": {}})
            continue
        print(c(f"  ⟳ Running {label} …", DIM), flush=True)
        try:
            results.append(fn())
        except Exception as e:
            mod_name = label.split("·",1)[1].strip()
            results.append({"module": mod_name, "score": 0,
                            "flags": [(f"Unhandled exception: {e}", YELLOW)],
                            "info": {}, "error": str(e)})

    final, verdict, risk_col = aggregate(results)
    print_report(url, results, final, verdict, risk_col)
    return final, verdict, results


def main():
    banner = f"""
{BOLD}{'╔'+'═'*66+'╗'}
║{'  UNIFIED PHISHING WEBSITE DETECTOR  v2.0':^66}║
║{'  11 Modules · SSL · URL · IP · Forms · OTP · Permissions':^66}║
{'╚'+'═'*66+'╝'}{RESET}"""
    print(banner)

    while True:
        url = input(f"\n{BOLD}  Enter URL to scan{RESET} (or 'q' to quit): ").strip()
        if url.lower() in ("q", "quit", "exit"):
            print("\n  Goodbye.\n"); break
        if not url:
            continue

        print(f"\n  {c('Scan mode:', BOLD)}")
        print("    1 · Full scan (all 11 modules, includes browser automation)")
        print("    2 · Fast scan (static only, no Selenium/Playwright)")
        print("    3 · Tune permission patterns (then scan)")
        mode = input("  Choose [1/2/3, default=1]: ").strip() or "1"
        if mode == "3":
            tune_permission_patterns()
            mode = input("  Now choose scan mode [1/2, default=1]: ").strip() or "1"
        enable_browser = (mode != "2")

        print(f"\n{c('  Starting scan …', CYAN)}\n")
        scan(url, enable_browser=enable_browser)

        again = input(f"\n  {c('Scan another URL? [y/N]:', BOLD)} ").strip().lower()
        if again not in ("y", "yes"):
            print("\n  Goodbye.\n"); break


if __name__ == "__main__":
    main()
