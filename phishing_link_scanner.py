import re
import requests
import whois
from urllib.parse import urlparse
from datetime import datetime

def check_url_length(url):
    if len(url)>75:
        return "suspicious: long url "
    return "safe: url length normal "

def check_url_https(url):
    if url.startswith("https://"):
        return "safe: uses https "
    return "suspicious: does not use https "

def check_url_phishing_keyword(url):
    phishing_keyword=["login","secure","paypal","bank","ebay","update","verify","account","password","free"]
    for keyword in phishing_keyword:
        if keyword in url.lower():
            return "suspicious: contains phishing keywords "
    return "safe: no common phishing keywords "

def check_url_domain_age(url):
    try:
        domain=urlparse(url).netloc
        domain_info=whois.whois(domain)
        if domain_info.creation_date:
            creation_date=domain_info.creation_date
            if isinstance(creation_date,list):
                creation_date=creation_date[0]
            age=(datetime.now()-creation_date).days  
            if age<180:
                return"suspicious: domain is too new "
            return "safe: domain is old enough "  
        return " suspicious: could not determine the domain age "
    except:
        return "suspicious: whois lookup failed "

def check_url_redirection(url):
    try:
        response=requests.get(url,allow_redirects=True,timeout=5)
        if len(response.history>3):
            return "suspicious: too many redirects"
        return "safe: no excessive redirects"
    except:
        return"suspicious: unable to fetch url"

def url_scan(url):
    print("scanning url is:",url)
    print(check_url_length(url))
    print(check_url_https(url))
    print(check_url_phishing_keyword(url))
    print(check_url_domain_age(url))
    print(check_url_redirection(url))  

if __name__=="__main__":
    url_input=input("enter the url: ")
    url_scan(url_input) 


