#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unified Phishing Feature Extractor.
This refactored file combines all feature extraction logic into a robust, 
modular, and usable class.
"""

import re
import time
import socket
import logging
import requests
import whois
import tldextract
import dotenv
import os
from urllib.parse import urlparse, urljoin, urlencode
from datetime import datetime
from bs4 import BeautifulSoup
dotenv.load_dotenv()
# Configure logging to suppress verbose outputs from libraries and show our own messages
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Disable excessive logging from underlying libraries
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("whois").setLevel(logging.WARNING)

# ================== CONSTANTS AND CONFIGURATION ==================

HINTS = ['wp', 'login', 'includes', 'admin', 'content', 'site', 'images', 'js', 'alibaba', 'css', 'myaccount', 'dropbox', 'themes', 'plugins', 'signin', 'view']

# A comprehensive list of brands for feature checking
ALL_BRANDS = [
    "accenture", "activisionblizzard", "adidas", "adobe", "adultfriendfinder", "agriculturalbankofchina",
    "akamai", "alibaba", "aliexpress", "alipay", "alliance", "alliancedata", "allianceone", "allianz",
    "alphabet", "amazon", "americanairlines", "americanexpress", "americantower", "andersons", "apache",
    "apple", "arrow", "ashleymadison", "audi", "autodesk", "avaya", "avisbudget", "avon", "axa", "badoo",
    "baidu", "bankofamerica", "bankofchina", "bankofnewyorkmellon", "barclays", "barnes", "bbc", "bbt",
    "bbva", "bebo", "benchmark", "bestbuy", "bim", "bing", "biogen", "blackstone", "blogger", "blogspot",
    "bmw", "bnpparibas", "boeing", "booking", "broadcom", "burberry", "caesars", "canon", "cardinalhealth",
    "carmax", "carters", "caterpillar", "cheesecakefactory", "chinaconstructionbank", "cinemark", "cintas",
    "cisco", "citi", "citigroup", "cnet", "coca-cola", "colgate", "colgate-palmolive", "columbiasportswear",
    "commonwealth", "communityhealth", "continental", "dell", "deltaairlines", "deutschebank", "disney",
    "dolby", "dominos", "donaldson", "dreamworks", "dropbox", "eastman", "eastmankodak", "ebay", "edison",
    "electronicarts", "equifax", "equinix", "expedia", "express", "facebook", "fedex", "flickr",
    "footlocker", "ford", "fordmotor", "fossil", "fosterwheeler", "foxconn", "fujitsu", "gap", "gartner",
    "genesis", "genuine", "genworth", "gigamedia", "gillette", "github", "global", "globalpayments",
    "goodyeartire", "google", "gucci", "harley-davidson", "harris", "hewlettpackard", "hilton",
    "hiltonworldwide", "hmstatil", "honda", "hsbc", "huawei", "huntingtonbancshares", "hyundai", "ibm",
    "ikea", "imdb", "imgur", "ingbank", "insight", "instagram", "intel", "jackdaniels", "jnj", "jpmorgan",
    "jpmorganchase", "kelly", "kfc", "kindermorgan", "lbrands", "lego", "lennox", "lenovo", "lindsay",
    "linkedin", "livejasmin", "loreal", "louisvuitton", "mastercard", "mcdonalds", "mckesson", "mckinsey",
    "mercedes-benz", "microsoft", "microsoftonline", "mini", "mitsubishi", "morganstanley", "motorola",
    "mrcglobal", "mtv", "myspace", "nescafe", "nestle", "netflix", "nike", "nintendo", "nissan",
    "nissanmotor", "nvidia", "nytimes", "oracle", "panasonic", "paypal", "pepsi", "pepsico", "philips",
    "pinterest", "pocket", "pornhub", "porsche", "prada", "rabobank", "reddit", "regal",
    "royalbankofcanada", "samsung", "scotiabank", "shell", "siemens", "skype", "snapchat", "sony",
    "soundcloud", "spiritairlines", "spotify", "sprite", "stackexchange", "stackoverflow", "starbucks",
    "swatch", "swift", "symantec", "synaptics", "target", "telegram", "tesla", "teslamotors", "theguardian",
    "homedepot", "piratebay", "tiffany", "tinder", "tmall", "toyota", "tripadvisor", "tumblr", "twitch",
    "twitter", "underarmour", "unilever", "universal", "ups", "verizon", "viber", "visa", "volkswagen",
    "volvocars", "walmart", "wechat", "weibo", "whatsapp", "wikipedia", "wordpress", "yahoo", "yamaha",
    "yandex", "youtube", "zara", "zebra", "iphone", "icloud", "itunes", "sinara", "normshield", "bga",
    "sinaralabs", "roksit", "cybrml", "turkcell", "n11", "hepsiburada", "migros"
]

SUSPICIOUS_TLDS = [
    'fit', 'tk', 'gp', 'ga', 'work', 'ml', 'date', 'wang', 'men', 'icu', 'online', 'click',
    'country', 'stream', 'download', 'xin', 'racing', 'jetzt', 'ren', 'mom', 'party', 'review',
    'trade', 'accountants', 'science', 'ninja', 'xyz', 'faith', 'zip', 'cricket', 'win',
    'accountant', 'realtor', 'top', 'christmas', 'gdn', 'link', 'asia', 'club', 'la', 'ae',
    'exposed', 'pe', 'go.id', 'rs', 'k12.pa.us', 'or.kr', 'ce.ke', 'audio', 'gob.pe', 'gov.az',
    'website', 'bj', 'mx', 'media', 'sa.gov.au'
]

SHORTENING_SERVICES = re.compile(
    'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|'
    'db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|ity\.im|'
    'q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
    'prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
    'link\.zip\.net'
)

# ================== MAIN FEATURE EXTRACTOR CLASS ==================

class PhishingFeatureExtractor:
    """
    A class to extract URL, content, and external features from a URL to detect phishing.
    """

    def __init__(self):
        """
        Initializes the feature extractor.
        
        Args:
            opr_api_key (str, optional): API key for OpenPageRank. Defaults to None.
        """
        self.opr_api_key = os.getenv('API')
        self.feature_names = self._get_feature_names()

    # --------------------------------------------------------------------------
    # Main Public Method
    # --------------------------------------------------------------------------

    def extract_features(self, url, perform_slow_checks=False, request_timeout=5):
        """
        Extracts all features from the given URL.
        
        Args:
            url (str): The URL to analyze.
            perform_slow_checks (bool): If True, performs slow content checks like hyperlink
                                        redirection and error checking. Defaults to False.
            request_timeout (int): Timeout in seconds for web requests.
            
        Returns:
            dict: A dictionary containing the extracted features.
                  Returns a dictionary with an 'error' key if extraction fails at a critical step.
        """
        features = {'url': url}
        
        # 1. Decompose URL and extract URL-based features (works offline)
        try:
            url_components = self._decompose_url(url)
            features.update(self._extract_url_features(url, url_components))
        except Exception as e:
            logging.error(f"Error decomposing URL {url}: {e}")
            return {'url': url, 'error': f"Invalid URL or decomposition failed: {e}"}

        # 2. Attempt to access the URL and get its content
        try:
            response = requests.get(url, timeout=request_timeout, headers={'User-Agent': 'Mozilla/5.0'})
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        except requests.exceptions.RequestException as e:
            logging.warning(f"Could not access {url}: {e}")
            features.update(self._get_default_content_features())
            features.update(self._get_default_external_features())
            features['analysis_status'] = f'Content/External feature extraction failed: {e}'
            return features

        # 3. Extract content-based features from the page content
        try:
            content = response.text
            soup = BeautifulSoup(content, 'html.parser')
            features.update(self._extract_content_features(soup, url_components, perform_slow_checks, request_timeout))
        except Exception as e:
            logging.error(f"Error parsing content for {url}: {e}")
            features.update(self._get_default_content_features())
            features['analysis_status'] = f'Content parsing failed: {e}'

        # 4. Extract third-party (external) features
        try:
            features.update(self._extract_external_features(url, url_components))
        except Exception as e:
            logging.error(f"Error extracting external features for {url}: {e}")
            features.update(self._get_default_external_features())
            features['analysis_status'] = f'External feature extraction failed: {e}'
        
        if 'analysis_status' not in features:
             features['analysis_status'] = 'Success'

        return features

    # --------------------------------------------------------------------------
    # URL Decomposition and Feature Extraction
    # --------------------------------------------------------------------------

    def _decompose_url(self, url):
        """Creates a dictionary of URL components."""
        ext = tldextract.extract(url)
        parsed = urlparse(url)
        
        components = {
            'scheme': parsed.scheme,
            'hostname': parsed.hostname if parsed.hostname else '',
            'path': parsed.path,
            'query': parsed.query,
            'domain': ext.domain,
            'suffix': ext.suffix,
            'subdomain': ext.subdomain,
            'registered_domain': ext.registered_domain if ext.registered_domain else ext.domain,
        }
        
        # Create word lists
        w_domain = re.split(r'[-.]', components['domain'].lower())
        w_subdomain = re.split(r'[-.]', components['subdomain'].lower())
        w_path = re.split(r'[-./?=@&%:_]', components['path'].lower())
        components['words_raw'] = list(filter(None, w_domain + w_subdomain + w_path))
        components['words_host'] = list(filter(None, w_domain + w_subdomain))
        components['words_path'] = list(filter(None, w_path))
        
        return components

    def _extract_url_features(self, url, components):
        """Extracts features based on the URL string itself."""
        hostname = components['hostname']
        words_raw = components['words_raw']

        features = {
            'length_url': len(url),
            'length_hostname': len(hostname),
            'having_ip_address': 1 if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', hostname) else 0,
            'count_dots': url.count('.'),
            'count_hyphens': hostname.count('-'),
            'count_at': url.count('@'),
            'count_question': url.count('?'),
            'count_and': url.count('&'),
            'count_or': url.count('|'),
            'count_equal': url.count('='),
            'count_underscore': url.count('_'),
            'count_tilde': url.count('~'),
            'count_percent': url.count('%'),
            'count_slash': url.count('/'),
            'count_star': url.count('*'),
            'count_colon': url.count(':'),
            'count_comma': url.count(','),
            'count_semicolon': url.count(';'),
            'count_dollar': url.count('$'),
            'count_space': url.count(' ') + url.count('%20'),
            'check_www': hostname.lower().count('www'),
            'check_com': components['path'].lower().count('com'),
            'count_double_slash': 1 if url.find('//', 7) != -1 else 0, # check for // after protocol
            'count_http_token': components['path'].lower().count('http'),
            'https_token': 0 if components['scheme'] == 'https' else 1,
            'ratio_digits_url': len(re.findall(r'\d', url)) / len(url) if url else 0,
            'ratio_digits_host': len(re.findall(r'\d', hostname)) / len(hostname) if hostname else 0,
            'punycode': 1 if "xn--" in url.lower() else 0,
            'port': 1 if re.search(":[0-9]+", hostname) else 0,
            'tld_in_path': 1 if components['suffix'] and components['suffix'] in components['path'].lower() else 0,
            'tld_in_subdomain': 1 if components['suffix'] and components['suffix'] in components['subdomain'].lower() else 0,
            'abnormal_subdomain': 1 if re.search(r'^(www[0-9]+\.|ww\d+\.|w[w]?\d-)', hostname) else 0,
            'count_subdomains': len(components['subdomain'].split('.')) if components['subdomain'] else 0,
            'prefix_suffix': 1 if '-' in hostname else 0,
            'shortening_service': 1 if SHORTENING_SERVICES.search(hostname) else 0,
            'path_extension': 1 if components['path'].lower().endswith('.txt') else 0,
            'length_words_raw': len(words_raw),
            'char_repeat': self._char_repeat(words_raw),
            'shortest_word_length': min(len(w) for w in words_raw) if words_raw else 0,
            'longest_word_length': max(len(w) for w in words_raw) if words_raw else 0,
            'average_word_length': sum(len(w) for w in words_raw) / len(words_raw) if words_raw else 0,
            'phish_hints': sum(components['path'].lower().count(hint) for hint in HINTS),
            'domain_in_brand': 1 if components['domain'] in ALL_BRANDS else 0,
            'brand_in_path': 1 if any(brand in components['path'] for brand in ALL_BRANDS) else 0,
            'suspecious_tld': 1 if components['suffix'] in SUSPICIOUS_TLDS else 0,
        }
        return features

    # --------------------------------------------------------------------------
    # Content-based Feature Extraction
    # --------------------------------------------------------------------------

    def _extract_content_features(self, soup, url_components, perform_slow_checks, timeout):
        """Extracts features from the HTML content of a page."""
        
        # Extract and classify all links
        links = self._classify_links(soup, url_components)
        
        features = {}
        
        # Hyperlink features
        total_hyperlinks = links['total']
        features['nb_hyperlinks'] = total_hyperlinks
        features['internal_hyperlinks'] = len(links['internal']) / total_hyperlinks if total_hyperlinks > 0 else 0
        features['external_hyperlinks'] = len(links['external']) / total_hyperlinks if total_hyperlinks > 0 else 0
        features['null_hyperlinks'] = len(links['null']) / total_hyperlinks if total_hyperlinks > 0 else 0
        
        # CSS features
        features['external_css'] = sum(1 for link in links['external'] if link.endswith('.css'))
        
        # Redirection and Error features (optional and slow)
        if perform_slow_checks:
            features['internal_redirection'] = self._count_redirections(links['internal'], timeout) / len(links['internal']) if links['internal'] else 0
            features['external_redirection'] = self._count_redirections(links['external'], timeout) / len(links['external']) if links['external'] else 0
            features['internal_errors'] = self._count_errors(links['internal'], timeout) / len(links['internal']) if links['internal'] else 0
            features['external_errors'] = self._count_errors(links['external'], timeout) / len(links['external']) if links['external'] else 0
        else:
            features.update({'internal_redirection': -1, 'external_redirection': -1, 'internal_errors': -1, 'external_errors': -1})

        # Form features
        forms = soup.find_all('form', action=True)
        form_actions = [form.get('action', '').lower() for form in forms]
        features['login_form'] = 1 if any('login' in fa or 'signin' in fa for fa in form_actions) else 0
        features['submitting_to_email'] = 1 if any(fa.startswith('mailto:') for fa in form_actions) else 0
        features['sfh'] = 1 if any(fa in ['', '#', 'about:blank'] for fa in form_actions) else 0
        
        # Other content features
        page_text = soup.get_text()
        title = soup.title.string if soup.title else ''
        
        features['external_favicon'] = 1 if len(links['favicon_external']) > 0 else 0
        features['iframe'] = 1 if soup.find('iframe', {'style': re.compile(r'visibility:\s*hidden|display:\s*none')}) or soup.find('iframe', {'width':'0', 'height':'0'}) else 0
        features['popup_window'] = 1 if 'prompt(' in page_text.lower() else 0
        features['safe_anchor'] = len(links['anchor_unsafe']) / len(links['anchor_all']) if links['anchor_all'] else 0
        features['onmouseover'] = 1 if 'onmouseover' in str(soup).lower() else 0
        features['right_clic'] = 1 if 'event.button ?== ?2' in str(soup) else 0
        features['empty_title'] = 1 if not title else 0
        features['domain_in_title'] = 0 if url_components['domain'] in title.lower() else 1
        
        try:
            copyright_match = re.search(r'©|(©)|copyright', str(soup).lower())
            if copyright_match:
                surrounding_text = str(soup).lower()[max(0, copyright_match.start()-100):copyright_match.end()+100]
                features['domain_with_copyright'] = 0 if url_components['domain'] in surrounding_text else 1
            else:
                features['domain_with_copyright'] = 1 # No copyright found, suspicious
        except:
            features['domain_with_copyright'] = -1 # Error state
            
        return features

    # --------------------------------------------------------------------------
    # External (Third-Party) Feature Extraction
    # --------------------------------------------------------------------------
    
    def _extract_external_features(self, url, components):
        """Extracts features from third-party services like WHOIS, DNS, etc."""
        domain = components['registered_domain']
        features = {}

        # WHOIS based features
        try:
            w = whois.whois(domain)
            if w.creation_date:
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                age_days = (datetime.now() - creation_date).days
                features['domain_age'] = age_days // 365
            else:
                features['domain_age'] = -1

            if w.expiration_date:
                exp_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                features['domain_registration_length'] = (exp_date - datetime.now()).days
            else:
                features['domain_registration_length'] = -1
            
            features['whois_registered_domain'] = 0 if w.domain_name else 1
        except Exception:
            features.update({'domain_age': -1, 'domain_registration_length': -1, 'whois_registered_domain': 1})
        
        # DNS Record
        try:
            import dns.resolver
            dns.resolver.resolve(domain, 'NS')
            features['dns_record'] = 0
        except Exception:
            features['dns_record'] = 1
        
        # Google Index (highly unreliable due to blocking)
        try:
            user_agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            google_search = "https://www.google.com/search?" + urlencode({'q': f'site:{url}'})
            response = requests.get(google_search, headers={'User-Agent': user_agent})
            soup = BeautifulSoup(response.text, "html.parser")
            features['google_index'] = 1 if soup.find(id="rso") is None else 0
        except Exception:
            features['google_index'] = -1 # Error

        # Page Rank (requires API key)
        if self.opr_api_key:
            try:
                opr_url = f'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D={domain}'
                response = requests.get(opr_url, headers={'API-OPR': self.opr_api_key})
                result = response.json()
                features['page_rank'] = int(result['response'][0]['page_rank_integer'])
            except Exception:
                features['page_rank'] = -1
        else:
            features['page_rank'] = -1 # No key provided

        # Web traffic from a third-party site (unreliable and removed)
        features['web_traffic'] = -1 # Alexa API is defunct
        
        # Statistical report (blocklist-based)
        features['statistical_report'] = self._statistical_report(url, domain)

        return features

    # --------------------------------------------------------------------------
    # Helper Methods
    # --------------------------------------------------------------------------
    
    def _char_repeat(self, words):
        """Counts repeated characters in words."""
        count = 0
        for word in words:
            for i in range(len(word) - 1):
                if word[i] == word[i+1]:
                    count += 1
        return count
        
    def _classify_links(self, soup, url_components):
        """Extracts and classifies all links from a BeautifulSoup object."""
        links = {'internal': [], 'external': [], 'null': [], 'favicon_external': [], 'anchor_all':[], 'anchor_unsafe':[]}
        
        base_url = f"{url_components['scheme']}://{url_components['hostname']}/"
        registered_domain = url_components['registered_domain']

        tags_with_links = soup.find_all(['a', 'link', 'img', 'script', 'iframe'], href=True) + \
                          soup.find_all(['img', 'script', 'iframe', 'embed', 'audio'], src=True)
        
        for tag in tags_with_links:
            href = tag.get('href') or tag.get('src')
            if not href: continue

            # Classify anchor tags
            if tag.name == 'a':
                links['anchor_all'].append(href)
                if any(k in href for k in ['#', 'javascript', 'mailto']):
                    links['anchor_unsafe'].append(href)

            # Resolve relative URLs
            full_url = urljoin(base_url, href)
            
            # Classify link type
            if href.startswith(('javascript:', 'mailto:', '#')) or not href.strip():
                links['null'].append(full_url)
            else:
                link_domain = tldextract.extract(full_url).registered_domain
                if link_domain == registered_domain:
                    links['internal'].append(full_url)
                else:
                    links['external'].append(full_url)
                    # Check for external favicons
                    if tag.name == 'link' and 'icon' in ''.join(tag.get('rel', '')):
                        links['favicon_external'].append(full_url)
        
        links['total'] = len(links['internal']) + len(links['external']) + len(links['null'])
        return links

    def _count_redirections(self, links, timeout):
        count = 0
        for link in links[:10]: # Limit to first 10 to avoid excessive requests
            try:
                r = requests.head(link, timeout=timeout, allow_redirects=True)
                if len(r.history) > 0:
                    count += 1
            except requests.RequestException:
                continue
        return count

    def _count_errors(self, links, timeout):
        count = 0
        for link in links[:10]: # Limit to first 10
            try:
                r = requests.head(link, timeout=timeout)
                if r.status_code >= 400:
                    count += 1
            except requests.RequestException:
                continue
        return count
        
    def _statistical_report(self, url, domain):
        """Checks URL/IP against a hardcoded blocklist."""
        suspicious_patterns = [
            'at.ua', 'usa.cc', 'baltazarpresentes.com.br', 'pe.hu', 'esy.es',
            'hol.es', 'sweddy.com', 'myjino.ru', '96.lt', 'ow.ly'
        ]
        if any(pattern in url for pattern in suspicious_patterns):
            return 1

        suspicious_ips = [
            '146.112.61.108', '213.174.157.151', '121.50.168.88', '192.185.217.116'
            # Add more IPs if needed, this is just a sample
        ]
        try:
            ip_address = socket.gethostbyname(domain)
            if ip_address in suspicious_ips:
                return 1
        except socket.error:
            return -1 # DNS resolution failed
        return 0

    def _get_default_content_features(self):
        """Returns a dictionary of default (error state) values for content features."""
        keys = [
            'nb_hyperlinks', 'internal_hyperlinks', 'external_hyperlinks', 'null_hyperlinks',
            'external_css', 'internal_redirection', 'external_redirection', 'internal_errors',
            'external_errors', 'login_form', 'submitting_to_email', 'sfh', 'external_favicon',
            'iframe', 'popup_window', 'safe_anchor', 'onmouseover', 'right_clic',
            'empty_title', 'domain_in_title', 'domain_with_copyright'
        ]
        return {key: -1 for key in keys}
        
    def _get_default_external_features(self):
        """Returns a dictionary of default (error state) values for external features."""
        keys = [
            'domain_age', 'domain_registration_length', 'whois_registered_domain', 'dns_record',
            'google_index', 'page_rank', 'web_traffic', 'statistical_report'
        ]
        return {key: -1 for key in keys}

    def _get_feature_names(self):
        """Returns a list of all feature names in order."""
        # Create a dummy URL and components to get the keys
        dummy_url = "http://www.example.com/path"
        dummy_components = self._decompose_url(dummy_url)
        
        # Get keys from each feature group
        url_features = list(self._extract_url_features(dummy_url, dummy_components).keys())
        content_features = list(self._get_default_content_features().keys())
        external_features = list(self._get_default_external_features().keys())
        
        return ['url'] + url_features + content_features + external_features + ['analysis_status']

# ================== EXAMPLE USAGE ==================

# def main():
#     """
#     Main function to demonstrate the use of the PhishingFeatureExtractor.
#     """
#     # Replace with your OpenPageRank API key if you have one 
    
#     extractor = PhishingFeatureExtractor()
    
#     # --- Example 1: Legitimate URL ---
#     legitimate_url = "https://www.github.com/features/actions"
#     print(f"[*] Analyzing legitimate URL: {legitimate_url}")
    
#     start_time = time.time()
#     features = extractor.extract_features(legitimate_url)
#     end_time = time.time()

#     if 'error' in features:
#         print(f"[!] Error: {features['error']}\n")
#     else:
#         print(f"[*] Analysis complete in {end_time - start_time:.2f} seconds.")
#         print(f"[*] Analysis Status: {features.get('analysis_status', 'N/A')}")
#         # Print a few key features
#         print(f"    - URL Length: {features.get('length_url', 'N/A')}")
#         print(f"    - HTTPS: {'Yes' if features.get('https_token', 1) == 0 else 'No'}")
#         print(f"    - Domain Age (years): {features.get('domain_age', 'N/A')}")
#         print(f"    - Google Index: {'Indexed' if features.get('google_index', 1) == 0 else 'Not Indexed/Error'}")
#         print("-" * 50)
#         print(features)
#     # --- Example 2: Phishing URL (example, may not be live) ---
#     phishing_url = "http://paypal.com.security-check.com/login"
#     print(f"[*] Analyzing potentially malicious URL: {phishing_url}")
    
#     start_time = time.time()
#     features = extractor.extract_features(phishing_url)
#     end_time = time.time()
    
#     if 'error' in features:
#         print(f"[!] Error: {features['error']}\n")
#     else:
#         print(f"[*] Analysis complete in {end_time - start_time:.2f} seconds.")
#         print(f"[*] Analysis Status: {features.get('analysis_status', 'N/A')}")
#         # Print a few key features
#         print(f"    - URL Length: {features.get('length_url', 'N/A')}")
#         print(f"    - Suspicious TLD: {'Yes' if features.get('suspecious_tld', 0) == 1 else 'No'}")
#         print(f"    - Domain in Brand: {'Yes' if features.get('domain_in_brand', 0) == 1 else 'No'}")
#         print(f"    - Domain Age (years): {features.get('domain_age', 'N/A')}")
#         print("-" * 50)

#     # --- Example 3: URL that might be down ---
#     down_url = "http://this-is-a-fake-domain-for-testing12345.com/"
#     print(f"[*] Analyzing a URL that is likely down: {down_url}")

#     start_time = time.time()
#     features = extractor.extract_features(down_url)
#     end_time = time.time()

#     if 'error' in features:
#         print(f"[!] Error: {features['error']}\n")
#     else:
#         print(f"[*] Analysis complete in {end_time - start_time:.2f} seconds.")
#         print(f"[*] Analysis Status: {features.get('analysis_status', 'N/A')}")
#         # Even if the URL is down, offline features are still extracted
#         print(f"    - URL Length: {features.get('length_url', 'N/A')}")
#         print(f"    - Count Dots: {features.get('count_dots', 'N/A')}")
#         print("-" * 50)


# if __name__ == "__main__":
#     main()
