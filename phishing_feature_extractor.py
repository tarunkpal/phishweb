import re
import time
import logging
import requests
import whois
import tldextract
from urllib.parse import urlparse, urljoin, urlencode
from datetime import datetime
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("whois").setLevel(logging.WARNING)

# ================== CONSTANTS AND CONFIGURATION ==================
HINTS = ['wp', 'login', 'includes', 'admin', 'content', 'site', 'images', 'js', 'alibaba', 'css', 'myaccount', 'dropbox', 'themes', 'plugins', 'signin', 'view']

# ================== MAIN FEATURE EXTRACTOR CLASS ==================

class PhishingFeatureExtractor:
    """
    A class to extract a specific subset of 32 features from a URL for phishing detection.
    """

    def __init__(self, opr_api_key=None):
        """
        Initializes the feature extractor.
        
        Args:
            opr_api_key (str, optional): API key for OpenPageRank. Defaults to None.
        """
        self.opr_api_key = 'g8g0csg4wg88k8wo004s8k0soccokc040c0w0sk0'
        self.feature_names = [
            'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens', 'nb_qm',
            'nb_slash', 'nb_www', 'length_words_raw', 'char_repeat',
            'shortest_words_raw', 'shortest_word_host', 'shortest_word_path',
            'longest_words_raw', 'longest_word_host', 'avg_words_raw',
            'avg_word_host', 'avg_word_path', 'phish_hints', 'nb_hyperlinks',
            'ratio_intHyperlinks', 'ratio_extHyperlinks', 'ratio_extRedirection',
            'links_in_tags', 'safe_anchor', 'domain_in_title',
            'domain_with_copyright', 'domain_registration_length', 'domain_age',
            'web_traffic', 'google_index', 'page_rank'
        ]

    def extract_features(self, url, request_timeout=5):
        """
        Extracts the 32 specified features from the given URL.
        
        Args:
            url (str): The URL to analyze.
            request_timeout (int): Timeout in seconds for web requests.
            
        Returns:
            dict: A dictionary containing the 32 extracted features.
                  Returns a dictionary with an 'error' key if extraction fails critically.
        """
        features = {}

        # 1. Decompose URL
        try:
            url_components = self._decompose_url(url)
        except Exception as e:
            logging.error(f"Error decomposing URL {url}: {e}")
            return {'url': url, 'error': f"Invalid URL or decomposition failed: {e}"}

        # 2. Extract URL-based features (Offline)
        features.update(self._extract_url_features(url, url_components))

        # 3. Attempt to access the URL for content and external features
        try:
            response = requests.get(url, timeout=request_timeout, headers={'User-Agent': 'Mozilla/5.0'})
            response.raise_for_status()
            content = response.text
            soup = BeautifulSoup(content, 'html.parser')
            # Add redirection feature from response
            features['ratio_extRedirection'] = self._count_external_redirections_from_links(
                self._classify_links(soup, url_components)['external'],
                timeout=2 # Use a shorter timeout for this slow check
            )
        except requests.exceptions.RequestException as e:
            logging.warning(f"Could not access or parse content from {url}: {e}")
            soup = BeautifulSoup("", 'html.parser') # Create empty soup
            features.update(self._get_default_content_features())
            features.update(self._get_default_external_features())
            features['analysis_status'] = f'Content/External feature extraction failed: {e}'
            return features

        # 4. Extract content and external features
        features.update(self._extract_content_features(soup, url_components))
        features.update(self._extract_external_features(url, url_components))
        
        features['analysis_status'] = 'Success'
        
        # Ensure only the required features are in the final dictionary
        final_features = {key: features.get(key, -1) for key in self.feature_names}
        final_features['url'] = url
        final_features['analysis_status'] = features['analysis_status']
        
        return final_features

    # --------------------------------------------------------------------------
    # Helper Methods for Feature Extraction
    # --------------------------------------------------------------------------

    def _decompose_url(self, url):
        """Creates a dictionary of URL components."""
        ext = tldextract.extract(url)
        parsed = urlparse(url)
        hostname = parsed.hostname if parsed.hostname else ''
        path = parsed.path
        
        components = {
            'scheme': parsed.scheme, 'hostname': hostname, 'path': path,
            'domain': ext.domain, 'registered_domain': ext.registered_domain or ext.domain,
        }
        
        w_domain = re.split(r'[-.]', components['domain'].lower())
        w_subdomain = re.split(r'[-.]', ext.subdomain.lower())
        w_path = re.split(r'[-./?=@&%:_]', path.lower())
        
        components['words_raw'] = list(filter(None, w_domain + w_subdomain + w_path))
        components['words_host'] = list(filter(None, w_domain + w_subdomain))
        components['words_path'] = list(filter(None, w_path))
        
        return components

    def _extract_url_features(self, url, components):
        """Extracts the required subset of URL-based features."""
        hostname = components['hostname']
        words_raw, words_host, words_path = components['words_raw'], components['words_host'], components['words_path']

        return {
            'length_url': len(url),
            'length_hostname': len(hostname),
            'ip': 1 if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', hostname) else 0,
            'nb_dots': url.count('.'),
            'nb_hyphens': hostname.count('-'),
            'nb_qm': url.count('?'),
            'nb_slash': url.count('/'),
            'nb_www': hostname.lower().count('www'),
            'length_words_raw': len(words_raw),
            'char_repeat': self._char_repeat(words_raw),
            'shortest_words_raw': min(len(w) for w in words_raw) if words_raw else 0,
            'shortest_word_host': min(len(w) for w in words_host) if words_host else 0,
            'shortest_word_path': min(len(w) for w in words_path) if words_path else 0,
            'longest_words_raw': max(len(w) for w in words_raw) if words_raw else 0,
            'longest_word_host': max(len(w) for w in words_host) if words_host else 0,
            'avg_words_raw': sum(len(w) for w in words_raw) / len(words_raw) if words_raw else 0,
            'avg_word_host': sum(len(w) for w in words_host) / len(words_host) if words_host else 0,
            'avg_word_path': sum(len(w) for w in words_path) if words_path else 0,
            'phish_hints': sum(components['path'].lower().count(hint) for hint in HINTS),
        }

    def _extract_content_features(self, soup, url_components):
        """Extracts the required subset of content-based features."""
        if not soup.body:
            return self._get_default_content_features()
        
        links = self._classify_links(soup, url_components)
        title = soup.title.string if soup.title else ''
        total_hyperlinks = links['total']

        features = {
            'nb_hyperlinks': total_hyperlinks,
            'ratio_intHyperlinks': len(links['internal']) / total_hyperlinks if total_hyperlinks > 0 else 0,
            'ratio_extHyperlinks': len(links['external']) / total_hyperlinks if total_hyperlinks > 0 else 0,
            'links_in_tags': len(links['tag_links_internal']) / (len(links['tag_links_internal']) + len(links['tag_links_external'])) if (len(links['tag_links_internal']) + len(links['tag_links_external'])) > 0 else 0,
            'safe_anchor': len(links['anchor_unsafe']) / len(links['anchor_all']) if links['anchor_all'] else 0,
            'domain_in_title': 0 if url_components['domain'] in title.lower() else 1,
        }

        try:
            copyright_match = re.search(r'©|(©)|copyright', str(soup).lower())
            if copyright_match:
                surrounding_text = str(soup).lower()[max(0, copyright_match.start() - 100):copyright_match.end() + 100]
                features['domain_with_copyright'] = 0 if url_components['domain'] in surrounding_text else 1
            else:
                features['domain_with_copyright'] = 1
        except Exception:
            features['domain_with_copyright'] = -1
            
        return features

    def _extract_external_features(self, url, components):
        """Extracts the required subset of external features."""
        domain = components['registered_domain']
        features = {'domain_age': -1, 'domain_registration_length': -1, 'google_index': 1, 'page_rank': -1, 'web_traffic': -1}
        
        try:
            w = whois.whois(domain)
            if w.creation_date:
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                features['domain_age'] = (datetime.now() - creation_date).days
            if w.expiration_date:
                exp_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                features['domain_registration_length'] = (exp_date - datetime.now()).days
        except Exception:
            pass
        
        try:
            google_search = "https://www.google.com/search?" + urlencode({'q': f'site:{url}'})
            response = requests.get(google_search, headers={'User-Agent': 'Mozilla/5.0'}, timeout=3)
            if response.status_code == 200 and 'Our systems have detected unusual traffic' not in response.text:
                soup = BeautifulSoup(response.text, "html.parser")
                features['google_index'] = 1 if soup.find(id="rso") is None else 0
        except Exception:
            pass

        if self.opr_api_key:
            try:
                opr_url = f'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D={domain}'
                response = requests.get(opr_url, headers={'API-OPR': self.opr_api_key}, timeout=3)
                result = response.json()
                features['page_rank'] = int(result['response'][0]['page_rank_integer'])
            except Exception:
                pass
        
        return features

    def _get_default_content_features(self):
        """Returns default values for content features when a page is inaccessible."""
        return {
            'nb_hyperlinks': -1, 'ratio_intHyperlinks': -1, 'ratio_extHyperlinks': -1,
            'ratio_extRedirection': -1, 'links_in_tags': -1, 'safe_anchor': -1,
            'domain_in_title': -1, 'domain_with_copyright': -1
        }
        
    def _get_default_external_features(self):
        """Returns default values for external features when a page is inaccessible."""
        return {
            'domain_registration_length': -1, 'domain_age': -1, 'web_traffic': -1,
            'google_index': 1, 'page_rank': -1
        }
        
    def _classify_links(self, soup, components):
        """Helper to classify links for feature calculation."""
        base_url = f"{components['scheme']}://{components['hostname']}/"
        domain = components['registered_domain']
        
        links = {'internal': [], 'external': [], 'null': [], 'anchor_all': [], 'anchor_unsafe': [],
                 'tag_links_internal': [], 'tag_links_external': []}

        for tag in soup.find_all(['a', 'link', 'script']):
            href = tag.get('href') or tag.get('src')
            if not href: continue

            full_url = urljoin(base_url, href)
            link_domain = tldextract.extract(full_url).registered_domain

            is_internal = link_domain == domain
            is_null = href.startswith(('#', 'javascript:', 'mailto:')) or not href.strip()

            if is_null: links['null'].append(full_url)
            elif is_internal: links['internal'].append(full_url)
            else: links['external'].append(full_url)

            if tag.name == 'a':
                links['anchor_all'].append(href)
                if is_null: links['anchor_unsafe'].append(href)
            elif tag.name in ['link', 'script']:
                if is_internal: links['tag_links_internal'].append(full_url)
                else: links['tag_links_external'].append(full_url)
        
        links['total'] = len(links['internal']) + len(links['external']) + len(links['null'])
        return links

    def _count_external_redirections_from_links(self, external_links, timeout):
        """Counts redirections in a sample of external links."""
        count = 0
        # Limit to first 5 external links to avoid being too slow
        for link in external_links[:5]:
            try:
                r = requests.head(link, timeout=timeout, allow_redirects=True)
                if len(r.history) > 0:
                    count += 1
            except requests.RequestException:
                continue
        return count / len(external_links[:5]) if external_links else 0
        
    def _char_repeat(self, words):
        """Counts consecutive repeated characters in words."""
        count = 0
        for word in words:
            for i in range(len(word) - 1):
                if word[i] == word[i+1]:
                    count += 1
        return count
