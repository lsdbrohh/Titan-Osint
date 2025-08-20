import subprocess, sys, importlib, asyncio, aiohttp, json, time, random, re, hashlib, base64, os
from urllib.parse import urlparse, urljoin, quote
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor
import numpy as np

# Auto-install dependencies
deps = {"aiohttp": "aiohttp", "beautifulsoup4": "bs4", "colorama": "colorama", "fake-useragent": "fake_useragent", 
        "asyncio-throttle": "asyncio_throttle", "aiofiles": "aiofiles", "requests": "requests", "numpy": "numpy",
        "scikit-learn": "sklearn", "pycryptodome": "Crypto", "phonenumbers": "phonenumbers", "whois": "whois"}

for pkg, module in deps.items():
    try: importlib.import_module(module.split(".")[0])
    except ImportError: subprocess.run([sys.executable, "-m", "pip", "install", pkg, "--quiet"])

from fake_useragent import UserAgent
from asyncio_throttle import Throttler
import aiofiles
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
try: import phonenumbers; import whois
except: phonenumbers, whois = None, None

init(autoreset=True)

class EnhancedIntelligence:
    def __init__(self):
        self.ua = UserAgent()
        self.crypto_key = get_random_bytes(32)
        self.platforms = {
            "Twitter": {"url": "https://twitter.com/{}", "api": ["https://api.twitter.com/1.1/users/show.json?screen_name={}", "https://twitter.com/i/api/graphql/*/UserByScreenName"], "patterns": [r'"screen_name"\s*:\s*"([^"]+)"', r'data-screen-name="([^"]+)"'], "meta": ["followers_count", "following_count", "verified", "created_at", "location", "description"]},
            "Instagram": {"url": "https://www.instagram.com/{}/", "api": ["https://www.instagram.com/api/v1/users/web_profile_info/?username={}", "https://i.instagram.com/api/v1/users/{}/info/"], "patterns": [r'"username"\s*:\s*"([^"]+)"'], "meta": ["edge_followed_by", "edge_follow", "is_verified", "biography", "external_url", "profile_pic_url"]},
            "GitHub": {"url": "https://github.com/{}", "api": ["https://api.github.com/users/{}", "https://github.com/{}.json"], "patterns": [r'"login"\s*:\s*"([^"]+)"'], "meta": ["public_repos", "followers", "following", "created_at", "location", "blog", "company", "bio"]},
            "LinkedIn": {"url": "https://www.linkedin.com/in/{}/", "api": ["https://www.linkedin.com/voyager/api/identity/profiles/{}/profileView"], "patterns": [r'"publicIdentifier"\s*:\s*"([^"]+)"'], "meta": ["headline", "industry", "location", "connections", "experience", "education"]},
            "Reddit": {"url": "https://www.reddit.com/user/{}/", "api": ["https://www.reddit.com/user/{}/about.json", "https://www.reddit.com/user/{}.json"], "patterns": [r'"name"\s*:\s*"([^"]+)"'], "meta": ["link_karma", "comment_karma", "verified", "created", "is_gold", "is_mod"]},
            "TikTok": {"url": "https://www.tiktok.com/@{}", "api": ["https://www.tiktok.com/api/user/detail/?uniqueId={}"], "patterns": [r'"uniqueId"\s*:\s*"([^"]+)"'], "meta": ["followerCount", "followingCount", "verified", "signature", "avatarThumb"]},
            "YouTube": {"url": "https://www.youtube.com/@{}", "api": ["https://www.youtube.com/c/{}/about", "https://www.googleapis.com/youtube/v3/channels"], "patterns": [r'"channelId"\s*:\s*"([^"]+)"'], "meta": ["subscriberCount", "videoCount", "viewCount", "description", "country", "publishedAt"]},
            "Facebook": {"url": "https://www.facebook.com/{}", "api": ["https://graph.facebook.com/{}"], "patterns": [r'"id"\s*:\s*"([^"]+)"'], "meta": ["name", "username", "verified", "link", "about", "category"]},
            "Twitch": {"url": "https://www.twitch.tv/{}", "api": ["https://gql.twitch.tv/gql"], "patterns": [r'"login"\s*:\s*"([^"]+)"'], "meta": ["followers", "views", "partnered", "description", "game"]},
            "Discord": {"url": "https://discord.com/users/{}", "api": ["https://discord.com/api/v9/users/{}"], "patterns": [r'"username"\s*:\s*"([^"]+)"'], "meta": ["discriminator", "avatar", "banner", "flags", "premium_type"]},
            "Pinterest": {"url": "https://www.pinterest.com/{}/", "api": ["https://www.pinterest.com/resource/UserResource/get/?source_url=/{}"], "patterns": [r'"username"\s*:\s*"([^"]+)"'], "meta": ["follower_count", "following_count", "pin_count", "board_count"]},
            "Snapchat": {"url": "https://www.snapchat.com/add/{}", "api": ["https://www.snapchat.com/add/{}"], "patterns": [r'data-username="([^"]+)"'], "meta": ["display_name", "bitmoji", "snap_score"]},
            "OnlyFans": {"url": "https://onlyfans.com/{}", "api": ["https://onlyfans.com/api2/v2/users/{}"], "patterns": [r'"username"\s*:\s*"([^"]+)"'], "meta": ["postsCount", "favoritesCount", "isVerified", "subscribersCount"]},
            "Medium": {"url": "https://medium.com/@{}", "api": ["https://medium.com/@{}?format=json"], "patterns": [r'"username"\s*:\s*"([^"]+)"'], "meta": ["followersCount", "followingCount", "bio", "twitterScreenName"]},
            "Telegram": {"url": "https://t.me/{}", "api": [], "patterns": [r'"username"\s*:\s*"([^"]+)"'], "meta": ["description", "members_count", "type"]},
            "Steam": {"url": "https://steamcommunity.com/id/{}", "api": ["https://api.steampowered.com/ISteamUser/ResolveVanityURL/v0001/?key=STEAM_KEY&vanityurl={}"], "patterns": [r'"personaname"\s*:\s*"([^"]+)"'], "meta": ["personaname", "profileurl", "avatar", "realname", "loccountrycode"]},
            "Spotify": {"url": "https://open.spotify.com/user/{}", "api": [], "patterns": [r'"username"\s*:\s*"([^"]+)"'], "meta": ["display_name", "followers", "playlists"]},
            "SoundCloud": {"url": "https://soundcloud.com/{}", "api": ["https://api.soundcloud.com/users/{}"], "patterns": [r'"username"\s*:\s*"([^"]+)"'], "meta": ["followers_count", "followings_count", "track_count", "description"]},
            "Behance": {"url": "https://www.behance.net/{}", "api": ["https://www.behance.net/v2/users/{}"], "patterns": [r'"username"\s*:\s*"([^"]+)"'], "meta": ["followers", "following", "project_views", "appreciations"]},
            "DeviantArt": {"url": "https://www.deviantart.com/{}", "api": [], "patterns": [r'"username"\s*:\s*"([^"]+)"'], "meta": ["watchers", "watching", "deviations"]},
            "Flickr": {"url": "https://www.flickr.com/people/{}", "api": ["https://api.flickr.com/services/rest/?method=flickr.people.getInfo&user_id={}"], "patterns": [r'"username"\s*:\s*"([^"]+)"'], "meta": ["photos", "followers", "following", "pro_user"]},
            "Vimeo": {"url": "https://vimeo.com/{}", "api": ["https://api.vimeo.com/users/{}"], "patterns": [r'"name"\s*:\s*"([^"]+)"'], "meta": ["videos", "followers", "following", "bio"]},
            "Mastodon": {"url": "https://mastodon.social/@{}", "api": ["https://mastodon.social/api/v1/accounts/lookup?acct={}"], "patterns": [r'"username"\s*:\s*"([^"]+)"'], "meta": ["followers_count", "following_count", "statuses_count", "note"]},
            "AboutMe": {"url": "https://about.me/{}", "api": [], "patterns": [r'"username"\s*:\s*"([^"]+)"'], "meta": ["bio", "location", "website"]},
            "AngelList": {"url": "https://angel.co/u/{}", "api": [], "patterns": [r'"slug"\s*:\s*"([^"]+)"'], "meta": ["bio", "location", "investor", "founder"]},
            "Goodreads": {"url": "https://www.goodreads.com/user/show/{}", "api": [], "patterns": [r'"name"\s*:\s*"([^"]+)"'], "meta": ["books", "reviews", "friends"]},
            "LastFM": {"url": "https://www.last.fm/user/{}", "api": ["http://ws.audioscrobbler.com/2.0/?method=user.getinfo&user={}"], "patterns": [r'"name"\s*:\s*"([^"]+)"'], "meta": ["playcount", "artist_count", "track_count", "album_count"]},
            "Patreon": {"url": "https://www.patreon.com/{}", "api": [], "patterns": [r'"name"\s*:\s*"([^"]+)"'], "meta": ["patron_count", "creation_count", "is_creators"]},
            "Keybase": {"url": "https://keybase.io/{}", "api": ["https://keybase.io/_/api/1.0/user/lookup.json?username={}"], "patterns": [r'"username"\s*:\s*"([^"]+)"'], "meta": ["proofs", "followers", "following", "bio"]},
            "GitLab": {"url": "https://gitlab.com/{}", "api": ["https://gitlab.com/api/v4/users?username={}"], "patterns": [r'"username"\s*:\s*"([^"]+)"'], "meta": ["public_repos", "followers", "following", "bio"]},
            "Bitbucket": {"url": "https://bitbucket.org/{}", "api": ["https://api.bitbucket.org/2.0/users/{}"], "patterns": [r'"username"\s*:\s*"([^"]+)"'], "meta": ["repositories", "followers", "following", "location"]},
            "HackerNews": {"url": "https://news.ycombinator.com/user?id={}", "api": ["https://hacker-news.firebaseio.com/v0/user/{}.json"], "patterns": [r'"id"\s*:\s*"([^"]+)"'], "meta": ["karma", "created", "about"]},
            "ProductHunt": {"url": "https://www.producthunt.com/@{}", "api": [], "patterns": [r'"username"\s*:\s*"([^"]+)"'], "meta": ["followers", "following", "made", "hunted"]},
            "Dribbble": {"url": "https://dribbble.com/{}", "api": ["https://api.dribbble.com/v2/user/{}"], "patterns": [r'"username"\s*:\s*"([^"]+)"'], "meta": ["followers", "following", "likes_received", "shots_count"]},
            "500px": {"url": "https://500px.com/p/{}", "api": [], "patterns": [r'"username"\s*:\s*"([^"]+)"'], "meta": ["followers", "following", "photos", "affection"]},
            "Gravatar": {"url": "https://gravatar.com/{}", "api": ["https://www.gravatar.com/{}.json"], "patterns": [r'"hash"\s*:\s*"([^"]+)"'], "meta": ["displayName", "profileUrl", "photos"]},
            "Skype": {"url": "skype:{}", "api": [], "patterns": [], "meta": ["display_name", "mood", "country"]},
            "Academia": {"url": "https://independent.academia.edu/{}", "api": [], "patterns": [r'"name"\s*:\s*"([^"]+)"'], "meta": ["followers", "following", "papers", "citations"]},
            "ResearchGate": {"url": "https://www.researchgate.net/profile/{}", "api": [], "patterns": [r'"name"\s*:\s*"([^"]+)"'], "meta": ["publications", "citations", "reads", "followers"]},
            "ORCID": {"url": "https://orcid.org/{}", "api": ["https://pub.orcid.org/v3.0/{}/record"], "patterns": [r'"orcid-id"\s*:\s*"([^"]+)"'], "meta": ["given-names", "family-name", "works-count", "employment"]},
            "Crunchbase": {"url": "https://www.crunchbase.com/person/{}", "api": [], "patterns": [r'"name"\s*:\s*"([^"]+)"'], "meta": ["location", "jobs", "investments", "founded"]}
        }
        self.throttlers = {p: Throttler(rate_limit=random.randint(8, 20), period=1) for p in self.platforms}
        
    def generate_variations(self, username):
        base = [username, username.lower(), username.upper(), username.capitalize()]
        
        nums = ['123', '1', '2', '01', '02', '21', '69', '99', '00', '007', '2023', '2024', '2025']
        texts = ['official', 'real', 'og', 'pro', 'dev', 'x', 'xx', 'xxx', '_', '__', 'the', 'i', 'im']
        prefixes = ['the', 'real', 'official', 'mr', 'ms', 'dr', 'i', 'im', 'itz', 'its', 'el', 'la']
        
        variations = set(base)
        
        for item in nums + texts:
            variations.update([username + item, item + username, username + '_' + item, item + '_' + username])
        
        for prefix in prefixes:
            variations.update([prefix + username, prefix + '_' + username, prefix + '.' + username])
        
        variations.update([
            username.replace('_', ''), username.replace('_', '.'), username.replace('_', '-'),
            username.replace('.', ''), username.replace('.', '_'), username.replace('.', '-'),
            username.replace('-', ''), username.replace('-', '_'), username.replace('-', '.'),
            re.sub(r'[aeiou]', '', username), username[::-1], username + username[-1:],
            username[0] + username[1:].replace(username[1], ''),
            ''.join([c for i, c in enumerate(username) if i % 2 == 0]),
            username.replace('a', '4').replace('e', '3').replace('i', '1').replace('o', '0'),
            username + 'x' * random.randint(1, 3)
        ])
        
        return list(variations)[:50]
    
    def extract_advanced_metadata(self, content, headers, platform_config):
        soup = BeautifulSoup(content, 'html.parser')
        metadata = {}
        
        # JSON-LD structured data
        json_scripts = soup.find_all('script', type='application/ld+json')
        for script in json_scripts:
            try:
                data = json.loads(script.string)
                if isinstance(data, dict):
                    metadata.update({f"jsonld_{k}": v for k, v in data.items() if isinstance(v, (str, int, float))})
            except: continue
        
        # OpenGraph and Twitter meta tags
        meta_tags = soup.find_all('meta')
        for tag in meta_tags:
            name = tag.get('name') or tag.get('property') or tag.get('itemprop')
            content_attr = tag.get('content')
            if name and content_attr:
                metadata[f"meta_{name}"] = content_attr
        
        # All JSON data patterns
        json_matches = re.findall(r'\{[^{}]*"[^"]*":[^{}]*\}', content)
        for i, json_str in enumerate(json_matches[:10]):
            try:
                data = json.loads(json_str)
                for extractor in platform_config.get("meta", []):
                    if extractor in data:
                        metadata[f"json_{extractor}"] = data[extractor]
            except: continue
        
        # Extract emails, phones, URLs
        emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)
        phones = re.findall(r'[\+]?[1-9]?[\d]{1,3}[-.\s]?\(?\d{1,3}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}', content)
        urls = re.findall(r'https?://[^\s<>"]+', content)
        
        if emails: metadata['extracted_emails'] = emails[:5]
        if phones and phonenumbers: 
            try:
                parsed_phones = [phonenumbers.format_number(phonenumbers.parse(phone, None), phonenumbers.PhoneNumberFormat.E164) 
                               for phone in phones[:3]]
                metadata['extracted_phones'] = parsed_phones
            except: metadata['extracted_phones'] = phones[:3]
        if urls: metadata['extracted_urls'] = urls[:10]
        
        # Social media handles
        social_handles = re.findall(r'@([a-zA-Z0-9_]{1,15})', content)
        hashtags = re.findall(r'#([a-zA-Z0-9_]+)', content)
        if social_handles: metadata['social_handles'] = list(set(social_handles))[:10]
        if hashtags: metadata['hashtags'] = list(set(hashtags))[:10]
        
        # Extract text content for analysis
        text_content = soup.get_text()
        words = re.findall(r'\b\w+\b', text_content.lower())
        if len(words) > 20:
            word_freq = {}
            for word in words:
                if len(word) > 3:
                    word_freq[word] = word_freq.get(word, 0) + 1
            top_words = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)[:15]
            metadata['top_keywords'] = [word for word, freq in top_words]
        
        # Network information
        metadata['server'] = headers.get('server', 'Unknown')
        metadata['x_powered_by'] = headers.get('x-powered-by', 'Not specified')
        metadata['content_type'] = headers.get('content-type', 'Unknown')
        metadata['content_length'] = headers.get('content-length', 'Unknown')
        metadata['last_modified'] = headers.get('last-modified', 'Unknown')
        metadata['cache_control'] = headers.get('cache-control', 'Unknown')
        metadata['cdn_detected'] = any(cdn in str(headers).lower() for cdn in ['cloudflare', 'fastly', 'akamai', 'amazon', 'google'])
        
        # Security headers analysis
        security_headers = ['x-frame-options', 'x-content-type-options', 'strict-transport-security', 
                          'content-security-policy', 'x-xss-protection', 'referrer-policy']
        metadata['security_score'] = sum(1 for h in security_headers if h in headers) * 16.67
        
        return metadata
    
    def calculate_advanced_confidence(self, content, headers, status_code, response_time, username, platform, metadata):
        weights = {
            'status': 0.20, 'content': 0.25, 'metadata': 0.20, 'network': 0.15, 
            'timing': 0.10, 'extraction': 0.10
        }
        
        # Status confidence
        status_scores = {200: 95, 301: 80, 302: 75, 403: 50, 404: 5, 429: 35, 500: 15}
        status_confidence = status_scores.get(status_code, 20)
        
        # Content analysis
        profile_indicators = len(re.findall(r'(?i)(followers?|following|posts?|tweets?|repos?|subscribers?|views?|likes?|profile|bio|about)', content))
        username_mentions = len(re.findall(re.escape(username.lower()), content.lower()))
        json_data_count = len(re.findall(r'\{[^{}]*"[^"]*":[^{}]*\}', content))
        content_confidence = min((profile_indicators * 6) + (username_mentions * 15) + (json_data_count * 4), 100)
        
        # Metadata richness
        metadata_confidence = min(len(metadata) * 3, 100)
        
        # Network indicators
        network_confidence = 70 if metadata.get('cdn_detected') else 40
        network_confidence += metadata.get('security_score', 0) * 0.3
        
        # Response timing
        timing_confidence = max(100 - (response_time / 20), 30) if isinstance(response_time, (int, float)) else 50
        
        # Data extraction success
        extraction_items = ['extracted_emails', 'extracted_phones', 'extracted_urls', 'social_handles', 'top_keywords']
        extraction_confidence = sum(15 for item in extraction_items if metadata.get(item)) + 25
        
        final_confidence = (
            weights['status'] * status_confidence +
            weights['content'] * content_confidence +
            weights['metadata'] * metadata_confidence +
            weights['network'] * network_confidence +
            weights['timing'] * timing_confidence +
            weights['extraction'] * extraction_confidence
        )
        
        return min(max(final_confidence, 0), 100)
    
    async def scan_platform(self, session, platform, username, variation):
        config = self.platforms[platform]
        endpoints = [config["url"].format(variation)] + [ep.format(variation) for ep in config.get("api", [])]
        
        best_result = None
        max_confidence = 0
        
        for endpoint_url in endpoints:
            try:
                async with self.throttlers[platform]:
                    start_time = time.time()
                    
                    headers = {
                        'User-Agent': self.ua.random,
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Language': random.choice(['en-US,en;q=0.9', 'en-GB,en;q=0.8']),
                        'Accept-Encoding': 'gzip, deflate, br',
                        'Connection': 'keep-alive',
                        'Upgrade-Insecure-Requests': '1',
                        'Cache-Control': random.choice(['no-cache', 'max-age=0']),
                        'DNT': '1'
                    }
                    
                    if platform in ['Instagram', 'TikTok']:
                        headers['X-Requested-With'] = 'XMLHttpRequest'
                    
                    await asyncio.sleep(random.uniform(1, 4))
                    
                    timeout = aiohttp.ClientTimeout(total=25)
                    async with session.get(endpoint_url, headers=headers, timeout=timeout, 
                                         ssl=False, allow_redirects=True) as response:
                        
                        response_time = (time.time() - start_time) * 1000
                        content = await response.text()
                        
                        # Extract comprehensive metadata
                        metadata = self.extract_advanced_metadata(content, response.headers, config)
                        
                        # Calculate advanced confidence score
                        confidence = self.calculate_advanced_confidence(
                            content, response.headers, response.status, response_time, 
                            variation, platform, metadata
                        )
                        
                        if confidence > max_confidence and confidence > 40:
                            # Additional network analysis
                            parsed_url = urlparse(endpoint_url)
                            try:
                                import socket
                                ip = socket.gethostbyname(parsed_url.hostname)
                            except:
                                ip = "Unknown"
                            
                            max_confidence = confidence
                            best_result = {
                                "platform": platform,
                                "username": variation,
                                "original_target": username,
                                "url": endpoint_url,
                                "status_code": response.status,
                                "confidence_score": round(confidence, 2),
                                "content_size": len(content),
                                "response_time_ms": round(response_time, 2),
                                "ip_address": ip,
                                "metadata": metadata,
                                "content_hash": hashlib.md5(content.encode()).hexdigest()[:16],
                                "timestamp": int(time.time()),
                                "headers_analyzed": len(response.headers),
                                "security_score": metadata.get('security_score', 0)
                            }
                            
            except Exception as e:
                continue
                
        return best_result
    
    async def comprehensive_scan(self, target_username):
        variations = self.generate_variations(target_username)
        results = []
        
        # Enhanced connector settings
        connector = aiohttp.TCPConnector(
            limit=150, limit_per_host=25, keepalive_timeout=120,
            enable_cleanup_closed=True, ssl=False, use_dns_cache=True,
            ttl_dns_cache=300
        )
        
        timeout = aiohttp.ClientTimeout(total=35, connect=25)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = []
            
            # Create tasks for all platform-variation combinations
            for platform in self.platforms.keys():
                for variation in variations:
                    task = self.scan_platform(session, platform, target_username, variation)
                    tasks.append(task)
            
            # Process results with real-time feedback
            completed = 0
            total = len(tasks)
            high_confidence_results = []
            
            print(f"\n{Fore.CYAN}Scanning {len(self.platforms)} platforms with {len(variations)} variations...")
            print(f"{Fore.CYAN}Total endpoints to check: {total}")
            
            for completed_task in asyncio.as_completed(tasks):
                try:
                    result = await completed_task
                    completed += 1
                    
                    progress = (completed / total) * 100
                    print(f"\r{Fore.CYAN}Progress: {progress:.1f}% | Found: {len(high_confidence_results)} | Checking: {completed}/{total}", end="", flush=True)
                    
                    if result and result["confidence_score"] >= 45:
                        high_confidence_results.append(result)
                        results.append(result)
                        self._display_result(result)
                        
                except Exception:
                    completed += 1
        
        # Remove duplicates and sort by confidence
        unique_results = self._deduplicate_results(results)
        sorted_results = sorted(unique_results, key=lambda x: x['confidence_score'], reverse=True)
        
        print(f"\n{Fore.GREEN}Scan completed! Found {len(sorted_results)} unique profiles.")
        return sorted_results
    
    def _deduplicate_results(self, results):
        unique = {}
        for result in results:
            key = f"{result['platform']}:{result['username']}"
            if key not in unique or result['confidence_score'] > unique[key]['confidence_score']:
                unique[key] = result
        return list(unique.values())
    
    def _display_result(self, result):
        confidence = result["confidence_score"]
        
        if confidence >= 90:
            color, status = Fore.GREEN, "VERIFIED"
        elif confidence >= 75:
            color, status = Fore.YELLOW, "HIGH-CONF"
        elif confidence >= 60:
            color, status = Fore.CYAN, "MODERATE"
        else:
            color, status = Fore.MAGENTA, "POSSIBLE"
        
        print(f"\n{color}┌─ {result['platform']} | {status} | {confidence}%")
        print(f"{color}│  User: {result['username']} | IP: {result['ip_address']}")
        print(f"{color}│  URL: {result['url']}")
        print(f"{color}│  Data: {len(result['metadata'])} fields | {result['content_size']} bytes | {result['response_time_ms']}ms")
        
        # Show key metadata
        meta = result['metadata']
        if meta.get('extracted_emails'):
            print(f"{color}│  Emails: {', '.join(meta['extracted_emails'][:2])}")
        if meta.get('social_handles'):
            print(f"{color}│  Handles: @{', @'.join(meta['social_handles'][:3])}")
        if meta.get('top_keywords'):
            print(f"{color}│  Keywords: {', '.join(meta['top_keywords'][:5])}")
        
        print(f"{color}│  Security: {meta.get('security_score', 0):.0f}% | CDN: {'Yes' if meta.get('cdn_detected') else 'No'}")
        print(f"{color}└─")

class DataExporter:
    def __init__(self):
        self.crypto_key = get_random_bytes(32)
    
    async def export_intelligence(self, results, target):
        if not results:
            print(f"{Fore.RED}No data to export.")
            return
        
        timestamp = int(time.time())
        stats = self._generate_statistics(results)
        
        # Enhanced JSON export with full analysis
        enhanced_data = {
            "scan_metadata": {
                "target": target,
                "timestamp": timestamp,
                "total_results": len(results),
                "platforms_found": len(set(r['platform'] for r in results)),
                "avg_confidence": sum(r['confidence_score'] for r in results) / len(results),
                "scan_duration": "Real-time",
                "methodology": "Advanced Neural OSINT"
            },
            "statistical_analysis": stats,
            "detailed_results": results,
            "cross_platform_analysis": self._cross_platform_analysis(results),
            "security_assessment": self._security_assessment(results),
            "data_extraction_summary": self._extraction_summary(results)
        }
        
        # JSON export
        json_filename = f"osint_intelligence_{target}_{timestamp}.json"
        async with aiofiles.open(json_filename, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(enhanced_data, indent=2, ensure_ascii=False))
        
        # CSV export for data analysis
        csv_filename = f"osint_data_{target}_{timestamp}.csv"
        await self._export_csv(results, csv_filename)
        
        # Summary report
        txt_filename = f"osint_report_{target}_{timestamp}.txt"
        await self._export_summary(enhanced_data, txt_filename)
        
        print(f"{Fore.GREEN}Intelligence exported:")
        print(f"{Fore.GREEN}│  JSON: {json_filename}")
        print(f"{Fore.GREEN}│  CSV:  {csv_filename}")
        print(f"{Fore.GREEN}│  TXT:  {txt_filename}")
    
    def _generate_statistics(self, results):
        confidence_scores = [r['confidence_score'] for r in results]
        platforms = [r['platform'] for r in results]
        response_times = [r['response_time_ms'] for r in results]
        
        return {
            "confidence_distribution": {
                "mean": np.mean(confidence_scores),
                "median": np.median(confidence_scores),
                "std_dev": np.std(confidence_scores),
                "min": min(confidence_scores),
                "max": max(confidence_scores),
                "ranges": {
                    "90-100%": sum(1 for c in confidence_scores if c >= 90),
                    "75-89%": sum(1 for c in confidence_scores if 75 <= c < 90),
                    "60-74%": sum(1 for c in confidence_scores if 60 <= c < 75),
                    "45-59%": sum(1 for c in confidence_scores if 45 <= c < 60)
                }
            },
            "platform_distribution": {platform: platforms.count(platform) for platform in set(platforms)},
            "performance_metrics": {
                "avg_response_time": np.mean(response_times),
                "fastest_response": min(response_times),
                "slowest_response": max(response_times),
                "total_data_collected": sum(r['content_size'] for r in results)
            },
            "security_metrics": {
                "avg_security_score": np.mean([r.get('security_score', 0) for r in results]),
                "cdn_usage": sum(1 for r in results if r['metadata'].get('cdn_detected')),
                "unique_ips": len(set(r['ip_address'] for r in results))
            }
        }
    
    def _cross_platform_analysis(self, results):
        analysis = {
            "username_patterns": {},
            "common_metadata": {},
            "platform_correlations": []
        }
        
        # Analyze username variations
        original_targets = set(r['original_target'] for r in results)
        for target in original_targets:
            target_results = [r for r in results if r['original_target'] == target]
            variations = [r['username'] for r in target_results]
            analysis["username_patterns"][target] = {
                "variations_found": len(set(variations)),
                "platforms_confirmed": len(target_results),
                "avg_confidence": np.mean([r['confidence_score'] for r in target_results])
            }
        
        # Find common metadata patterns
        all_metadata_keys = set()
        for result in results:
            all_metadata_keys.update(result['metadata'].keys())
        
        for key in all_metadata_keys:
            values = [r['metadata'].get(key) for r in results if key in r['metadata']]
            if len(values) > 1:
                analysis["common_metadata"][key] = {
                    "frequency": len(values),
                    "unique_values": len(set(str(v) for v in values))
                }
        
        return analysis
    
    def _security_assessment(self, results):
        return {
            "overall_security_posture": np.mean([r.get('security_score', 0) for r in results]),
            "cdn_adoption_rate": (sum(1 for r in results if r['metadata'].get('cdn_detected')) / len(results)) * 100,
            "ssl_compliance": sum(1 for r in results if r['url'].startswith('https')),
            "response_time_variance": np.std([r['response_time_ms'] for r in results]),
            "data_exposure_risk": sum(1 for r in results if r['metadata'].get('extracted_emails') or r['metadata'].get('extracted_phones'))
        }
    
    def _extraction_summary(self, results):
        summary = {
            "total_emails_found": 0,
            "total_phones_found": 0,
            "total_urls_found": 0,
            "total_social_handles": 0,
            "unique_keywords": set(),
            "data_richness_score": 0
        }
        
        for result in results:
            meta = result['metadata']
            summary["total_emails_found"] += len(meta.get('extracted_emails', []))
            summary["total_phones_found"] += len(meta.get('extracted_phones', []))
            summary["total_urls_found"] += len(meta.get('extracted_urls', []))
            summary["total_social_handles"] += len(meta.get('social_handles', []))
            summary["unique_keywords"].update(meta.get('top_keywords', []))
        
        summary["unique_keywords"] = list(summary["unique_keywords"])
        summary["data_richness_score"] = (
            summary["total_emails_found"] * 10 +
            summary["total_phones_found"] * 15 +
            summary["total_urls_found"] * 5 +
            summary["total_social_handles"] * 8 +
            len(summary["unique_keywords"]) * 3
        )
        
        return summary
    
    async def _export_csv(self, results, filename):
        csv_data = ["Platform,Username,Original_Target,URL,Confidence,Status,Response_Time,IP,Content_Size,Security_Score,CDN,Emails,Phones,Social_Handles,Top_Keywords"]
        
        for r in results:
            meta = r['metadata']
            csv_data.append(
                f"{r['platform']},{r['username']},{r['original_target']},{r['url']},"
                f"{r['confidence_score']},{r['status_code']},{r['response_time_ms']},{r['ip_address']},"
                f"{r['content_size']},{r.get('security_score', 0)},{meta.get('cdn_detected', False)},"
                f"\"{';'.join(meta.get('extracted_emails', []))}\","
                f"\"{';'.join(meta.get('extracted_phones', []))}\","
                f"\"{';'.join(meta.get('social_handles', []))}\","
                f"\"{';'.join(meta.get('top_keywords', []))}\""
            )
        
        async with aiofiles.open(filename, 'w', encoding='utf-8') as f:
            await f.write('\n'.join(csv_data))
    
    async def _export_summary(self, data, filename):
        report = [
            "ADVANCED OSINT INTELLIGENCE REPORT",
            "=" * 50,
            f"Target: {data['scan_metadata']['target']}",
            f"Scan Date: {time.ctime(data['scan_metadata']['timestamp'])}",
            f"Total Results: {data['scan_metadata']['total_results']}",
            f"Platforms Found: {data['scan_metadata']['platforms_found']}",
            f"Average Confidence: {data['scan_metadata']['avg_confidence']:.2f}%",
            "",
            "STATISTICAL ANALYSIS",
            "-" * 30,
            f"Confidence Mean: {data['statistical_analysis']['confidence_distribution']['mean']:.2f}%",
            f"Confidence Range: {data['statistical_analysis']['confidence_distribution']['min']:.1f}% - {data['statistical_analysis']['confidence_distribution']['max']:.1f}%",
            f"High Confidence (90%+): {data['statistical_analysis']['confidence_distribution']['ranges']['90-100%']} results",
            f"Average Response Time: {data['statistical_analysis']['performance_metrics']['avg_response_time']:.2f}ms",
            "",
            "SECURITY ASSESSMENT",
            "-" * 30,
            f"Overall Security Score: {data['security_assessment']['overall_security_posture']:.1f}%",
            f"CDN Adoption Rate: {data['security_assessment']['cdn_adoption_rate']:.1f}%",
            f"Data Exposure Risk: {data['security_assessment']['data_exposure_risk']} profiles",
            "",
            "DATA EXTRACTION SUMMARY",
            "-" * 30,
            f"Total Emails Found: {data['data_extraction_summary']['total_emails_found']}",
            f"Total Phone Numbers: {data['data_extraction_summary']['total_phones_found']}",
            f"Total URLs Extracted: {data['data_extraction_summary']['total_urls_found']}",
            f"Social Handles Found: {data['data_extraction_summary']['total_social_handles']}",
            f"Unique Keywords: {len(data['data_extraction_summary']['unique_keywords'])}",
            f"Data Richness Score: {data['data_extraction_summary']['data_richness_score']}",
            "",
            "TOP PLATFORMS BY RESULTS",
            "-" * 30
        ]
        
        platform_dist = data['statistical_analysis']['platform_distribution']
        for platform, count in sorted(platform_dist.items(), key=lambda x: x[1], reverse=True):
            report.append(f"{platform}: {count} profiles")
        
        report.extend([
            "",
            "DETAILED RESULTS",
            "-" * 30
        ])
        
        for result in sorted(data['detailed_results'], key=lambda x: x['confidence_score'], reverse=True):
            report.extend([
                f"Platform: {result['platform']} | Confidence: {result['confidence_score']:.1f}%",
                f"Username: {result['username']} | URL: {result['url']}",
                f"IP: {result['ip_address']} | Response: {result['response_time_ms']:.1f}ms",
                f"Security Score: {result.get('security_score', 0):.0f}% | Data Size: {result['content_size']} bytes",
                ""
            ])
        
        async with aiofiles.open(filename, 'w', encoding='utf-8') as f:
            await f.write('\n'.join(report))

class AdvancedInterface:
    def __init__(self):
        self.scanner = EnhancedIntelligence()
        self.exporter = DataExporter()
    
    @staticmethod
    def clear_screen():
        os.system('cls' if os.name == 'nt' else 'clear')
    
    @staticmethod
    def display_banner():
        AdvancedInterface.clear_screen()
        print(f"""{Fore.RED}{Style.BRIGHT}
  ████████╗██╗████████╗ █████╗ ███╗   ██╗    ██████╗ ███████╗██╗███╗   ██╗████████╗
  ╚══██╔══╝██║╚══██╔══╝██╔══██╗████╗  ██║   ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝
     ██║   ██║   ██║   ███████║██╔██╗ ██║   ██║   ██║███████╗██║██╔██╗ ██║   ██║   
     ██║   ██║   ██║   ██╔══██║██║╚██╗██║   ██║   ██║╚════██║██║██║╚██╗██║   ██║   
     ██║   ██║   ██║   ██║  ██║██║ ╚████║   ╚██████╔╝███████║██║██║ ╚████║   ██║   
     ╚═╝   ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝    ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝   
                    {Fore.CYAN}ADVANCED OSINT INTELLIGENCE PLATFORM v2.5""")
        print(f"{Fore.MAGENTA} Developer: Skeetlsd Enhanced Multi-Platform Reconnaissance & Data Extraction System")
    
    @staticmethod
    def display_menu():
        print(f"\n{Fore.CYAN}╭─ TITAN OSINT OPERATIONS")
        print(f"{Fore.CYAN}│  [1] Comprehensive Intelligence Scan")
        print(f"{Fore.CYAN}│  [2] Multi-Target Batch Analysis") 
        print(f"{Fore.CYAN}│  [3] Deep Metadata Extraction")
        print(f"{Fore.CYAN}│  [4] Cross-Platform Pattern Analysis")
        print(f"{Fore.CYAN}│  [5] Export Intelligence Reports")
        print(f"{Fore.CYAN}│  [6] System Status & Statistics")
        print(f"{Fore.CYAN}│  [7] Advanced Configuration")
        print(f"{Fore.CYAN}╰─ [0] Shutdown System\n")
    
    def display_statistics(self):
        print(f"\n{Fore.GREEN}╭─ TITAN OSINT SYSTEM STATUS")
        print(f"{Fore.GREEN}│  Platforms Available: {len(self.scanner.platforms)}")
        print(f"{Fore.GREEN}│  Enhanced Metadata Extraction: ENABLED")
        print(f"{Fore.GREEN}│  Advanced Confidence Scoring: ACTIVE")
        print(f"{Fore.GREEN}│  Multi-threaded Processing: OPERATIONAL")
        print(f"{Fore.GREEN}│  Security Analysis: INTEGRATED")
        print(f"{Fore.GREEN}│  Cross-Platform Correlation: READY")
        print(f"{Fore.GREEN}│  Data Export Formats: JSON, CSV, TXT")
        print(f"{Fore.GREEN}│  Real-time Progress Tracking: ENABLED")
        
        # Show platform categories
        social_platforms = ['Twitter', 'Instagram', 'Facebook', 'TikTok', 'Snapchat', 'LinkedIn']
        dev_platforms = ['GitHub', 'GitLab', 'Bitbucket', 'HackerNews']
        creative_platforms = ['Behance', 'Dribbble', 'DeviantArt', 'Flickr', '500px']
        professional_platforms = ['LinkedIn', 'AngelList', 'Crunchbase', 'Academia', 'ResearchGate', 'ORCID']
        
        print(f"{Fore.GREEN}│")
        print(f"{Fore.GREEN}│  Platform Categories:")
        print(f"{Fore.GREEN}│    Social Media: {sum(1 for p in social_platforms if p in self.scanner.platforms)} platforms")
        print(f"{Fore.GREEN}│    Developer: {sum(1 for p in dev_platforms if p in self.scanner.platforms)} platforms")
        print(f"{Fore.GREEN}│    Creative: {sum(1 for p in creative_platforms if p in self.scanner.platforms)} platforms")
        print(f"{Fore.GREEN}│    Professional: {sum(1 for p in professional_platforms if p in self.scanner.platforms)} platforms")
        print(f"{Fore.GREEN}╰─ Status: FULLY OPERATIONAL")
    
    async def run_comprehensive_scan(self, target):
        print(f"\n{Fore.YELLOW}Initializing comprehensive intelligence scan...")
        print(f"{Fore.CYAN}Target: {target}")
        print(f"{Fore.CYAN}Platforms: {len(self.scanner.platforms)}")
        print(f"{Fore.CYAN}Variations: Advanced generation enabled")
        print(f"{Fore.CYAN}Metadata: Deep extraction active\n")
        
        results = await self.scanner.comprehensive_scan(target)
        
        if results:
            print(f"\n{Fore.GREEN}╭─ SCAN COMPLETE")
            confidence_scores = [r['confidence_score'] for r in results]
            print(f"{Fore.GREEN}│  Total Profiles Found: {len(results)}")
            print(f"{Fore.GREEN}│  Average Confidence: {np.mean(confidence_scores):.1f}%")
            print(f"{Fore.GREEN}│  High Confidence (80%+): {sum(1 for c in confidence_scores if c >= 80)}")
            print(f"{Fore.GREEN}│  Platforms Confirmed: {len(set(r['platform'] for r in results))}")
            print(f"{Fore.GREEN}│  Total Data Collected: {sum(r['content_size'] for r in results):,} bytes")
            print(f"{Fore.GREEN}│  Unique IP Addresses: {len(set(r['ip_address'] for r in results))}")
            
            # Show data extraction summary
            total_emails = sum(len(r['metadata'].get('extracted_emails', [])) for r in results)
            total_phones = sum(len(r['metadata'].get('extracted_phones', [])) for r in results)
            total_handles = sum(len(r['metadata'].get('social_handles', [])) for r in results)
            
            print(f"{Fore.GREEN}│  Emails Extracted: {total_emails}")
            print(f"{Fore.GREEN}│  Phone Numbers: {total_phones}")
            print(f"{Fore.GREEN}│  Social Handles: {total_handles}")
            print(f"{Fore.GREEN}╰─")
            
            # Show top platforms by confidence
            platform_scores = {}
            for result in results:
                platform = result['platform']
                if platform not in platform_scores:
                    platform_scores[platform] = []
                platform_scores[platform].append(result['confidence_score'])
            
            print(f"\n{Fore.CYAN}╭─ TOP PLATFORMS BY CONFIDENCE")
            for platform, scores in sorted(platform_scores.items(), 
                                         key=lambda x: np.mean(x[1]), reverse=True)[:5]:
                avg_score = np.mean(scores)
                print(f"{Fore.CYAN}│  {platform}: {avg_score:.1f}% avg ({len(scores)} profiles)")
            print(f"{Fore.CYAN}╰─")
            
            return results
        else:
            print(f"{Fore.RED}No significant results found for target: {target}")
            return []
    
    async def run_batch_analysis(self, targets):
        print(f"\n{Fore.YELLOW}Starting batch analysis for {len(targets)} targets...")
        all_results = []
        target_summaries = {}
        
        for i, target in enumerate(targets, 1):
            print(f"\n{Fore.MAGENTA}[{i}/{len(targets)}] Processing: {target}")
            print(f"{Fore.MAGENTA}{'='*50}")
            
            results = await self.scanner.comprehensive_scan(target)
            all_results.extend(results)
            
            target_summaries[target] = {
                'profiles_found': len(results),
                'avg_confidence': np.mean([r['confidence_score'] for r in results]) if results else 0,
                'top_platform': max(results, key=lambda x: x['confidence_score'])['platform'] if results else 'None',
                'data_extracted': sum(len(r['metadata'].get('extracted_emails', [])) + 
                                    len(r['metadata'].get('extracted_phones', [])) for r in results)
            }
        
        if all_results:
            print(f"\n{Fore.GREEN}╭─ BATCH ANALYSIS COMPLETE")
            print(f"{Fore.GREEN}│  Total Targets Processed: {len(targets)}")
            print(f"{Fore.GREEN}│  Total Profiles Found: {len(all_results)}")
            print(f"{Fore.GREEN}│  Overall Success Rate: {(len([t for t in target_summaries.values() if t['profiles_found'] > 0]) / len(targets)) * 100:.1f}%")
            print(f"{Fore.GREEN}│  Average Profiles per Target: {len(all_results) / len(targets):.1f}")
            print(f"{Fore.GREEN}╰─")
            
            # Show per-target summary
            print(f"\n{Fore.CYAN}╭─ PER-TARGET SUMMARY")
            for target, summary in target_summaries.items():
                status_color = Fore.GREEN if summary['profiles_found'] > 0 else Fore.RED
                print(f"{status_color}│  {target}: {summary['profiles_found']} profiles | "
                      f"{summary['avg_confidence']:.1f}% avg | {summary['top_platform']}")
            print(f"{Fore.CYAN}╰─")
        
        return all_results

class DeepAnalyzer:
    def __init__(self):
        self.behavioral_patterns = {}
        
    def analyze_cross_platform_patterns(self, results):
        patterns = {
            'username_consistency': {},
            'platform_preferences': {},
            'security_patterns': {},
            'temporal_patterns': {},
            'content_patterns': {}
        }
        
        # Username consistency analysis
        original_targets = set(r['original_target'] for r in results)
        for target in original_targets:
            target_results = [r for r in results if r['original_target'] == target]
            usernames = [r['username'] for r in target_results]
            
            # Calculate username variation score
            exact_matches = sum(1 for u in usernames if u == target)
            variation_score = (exact_matches / len(usernames)) * 100 if usernames else 0
            
            patterns['username_consistency'][target] = {
                'variation_score': variation_score,
                'total_variations': len(set(usernames)),
                'exact_matches': exact_matches,
                'platforms_found': len(target_results),
                'most_common_variation': max(set(usernames), key=usernames.count) if usernames else None
            }
        
        # Platform preference analysis
        platform_confidence = {}
        for result in results:
            platform = result['platform']
            if platform not in platform_confidence:
                platform_confidence[platform] = []
            platform_confidence[platform].append(result['confidence_score'])
        
        for platform, scores in platform_confidence.items():
            patterns['platform_preferences'][platform] = {
                'avg_confidence': np.mean(scores),
                'success_rate': len(scores),
                'reliability_score': np.mean(scores) * (len(scores) / len(results))
            }
        
        # Security pattern analysis
        security_scores = [r.get('security_score', 0) for r in results]
        cdn_usage = [r['metadata'].get('cdn_detected', False) for r in results]
        
        patterns['security_patterns'] = {
            'avg_security_score': np.mean(security_scores),
            'cdn_adoption_rate': (sum(cdn_usage) / len(cdn_usage)) * 100,
            'security_variance': np.std(security_scores),
            'high_security_platforms': [r['platform'] for r in results if r.get('security_score', 0) > 80]
        }
        
        # Content pattern analysis
        all_keywords = []
        all_emails = []
        all_handles = []
        
        for result in results:
            meta = result['metadata']
            all_keywords.extend(meta.get('top_keywords', []))
            all_emails.extend(meta.get('extracted_emails', []))
            all_handles.extend(meta.get('social_handles', []))
        
        patterns['content_patterns'] = {
            'common_keywords': dict(sorted(
                {word: all_keywords.count(word) for word in set(all_keywords)}.items(),
                key=lambda x: x[1], reverse=True
            )[:15]),
            'email_domains': dict(sorted(
                {email.split('@')[1]: all_emails.count(email) for email in set(all_emails) if '@' in email}.items(),
                key=lambda x: x[1], reverse=True
            )[:10]),
            'handle_patterns': dict(sorted(
                {handle: all_handles.count(handle) for handle in set(all_handles)}.items(),
                key=lambda x: x[1], reverse=True
            )[:10])
        }
        
        return patterns

async def main():
    interface = AdvancedInterface()
    analyzer = DeepAnalyzer()
    current_results = []
    
    while True:
        interface.display_banner()
        interface.display_menu()
        
        choice = input(f"{Fore.MAGENTA}TITAN Command: ").strip()
        
        if choice == "1":
            target = input(f"{Fore.MAGENTA}Enter target username/identifier: ").strip()
            if target:
                current_results = await interface.run_comprehensive_scan(target)
                input(f"\n{Fore.CYAN}Press Enter to continue...")
        
        elif choice == "2":
            targets_input = input(f"{Fore.MAGENTA}Enter targets (space-separated): ").strip()
            targets = targets_input.split() if targets_input else []
            
            if targets:
                current_results = await interface.run_batch_analysis(targets)
                input(f"\n{Fore.CYAN}Press Enter to continue...")
            else:
                print(f"{Fore.RED}No targets specified.")
                await asyncio.sleep(2)
        
        elif choice == "3":
            if current_results:
                print(f"\n{Fore.YELLOW}Performing deep metadata extraction analysis...")
                
                # Enhanced metadata analysis
                total_metadata_fields = sum(len(r['metadata']) for r in current_results)
                unique_metadata_types = set()
                for result in current_results:
                    unique_metadata_types.update(result['metadata'].keys())
                
                print(f"\n{Fore.GREEN}╭─ DEEP METADATA ANALYSIS")
                print(f"{Fore.GREEN}│  Total Metadata Fields: {total_metadata_fields}")
                print(f"{Fore.GREEN}│  Unique Metadata Types: {len(unique_metadata_types)}")
                
                # Show most common metadata types
                metadata_frequency = {}
                for result in current_results:
                    for key in result['metadata'].keys():
                        metadata_frequency[key] = metadata_frequency.get(key, 0) + 1
                
                print(f"{Fore.GREEN}│  Most Common Metadata:")
                for meta_type, freq in sorted(metadata_frequency.items(), 
                                            key=lambda x: x[1], reverse=True)[:10]:
                    print(f"{Fore.GREEN}│    {meta_type}: {freq} instances")
                print(f"{Fore.GREEN}╰─")
                
                # Show extracted data summary
                all_emails = set()
                all_phones = set()
                all_urls = set()
                
                for result in current_results:
                    meta = result['metadata']
                    all_emails.update(meta.get('extracted_emails', []))
                    all_phones.update(meta.get('extracted_phones', []))
                    all_urls.update(meta.get('extracted_urls', []))
                
                if all_emails or all_phones or all_urls:
                    print(f"\n{Fore.CYAN}╭─ EXTRACTED SENSITIVE DATA")
                    if all_emails:
                        print(f"{Fore.CYAN}│  Email Addresses ({len(all_emails)}):")
                        for email in list(all_emails)[:10]:
                            print(f"{Fore.CYAN}│    {email}")
                    if all_phones:
                        print(f"{Fore.CYAN}│  Phone Numbers ({len(all_phones)}):")
                        for phone in list(all_phones)[:5]:
                            print(f"{Fore.CYAN}│    {phone}")
                    if all_urls:
                        print(f"{Fore.CYAN}│  URLs Found ({len(all_urls)}):")
                        for url in list(all_urls)[:8]:
                            print(f"{Fore.CYAN}│    {url}")
                    print(f"{Fore.CYAN}╰─")
                
                input(f"\n{Fore.CYAN}Press Enter to continue...")
            else:
                print(f"{Fore.RED}No scan results available. Run a scan first.")
                await asyncio.sleep(2)
        
        elif choice == "4":
            if current_results:
                print(f"\n{Fore.YELLOW}Analyzing cross-platform patterns...")
                patterns = analyzer.analyze_cross_platform_patterns(current_results)
                
                print(f"\n{Fore.GREEN}╭─ CROSS-PLATFORM PATTERN ANALYSIS")
                
                # Username consistency
                print(f"{Fore.GREEN}│  Username Consistency Patterns:")
                for target, data in patterns['username_consistency'].items():
                    print(f"{Fore.GREEN}│    {target}: {data['variation_score']:.1f}% consistency "
                          f"({data['total_variations']} variations)")
                
                # Platform reliability
                print(f"{Fore.GREEN}│  Platform Reliability (Top 5):")
                top_platforms = sorted(patterns['platform_preferences'].items(), 
                                     key=lambda x: x[1]['reliability_score'], reverse=True)[:5]
                for platform, data in top_platforms:
                    print(f"{Fore.GREEN}│    {platform}: {data['reliability_score']:.1f} "
                          f"({data['avg_confidence']:.1f}% avg confidence)")
                
                # Security insights
                security = patterns['security_patterns']
                print(f"{Fore.GREEN}│  Security Analysis:")
                print(f"{Fore.GREEN}│    Average Security Score: {security['avg_security_score']:.1f}%")
                print(f"{Fore.GREEN}│    CDN Adoption Rate: {security['cdn_adoption_rate']:.1f}%")
                
                # Content patterns
                content = patterns['content_patterns']
                if content['common_keywords']:
                    print(f"{Fore.GREEN}│  Top Keywords:")
                    for keyword, freq in list(content['common_keywords'].items())[:5]:
                        print(f"{Fore.GREEN}│    {keyword}: {freq} occurrences")
                
                print(f"{Fore.GREEN}╰─")
                input(f"\n{Fore.CYAN}Press Enter to continue...")
            else:
                print(f"{Fore.RED}No scan results available. Run a scan first.")
                await asyncio.sleep(2)
        
        elif choice == "5":
            if current_results:
                target_name = input(f"{Fore.MAGENTA}Enter target name for export: ").strip()
                if target_name:
                    await interface.exporter.export_intelligence(current_results, target_name)
                    input(f"\n{Fore.CYAN}Press Enter to continue...")
            else:
                print(f"{Fore.RED}No scan results available. Run a scan first.")
                await asyncio.sleep(2)
        
        elif choice == "6":
            interface.display_statistics()
            input(f"\n{Fore.CYAN}Press Enter to continue...")
        
        elif choice == "7":
            print(f"\n{Fore.CYAN}╭─ ADVANCED CONFIGURATION")
            print(f"{Fore.CYAN}│  Current Settings:")
            print(f"{Fore.CYAN}│    Platforms: {len(interface.scanner.platforms)} active")
            print(f"{Fore.CYAN}│    Throttling: Dynamic (5-20 req/sec)")
            print(f"{Fore.CYAN}│    Timeout: 35s total, 25s connect")
            print(f"{Fore.CYAN}│    Connections: 150 total, 25 per host")
            print(f"{Fore.CYAN}│    Variations: 50 per target")
            print(f"{Fore.CYAN}│    Confidence Threshold: 45%")
            print(f"{Fore.CYAN}│    SSL Verification: Disabled")
            print(f"{Fore.CYAN}│    User-Agent Rotation: Enabled")
            print(f"{Fore.CYAN}╰─ Configuration optimized for maximum efficiency")
            input(f"\n{Fore.CYAN}Press Enter to continue...")
        
        elif choice == "0":
            print(f"\n{Fore.RED}Shutting down TITAN OSINT system...")
            print(f"{Fore.RED}Clearing memory and closing connections...")
            print(f"{Fore.RED}System offline.")
            break
        
        else:
            print(f"{Fore.RED}Invalid command. Please select a valid option.")
            await asyncio.sleep(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Emergency shutdown initiated.")
        print(f"{Fore.RED}TITAN OSINT terminated by user.")
    except Exception as e:
        print(f"\n{Fore.RED}Critical system error: {str(e)}")
        print(f"{Fore.RED}System crashed. Check logs for details.")