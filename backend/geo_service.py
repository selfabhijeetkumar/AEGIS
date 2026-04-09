"""AEGIS IP Geolocation Service — resolve attacker IPs to locations."""
import requests
from typing import Dict
import time

# Cache to avoid hitting rate limits
_geo_cache: Dict[str, dict] = {}

# Common IPs for demo data with pre-cached locations
DEMO_GEOLOCATIONS = {
    "192.168.1.1": {"country": "Internal", "city": "LAN", "isp": "Private Network", "lat": 0, "lon": 0},
    "10.0.0.1": {"country": "Internal", "city": "LAN", "isp": "Private Network", "lat": 0, "lon": 0},
    "185.220.101.42": {"country": "Germany", "city": "Berlin", "isp": "Tor Exit Node", "lat": 52.52, "lon": 13.405},
    "45.33.32.156": {"country": "United States", "city": "Fremont", "isp": "Linode", "lat": 37.55, "lon": -122.05},
    "103.75.190.11": {"country": "China", "city": "Beijing", "isp": "China Telecom", "lat": 39.9, "lon": 116.4},
    "91.219.236.222": {"country": "Russia", "city": "Moscow", "isp": "VPN Provider", "lat": 55.75, "lon": 37.62},
    "209.141.55.26": {"country": "United States", "city": "Las Vegas", "isp": "FranTech Solutions", "lat": 36.17, "lon": -115.14},
    "5.188.86.172": {"country": "Russia", "city": "St. Petersburg", "isp": "PIN-DC", "lat": 59.93, "lon": 30.32},
    "218.92.0.107": {"country": "China", "city": "Nanjing", "isp": "China Telecom", "lat": 32.06, "lon": 118.78},
    "112.85.42.88": {"country": "China", "city": "Shanghai", "isp": "China Mobile", "lat": 31.23, "lon": 121.47},
    "77.247.181.163": {"country": "Netherlands", "city": "Amsterdam", "isp": "Tor Exit Node", "lat": 52.37, "lon": 4.895},
    "176.10.104.240": {"country": "Switzerland", "city": "Zurich", "isp": "Tor Exit Node", "lat": 47.37, "lon": 8.54},
    "198.98.56.12": {"country": "United States", "city": "New York", "isp": "Vultr Holdings", "lat": 40.71, "lon": -74.01},
    "23.129.64.130": {"country": "United States", "city": "Seattle", "isp": "Emerald Onion", "lat": 47.61, "lon": -122.33},
    "171.25.193.78": {"country": "Sweden", "city": "Stockholm", "isp": "DFRI", "lat": 59.33, "lon": 18.07},
    "62.210.105.116": {"country": "France", "city": "Paris", "isp": "Online S.A.S.", "lat": 48.86, "lon": 2.35},
    "89.234.157.254": {"country": "France", "city": "Lyon", "isp": "Marylou Media", "lat": 45.76, "lon": 4.84},
    "51.15.43.205": {"country": "Netherlands", "city": "Haarlem", "isp": "Scaleway", "lat": 52.38, "lon": 4.64},
    "193.218.118.183": {"country": "Ukraine", "city": "Kyiv", "isp": "Wnet Ukraine", "lat": 50.45, "lon": 30.52},
}


def get_ip_geolocation(ip: str) -> dict:
    """Get geolocation for an IP address."""
    # Check cache first
    if ip in _geo_cache:
        return _geo_cache[ip]

    # Check demo data
    if ip in DEMO_GEOLOCATIONS:
        _geo_cache[ip] = DEMO_GEOLOCATIONS[ip]
        return DEMO_GEOLOCATIONS[ip]

    # Private IPs
    if ip.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                       "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                       "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")):
        result = {"country": "Internal", "city": "LAN", "isp": "Private Network", "lat": 0, "lon": 0}
        _geo_cache[ip] = result
        return result

    # Try ip-api.com (free, 45 req/min)
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=country,city,isp,lat,lon", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            result = {
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0)
            }
            _geo_cache[ip] = result
            return result
    except Exception:
        pass

    # Fallback
    result = {"country": "Unknown", "city": "Unknown", "isp": "Unknown", "lat": 0, "lon": 0}
    _geo_cache[ip] = result
    return result


def batch_geolocate(ips: list) -> Dict[str, dict]:
    """Batch geolocate a list of IPs."""
    results = {}
    for ip in ips:
        results[ip] = get_ip_geolocation(ip)
        time.sleep(0.02)  # Rate limit respect
    return results
