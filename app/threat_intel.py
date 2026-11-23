
from app.virustotal import VirusTotal
from config.settings import VIRUSTOTAL_API_KEY


class ThreatIntelligence:

    def __init__(self):
        self.virustotal = VirusTotal(VIRUSTOTAL_API_KEY)

    def check_hash(self, file_hash):
        return self.virustotal.check_hash(file_hash)

    def check_url(self, url):
        return self.virustotal.check_url(url)

    def check_domain(self, domain):
        return self.virustotal.check_domain(domain)

    def check_ip(self, ip_address):
        return self.virustotal.check_ip(ip_address)
