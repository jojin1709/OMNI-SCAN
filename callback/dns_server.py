import dns.resolver

def check_dns_resolution(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return [str(rdata) for rdata in answers]
    except Exception:
        return []

def check_txt_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        return [str(rdata) for rdata in answers]
    except Exception:
        return []