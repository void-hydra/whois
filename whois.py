import socket
import re
from contextlib import closing

banner = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣴⠾⠛⠉⠉⠉⠉⠛⠿⣦⡀⠀⠀⠀⠀
⠀⠀⠀⠀⢠⡿⠁⠀⢀⣠⣤⣤⣄⡀⠀⠈⢿⡆⠀⠀⠀
⠀⠀⢀⣿⣁⣀⣠⡿⠋⠀⠀⠙⢿⣄⣀⣈⣿⡀⠀⠀
⠀⠀⢸⣿⠛⠛⢻⣧⠀⠿⠇⠀⣼⡟⠛⠛⣿⡇⠀⠀
⠀⠀⢸⣿⠀⠀⠀⠙⢷⣦⣴⡾⠋⠀⠀⠀⣿⡇⠀⠀
⠀⠀⢸⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⠀ papoi <3
⠀⠀⣸⣿⠀⠀⠀⠛⠷⠶⠶⠾⠛⠀⠀⠀⣿⣇⠀⠀
⠀⣸⣿⣿⢷⣦⣀⣀⣀⣀⣀⣀⣀⣀⣴⡾⣿⣿⣇⠀
⢠⣿⢸⣿⠀⣿⡏⠉⠉⠉⠉⠉⠉⢹⣿⠀⣿⡇⣿⡄
⢸⡏⢸⣿⣀⣿⡇⠀⠀⠀⠀⠀⠀⢸⣿⣀⣿⡇⢹⡇
⢸⡇⠀⢿⣏⠉⠁⠀⠀⠀⠀⠀⠀⠈⠉⣹⡿⠀⢸⡇
⢸⣿⣤⣌⠛⠷⣶⣶⣶⣶⣶⣶⣶⣶⠾⠛⣡⣤⣿⡇
⠘⠿⠿⠇⠀⠀⠀⢿⡾⠇⠸⢷⡿⠀⠀⠀⠸⠿⠿⠃
⠀⠀⠀⠀⠀⠀⠀⠛⠛⠁⠈⠛⠛⠀⠀⠀⠀⠀⠀"""

print(banner)
print("feito por: void")
print("R3C0N T00L\n")
print("um salve pro: hydra ")

WHOIS_SERVERS = {
    ".com": "whois.verisign-grs.com",
    ".net":     "whois.verisign-grs.com",
    ".org":     "whois.pir.org",
    ".br":"wois.registro.br",
    ".io":      "whois.nic.io",
    ".ai":      "whois.nic.ai",
    ".dev":     "whois.nic.google",
    ".app":     "whois.nic.google",
    ".cc":      "ccwhois.verisign-grs.com",
    ".ca":      "whois.cira.ca",
    ".uk":      "whois.nic.uk",
    ".de":      "whois.denic.de",
    ".fr":      "whois.afnic.fr",
    ".info":    "whois.afilias.net",
    ".xyz":     "whois.nic.xyz",
    ".me":      "whois.nic.me",
    ".co":      "whois.nic.co",
    ".in":      "whois.inregistry.net",
    ".jp":      "whois.dns.jp",
    ".cn":      "whois.cnnic.cn",
    ".kr":      "whois.kr",
    ".ru":      "whois.tcinet.ru",
    ".tv":      "whois.nic.tv",
    ".biz":     "whois.biz",
    ".us":      "whois.verisign-grs.com",
    ".edu":     "whois.educause.net",
    ".gov":     "whois.gov",
    ".mil":     "whois.nic.mil",
    ".int":     "whois.iana.org",
    ".ar":      "whois.nic.ar",
    ".mx":      "whois.mx",
    ".cl":      "whois.nic.cl",
    ".pt":      "whois.dns.pt",
    ".it":      "whois.nic.it",
    ".es":      "whois.nic.es",
    ".nl":      "whois.sidn.nl",
    ".se":      "whois.ripe.net",
    ".no":      "whois.norid.no",
    ".ch":      "whois.nic.ch",
    ".at":      "whois.dnic.at",
    ".pl":      "whois.dns.pl",
    ".cz":      "whois.nic.cz",
    ".au":      "whois.auda.org.au",
    ".nz":      "whois.srs.internetnz.co.nz",
}

IANA_SERVER = "whois.iana.org"
TIMEOUT = 5 


def get_tld(domain: str) -> str:
    """Extrai o TLD do domínio (último segmento)."""
    return "." + domain.rsplit(".", 1)[-1].lower()


def resolve_server(domain: str) -> str:
    """Retorna o servidor WHOIS correto para o domínio."""
    tld = get_tld(domain)
    if tld in WHOIS_SERVERS:
        return WHOIS_SERVERS[tld]
    print(f"[i] TLD {tld} não encontrado na tabela local, consultando IANA...")
    try:
        raw = _raw_query(IANA_SERVER, tld.lstrip("."))
        match = re.search(r"whois:\s*(\S+)", raw, re.IGNORECASE)
        if match:
            server = match.group(1).strip()
            print(f"[i] Servidor encontrado via IANA: {server}")
            return server
    except Exception as e:
        print(f"[!] Erro ao consultar IANA: {e}")
    return "whois.verisign-grs.com"  

def _raw_query(server: str, query: str) -> str:
    """Executa uma consulta WHOIS bruta e retorna a resposta como string."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(TIMEOUT)
        sock.connect((server, 43))
        sock.sendall((query + "\r\n").encode("ascii"))
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


def whois_lookup(domain: str) -> str:
    """Faz a consulta WHOIS completa para o domínio."""
    domain = domain.strip().lower().lstrip("www.")
    server = resolve_server(domain)
    print(f"\n[*] Consultando: {domain}")
    print(f"[*] Servidor WHOIS: {server}\n")
    try:
        return _raw_query(server, domain)
    except socket.timeout:
        return "[ERRO] Timeout ao conectar ao servidor WHOIS."
    except socket.gaierror:
        return "[ERRO] Não foi possível resolver o nome do servidor."
    except ConnectionRefusedError:
        return "[ERRO] Conexão recusada pelo servidor."
    except OSError as e:
        return f"[ERRO] Falha de conexão: {e}"


def main():
    while True:
        target = input("qual dominio vc quer buscar? - ").strip()
        if not target:
            continue
        result = whois_lookup(target)
        print("\n" + "=" * 60)
        print(result)
        print("=" * 60)
        again = input("\nbuscar outro? [s/N]: ").strip().lower()
        if again != "s":
            print("\n[+] encerrando. bye!")
            break


if __name__ == "__main__":
    main()
