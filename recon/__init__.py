"""Backend de reconhecimento DNS do ZoneT_01.

Usa exclusivamente as ferramentas clássicas do ecossistema DNS (dig, nslookup,
whois) via subprocess — sem bibliotecas DNS pesadas. Todo o tráfego de saída é
forçado pela cadeia de anonimização dnscrypt-proxy -> Tor.
"""
