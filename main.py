

import argparse
import hashlib
import json
import sys
import time
from dataclasses import dataclass, asdict
from typing import Optional

try:
    import requests
except ImportError:
    sys.exit("Falta a lib 'requests'. Instale com: pip install requests")

requests.packages.urllib3.disable_warnings()  # pra -k/--insecure não poluir o output

DEFAULT_METHODS = [
    "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH",
    "OPTIONS", "TRACE", "TRACK", "CONNECT",
    "FOOBAR", "ADMIN",  # verbos arbitrários — alguns proxies/WAFs só filtram métodos conhecidos
]

OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
    "X-Original-Method",
]

DENIED_STATUSES = {401, 403, 405}


@dataclass
class Result:
    technique: str            # "baseline", "method" ou "header-override"
    method: str                # método HTTP efetivamente usado na linha de requisição
    detail: str                 # ex: nome do header de override, ou "-"
    status: Optional[int]
    length: Optional[int]
    body_hash: Optional[str]
    elapsed_ms: Optional[float]
    error: Optional[str] = None
    suspicious: bool = False


def body_fingerprint(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()[:16]


def do_request(session, url, method, headers=None, timeout=10, verify=True, data=None):
    try:
        start = time.time()
        resp = session.request(
            method=method,
            url=url,
            headers=headers or {},
            timeout=timeout,
            verify=verify,
            allow_redirects=False,
            data=data,
        )
        elapsed = (time.time() - start) * 1000
        return resp, elapsed, None
    except requests.RequestException as e:
        return None, None, str(e)


def classify(baseline: "Result", r: "Result") -> bool:
    """Marca como suspeito se o baseline foi negado e essa variação não foi,
    ou se o conteúdo retornado parece ter liberado algo que antes era negado."""
    if r.error or r.status is None:
        return False
    if baseline.status in DENIED_STATUSES and r.status not in DENIED_STATUSES:
        return True
    if baseline.status in DENIED_STATUSES and r.status < 400 and r.length and r.length > 0:
        return True
    return False


def run_scan(url, base_headers, methods, timeout, verify, extra_data):
    session = requests.Session()
    results = []

    base_method = methods[0] if methods else "GET"
    resp, elapsed, err = do_request(session, url, base_method, base_headers, timeout, verify)
    if err:
        baseline = Result(technique="baseline", method=base_method, detail="-",
                           status=None, length=None, body_hash=None, elapsed_ms=None, error=err)
    else:
        baseline = Result(
            technique="baseline", method=base_method, detail="-",
            status=resp.status_code, length=len(resp.content),
            body_hash=body_fingerprint(resp.content), elapsed_ms=round(elapsed, 1),
        )
    results.append(baseline)

    for m in methods:
        if m == base_method:
            continue
        resp, elapsed, err = do_request(session, url, m, base_headers, timeout, verify,
                                         data=extra_data if m in ("POST", "PUT", "PATCH") else None)
        if err:
            r = Result(technique="method", method=m, detail="-",
                       status=None, length=None, body_hash=None, elapsed_ms=None, error=err)
        else:
            r = Result(
                technique="method", method=m, detail="-",
                status=resp.status_code, length=len(resp.content),
                body_hash=body_fingerprint(resp.content), elapsed_ms=round(elapsed, 1),
            )
            r.suspicious = classify(baseline, r)
        results.append(r)

    for h in OVERRIDE_HEADERS:
        for override_value in ("GET", "PUT", "DELETE"):
            headers = dict(base_headers)
            headers[h] = override_value
            resp, elapsed, err = do_request(session, url, base_method, headers, timeout, verify)
            if err:
                r = Result(technique="header-override", method=base_method,
                           detail=f"{h}: {override_value}",
                           status=None, length=None, body_hash=None, elapsed_ms=None, error=err)
            else:
                r = Result(
                    technique="header-override", method=base_method,
                    detail=f"{h}: {override_value}",
                    status=resp.status_code, length=len(resp.content),
                    body_hash=body_fingerprint(resp.content), elapsed_ms=round(elapsed, 1),
                )
                r.suspicious = classify(baseline, r)
            results.append(r)

    return baseline, results


def print_report(url, baseline, results):
    print(f"\nAlvo: {url}")
    print(f"Baseline ({baseline.method}): status={baseline.status} "
          f"tamanho={baseline.length} hash={baseline.body_hash}\n")

    header = f"{'TÉCNICA':<16}{'MÉTODO':<10}{'DETALHE':<30}{'STATUS':<8}{'TAMANHO':<10}{'SUSPEITO'}"
    print(header)
    print("-" * len(header))

    found_any = False
    for r in results:
        if r.technique == "baseline":
            continue
        status_str = str(r.status) if r.status is not None else f"ERRO:{r.error}"
        flag = "⚠️  SIM" if r.suspicious else ""
        if r.suspicious:
            found_any = True
        print(f"{r.technique:<16}{r.method:<10}{r.detail:<30}{status_str:<8}"
              f"{str(r.length):<10}{flag}")

    print()
    if found_any:
        print("⚠️  Possível HTTP Method Tampering encontrado — veja as linhas marcadas acima.")
        print("   Confirme manualmente: o status mudou de negado (401/403/405) pra liberado,")
        print("   e o corpo retornado realmente expõe o recurso protegido.")
    else:
        print("Nenhuma variação suspeita encontrada com os testes aplicados.")
        print("Isso não garante ausência da vulnerabilidade — teste manualmente também.")


def main():
    parser = argparse.ArgumentParser(
        description="Scanner de HTTP Method Tampering — uso autorizado apenas.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-u", "--url", required=True, help="URL alvo (ex: https://alvo.com/admin)")
    parser.add_argument("-H", "--header", action="append", default=[],
                         help='Header extra, pode repetir. Ex: -H "Cookie: session=abc"')
    parser.add_argument("--methods", default=",".join(DEFAULT_METHODS),
                         help="Lista de métodos separados por vírgula")
    parser.add_argument("--timeout", type=float, default=10, help="Timeout por requisição (s)")
    parser.add_argument("-k", "--insecure", action="store_true",
                         help="Não validar certificado TLS")
    parser.add_argument("--data", default=None,
                         help="Corpo pra enviar em POST/PUT/PATCH (string raw)")
    parser.add_argument("-o", "--output", help="Salvar relatório completo em JSON")
    args = parser.parse_args()

    headers = {}
    for h in args.header:
        if ":" not in h:
            sys.exit(f"Header inválido (esperado 'Nome: valor'): {h}")
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()

    methods = [m.strip().upper() for m in args.methods.split(",") if m.strip()]

    print("=" * 60)
    print(" HTTP Method Tampering Scanner — uso autorizado apenas")
    print("=" * 60)

    baseline, results = run_scan(
        args.url, headers, methods, args.timeout, not args.insecure, args.data,
    )
    print_report(args.url, baseline, results)

    if args.output:
        payload = {
            "url": args.url,
            "baseline": asdict(baseline),
            "results": [asdict(r) for r in results],
        }
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print(f"\nRelatório salvo em: {args.output}")


if __name__ == "__main__":
    main()
