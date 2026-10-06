# HTTP Method Tampering Scanner

> Scanner em Python para detecção de vulnerabilidades de **HTTP Method Tampering** (também chamado de *HTTP Verb Tampering*) em aplicações e endpoints web.

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](#licença)
[![Uso](https://img.shields.io/badge/uso-autorizado%20apenas-red.svg)](#aviso-legal)

---

## Índice

- [Sobre](#sobre)
- [O que é HTTP Method Tampering?](#o-que-é-http-method-tampering)
- [Como a ferramenta funciona](#como-a-ferramenta-funciona)
- [Técnicas aplicadas](#técnicas-aplicadas)
- [Requisitos](#requisitos)
- [Instalação](#instalação)
- [Uso](#uso)
- [Argumentos da linha de comando](#argumentos-da-linha-de-comando)
- [Exemplos](#exemplos)
- [Entendendo o relatório](#entendendo-o-relatório)
- [Saída em JSON](#saída-em-json)
- [Lógica de detecção](#lógica-de-detecção)
- [Limitações](#limitações)
- [Aviso legal](#aviso-legal)
- [Licença](#licença)

---

## Sobre

Esta ferramenta é um scanner de linha de comando que automatiza a verificação de **HTTP Method Tampering** — uma classe de vulnerabilidade na qual controles de acesso aplicados a um método HTTP (ex.: `GET`) podem ser contornados usando métodos alternativos ou cabeçalhos de *override*.

O scanner envia uma requisição de referência (*baseline*), depois repete a mesma requisição variando o método HTTP e injetando cabeçalhos de *method override*, comparando as respostas para identificar casos em que um recurso **antes negado** passa a ser **liberado**.

É destinado a profissionais de segurança, pentesters e equipes de Blue/Red Team em **testes autorizados**.

---

## O que é HTTP Method Tampering?

Muitas aplicações restringem acesso a recursos com base no método HTTP. Por exemplo, um desenvolvedor pode bloquear requisições `GET` a `/admin`, mas esquecer de aplicar a mesma regra a `POST`, `HEAD`, ou a métodos não convencionais. Além disso:

- **WAFs e proxies** frequentemente filtram apenas métodos conhecidos, deixando passar verbos arbitrários (ex.: `FOOBAR`, `TRACK`).
- Alguns frameworks respeitam cabeçalhos de *override* (`X-HTTP-Method-Override`, etc.), permitindo que um `POST` seja reinterpretado como `DELETE` ou `PUT` internamente — contornando controles aplicados na borda.

O resultado prático pode ser **bypass de autenticação/autorização** (OWASP: *Broken Access Control*).

---

## Como a ferramenta funciona

1. Faz uma requisição **baseline** com o primeiro método da lista (por padrão `GET`).
2. Repete a requisição para cada método adicional da lista.
3. Injeta cabeçalhos de *method override* com valores alternativos (`GET`, `PUT`, `DELETE`).
4. Para cada resposta, coleta: **status HTTP**, **tamanho do corpo**, **hash do corpo** (SHA-256, 16 chars) e **tempo de resposta**.
5. Compara cada variação contra o baseline e sinaliza as respostas **suspeitas**.
6. Gera um relatório em tabela no terminal e, opcionalmente, um relatório completo em JSON.

> As requisições **não seguem redirecionamentos** (`allow_redirects=False`), para que a resposta real de cada método seja observada sem mascaramento.

---

## Técnicas aplicadas

| Técnica | Descrição |
|---|---|
| `baseline` | Requisição de referência com o método base (primeiro da lista). |
| `method` | Mesma URL testada com métodos alternativos, incluindo verbos não convencionais (`FOOBAR`, `ADMIN`, `TRACK`, `CONNECT`, etc.). |
| `header-override` | Requisição com o método base, mas injetando cabeçalhos de override para reinterpretar o verbo no backend. |

**Métodos testados por padrão:**
`GET`, `HEAD`, `POST`, `PUT`, `DELETE`, `PATCH`, `OPTIONS`, `TRACE`, `TRACK`, `CONNECT`, `FOOBAR`, `ADMIN`

**Cabeçalhos de override testados:**
`X-HTTP-Method-Override`, `X-HTTP-Method`, `X-Method-Override`, `X-Original-Method`

---

## Requisitos

- **Python 3.7+**
- Biblioteca [`requests`](https://pypi.org/project/requests/)

---

## Instalação

```bash
# Clone ou copie o projeto
cd httoTempering

# Instale a dependência
pip install requests
```

> Se a lib `requests` não estiver instalada, o script encerra com uma mensagem instruindo a instalação.

---

## Uso

```bash
python main.py -u <URL> [opções]
```

Exemplo mínimo:

```bash
python main.py -u https://alvo.com/admin
```

---

## Argumentos da linha de comando

| Flag | Alias | Obrigatório | Padrão | Descrição |
|---|---|:---:|---|---|
| `--url` | `-u` | ✅ | — | URL alvo (ex.: `https://alvo.com/admin`). |
| `--header` | `-H` | ❌ | `[]` | Cabeçalho extra no formato `Nome: valor`. Pode repetir. |
| `--methods` | — | ❌ | lista completa | Métodos HTTP separados por vírgula. |
| `--timeout` | — | ❌ | `10` | Timeout por requisição, em segundos. |
| `--insecure` | `-k` | ❌ | `false` | Não valida o certificado TLS. |
| `--data` | — | ❌ | `None` | Corpo (raw) enviado em `POST`/`PUT`/`PATCH`. |
| `--output` | `-o` | ❌ | — | Salva o relatório completo em arquivo JSON. |

---

## Exemplos

**Teste básico de um endpoint protegido:**
```bash
python main.py -u https://alvo.com/admin
```

**Com cookie de sessão autenticada:**
```bash
python main.py -u https://alvo.com/admin -H "Cookie: session=abc123"
```

**Múltiplos cabeçalhos:**
```bash
python main.py -u https://alvo.com/api/users \
  -H "Authorization: Bearer <token>" \
  -H "X-Forwarded-For: 127.0.0.1"
```

**Lista customizada de métodos:**
```bash
python main.py -u https://alvo.com/admin --methods "GET,POST,PUT,DELETE,FOOBAR"
```

**Ambiente de laboratório com certificado autoassinado:**
```bash
python main.py -u https://localhost:8443/admin -k
```

**Enviando corpo em métodos de escrita e salvando o relatório:**
```bash
python main.py -u https://alvo.com/api/item/1 \
  --data '{"role":"admin"}' \
  -o relatorio.json
```

---

## Entendendo o relatório

Saída típica no terminal:

```
============================================================
 HTTP Method Tampering Scanner — uso autorizado apenas
============================================================

Alvo: https://alvo.com/admin
Baseline (GET): status=403 tamanho=162 hash=9f2b1c4a7e8d0f33

TÉCNICA         MÉTODO    DETALHE                       STATUS  TAMANHO   SUSPEITO
----------------------------------------------------------------------------------
method          POST      -                             200     5120      ⚠️  SIM
method          HEAD      -                             403     0
header-override GET       X-HTTP-Method-Override: PUT   200     840       ⚠️  SIM
...

⚠️  Possível HTTP Method Tampering encontrado — veja as linhas marcadas acima.
```

Colunas:

- **TÉCNICA** — `baseline`, `method` ou `header-override`.
- **MÉTODO** — método HTTP usado na linha de requisição.
- **DETALHE** — cabeçalho de override injetado (ou `-`).
- **STATUS** — código HTTP retornado (ou `ERRO:<mensagem>`).
- **TAMANHO** — tamanho do corpo em bytes.
- **SUSPEITO** — `⚠️ SIM` quando a variação parece ter contornado o controle do baseline.

---

## Saída em JSON

Com `-o relatorio.json`, é gravado um documento estruturado:

```json
{
  "url": "https://alvo.com/admin",
  "baseline": {
    "technique": "baseline",
    "method": "GET",
    "detail": "-",
    "status": 403,
    "length": 162,
    "body_hash": "9f2b1c4a7e8d0f33",
    "elapsed_ms": 88.4,
    "error": null,
    "suspicious": false
  },
  "results": [
    {
      "technique": "method",
      "method": "POST",
      "detail": "-",
      "status": 200,
      "length": 5120,
      "body_hash": "a1b2c3d4e5f60718",
      "elapsed_ms": 102.7,
      "error": null,
      "suspicious": true
    }
  ]
}
```

Útil para integração com pipelines, triagem automatizada e evidências de relatório.

---

## Lógica de detecção

Uma variação é marcada como **suspeita** quando:

- O baseline retornou um status de **negação** (`401`, `403` ou `405`), **e**
- A variação retornou um status **fora** do conjunto de negação; **ou**
- A variação retornou status `< 400` **com corpo não vazio** (indício de que o recurso protegido foi efetivamente exposto).

Respostas com erro de rede ou sem status não são classificadas como suspeitas.

> A detecção é **heurística**. Toda sinalização deve ser **confirmada manualmente**: verifique se o status realmente mudou de negado para liberado e se o corpo retornado expõe o recurso protegido.

---

## Limitações

- Não segue redirecionamentos — respostas `3xx` são reportadas como tais.
- A heurística compara apenas status e tamanho/corpo; aplicações que retornam `200` genérico para tudo podem gerar falsos positivos/negativos.
- Não testa automaticamente combinações de método + override simultâneas além das previstas.
- A ausência de sinalização **não garante** que o alvo esteja seguro — complemente com testes manuais.

---

## Aviso legal

> ⚠️ **Uso autorizado apenas.**

Esta ferramenta foi desenvolvida para fins **educacionais** e para **testes de segurança autorizados**. Utilizá-la contra sistemas sem permissão explícita e por escrito do proprietário é **ilegal** e pode constituir crime.

O autor não se responsabiliza por qualquer uso indevido. Você é inteiramente responsável por garantir que possui autorização para testar o alvo.

---

## Licença

Distribuído sob a licença MIT. Consulte o arquivo `LICENSE` para detalhes.
