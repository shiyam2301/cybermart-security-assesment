# CyberMart Web Security Assessment

**Portfolio lab · 8–9 November 2026 (Kali VM clock)**  
**Target** `http://127.0.0.1:3000` · Kali Linux in VirtualBox  
**Tools** Nmap 7.991, Burp Suite Community Edition 2026.9, Firefox, Burp’s browser, and Python `unittest` with `urllib.request`

## Executive summary

I assessed CyberMart, a deliberately vulnerable storefront running locally with fictional data. I reproduced a login bypass that returned the administrator role, changed the confirmed price of a $32 item to $1, and retrieved order details belonging to a different user by changing an order ID. I also documented the plaintext login request and the HTTP service details exposed during reconnaissance.

![CyberMart storefront running on port 3000 inside Kali](report-evidence/storefront.png)

## Scope and method

Testing covered the local storefront and its HTTP API. I used Nmap to discover the service, Burp Proxy to capture baseline requests, and Repeater and browser requests to change one input at a time and compare the responses. The server banner identified `CyberMart-Lab/1.0 Python/3.13.12`. Severity is qualitative and reflects the likely impact if the behavior existed in a deployed application.

| ID | Finding | Severity | Evidence |
| --- | --- | --- | --- |
| F-01 | SQL injection bypasses credential validation | High | Burp returned `role: admin` with an empty password |
| F-02 | Checkout trusts the client-supplied price | Medium | Order `1005` was confirmed at $1 for a $32 product |
| F-03 | Order lookup exposes another user's record | Medium | Changing the order ID returned a record with a different `user_id` and delivery details |
| F-04 | Login sends credentials over HTTP | Medium | Burp showed a readable password in the request sent over HTTP |
| O-01 | Server banner and advertised HTTP methods | Informational | Nmap captured the server version and an `Allow` header containing `TRACE` |

## F-01 · SQL injection in login

**Endpoint** `POST /api/login` · **Evidence** Burp Repeater, `Screenshot_2026-11-09_00_00_44.png`

1. Capture a normal login in Burp Proxy and send it to Repeater. The baseline returns customer ID `2` and role `customer`.
2. Replace the email with `' OR 1=1 --` and leave the password empty. Send the request.
3. Compare the returned ID and role with the baseline.

```json
{"email":"' OR 1=1 --","password":""}
```

The response was `200 OK` and contained `{"user":{"id":1,"email":"admin@cybermart.local","role":"admin"}}`. The login endpoint should reject invalid credentials. The result demonstrates a bypass of credential validation at this endpoint. A privileged session or administrative action would require separate verification.

**Remediation** Use a parameterized query to look up the account and verify its stored password hash separately. Retest with a legitimate account, an incorrect password, and the same injected value.

## F-02 · Checkout price tampering

**Endpoint** `POST /api/checkout` · **Evidence** Burp Proxy and Repeater, screenshots ending `23_48_23`, `23_49_10`, and `23_49_31`

1. Capture checkout for Classic sunglasses, product ID `11`, listed at $32.
2. In Repeater, keep the product ID and change `price` from `32` to `1`.
3. Send the modified request and compare it with a replay at the listed price.

| Request body | Result |
| --- | --- |
| `{"productId":11,"price":32}` | `200 OK`, order `1006`, total `32.0` |
| `{"productId":11,"price":1}` | `200 OK`, order `1005`, total `1.0` |

The server confirmed the modified order at $1, a $31 reduction. A deployed store with this behavior could accept underpriced orders.

**Remediation** Calculate totals on the server using the catalog price, quantity, and eligible discounts. Retest the modified request and verify that the server rejects it or uses the catalog price.

## F-03 · Broken object-level authorization in order lookup

**Endpoint** `GET /api/orders/{id}` · **Evidence** Browser and Burp Proxy, screenshots ending `23_50_54`, `23_51_14`, and `23_54_24`

1. Open `/api/orders/1003` and observe the wireless headphones order for `user_id: 2`.
2. Change the path to `/api/orders/1002` in the same browser.
3. The server returns `200 OK` with a keyboard order for `user_id: 3`, including a private delivery field. Burp history also shows a `404` for nonexistent order `1008`.

![The browser displays order 1002 for user 3](report-evidence/order-lookup.png)

Changing the identifier exposed another user's order data. The endpoint should validate access to each requested order before returning any details.

**Remediation** Require an authenticated identity and check order ownership or an explicit staff permission on every lookup. Retest with the owner, a different account, and an unauthenticated request.

## F-04 · Plaintext login transport

**Endpoint** `POST /api/login` · **Evidence** Burp Proxy and Repeater, screenshots ending `23_54_24` and `23_55_20`

1. Browse to the HTTP storefront through Burp and log in with the sample customer account.
2. Inspect the login request in HTTP history. The destination uses `http://` and the JSON contains a readable `password` field.

The lab uses loopback. On a deployed service using the same transport, someone able to observe traffic could read submitted credentials.

**Remediation** Serve the application over HTTPS and prevent login requests over plaintext HTTP. Verify transport protection with a packet capture during retesting.

## O-01 · HTTP reconnaissance

```bash
nmap -sV -p 3000 127.0.0.1
nmap -sV -p 3000 --script http-title,http-headers,http-methods,http-robots.txt 127.0.0.1
```

Nmap reported port `3000/tcp` open and displayed the tentative label `ppp?`. The raw `GetRequest` fingerprint contained `HTTP/1.0 200 OK`, the CyberMart banner, and the storefront HTML, which identified the service as HTTP. The `HTTPOptions` fingerprint advertised `GET, HEAD, POST, OPTIONS, TRACE`. The screenshots document the advertisement of `TRACE` and the version banner. Evidence came from screenshots ending `23_40_22`, `23_44_26`, and `23_45_00`.

For a deployed service, disable unused HTTP methods and reduce unnecessary version disclosure.

## Automated HTTP verification

On 9 November 2026, the project’s Python integration suite ran against a fresh localhost instance on the Windows development host. All three test cases passed. Each case exercised multiple requests and checked response bodies, status codes, or application state. The checks below are separate from the Kali screenshot evidence.

| Area | Automated observation | Recommended control |
| --- | --- | --- |
| Baseline and negative controls | The storefront loaded, the catalog returned 30 items, valid login and checkout succeeded, bad credentials returned `401`, and a malformed order ID returned `400`. | Preserve these controls when retesting fixes. |
| Login bypass and order authorization | Injected credentials returned the admin role. A request without credentials returned order `1002`, owned by user `3`. | Parameterize account lookup and require ownership checks. |
| Checkout tampering | Submitting a one-cent price triggered the lab’s price tampering condition. The manual Burp evidence above independently shows a confirmed order at a modified price. | Recalculate the price from the catalog. |
| Product search SQL injection | An always-true predicate in `q` returned all 30 products. | Bind the search value as a query parameter. |
| Review and search XSS surfaces | The reviews API preserved an event-handler payload, and `/search` reflected executable markup in HTML. | Render reviews as text and encode search terms for the HTML context. |
| Warehouse authentication | `/admin/` challenged with HTTP Basic authentication and accepted the default credentials. | Remove shared defaults and require strong credentials. |
| Sensitive file exposure | The customer backup, synthetic `.env`, and simulated Git `HEAD` marker were publicly readable. | Restrict backups and configuration to authenticated administrative access and keep them outside public paths. |
| Path traversal | `../private/warehouse.env` reached a private fixture. An attempt to read `/etc/passwd` returned `404`. | Restrict downloads to an allowlist. The demonstrated impact is limited to the lab’s virtual filesystem. |
| Open redirect | `/redirect` returned `302` with a caller-supplied external `Location`. | Accept approved destinations or relative paths only. |
| HTTP method handling | `OPTIONS` listed `TRACE`, a direct `TRACE` request echoed a test header, and `HEAD` returned headers with an empty body. | Disable unused methods and preserve normal `HEAD` behavior. |
| Reset behavior | Reset cleared challenge progress and restored the initial review. | Use the reset to establish a repeatable baseline between lab runs. |

```bash
python3 -m unittest -v test_server.py
```

## Coverage and retest status

The screenshots document Kali browser, Burp, and Nmap work. The integration suite verifies HTTP behavior. Browser execution of the XSS payloads and independent packet capture remain unverified. Wireshark, tcpdump, Metasploit, sqlmap, and ZAP are listed in the lab guide as follow-up exercises. Remediation and post-fix retesting are pending.

One interview example is the checkout test. The product ID stayed constant while the request price changed. The server response confirmed a different order total, which demonstrated the business impact directly. For reconnaissance, the raw HTTP response provided stronger evidence of the protocol than Nmap’s tentative `ppp?` label.

The request and response excerpts above are transcribed from the screenshots. Public evidence omits cookie values and the sample password. The order details shown are fictional lab data.
