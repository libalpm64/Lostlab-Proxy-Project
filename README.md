# Lostlab Proxy

Lostlab Proxy is a free and open-source reverse proxy designed to be lightweight, fast, and secure. It helps protect your website from DDoS attacks, web scraping, and automated bots while providing a memory-safe solution.

## Use Cases

- **DDoS Protection**: Protect your website by wasting attackers' CPU resources through cookie or JavaScript challenges.
- **Prevent Web Scraping and Bots**: Block crawlers and automated bots from accessing your endpoints.
- **Memory-Safe Reverse Proxy**: Ensure safe and reliable handling of requests with minimal overhead.

## Features

- **Security**: Establishes a secure tunnel between your proxy and backend, preventing the actual backend IP from being exposed. Even if the proxy IP is leaked, your backend remains protected.
- **Speed**: In testing, Lostlab Proxy is significantly faster than traditional Go-based reverse proxies. It can handle a large number of requests on a single node without rate limiting.

## Requirements:
- **TLS**, You need a Client Edge (Private key, Cert).
