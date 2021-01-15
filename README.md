# IoT Content Object Security with OSCORE and NDN (IFIP Networking 2020)

[![Paper][paper-badge]][paper-link]
[![Preprint][preprint-badge]][preprint-link]

This repository contains code and documentation to reproduce experimental results of the paper **"[IoT Content Object Security with OSCORE and NDN: A First Experimental Comparison][preprint-link]"** published in Proc. of IFIP Networking Conference 2020.

* Cenk Gündogan, Christian Amsüss, Thomas C. Schmidt, Matthias Wählisch,
**IoT Content Object Security with OSCORE and NDN: A First Experimental Comparison**,
In: Proc. of 19th IFIP Networking Conference, p. 19-27, Piscataway, NJ, USA: IEEE, 2020.

> The emerging Internet of Things (IoT) challenges the end-to-end transport of the Internet by low power lossy links and gateways that perform protocol translations. Protocols such as CoAP or MQTT-SN are degraded by the overhead of DTLS sessions, which in common deployment protect content transfer only up to the gateway. To preserve content security end-to-end via gateways and proxies, the IETF recently developed Object Security for Constrained RESTful Environments (OSCORE), which extends CoAP with content object security features commonly known from Information Centric Networks (ICN). This paper presents a comparative analysis of protocol stacks that protect request-response transactions. We measure protocol performances of CoAP over DTLS, OSCORE, and the information-centric Named Data Networking (NDN) protocol on a large-scale IoT testbed in single- and multi-hop scenarios. Our findings indicate that (a) OSCORE improves on CoAP over DTLS in error-prone wireless regimes due to omitting the overhead of maintaining security sessions at endpoints, and (b) NDN attains superior robustness and reliability due to its intrinsic network caches and hop-wise retransmissions.

[paper-link]: https://ieeexplore.ieee.org/document/9142731
[preprint-link]: https://arxiv.org/abs/2001.08023
[paper-badge]: https://img.shields.io/badge/Paper-IEEE%20Xplore-green
[preprint-badge]: https://img.shields.io/badge/Preprint-arXiv-green
