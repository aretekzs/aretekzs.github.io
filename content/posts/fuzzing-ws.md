+++
title = "Fuzzing WebSockets for Server-Side Vulnerabilities"
date = 2025-04-15
draft = false
[extra]
toc = true
display_published = true 
+++

## [Introduction](#introduction)

Since RFC 6455 [[^1]] landed in 2011, WebSockets have become a core part of many real-time applications.

But here’s a paradox: in theory, traditional HTTP vulnerabilities are expected to apply to WebSockets [[^2]][[^3]][[^4]][[^5]][[^6]]. Yet in practice, public reports and CVEs show near-zero WebSocket-specific server-side flaws. This raises the question: are systems truly secure, or is the tooling for WebSocket security still underdeveloped?

This work aims to address that gap by proposing a new approach on how to fuzz WebSocket messages, and also move past the manual analysis required by most existing tools. To achieve this, the Backslash Powered Scanner extension for Burp Suite was enhanced to support WebSocket fuzzing.

<center>
  <video src="/videos/demo.mp4" controls style="max-width: 90%; height: auto;"></video>
</center>
<div class="centered" style="text-align: center; font-style: italic;">
Demo
</div>


## [Brief Explanation of the WebSocket Protocol](#brief-explanation-of-the-websocket-protocol)

This article will not provide a detailed walkthrough of the WebSocket protocol. If you need that level of depth, please refer to RFC 6455 [[^1]].

HTTP is inherently a request-response protocol. The client sends a request, the server replies, and that cycle repeats. This design makes it easy for security tools to insert payloads, observe responses, and flag anomalies. WebSockets, on the other hand, depart entirely from this paradigm.

After an initial HTTP handshake, the connection is upgraded to a persistent, bidirectional channel. From that point on, both client and server can send data independently, at any time, without waiting for a response or following a strict sequence. This results in a communication model that is asynchronous, stateful and long-lived.

Messages in WebSocket connection are transmitted as frames, which are low-level units that encapsulate the actual payload. Each frame includes metadata such as an _opcode_ (indicating message type), masking information (required for client-to-server messages to mitigate attacks such as cache poisoning), and fragmentation flags (to support message splitting across multiple frames). Each message can be composed of one or more frames, and messages can be of two different types: text or binary. Both types can be intermixed within the same session.

<center><img src="/images/ws_frame.png" alt="Text representation of a WebSocket frame" title="Text representation of a WebSocket frame" style="max-width: 100%; height: auto;"></center>

<div class="centered" style="text-align: center; font-style: italic;">

Text representation of a WebSocket frame [[^1]]</div>

There are no HTTP status codes, no headers and no request-response boundaries. Just a stream of raw frames - text or binary, sometimes wrapped in custom formats or encodings - moving in both directions.

This design is great for performance and interactivity, but it's a nightmare for security tools. The assumption that an input will produce a corresponding, immediate response no longer holds. A message might trigger an effect ten seconds later. It might not trigger anything at all, or it might depend on a prior state set earlier in the session. R. Koch also mentions this in his work:

> *"With WebSockets vulnerability detection is not as easy as with HTTP. When you send a HTTP request there is always a response, where you can easily detect changed output, or slow response times. With WebSockets, communication is bi-directional and asynchronous. There is no request/response pattern, although a sub-protocol in use may define such. As a result automated detection is fairly hard and has to be done manually. However, tools can aid the search for vulnerabilities. The approach to take is similar to stored XSS attacks, where there is often no indication of a vulnerability. While the attack payload is stored in a database, it may appear on any page of the website. If there exists a request-response pattern in the WebSocket communication, you can measure the response time after sending crafted requests. Like with Blind SQL-injection attacks, one could send values that delay the execution of database or file system queries. If the execution slowed down, a hidden vulnerability may be detected."* [[^6]]

As a consequence, existing tools and logic mostly built for HTTP traffic are inneffective when applied to WebSocket-based applications.

## [Brief Discussion of WebSocket Security Tools](#brief-discussion-of-websocket-security-tools)

While not many, some attempts have been made over the years to improve WebSocket security tooling. Other valuable work exists as well, but here I’ll focus specifically on fuzzers.

The first mainstream tool to support WebSocket testing was Zed Attack Proxy (ZAP). R. Koch’s work [[^6]] allowed inspection and message tampering, and introduced a basic fuzzer using a custom wordlist. However, the results had to be manually analyzed.

A. Riancho [[^7]] and A. Hauser [[^8]] released similar tools: a simple WebSocket fuzzer that requires user-supplied wordlists and supports pre-messages before sending the actual payload. They mainly target JSON-based applications, but can be adapted to other formatas with custom scripting. Hauser’s tool requires manual inspection via a proxy, while Riancho's adds an attempt at automated analysis, although it is quite limited.

In 2019, M. Fowl [[^5]] proposed a different approach that involves translating WebSocket messages into HTTP requests and vice versa, effectively creating a fuzzing harness. This technique allows traditional web application security tools, such as SQLMap, to be used directly for WebSocket-heavy applications. Nevertheless, the approach is limited by its dependence on HTTP translation, which may fail for WebSocket interactions without direct HTTP equivalents. Additionally, its effectiveness is constrained by the capabilities of the underlying tools. VDA Labs followed a similar idea with their own prototype [[^9]].

Wsrepl [[^10]], developed by Doyensec, offered a more interactive and exploratory tool rather than a traditional fuzzer. It featured a command-line REPL for sending and receiving WebSocket messages, along with interesting additional utilities such as displaying message opcodes and injecting fake ping messages.

More recently, SocketSleuth [[^3]], created by E. Ward, became the first dedicated Burp Suite extension for WebSocket security testing. This tool was developed in response to the lack of automation features in Burp Suite—particularly the absence of Intruder-like functionality and match-and-replace rules for WebSocKet traffic. SocketSleuth introduced a refined message history interface, support for fuzzing, and configurable replacement rules. Despite these improvements, it still requires manual analysis of responses.

Around the same time, PortSwigger released WebSocket Turbo Intruder [[^11]], a Burp Suite extension designed to automate WebSocket fuzzing using customizable Python scripts. This tool offered advanced features for scripting attack logic and automating message dispatch. However, it still relies on the user to interpret and analyze results manually.

A common limitation persists across all tools: the lack of automated response analysis. Payloads must be manually crafted, and results manually reviewed. But before meaningful automation can be achieved, it is essential to first establish methods for detecting and handling WebSocket messages correctly.

## [How To Handle WebSocket Messages](#how-to-handle-websocket-messages)

As stated, WebSockets are complicated to fuzz. Their asynchronous, stateful nature breaks the usual assumptions that security tools rely on. 

To work around these challenges, this approach focuses on reliability and clarity. A new WebSocket connection is opened for each payload (to avoid side effects from earlier payloads that might affect the application’s state). If necessary (for example, with Socket.IO implementations), the scanner can wait a bit or send prerequisite messages before injecting the actual payload. Once the payload is sent, all incoming messages are captured during a configurable time window.

Responses are stored in a structured format, including metadata such as message type (text or binary) and response time. This structured approach simplifies message correlation and enables more accurate behavioral analysis.

The following visual representation may offer a clearer view:
<center><img src="/images/ws_mermaid_chart.png" alt="WebSocket fuzzing flow" title="WebSocket fuzzing flow" style="max-width: 60%; height: auto;"></center> <div class="centered" style="text-align: center; font-style: italic;">

WebSocket fuzzing flow</div>

And for comparison, here is the same representation for HTTP, which highlights the added complexity involved in fuzzing WebSocket traffic:
<center><img src="/images/http_mermaid_chart.png" alt="HTTP fuzzing flow" title="HTTP fuzzing flow" style="max-width: 60%; height: auto;"></center> <div class="centered" style="text-align: center; font-style: italic;">

HTTP fuzzing flow</div>

## [Adding WebSocket support to Backslash Powered Scanner](#adding-websocket-support-to-backslash-powered-scanner)

#### [Brief Explanation of the Backslash Powered Scanner](#brief-explanation-of-the-backslash-powered-scanner)

This article will not provide a detailed walkthrough of the Backslash Powered Scanner extension. If you need that level of depth, please refer to the whitepaper [[^12]].

The Backslash Powered Scanner [[^12]] is a Burp Suite extension that distinguishes itself from traditional vulnerability scanners by adopting an iterative, behavior-based approach inspired by manual testing techniques.

Unlike traditional scanners that rely on predefined, technology-specific payloads, this scanner utilizes a set of generic payloads containing special characters (e.g. backslashes, quotes, braces) to assess how the server processes and responds to these inputs. It begins by modifying the input and evaluating the response against predefined metrics, such as HTTP status codes, the total number of new lines in the response, and the frequency of various keywords. If a deviation is detected, the scanner investigates further; otherwise, the input is disregarded. In essence, rather than explicitly searching for known vulnerabilities, the scanner focuses on identifying anomalous or unexpected behavior, which may indicate potential security flaws.

It has demonstrated considerable effectiveness in fuzzing traditional HTTP-based applications. As such, enhancing it to support WebSocket fuzzing could significantly expand its utility.

#### [Response Analysis](#response-analysis)

As stated, the Backslash Powered Scanner extension takes advantage of predefined metrics to compare responses. But metrics used for HTTP traffic cannot be directly applied to WebSockets due to the fundamental differences between the protocols. As such, as a starting point, and with the flexibility to expand or refine these metrics in the future, I chose the following:

- the total number of messages received.
- the sequence of received message types (text or binary)
- the individual lengths of received messages
- the number of spaces in each message
- the number of HTML tags in each message

This ensures that WebSocket responses are evaluated based on meaningful attributes rather than traditional HTTP metrics like status codes and headers.

#### [Usage and Automation](#usage-and-automation)

Since Burp's Montoya API is still not as mature for WebSocket traffic as it is for HTTP, it's not yet straightforward to automatically fuzz all fields within a message. That said, some automation was manually implemented and can be expanded in the future. For now, and somewhat as a workaround, usage works as follows:

- Select a WebSocket message and launch the extension.
- If the message is in JSON or Socket.IO format, the extension will automatically fuzz all fields and JSON escape the payloads.
- If it's not, you can wrap the desired insertion point with `FUZZ`, and the extension will target that area.
- If no marker is provided, the extension will fuzz the entire message as a single unit.

In the settings, the user can configure the desired time window (in seconds) for listening to incoming messages. Additionally, it is possible to customize a delay (in milliseconds) before sending the payload, as well as define any prerequisite messages to be sent prior to the payload. If more than one message is required, these should be separated by `FUZZ`.

<center><img src="/images/ws_settings.png" alt="Settings example" title="Settings example" style="max-width: 100%; height: auto;"></center> <div class="centered" style="text-align: center; font-style: italic;">

Settings example</div>

## [Future Work and Challenges](#future-work-and-challenges)

There are several areas for improvement. Unfortunately, due to the inherent complexity of WebSockets, it would be impossible to implement everything and take all scenarios into account in the initial release. I chose to build a solid foundation first, with plans for updates over time. That said, here are a few key points to consider:

- Allow the user to open connections directly from a `ws://` or `wss://` URL, in addition to the current method of using the upgrade request.
- Allow the user to reuse the same connection, in addition to the current method of creating of creating a new connection for each payload.
- Improve the response analysis metrics.
- Add lower-level metrics (e.g., opcodes) when Burp’s Montoya API supports it.
- Add support for binary messages in some capacity.

In the real world, WebSockets are chaotic. For example, some implementations send messages to the server in JSON, and the server replies with compressed binary messages. Others require each message to include a timestamp and a signature. Supporting all these scenarios is no small task.

## [Acknowledgments](#acknowledgments)
I would like to thank James Kettle for his openness, his feedback, and for taking the time to answer my questions throughout the process. I am also grateful for the opportunity to contribute to his work.

I would also like to thank Andreas Happe and Erik Elbieh for their availability to answer my questions.

## [References](#references)

[^1]: Fette, I., & Melnikov, A. [*The WebSocket Protocol (RFC 6455)*](https://datatracker.ietf.org/doc/html/rfc6455). IETF. 2011
[^2]: PortSwigger. [*Testing for WebSockets security vulnerabilities*](https://portswigger.net/web-security/websockets#websockets-security-vulnerabilities). Web Security Academy. 2024
[^3]: Ward, E. [*Realtime Communications, Realtime Risks*](https://www.youtube.com/watch?v=JMEuxEW3e2k). 44CON Information Security Conference. 2023 
[^4]: Shekyan, S., & Toukharian, V. [*Hacking with WebSockets*](https://www.youtube.com/watch?v=-ALjHUqSz_Y). Black Hat USA. 2012
[^5]: Fowl, M., Defoe, N. [*Stable 35 Old Tools New Tricks Hacking WebSockets*](https://www.youtube.com/watch?v=MhxayMPknFI). Derbycon. 2019
[^6]: Koch, R. [*On WebSockets in Penetration Testing*](https://repositum.tuwien.at/retrieve/21955). Technische Universität Wien. 2013
[^7]: Riancho, A. [*Websocket Fuzzer*](https://github.com/andresriancho/websocket-fuzzer). 2018
[^8]: Hauser, A. [*WebSocket Fuzzing - Development of a Fuzzer*](https://www.scip.ch/en/?labs.20230420). SCIP. 2023
[^9]: VDA Labs. [*Hacking Web Sockets: All Web Pentest Tools Welcomed*](https://www.vdalabs.com/hacking-web-sockets-all-web-pentest-tools-welcomed/). 2024
[^10]: Konstantinov, A. [*Streamlining Websocket Pentesting with wsrepl*](https://blog.doyensec.com/2023/07/18/streamlining-websocket-pentesting-with-wsrepl.html). 2023
[^11]: PortSwigger. [*WebSocket Turbo Intruder*](https://portswigger.net/bappstore/ba292c5982ea426c95c9d7325d9a1066). 2023
[^12]: Kettle, J. [*Backslash Powered Scanning: hunting unknown vulnerability classes*](https://portswigger.net/research/backslash-powered-scanning-hunting-unknown-vulnerability-classes). PortSwigger. 2016
