# arcmilter [![Go Report Card](https://goreportcard.com/badge/github.com/masa23/arcmilter)](https://goreportcard.com/report/github.com/masa23/arcmilter) [![GoDoc](https://godoc.org/github.com/masa23/arcmilter?status.svg)](https://godoc.org/github.com/masa23/arcmilter) [![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/masa23/arcmilter/main/LICENSE)

* [日本語](README.ja.md)
* [English](README.md)

A milter that performs DKIM and ARC signatures.  
It uses [mmauth](https://github.com/masa23/mmauth) for DKIM and ARC signing and verification, as well as email authentication processing.

I intended to comply with [RFC6376](https://datatracker.ietf.org/doc/html/rfc6376) and [RFC8617](https://datatracker.ietf.org/doc/html/rfc8617), but since it is designed for personal use, thorough testing is needed for actual operation.  
I welcome feedback and pull requests.

## Signing Conditions

* DKIM
  * Sign authenticated SMTP mail or mail from `MyNetworks` when a private key is available for the From domain.
  * Do not sign emails that are already DKIM signed.
* ARC
  * Sign during receipt if there is a private key for the domain in the Rcpt-To field.
  * Do not sign during sending.

## Installation

### Binary Installation

* Please download the binary from the release page.
  * [Release Page](https://github.com/masa23/arcmilter/releases/latest/)

* For CentOS/RHEL, you can install it using the following command:
  ``` bash
  # rpm -ivh arcmilter_*_amd64.rpm
  ```
* For Debian/Ubuntu, you can install it using the following command:
  ``` bash
  # dpkg -i arcmilter_*_amd64.deb
  ```

### Manual Build & Installation

* You need to have an environment with golang installed.
  ``` bash
  # git clone github.com/masa23/arcmilter
  # (cd arcmilter/cmd/arcmilter && go build)

  # install -m 700 arcmilter/cmd/arcmilter/arcmilter /usr/local/bin/
  # install -m 600 arcmilter/cmd/arcmilter/arcmilter.yaml /usr/local/etc/arcmilter.yaml
  # sed -e 's#/usr/bin/arcmilter#/usr/local/bin/arcmilter#' -e '#/etc/arcmilter.yaml#/usr/local/etc/arcmilter/arcmilter.yaml#' \
          arcmilter/misc/files/arcmilterctl.service > /etc/systemd/system/arcmilterctl.service
  # systemctl daemon-reload
  ```

## Configuration

* Configuration File
  ``` bash
  # vi /etc/arcmilter/arcmilter.yaml

  MilterListen:
    Network: unix
    Address: /var/run/arcmilter.sock
    Mode: 0600
    Owner: postfix # Default: execution user
    Group: postfix # Default: execution group
    MaxConnections: 4 # Zero defaults to 64, or 4 when DKIM2 is enabled
  #MilterListen:
  #  Network: tcp
  #  Address: 127.0.0.1:10029
  #  AllowTCPWithSigning: true # Only after isolating the endpoint from other processes
  #  AllowedPeers: # Real Milter TCP peers; omission permits loopback only
  #    - 127.0.0.0/8
  #    - ::1/128
  ControlSocketFile:
    Path: /var/run/arcmilterctl.sock
    Mode: 0600
  PIDFile:
    Path: /var/run/arcmilter.pid
  LogFile:
    Path: /var/log/arcmilter.log
    Mode: 0600
  MyNetworks:
  - 127.0.0.0/8
  - ::1/128
  EnableDKIM2: false # Experimental DKIM2 verification
  DKIM2MaxMessageBytes: 33554432 # Message capture limit for verification and signing, in bytes
  DKIM2Forwarding:
    Mode: disabled # Use separate receive/send processes for forwarding
    # StoreDirectory: /var/lib/arcmilter/dkim2
    # ForwardRecipients: # Required by receive; list forwarding-only aliases with no local deliveries
    #   - forward@example.jp
    MaxAgeSeconds: 86400 # Maximum retention, 24 hours by default; capacity can cause earlier eviction
    MaxStoredBytes: 1073741824 # Shared store capacity, 1 GiB by default
    MaxStoredBytesPerRecipient: 0 # Automatically divide a safe per-alias/forward-source limit
    CacheFailureAction: skip-signing # Skip an additional signature on cache failure; tempfail is also available
    MultipleDeliveries: false # Set true when the MTA delivers multiple copies
    AllowRecipeDisclosure: false # Reject Recipes exposing previous content by default
  Domains:
    # Domain names can be specified using these pattern matching syntax:
    #
    # 1. Exact match: "example.jp" - Matches only this exact domain
    # 2. Wildcard: "*.example.jp" - Matches example.jp and all its subdomains
    # 3. Default: "*" - Used when no other pattern matches
    #
    # Matching priority: Exact match > Wildcard (more specific) > Default
    #
    # You can also specify multiple domains/patterns separated by commas:
    # "list:example.com,sub.example.com,*.example.net"
    #
    "example.jp": # Domain for DKIM signing in From field, and ARC signing in Rcpt-To field
      HeaderCanonicalization: "relaxed" # Header normalization method
      BodyCanonicalization: "relaxed"   # Body normalization method
      Selector: "default"               # Selector
      PrivateKeyFile: "/etc/arcmilter/keys/example.jp.key" # Path to private key
      DKIM: true  # Enable DKIM signing
      DKIM2: false # Enable experimental DKIM2 signing
      # DKIM2Selector: "default" # Defaults to Selector
      ARC: true   # Enable ARC signing
    "example.com": # You can configure multiple domains
      HeaderCanonicalization: "relaxed"
      BodyCanonicalization: "relaxed"
      Selector: "default"
      ARCSelector: "default"
      PrivateKeyFile: "/etc/arcmilter/keys/example.com.key"
      DKIM: true
      ARC: true
  User: mail  # User to run the milter
  Group: mail # Group to run the milter
  ARCSignHeaders: # Headers to sign with ARC (From is required)
    - "DKIM-Signature"
    - "Date"
    - "From"
    - "To"
    - "Message-Id"
  DKIMSignHeaders: # Headers to sign with DKIM
    - "Date"
    - "From"
    - "To"
    - "Reply-To"
    - "Message-ID"
    - "Subject"
  Debug: false
  ```

  The Milter channel is part of the signing-key trust boundary. Prefer a permission-restricted Unix socket. For TCP, restrict `AllowedPeers` to the Postfix/MTA hosts that actually connect to the Milter; omission permits loopback only. `MyNetworks` classifies the SMTP client reported by the MTA and does not authenticate the Milter peer. Never configure `0.0.0.0/0` or `::/0` in `AllowedPeers`. `MaxConnections` bounds concurrent Milter sessions and limits aggregate memory consumed by DKIM2 raw-message buffers.

  To use DKIM, ARC, or DKIM2 signing over TCP Milter, explicitly set `MilterListen.AllowTCPWithSigning: true`. An IP allowlist cannot authenticate another process on the same host; a loopback TCP listener can be used to forge signing requests. Enable TCP signing only when OS firewall rules or network isolation restrict connections to the MTA.

  Use a single YAML document for the configuration. Unknown settings and multiple documents separated by `---` are configuration errors. The configuration must be a regular file owned by root or the startup user and not writable by group or other users. Its read limit is 4 MiB.

  The parent creates the PID file with mode `0600` and holds an exclusive lock until exit. Place the configuration, Milter and control sockets, PID file, and log file in directories owned by root or the startup user and protected from untrusted writes. Existing PID and log files cannot be symbolic or hard links. Set `LogFile.Mode` to `0600` or `0640` so only the owner can write and the group can read when needed.

  Keep each `PrivateKeyFile` as a regular file owned by root or the startup user with mode `0600`. Symbolic or hard links, replaceable parent directories, and key files larger than 1 MiB are rejected.

  `SIGHUP` reloads signing, verification, cache settings, and connection limits. Restart the process to change the Milter Network or Address, Unix socket Mode/Owner/Group, control socket Path/Mode, or PID file Path. A reload containing these changes or an invalid configuration is rejected while the running configuration and child process remain active.

* Enabling DKIM2 (experimental)

  Set `EnableDKIM2: true` to verify DKIM2 on incoming messages. Results are logged and included as `dkim2=...` in `ARC-Authentication-Results` when the message receives an ARC signature.

  Enable outgoing signing with `DKIM2: true` in the `Domains` entry matching the From domain. On an outbound route with forwarding mode disabled, messages from an authenticated SMTP session or `MyNetworks` receive their first `DKIM2-Signature` and `Message-Instance` fields. Signing uses the existing RSA or Ed25519 key in `PrivateKeyFile`. `DKIM2Selector` defaults to `Selector`; if you choose a separate selector, publish the same public key at its `<selector>._domainkey.<domain>` name. DKIM2 uses SHA-256 independently of `HashAlgorithm`. Once a message is selected for initial signing, unexpected existing DKIM2 fields and signature generation or application failures cause a temporary failure rather than an unsigned downgrade. Neither stage of a two-stage `receive`/`send` forwarding setup makes initial signatures: From alone cannot distinguish external mail from local origination after reinjection.

  For internationalized domains, use ASCII A-labels such as `xn--bcher-kva.example` in `Domains` keys and `DKIM2Forwarding.SigningDomain`. DKIM2 maps valid U-labels such as `bücher.example` in SMTP paths and From or To/Cc addresses to A-labels before domain comparisons, and records A-label domains in the signature's `mf=` and `rt=` tags. This conversion leaves local parts, the original message, and the MTA's SMTP envelope unchanged.

  Global `EnableDKIM2` and per-domain `DKIM2` are independent and both default to false. `DKIM2MaxMessageBytes` limits message capture for verification and signing. Zero or omission uses 32 MiB; explicit limits must be between 1 and 33554432 bytes. Messages exceeding the limit skip DKIM2 processing while legacy DKIM/ARC verification and signing otherwise permitted by the normal policy continue. The legacy mmauth parser retains headers separately; also limit header size on the connecting MTA with `header_size_limit` or an equivalent setting.

  This experimental feature implements draft-09. Initial signing is skipped if any envelope recipient is absent from To/Cc, even in a single-recipient transaction, to avoid exposing BCC addresses. Changes to the envelope, body, or signed headers by the MTA or another filter after signing cause verification to fail; arrange for signing after those changes have finished.

* Adding DKIM2 signatures to Postfix alias forwarding

  Run separate `receive` and `send` stages so the original delivery envelope remains distinct from the forwarding envelope. The receive stage saves an original only when its recipient is explicitly listed in `ForwardRecipients`, its recipient domain has `DKIM2: true` (DNS domain matching ignores case), and DKIM2 verification succeeds. The send stage authenticates that saved original and adds a signature with `ForwardChecked` when the signed content is unchanged. For body or signed-header changes, it builds a reconstruction Recipe and uses `ReviseChecked`.

  ```text
  External SMTP -> arcmilter(receive) -> Postfix alias/canonical/SRS processing
                -> dedicated SMTP reinjection -> arcmilter(send) -> destination
  ```

  1. Set `DKIM2Forwarding.Mode: receive` and the shared store path in the receive configuration. Enable `DKIM2: true` in the `Domains` entry matching the incoming recipient domain. List only forwarding-only aliases whose expanded copies all pass through the send Milter and never reach local delivery in `ForwardRecipients`.

     ```yaml
     EnableDKIM2: true
     DKIM2Forwarding:
       Mode: receive
       StoreDirectory: /var/lib/arcmilter/dkim2
       ForwardRecipients:
         - forward@example.jp
       MaxAgeSeconds: 86400
       MaxStoredBytes: 1073741824
       MaxStoredBytesPerRecipient: 0
       CacheFailureAction: skip-signing
     ```

  2. Run the send stage as a separate process with `Mode: send` and the same `StoreDirectory`. Both processes must use the same service user and the signing domain's key and selector configuration. Give each process its own `MilterListen` address, PID file, control socket, and log file. Restrict the send stage's `MyNetworks` to the dedicated SMTP reinjection source.

     ```yaml
     DKIM2Forwarding:
       Mode: send
       StoreDirectory: /var/lib/arcmilter/dkim2
       MaxAgeSeconds: 86400
       MaxStoredBytes: 1073741824
       MaxStoredBytesPerRecipient: 0
       CacheFailureAction: skip-signing
       MultipleDeliveries: false
       AllowRecipeDisclosure: false
       # SigningDomain: example.jp # Select explicitly when the signer is ambiguous
     ```

  3. Have Postfix finish alias/canonical/SRS processing and any content changes, then reinject the message into a dedicated SMTP service using the send Milter. Merely configuring both `smtpd_milters` and `non_smtpd_milters` does not create this sequence. Postfix runs Milters before queueing, so place reinjection at the appropriate point in the existing forwarding route. See the [Postfix Milter documentation](https://www.postfix.org/MILTER_README.html) and [after-queue filter documentation](https://www.postfix.org/FILTER_README.html).

  To add a forwarding signature, the actual MAIL FROM supplied to the send Milter must be within the DKIM2 signing domain, or the null path `<>`. Apply any required SRS or other sender rewrite in the MTA before that stage. Do not rewrite the envelope or signed content after signing. The client address reported to the send Milter must also identify a reinjection source covered by its `MyNetworks`. Set `MultipleDeliveries: true` on the send stage when aliases produce several forwarding copies. This adds the `exploded` flag to declare multiple deliveries. Multiple distinct actual recipients in one SMTP transaction automatically set `exploded`. Use `MultipleDeliveries` to declare forwarding copies split across transactions that the Milter cannot observe.

  Set `DKIM2Forwarding.SigningDomain` on the send stage when the signing domain would otherwise be ambiguous, for example when a null MAIL FROM accompanies several receiving domains. The value is an ASCII DNS name (use A-labels for internationalized domains), is normalized to lowercase, and must match a `Domains` entry with `DKIM2: true`. At runtime it must also be one of the domains in the saved actual receiving recipients. For a non-null MAIL FROM, its domain must equal or be below the selected signing domain. This setting cannot authorize a domain that did not receive the message. Adding a signature to an existing DKIM2 chain requires the matching saved receiving context.

  Originals are saved as private 0600 files, and a random `X-ARCMilter-DKIM2-Context` ID links each message to its saved context. This internal header is removed before sending. `ForwardRecipients` is required in receive mode. Local parts use case-sensitive exact matching, while domains are case-insensitive; use `*@example.com` only for a forwarding-only domain or catch-all. Selected aliases must produce no local deliveries, including through nested aliases or `.forward` expansion, and every copy must pass through the send Milter. The receive Milter runs before Postfix alias expansion and cannot check this condition automatically. Do not list aliases that combine local delivery and forwarding. If one SMTP transaction mixes selected and unselected recipients, the message is not saved. Separate the forwarding-only destination in Postfix when an additional signature is required. An enabled mode requires an absolute `StoreDirectory`. Use a location the service user can create, or prepare a directory owned by that user with mode 0700. Parent directories must be owned by root or the service user and must not be replaceable by other users.

  The store is a short-lived cache. `MaxAgeSeconds` defaults to 86400 seconds (24 hours) when zero or omitted; explicit values must be between 1 and 1209600 seconds (14 days). The lifetime is measured from receipt and is not extended by reads. Expired originals are reclaimed during saves and every minute while the process is running, including when no mail arrives. `MaxStoredBytes` defaults to 1 GiB when zero or omitted and limits the total context-file bytes, including original messages and metadata. Management files such as `.state`, `.lock`, and FIFO indexes need additional space, so provision disk capacity above that limit. Fixed-size records and compaction bound index growth. By default, capacity pressure first removes expired originals and then evicts originals in creation order (FIFO). The lifetime is a maximum, not a minimum retention guarantee: capacity pressure can evict an original earlier. When one original alone exceeds a capacity limit, that save is skipped without evicting existing originals.

  `MaxStoredBytesPerRecipient` limits one listed alias or catch-all pattern. Zero or omission uses the smallest of 256 MiB, the total limit, and the total limit divided by the number of `ForwardRecipients`. A message matching several entries is charged to each. Recipient-quota pressure evicts the oldest originals charged to that quota; total-capacity pressure evicts from the whole cache. Normal saves and eviction reuse accounting and creation-order indexes; interrupted or damaged accounting is rebuilt when necessary. Failed context-header insertion rolls back only the newly created context. Originals remain reusable for retries and multiple copies rather than being removed immediately after signing. The Milter does not track final delivery or completion of every forwarding copy.

  `CacheFailureAction` defaults to `skip-signing`. Capture-limit overflow, insufficient capacity, or storage failures such as a full disk allow receiving to continue without attaching saved-context information. On the send stage, missing, expired, or evicted context skips the additional DKIM2 signature and allows delivery to continue only for a trusted reinjection source. The internal context header and unverifiable DKIM2 fields are removed before delivery. No initial DKIM or DKIM2 signature is made in the dedicated `send` mode, including when the forwarded message has a local From address. Use a separate outbound route with forwarding mode disabled for locally originated mail that needs initial signatures. Unverified mail is never reported as `dkim2=pass`. Capacity pressure or high incoming volume can increase the number of messages sent without a DKIM2 chain. The reason for each skipped signature is logged.

  To require an additional signature, set `CacheFailureAction: tempfail` on both stages. This does not evict unexpired originals for capacity and temporarily fails unavailable storage, missing context, or capture-limit overflow. Match the retention period to the reinjection queue's retry lifetime for this mode. If an external message fails DKIM2 verification at the receive stage, its DKIM2 fields are removed and delivery continues with its actual verification result; the receive stage does not save a forwarding context. Failed re-verification of a saved original at the send stage remains a temporary failure. Both policies still temporarily fail an untrusted reinjection source, malformed or duplicate context values, corrupted originals or unsafe permissions, modified prior DKIM2 fields, changes that cannot be reconstructed, signature-generation failures, and failed Milter operations. Recipes containing `d` or `u` steps carry previous values and are rejected by default to prevent disclosure of redacted data. Set `AllowRecipeDisclosure: true` on the send stage only when previous header values and removed body content may be disclosed to recipients. Copy-only Recipes remain allowed by default. A Recipe exceeding mmauth's parser limits also causes a temporary failure.

  In `receive` mode, messages with DKIM2 fields are verified even when their recipients are unselected or mixed with selected recipients. Unverified chains are removed before delivery. If an unselected message exceeds the capture limit and cannot be verified, its chain is removed and delivery continues even with `CacheFailureAction: tempfail`.

  A forwarding copy with one recipient can be signed even when that destination is absent from the original To/Cc: the signer explicitly supplies that actual recipient as `BCCRecipients`. A copy with multiple recipients temporarily fails when any recipient is absent from To/Cc. If necessary, split forwarding into one-recipient SMTP transactions before reinjection to prevent a signature's `rt=` from revealing another private recipient.

* Generating Private Key
  ``` bash
  # openssl genpkey -algorithm rsa -out /etc/arcmilter/keys/example.jp.key -pkeyopt rsa_keygen_bits:2048
  # chmod 0600 /etc/arcmilter/keys/example.jp.key
  ```

* Generating Public Key
  ``` bash
  # openssl pkey -in /etc/arcmilter/keys/example.jp.key -pubout -out /etc/arcmilter/keys/example.jp.pub
  ```

* Configuring DNS Records
  ``` bash
  # openssl pkey -in /etc/arcmilter/keys/example.jp.pub -pubin -outform DER | openssl base64 -A | tr -d '\n' | fold -w 120 | sed -e 's/^/"/g' -e 's/$/"/g'
  ```

* Example of DNS Record
  ``` zonefile
  <selector>._domainkey IN TXT  ("v=DKIM1; h=sha256; k=rsa; p="
                                 "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxBYDpP2LvLICZKSyzA9noR39zm8FGi2F2f83zldwvxyqaKgnmJ0sNsx86zfcbF1JosTLVXdyPE/u"
                                 "eaILXQ4CLK065m39NTv+UzIyg1Jsp9KeOnfia1/Bn3dYjLV/Ix84SwMtP15k7zY+2l4or38/uyhTGFpLF/bET2LlP8eBxXHtg6t1A798qR4/ZGVauKCDkbye"
                                 "YHjGJ6DktYmjk9Cv2DC7x3SYekHjGQMamswHZl7kYlKgiZKDVevXWcd5IFWONOObzZdgO2boDf/wrqS1eA0BFstbTRdENj1tH573pku3vrOPfJF123E8h6ii"
                                 "86jISHmtWg500WPJ8LB8Gzc7CQIDAQAB")
  ```

## Start

``` bash
# systemctl start arcmilter.service
```

## Example Configuration for Postfix

``` bash
# vi /etc/postfix/main.cf

For TCP
smtpd_milters = inet:127.0.0.1:10029

For UNIX socket
smtpd_milters = unix:/var/run/arcmilter.sock
```

## Tests

```bash
go test -race -count=1 -timeout=120s ./...
go vet ./...
sh scripts/test-coverage.sh
```

Integration tests use Unix sockets and subprocesses. They also exercise the child readiness timeout during configuration reloads, so a run takes tens of seconds. The `-race` flag also instruments the executable built for integration tests.

Coverage uses `go build -cover` and `GOCOVERDIR` to collect counters from subprocesses that exit normally. `coverage/unit.txt` and `coverage/integration.txt` contain separate reports; `coverage/coverage.txt` and `coverage/coverage.html` contain the combined report with duplicate functions merged. Unwritten counters from processes killed with SIGKILL cannot be collected. Pass an output directory as the script's first argument to change the destination.

## Thanks!

The following external libraries are used.

  * [d--j/go-milter](https://github.com/d--j/go-milter)
  * [masa23/mmauth](https://github.com/masa23/mmauth)
  * [k0kubun/pp](https://github.com/k0kubun/pp)
  * [yaml.v3](https://gopkg.in/yaml.v3)
