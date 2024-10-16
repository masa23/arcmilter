# arcmilter [![Go Report Card](https://goreportcard.com/badge/github.com/masa23/arcmilter)](https://goreportcard.com/report/github.com/masa23/arcmilter) [![GoDoc](https://godoc.org/github.com/masa23/arcmilter?status.svg)](https://godoc.org/github.com/masa23/arcmilter) [![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/masa23/arcmilter/main/LICENSE)

* [日本語](README.ja.md)
* [English](README.md)

A milter that performs DKIM and ARC signatures.  
I intended to comply with [RFC6376](https://datatracker.ietf.org/doc/html/rfc6376) and [RFC8617](https://datatracker.ietf.org/doc/html/rfc8617), but since it is designed for personal use, thorough testing is needed for actual operation.  
I welcome feedback and pull requests.

## Signing Conditions

* DKIM
  * Sign if there is a private key for the domain in the From field.
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
    Network: tcp
    Address: 127.0.0.1:10029
  #MilterListen:
  #  Network: unix
  #  Address: /var/run/arcmilter.sock
  #  Mode: 0600
  #  Owner: postfix // Default: Execution user
  #  Group: postfix // Default: Execution group
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
  Domains:
    "example.jp": // Domain for DKIM signing in From field, and ARC signing in Rcpt-To field
      HeaderCanonicalization: "relaxed" // Header normalization method
      BodyCanonicalization: "relaxed"   // Body normalization method
      Selector: "default"               // Selector
      PrivateKeyFile: "/etc/arcmilter/keys/example.jp.key" // Path to private key
      DKIM: true  // Enable DKIM signing
      ARC: true   // Enable ARC signing
    "example.com": // You can configure multiple domains
      HeaderBodyCanonicalization: "relaxed"
      BodyCanonicalization: "relaxed"
      Selector: "default"
      ARCSelector: "default"
      PrivateKeyFile: "/etc/arcmilter/keys/example.com.key"
      DKIM: true
      ARC: true
  User: mail  // User to run the milter
  Group: mail // Group to run the milter
  ARCSignHeaders: // Headers to sign with ARC
    - "DKIM-Signature"
    - "Date"
    - "From"
    - "To"
    - "Message-Id"
  DKIMSignHeaders: // Headers to sign with DKIM
    - "Date"
    - "From"
    - "To"
    - "Reply-To"
    - "Message-ID"
    - "Subject"
  Debug: false
  ```

* Generating Private Key
  ``` bash
  # openssl genpkey -algorithm rsa -out /etc/arcmilter/keys/example.jp.key -pkeyopt rsa_keygen_bits:2048
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

## Thanks!

The following external libraries are used.

  * [d--j/go-milter](https://github.com/d--j/go-milter)
  * [k0kubun/pp](https://github.com/k0kubun/pp)
  * [wttw/spf](https://github.com/wttw/spf)
  * [yaml.v3](https://gopkg.in/yaml.v3)

The following library was used as a reference during production.

  * [emersion/go-msgauth](https://github.com/emersion/go-msgauth/)
