# arcmilter [![Go Report Card](https://goreportcard.com/badge/github.com/masa23/arcmilter)](https://goreportcard.com/report/github.com/masa23/arcmilter) [![GoDoc](https://godoc.org/github.com/masa23/arcmilter?status.svg)](https://godoc.org/github.com/masa23/arcmilter) [![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/masa23/arcmilter/main/LICENSE)

DKIM署名およびARCの署名を行うmilterです。  
[RFC6376](https://datatracker.ietf.org/doc/html/rfc6376)、[RFC8617](https://datatracker.ietf.org/doc/html/rfc8617)に準拠させたつもりですが、  
個人での利用を想定しているため、実際の運用には十分なテストが必要です。  
フィードバックやプルリクエストをお待ちしています。

## 署名条件

* DKIM
  * Fromのドメインの秘密鍵があれば署名する
  * すでにDKIM署名済のメールは署名しない
* ARC
  * Rcpt-Toのドメインの秘密鍵があれば受信時に署名する
  * 送信時には署名しない

## インストール

### バイナリインストール

* リリースページからバイナリをダウンロードしてください。
  * [リリースページ](https://github.com/masa23/arcmilter/releases/latest/)

* CentOS/RHELの場合は、以下のコマンドでインストールできます。
  ``` bash
  # rpm -ivh arcmilter_*_amd64.rpm
  ```
* Debian/Ubuntuの場合は、以下のコマンドでインストールできます。
  ``` bash
  # dpkg -i arcmilter_*_amd64.deb
  ```

### 手動ビルド＆インストール

* golangが入ってる環境が必要です。
  ``` bash
  # git clone github.com/masa23/arcmilter
  # (cd arcmilter/cmd/arcmilter && go build)

  # install -m 700 arcmilter/cmd/arcmilter/arcmilter /usr/local/bin/
  # install -m 600 arcmilter/cmd/arcmilter/arcmilter.yaml /usr/local/etc/arcmilter.yaml
  # sed -e 's#/usr/bin/arcmilter#/usr/local/bin/arcmilter#' -e '#/etc/arcmilter.yaml#/usr/local/etc/arcmilter/arcmilter.yaml#' \
          arcmilter/misc/files/arcmilterctl.service > /etc/systemd/system/arcmilterctl.service
  # systemctl daemon-reload
  ```

## 設定

* 設定ファイル
  ``` bash
  # vi /etc/arcmilter/arcmilter.yaml

  MilterListen:
    Network: tcp
    Address: 127.0.0.1:10029
  #MilterListen:
  #  Network: unix
  #  Address: /var/run/arcmilter.sock
  #  Mode: 0600
  #  Owner: postfix // デフォルト: 実行ユーザ
  #  Group: postfix // デフォルト: 実行グループ
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
    "example.jp": // DKIM署名するFromのドメイン、ARC署名するRcpt-Toのドメイン
      HeaderCanonicalization: "relaxed" // ヘッダの正規化方法
      BodyCanonicalization: "relaxed"   // ボディの正規化方法
      Selector: "default"               // セレクタ
      PrivateKeyFile: "/etc/arcmilter/keys/example.jp.key" // 秘密鍵のパス
      DKIM: true  // DKIM署名を行うか
      ARC: true   // ARC署名を行うか
    "example.com": // 複数のドメインを設定可能
      HeaderBodyCanonicalization: "relaxed"
      BodyCanonicalization: "relaxed"
      Selector: "default"
      ARCSelector: "default"
      PrivateKeyFile: "/etc/arcmilter/keys/example.com.key"
      DKIM: true
      ARC: true
  User: mail  // milterの子プロセス実行ユーザ    デフォルト: 実行ユーザ
  Group: mail // milterの子プロセス実行グループ  デフォルト: 実行グループ
  ARCSignHeaders: // ARC署名するヘッダ
    - "DKIM-Signature"
    - "Date"
    - "From"
    - "To"
    - "Message-Id"
  DKIMSignHeaders: // DKIM署名するヘッダ
    - "Date"
    - "From"
    - "To"
    - "Reply-To"
    - "Message-ID"
    - "Subject"
  Debug: false
  ```

* 秘密鍵の生成
  ``` bash
  # openssl genpkey -algorithm rsa -out /etc/arcmilter/keys/example.jp.key -pkeyopt rsa_keygen_bits:2048
  ```

* 公開鍵の生成
  ``` bash
  # openssl pkey -in /etc/arcmilter/keys/example.jp.key -pubout -out /etc/arcmilter/keys/example.jp.pub
  ```

* DNSレコードの設定
  ``` bash
  # openssl pkey -in /etc/arcmilter/keys/example.jp.pub -pubin -outform DER | openssl base64 -A | tr -d '\n' | fold -w 120 | sed -e 's/^/"/g' -e 's/$/"/g'
  ```

* DNSレコードの例
  ``` zonefile
  <selector>._domainkey IN TXT  ("v=DKIM1; h=sha256; k=rsa; p="
                                 "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxBYDpP2LvLICZKSyzA9noR39zm8FGi2F2f83zldwvxyqaKgnmJ0sNsx86zfcbF1JosTLVXdyPE/u"
                                 "eaILXQ4CLK065m39NTv+UzIyg1Jsp9KeOnfia1/Bn3dYjLV/Ix84SwMtP15k7zY+2l4or38/uyhTGFpLF/bET2LlP8eBxXHtg6t1A798qR4/ZGVauKCDkbye"
                                 "YHjGJ6DktYmjk9Cv2DC7x3SYekHjGQMamswHZl7kYlKgiZKDVevXWcd5IFWONOObzZdgO2boDf/wrqS1eA0BFstbTRdENj1tH573pku3vrOPfJF123E8h6ii"
                                 "86jISHmtWg500WPJ8LB8Gzc7CQIDAQAB")
  ```

## 起動

``` bash
# systemctl start arcmilter.service
```

## Postfixの設定例

``` bash
# vi /etc/postfix/main.cf

TCPの場合
smtpd_milters = inet:127.0.0.1:10029

UNIXソケットの場合
smtpd_milters = unix:/var/run/arcmilter.sock
```

## Thanks!

以下の外部ライブラリを使用しています。

  * [d--j/go-milter](https://github.com/d--j/go-milter)
  * [k0kubun/pp](https://github.com/k0kubun/pp)
  * [wttw/spf](https://github.com/wttw/spf)
  * [yaml.v3](https://gopkg.in/yaml.v3)

以下のライブラリは制作に当たって参考にさせていただきました。

  * [emersion/go-msgauth](https://github.com/emersion/go-msgauth/)
