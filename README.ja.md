# arcmilter [![Go Report Card](https://goreportcard.com/badge/github.com/masa23/arcmilter)](https://goreportcard.com/report/github.com/masa23/arcmilter) [![GoDoc](https://godoc.org/github.com/masa23/arcmilter?status.svg)](https://godoc.org/github.com/masa23/arcmilter) [![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/masa23/arcmilter/main/LICENSE)

* [日本語](README.ja.md)
* [English](README.md)

DKIM署名およびARCの署名を行うmilterです。  
DKIM・ARCの署名と検証、およびメール認証処理には [mmauth](https://github.com/masa23/mmauth) を使用しています。

[RFC6376](https://datatracker.ietf.org/doc/html/rfc6376)、[RFC8617](https://datatracker.ietf.org/doc/html/rfc8617)に準拠させたつもりですが、  
個人での利用を想定しているため、実際の運用には十分なテストが必要です。  
フィードバックやプルリクエストをお待ちしています。

## 署名条件

* DKIM
  * SMTP認証済み、または `MyNetworks` 内からのメールで、Fromのドメインの秘密鍵があれば署名する
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
    Network: unix
    Address: /var/run/arcmilter.sock
    Mode: 0600
    Owner: postfix # デフォルト: 実行ユーザ
    Group: postfix # デフォルト: 実行グループ
    MaxConnections: 4 # 0は通常64、DKIM2有効時4
  #MilterListen:
  #  Network: tcp
  #  Address: 127.0.0.1:10029
  #  AllowTCPWithSigning: true # OS側でMTA以外の接続を遮断した場合だけ
  #  AllowedPeers: # 実際のMilter TCP接続元。省略時はloopbackのみ
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
  EnableDKIM2: false # DKIM2受信検証（実験的）
  DKIM2MaxMessageBytes: 33554432 # 検証・署名の原文保持上限（バイト）
  DKIM2Forwarding:
    Mode: disabled # 転送時はreceive/sendを別プロセスで使用
    # StoreDirectory: /var/lib/arcmilter/dkim2
    # ForwardRecipients: # receiveでは必須。ローカル配送を含まない転送専用aliasだけを列挙
    #   - forward@example.jp
    MaxAgeSeconds: 86400 # 原文の最大保持期間（既定24時間。容量不足では期限前にも回収）
    MaxStoredBytes: 1073741824 # 保存領域の合計上限（既定1 GiB）
    MaxStoredBytesPerRecipient: 0 # alias・転送元ごとの上限を全体容量と対象数から自動配分
    CacheFailureAction: skip-signing # 保存不能・欠落時は追加署名を省略。tempfailも指定可能
    MultipleDeliveries: false # 複数コピーを配送する運用ではtrue
    AllowRecipeDisclosure: false # 変更前の内容を開示するRecipeは既定拒否
  Domains:
    # ドメイン名は以下のパターンマッチング構文で指定できます：
    #
    # 1. 完全一致: "example.jp" - 完全一致するドメインのみ
    # 2. ワイルドカード: "*.example.jp" - example.jp およびそのサブドメインにマッチ
    # 3. デフォルト: "*" - どのパターンにもマッチしない場合に使用
    #
    # マッチングの優先順位: 完全一致 > ワイルドカード（より具体的なもの） > デフォルト
    #
    # 複数のドメイン・パターンをカンマ区切りで一括指定することもできます：
    # "list:example.com,sub.example.com,*.example.net"
    #
    "example.jp": # DKIM署名するFromのドメイン、ARC署名するRcpt-Toのドメイン
      HeaderCanonicalization: "relaxed" # ヘッダの正規化方法
      BodyCanonicalization: "relaxed"   # ボディの正規化方法
      Selector: "default"               # セレクタ
      PrivateKeyFile: "/etc/arcmilter/keys/example.jp.key" # 秘密鍵のパス
      DKIM: true  # DKIM署名を行うか
      DKIM2: false # DKIM2送信署名を行うか（実験的）
      # DKIM2Selector: "default" # 省略時はSelectorを使用
      ARC: true   # ARC署名を行うか
    "example.com": # 複数のドメインを設定可能
      HeaderCanonicalization: "relaxed"
      BodyCanonicalization: "relaxed"
      Selector: "default"
      ARCSelector: "default"
      PrivateKeyFile: "/etc/arcmilter/keys/example.com.key"
      DKIM: true
      ARC: true
  User: mail  # milterの子プロセス実行ユーザ    デフォルト: 実行ユーザ
  Group: mail # milterの子プロセス実行グループ  デフォルト: 実行グループ
  ARCSignHeaders: # ARC署名するヘッダ（From は必須）
    - "DKIM-Signature"
    - "Date"
    - "From"
    - "To"
    - "Message-Id"
  DKIMSignHeaders: # DKIM署名するヘッダ
    - "Date"
    - "From"
    - "To"
    - "Reply-To"
    - "Message-ID"
    - "Subject"
  Debug: false
  ```

  Milterの接続経路は署名鍵の信頼境界です。権限制限したUnix socketを推奨します。TCPの場合、`AllowedPeers`はMilterへ実際に接続するPostfix/MTAホストだけに限定してください。省略時はloopbackだけを許可します。`MyNetworks`はMTAが通知するSMTPクライアントの判定用であり、Milter peerの認証には使用しません。`0.0.0.0/0`や`::/0`を`AllowedPeers`へ設定しないでください。`MaxConnections`は同時Milter接続を制限し、DKIM2の原文バッファを使ったメモリ枯渇を抑止します。

  DKIM・ARC・DKIM2の署名をTCP Milterで行う場合は、`MilterListen.AllowTCPWithSigning: true` の明示が必要です。IP制限だけでは同じホストの別プロセスを認証できず、loopback TCPを開くと署名要求を偽装され得ます。TCP署名はOSのファイアウォールやネットワーク分離で接続元をMTAに限定した構成でのみ有効にしてください。

  設定ファイルは単一のYAML文書で記述してください。未知の設定項目や、`---` で区切った複数文書は設定エラーになります。設定ファイルはrootまたは起動ユーザーが所有し、グループ・その他のユーザーから書き換えられない通常ファイルにしてください。読み込み上限は4 MiBです。

  PIDファイルは親プロセスが権限`0600`で作成し、排他ロックを終了まで保持します。設定ファイル、Milter・制御ソケット、PID・ログファイルは、rootまたは起動ユーザーが所有し、第三者が書き換えられないディレクトリ内に配置してください。既存のPID・ログファイルにシンボリックリンクやハードリンクは使用できません。`LogFile.Mode` は `0600` または `0640` など、所有者の書き込みと必要に応じたグループ読み取りだけを許可してください。

  `PrivateKeyFile` はrootまたは起動ユーザー所有の通常ファイルとし、権限`0600`で保管してください。シンボリックリンク・ハードリンク、第三者が差し替え可能な親ディレクトリ、1 MiBを超える鍵ファイルは読み込みを拒否します。

  `SIGHUP` では署名・検証・キャッシュ設定や接続数制限を再読み込みできます。MilterのNetwork・Address、Unix socketのMode・Owner・Group、制御ソケットのPath・Mode、PIDファイルのPathを変更する場合はプロセスを再起動してください。これらの変更や不正な設定の再読み込みは拒否し、稼働中の設定と子プロセスを維持します。

* DKIM2の有効化（実験的）

  `EnableDKIM2: true` で受信メールのDKIM2検証を有効にします。検証結果はログに出力され、ARC署名対象のメールでは `ARC-Authentication-Results` に `dkim2=...` として含まれます。

  送信署名は、Fromドメインに対応する `Domains` の `DKIM2: true` で有効にします。転送モードを無効にした送信経路では、SMTP認証済み、または `MyNetworks` 内からのメールに初回の `DKIM2-Signature` と `Message-Instance` を追加します。既存の `PrivateKeyFile` のRSA・Ed25519鍵を使用し、`DKIM2Selector` の省略時は `Selector` を使用します。別のセレクタを指定する場合は、その `<selector>._domainkey.<domain>` にも同じ公開鍵を登録してください。DKIM2のハッシュは `HashAlgorithm` と独立したSHA-256です。署名対象と判定した後に既存DKIM2フィールドが見つかった場合や、署名生成・適用に失敗した場合は、未署名配送へダウングレードせず一時失敗にします。二段構成の `receive`・`send` では、外部メールとローカル発信メールをFromだけでは区別できないため、初回署名を行いません。

  国際化ドメインを使う場合、`Domains` のキーと `DKIM2Forwarding.SigningDomain` にはASCIIのA-label（例: `xn--bcher-kva.example`）を指定してください。DKIM2では、SMTPパスやFrom・To/Ccの有効なU-label（例: `bücher.example`）をA-labelへ変換してドメインを照合し、署名の `mf=`・`rt=` にもA-labelを記録します。この変換でローカル部やメール原文、MTAのSMTPエンベロープは変更しません。

  全体の `EnableDKIM2` とドメインごとの `DKIM2` は独立した設定で、省略時は両方無効です。`DKIM2MaxMessageBytes` は検証・署名用の原文保持上限で、0または省略時は32 MiB、指定できる範囲は1〜33554432バイトです。上限を超えたメールのDKIM2処理を省略しても、従来のDKIM・ARC検証と、通常の署名条件を満たす署名処理は継続します。従来のmmauth解析器はヘッダを別途保持するため、Milterに接続するMTA側でも `header_size_limit` などでヘッダ容量を制限してください。

  DKIM2はdraft-09に基づく実験的な機能です。初回署名では、BCC宛先の公開を防ぐため、To/Ccにないエンベロープ宛先を含むメールは、宛先が1件でも署名を省略します。署名後にMTAや他のフィルタがエンベロープ、本文、署名対象のヘッダを変更すると検証に失敗するため、変更が完了した段階で署名する構成で使用してください。

* Postfixのalias転送でDKIM2署名を追加する

  受信時と転送後のSMTPエンベロープを区別するため、`receive` と `send` の二段で動かします。受信側は、`ForwardRecipients` に明示したPostfixのalias・転送元宛先で、宛先ドメインの `DKIM2: true` が設定され（ドメイン名の大小文字は区別しません）、DKIM2検証に成功したメールだけの原文・エンベロープをサーバー内に保存します。転送後は保存原文を再検証して、本文・署名対象ヘッダに変更がなければ `ForwardChecked`、変更があれば復元用Recipeを生成して `ReviseChecked` で署名を追加します。

  ```text
  外部SMTP → arcmilter(receive) → Postfixのalias・canonical・SRS等
          → 専用SMTP再投入 → arcmilter(send) → 転送先
  ```

  1. 受信側の設定で `DKIM2Forwarding.Mode: receive` と共有保存先を指定し、受信宛先に対応する `Domains` の `DKIM2: true` を有効にします。`ForwardRecipients` には、展開後の全コピーが送信側Milterを通り、ローカル配送を含まない転送専用aliasだけを指定します。

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

  2. 別プロセスの送信側では `Mode: send` と同じ `StoreDirectory` を指定します。両プロセスを同じサービスユーザーで実行し、署名ドメインの鍵・セレクタ設定を共有してください。`MilterListen`、PIDファイル、制御ソケット、ログファイルにはそれぞれ別のパスまたはアドレスを使用します。送信側の `MyNetworks` は、専用SMTP再投入の接続元だけに限定してください。

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
       # SigningDomain: example.jp # null送信元などで署名ドメインの選択が曖昧な場合
     ```

  3. Postfix側でalias/canonical/SRS等の変更を終え、転送後の送信元・宛先とメール内容が確定した段階で、送信側Milterを使う専用SMTPサービスへ再投入します。`smtpd_milters` と `non_smtpd_milters` を並べるだけではこの二段構成にはなりません。PostfixのMilterはキュー投入前に動作するため、既存の転送経路に合わせて再投入の位置を設定してください。[PostfixのMilter説明](https://www.postfix.org/MILTER_README.html)と[キュー投入後フィルタの説明](https://www.postfix.org/FILTER_README.html)も参照してください。

  追加署名を行う場合、送信側Milterが受け取る実際のMAIL FROMは、DKIM2署名ドメイン配下のアドレス、またはnull送信元 `<>` である必要があります。必要なSRS等の書換えはMTA側で行い、署名後は送信元・宛先・署名対象内容を変更しない構成にしてください。Milterに通知される接続元も、送信側の `MyNetworks` に含まれる再投入元として扱われる必要があります。aliasが複数の転送コピーを作る運用では、送信側の `MultipleDeliveries: true` を明示してください。追加署名に `exploded` フラグを付け、複数配送であることを宣言します。同じSMTPトランザクションで異なる実宛先が複数ある場合は、自動で `exploded` を付けます。`MultipleDeliveries` は、Milterから見えない別トランザクションへの転送コピーの分割を申告するための設定です。

  `MAIL FROM <>` で複数の受信ドメインがある場合など、署名ドメインを一意に選べないときは、送信側の `DKIM2Forwarding.SigningDomain` を指定してください。値は小文字へ正規化するASCIIのDNS名（国際化ドメインはA-label）で、`Domains` の `DKIM2: true` に一致する必要があります。実行時にも、そのドメインが保存した実受信宛先のドメイン群に含まれることを確認します。非nullのMAIL FROMでは、送信元のドメインが指定した署名ドメイン自身か、その配下である必要があります。受信していない別ドメインの鍵を選ぶ用途には使えません。既存DKIM2署名への追加署名には、対応する受信段の保存情報が必要です。

  受信原文は共有保存先に0600のファイルとして保持し、メールには乱数IDの `X-ARCMilter-DKIM2-Context` を付けて対応付けます。この内部ヘッダは送信前に除去します。`receive` では `ForwardRecipients` が必須です。ローカル部は大文字・小文字を区別する完全一致で、ドメインは大小文字を区別しません。転送専用ドメインやcatch-allは `*@example.jp` と指定できます。対象aliasは、ネストしたaliasや `.forward` の展開も含めてローカル配送を作らず、全コピーが送信側Milterを通る必要があります。受信側MilterはPostfixのalias展開前に動作するため、この条件を自動では判定できません。ローカル配送を併用するaliasは `ForwardRecipients` に指定しないでください。同じSMTPトランザクションに対象宛先と対象外宛先が混在する場合、そのメールは保存しません。追加署名が必要ならPostfix側で転送専用の宛先を分けてください。`StoreDirectory` は有効時に必須の絶対パスです。サービスユーザーが作成できる場所を指定するか、あらかじめ同ユーザー所有・0700のディレクトリを用意してください。親ディレクトリもrootまたはサービスユーザーが所有し、第三者が置換できない権限にしてください。

  保存先は短期キャッシュとして扱います。`MaxAgeSeconds` は0または省略時に86400秒（24時間）、指定範囲は1〜1209600秒（14日）で、受信時刻からの最大保持期間です。読込で期限は延長しません。期限切れ原文は保存時に回収し、稼働中は無通信でも1分周期で回収します。`MaxStoredBytes` は0または省略時に1 GiBで、原文とメタデータを含むcontextファイルの合計に適用します。`.state`・`.lock`・FIFO索引などの管理領域は別途必要なため、保存先には上限より余裕のあるディスク容量を確保してください。索引は固定長レコードと圧縮で膨張を抑えます。既定では容量不足になると、期限切れ原文を先に回収し、それでも足りなければ保存時刻の古い順（FIFO）に削除します。24時間は最低保持保証ではなく、容量不足では期限前でも削除されます。1通だけで容量上限を超える場合は既存原文を削除せず、その原文の保存を省略します。

  `MaxStoredBytesPerRecipient` はalias・転送元1件（またはcatch-allパターン）ごとの上限です。0または省略時は、256 MiB、全体上限、全体上限を`ForwardRecipients`数で割った値のうち最小を使います。複数宛先に一致するメールは各上限へ課金します。宛先別の容量不足では、その上限を消費する原文から古い順に回収し、全体の容量不足では全体から回収します。通常の保存・回収は容量管理情報と保存順索引を再利用し、中断や管理情報の破損からの復旧時に再構築します。コンテキストヘッダの挿入に失敗した保存分は取り消します。キャッシュは再送・複数コピーから再利用でき、署名直後には削除しません。Milterは最終配送完了や全コピーの処理完了を追跡しません。

  `CacheFailureAction` は既定で `skip-signing` です。原文保持上限超過、容量不足、ディスク満杯などの保存不能時は保存情報を付けずに受信を継続します。送信側も、信頼された再投入元からの入力に限り、保存情報の欠落・期限切れ・回収済みの場合は追加DKIM2署名を省略して配送を継続します。内部contextヘッダと検証できない既存DKIM2フィールドは配送前に除去します。専用の `send` モードでは、転送メールのFromがローカルドメインでも初回DKIM・DKIM2署名を行いません。ローカル発信メールの初回署名には転送モードを無効にした別の送信経路を使用してください。未検証を `dkim2=pass` と扱うことはありません。容量逼迫や大量流入時には、DKIM2チェーンなしで配送するメールが増える可能性があります。ログに署名省略理由を記録します。

  追加署名を必須にする場合は、受信側・送信側の両方で `CacheFailureAction: tempfail` を指定してください。期限前の原文を容量確保のために削除せず、保存不能・欠落・原文保持上限超過を一時失敗にします。この運用では、原文の保持期間を再投入キューの再送期間に合わせる必要があります。受信段で外部メールのDKIM2検証が成功しない場合はcontextを保存せず、その検証結果を維持して配送を継続します。送信段で保存済み原文の再検証に失敗した場合は一時失敗です。どちらの設定でも、信頼された再投入元以外からの入力、不正・重複context、保存原文の破損や不正な権限、既存DKIM2フィールドの改変、復元できない変更、署名生成・Milter操作の失敗は一時失敗です。Fromや本文の変更も復元用Recipeで扱えますが、変更前の値を格納する `d` または `u` ステップを含むRecipeは、機密情報の再開示を防ぐため既定で一時失敗にします。変更前のヘッダ値・削除本文を転送先へ開示してよい運用に限り、送信側で `AllowRecipeDisclosure: true` を明示してください。`copy` だけの非開示Recipeは既定でも使用できます。Recipeがmmauthの解析上限を超える場合も一時失敗となります。

  `receive` は `ForwardRecipients` 対象外や対象・対象外が混在するメールでも、DKIM2フィールドがあれば検証します。未検証チェーンは配送前に除去し、対象外のメールで原文保持上限を超えて検証できない場合も、`CacheFailureAction: tempfail` に関係なくチェーンを除去して配送します。

  転送コピーが1宛先なら、その実宛先を `BCCRecipients` に明示して署名できるため、元のTo/Ccに転送先が載っている必要はありません。複数宛先のコピーでTo/Ccにない宛先が混在すると一時失敗となるため、必要ならPostfix側で1宛先ずつに分けて再投入してください。これにより、追加署名の `rt=` から別の非公開宛先が漏れることを防ぎます。

* 秘密鍵の生成
  ``` bash
  # openssl genpkey -algorithm rsa -out /etc/arcmilter/keys/example.jp.key -pkeyopt rsa_keygen_bits:2048
  # chmod 0600 /etc/arcmilter/keys/example.jp.key
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

## テスト

```bash
go test -race -count=1 -timeout=120s ./...
go vet ./...
sh scripts/test-coverage.sh
```

結合テストではUNIXソケットと子プロセスを使用します。設定再読み込みの準備完了タイムアウトも検証するため、実行には数十秒かかります。`-race` は結合テスト用の実行ファイルにも適用されます。

カバレッジ計測では `go build -cover` と `GOCOVERDIR` を使い、正常終了した子プロセスの実行分も回収します。`coverage/unit.txt`、`coverage/integration.txt` にそれぞれの結果、`coverage/coverage.txt` と `coverage/coverage.html` に重複を除いて統合した結果を出力します。SIGKILLで強制終了したプロセスの未出力カウンターは回収できません。出力先はスクリプトの第1引数で変更できます。

## Thanks!

以下の外部ライブラリを使用しています。

  * [d--j/go-milter](https://github.com/d--j/go-milter)
  * [masa23/mmauth](https://github.com/masa23/mmauth)
  * [k0kubun/pp](https://github.com/k0kubun/pp)
  * [yaml.v3](https://gopkg.in/yaml.v3)
