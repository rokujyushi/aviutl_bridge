# bridge.dll ドキュメント

このディレクトリには、bridge.dll の技術ドキュメントが含まれています。

## ドキュメント一覧

### [shared_memory.md](shared_memory.md)
共有メモリアクセスに関する詳細な技術ドキュメントです。

**内容:**
- 共有メモリの仕組みとアーキテクチャ
- File Mapping Object の使用方法
- データ構造の詳細（ヘッダー、ピクセルデータ）
- 外部プログラムからのアクセス手順
- メモリアクセスモード（読み取り/書き込み/直接）
- 通信プロトコルの詳細
- プロセス管理とライフサイクル
- パフォーマンス最適化のヒント
- トラブルシューティング

**対象読者:**
- bridge.dll を使用する外部プログラムを開発する方
- bridge.dll の内部実装を理解したい方
- Windows API（File Mapping）について学びたい方

### [examples.md](examples.md)
bridge.dll を使用した外部プログラムの実装例集です。

**内容:**
- 基本的な例（エコー、カウンター）
- 画像処理の例（グレースケール、明るさ調整、ぼかし）
- 高度な例（外部ライブラリの使用、直接モードの活用、JSON パラメータ）
- エラーハンドリングの例
- パフォーマンス測定

**対象読者:**
- 実際にコードを書いて bridge.dll を活用したい方
- 具体的な実装例を見ながら学びたい方
- ベストプラクティスを知りたい方

## クイックスタート

### 1. 基本を理解する

まず [README.md](../README.md) を読んで、bridge.dll の基本的な使い方を理解してください。

### 2. 共有メモリの仕組みを学ぶ

[shared_memory.md](shared_memory.md) で共有メモリアクセスの詳細を学びます。特に以下のセクションが重要です：

- アーキテクチャ
- データ構造の詳細
- 外部プログラムからの共有メモリアクセス

### 3. 実装例を試す

[examples.md](examples.md) の例を参考に、自分のプログラムを作成します。まずは簡単な例から始めることをお勧めします：

1. **例1: エコープログラム** - 基本的な入出力を理解
2. **例3: グレースケール変換** - 共有メモリを使った画像処理の基本
3. **例4: 明るさ調整** - パラメータを受け取る方法
4. **例7: 直接モードの活用** - パフォーマンス最適化

## よくある質問

### Q: 環境変数 `BRIDGE_FMO` が取得できません

A: Lua から `bridge.call()` を呼び出す際、第3引数にモード（"r", "w", "rw" など）を指定する必要があります。モードを指定しない場合、共有メモリは使用されません。

```lua
-- NG: モードなし
local result = require("bridge").call("program.exe", "data");

-- OK: モードあり
local result = require("bridge").call("program.exe", "data", "rw");
```

### Q: ピクセルデータの形式は？

A: BGRA 形式です。各ピクセルは 4 バイト（Blue, Green, Red, Alpha）で、`obj.getpixeldata()` と同じ形式です。詳細は [shared_memory.md](shared_memory.md#ピクセルデータ構造体pixel) を参照してください。

### Q: 外部プログラムを何度も呼び出すとき、毎回起動されますか？

A: いいえ。bridge.dll は外部プログラムのプロセスを管理しており、同じ実行ファイルパスであればプロセスを再利用します。外部プログラムでループを実装すれば、起動コストを削減できます。詳細は [shared_memory.md](shared_memory.md#プロセス管理) を参照してください。

### Q: 処理が遅いのですが、どうすれば高速化できますか？

A: いくつかの方法があります：

1. **直接モード（"p"）を使用**: `obj.getpixeldata()` / `obj.putpixeldata()` の呼び出し回数を減らす
2. **プロセスを再利用**: 外部プログラムでループを実装する
3. **必要なモードのみ指定**: 読み取り専用なら "r" のみ、書き込み専用なら "w" のみ

詳細は [shared_memory.md](shared_memory.md#パフォーマンスの考慮事項) と [examples.md](examples.md#例7-直接モードpの活用) を参照してください。

### Q: エラーメッセージをデバッグ出力に表示したい

A: Windows API の `OutputDebugStringA()` を使用してください。DebugView などのツールで出力を確認できます。

```c
#include <windows.h>

OutputDebugStringA("Debug message\n");
```

### Q: 画像サイズが動的に変わる場合の対処法は？

A: 共有メモリは拡張編集の最大画像サイズで初期化されます。ヘッダーの `width` と `height` フィールドに実際の画像サイズが設定されるので、これを使用してください。

```c
struct share_mem_header *h = (struct share_mem_header *)view;
int actual_width = h->width;
int actual_height = h->height;
```

## リソース

### ソースコード
- [src/bridge.h](../src/bridge.h) - 共有メモリのヘッダー定義
- [src/bridge.c](../src/bridge.c) - 共有メモリの実装
- [src/process.c](../src/process.c) - プロセス管理の実装
- [src/luamain.c](../src/luamain.c) - Lua インターフェース

### Windows API リファレンス
- [File Mapping (Microsoft Docs)](https://docs.microsoft.com/en-us/windows/win32/memory/file-mapping)
- [CreateFileMappingW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappingw)
- [OpenFileMappingA](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-openfilemappinga)
- [MapViewOfFile](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile)

## フィードバック

ドキュメントに関するフィードバックや改善提案は、GitHub の Issue でお願いします：
https://github.com/oov/aviutl_bridge/issues

## ライセンス

このドキュメントは bridge.dll と同じライセンス（プロジェクトのライセンスを参照）で提供されます。
