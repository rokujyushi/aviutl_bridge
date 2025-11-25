# 共有メモリアクセスに関する技術ドキュメント

## 概要

bridge.dll は、AviUtl の拡張編集プラグインから外部プログラムと画像データを効率的にやり取りするために、Windows の File Mapping Object（共有メモリ）を使用しています。このドキュメントでは、共有メモリアクセスの仕組みと使用方法について詳しく説明します。

## アーキテクチャ

### 基本的な通信フロー

```
[AviUtl/拡張編集]
     ↓ (Lua script)
[bridge.dll]
     ↓ (stdin/stdout + 共有メモリ)
[外部プログラム]
```

bridge.dll は以下の2つの通信手段を組み合わせています：

1. **標準入出力（stdin/stdout）**: テキストデータと制御情報の送受信
2. **共有メモリ（File Mapping Object）**: 画像データの高速な共有

## 共有メモリの初期化

### bridge.dll 側の初期化処理

bridge.dll は、拡張編集から最大画像サイズを取得し、必要なサイズの共有メモリを確保します。

#### 初期化コード（bridge.c の `bridge_init` 関数）

```c
bool bridge_init(int32_t const max_width, int32_t const max_height) {
  // ヘッダーサイズとボディサイズの計算
  int const header_size = sizeof(struct share_mem_header);
  int const body_size = max_width * 4 * max_height;
  
  // 共有メモリの名前を生成（プロセスIDを使用してユニークに）
  wsprintfW(g_mapped_file_name, L"aviutl_bridge_fmo_%08x", GetCurrentProcessId());
  
  // File Mapping Object の作成
  HANDLE mapped_file = CreateFileMappingW(
      INVALID_HANDLE_VALUE,           // ファイルではなくメモリに作成
      NULL,                           // セキュリティ属性
      PAGE_READWRITE,                 // 読み書き可能
      0,                              // 高位サイズ（32bit では0）
      (DWORD)(header_size + body_size), // 低位サイズ
      g_mapped_file_name);            // オブジェクト名
  
  // ビューのマッピング
  void *const view = MapViewOfFile(
      mapped_file,       // マッピングオブジェクト
      FILE_MAP_WRITE,    // 書き込みアクセス
      0, 0,              // オフセット
      0);                // 全体をマップ
  
  // ヘッダー情報の設定
  struct share_mem_header *const v = (struct share_mem_header *)view;
  v->header_size = header_size;
  v->body_size = (uint32_t)body_size;
  v->version = 1;
  v->width = (uint32_t)max_width;
  v->height = (uint32_t)max_height;
  
  return true;
}
```

### 共有メモリのメモリレイアウト

```
+------------------------+
| share_mem_header       |  ← ヘッダー部（20 bytes）
|  - header_size: 20     |
|  - body_size: W*H*4    |
|  - version: 1          |
|  - width: W            |
|  - height: H           |
+------------------------+
| Pixel Data             |  ← ボディ部（width * height * 4 bytes）
|  [0,0] [1,0] ... [W,0] |     BGRA形式のピクセル配列
|  [0,1] [1,1] ... [W,1] |
|  ...                   |
|  [0,H] [1,H] ... [W,H] |
+------------------------+
```

## データ構造の詳細

### ヘッダー構造体（share_mem_header）

```c
struct share_mem_header {
  uint32_t header_size;  // ヘッダーのサイズ（バイト）
  uint32_t body_size;    // ボディのサイズ（バイト）
  uint32_t version;      // プロトコルバージョン（現在は1）
  uint32_t width;        // 画像の幅（ピクセル）
  uint32_t height;       // 画像の高さ（ピクセル）
};
```

各フィールドの説明：

- **header_size**: ヘッダー構造体のサイズ。将来的にヘッダーが拡張された場合でも、このフィールドを使用することで互換性を保つことができます。
- **body_size**: ピクセルデータ領域の最大サイズ（バイト単位）。
- **version**: プロトコルバージョン番号。現在は常に 1。
- **width**: 現在処理中の画像の幅（ピクセル単位）。
- **height**: 現在処理中の画像の高さ（ピクセル単位）。

### ピクセルデータ構造体（pixel）

```c
struct pixel {
  uint8_t b;  // Blue (0-255)
  uint8_t g;  // Green (0-255)
  uint8_t r;  // Red (0-255)
  uint8_t a;  // Alpha (0-255, 透明度)
};
```

ピクセルデータは BGRA 形式で格納されています。これは、`obj.getpixeldata()` / `obj.putpixeldata()` と同じ形式です。

## 外部プログラムからの共有メモリアクセス

### 環境変数を使った共有メモリ名の取得

bridge.dll は、外部プログラムを起動する際に環境変数 `BRIDGE_FMO` を設定します。この環境変数には、共有メモリの名前が格納されています。

```c
// process.c の process_start 関数内
env = build_environment_strings(envvar_name, envvar_value);
// envvar_name = L"BRIDGE_FMO"
// envvar_value = L"aviutl_bridge_fmo_XXXXXXXX" (XXXXXXXXはプロセスID)
```

### 外部プログラムでの共有メモリアクセス手順

以下は、外部プログラムで共有メモリにアクセスするための標準的な手順です：

```c
#include <stdio.h>
#include <stdint.h>
#include <windows.h>

struct share_mem_header {
    uint32_t header_size;
    uint32_t body_size;
    uint32_t version;
    uint32_t width;
    uint32_t height;
};

struct pixel {
    uint8_t b;
    uint8_t g;
    uint8_t r;
    uint8_t a;
};

int main() {
    // 1. 環境変数から共有メモリ名を取得
    char fmo_name[32];
    if (GetEnvironmentVariableA("BRIDGE_FMO", fmo_name, 32) == 0) {
        // 環境変数が設定されていない場合は、
        // 画像データの受け渡しが不要なモードで実行されている
        fprintf(stderr, "BRIDGE_FMO not set\n");
        return 1;
    }
    
    // 2. File Mapping Object を開く
    HANDLE fmo = OpenFileMappingA(
        FILE_MAP_ALL_ACCESS,  // 読み書きアクセス
        FALSE,                // 継承不可
        fmo_name);            // 環境変数から取得した名前
    if (!fmo) {
        fprintf(stderr, "Cannot open file mapping object\n");
        return 1;
    }
    
    // 3. メモリビューをマップ
    void *view = MapViewOfFile(
        fmo,              // マッピングオブジェクト
        FILE_MAP_WRITE,   // 読み書きアクセス
        0, 0,             // オフセット
        0);               // 全体をマップ
    if (!view) {
        fprintf(stderr, "Cannot map view of file\n");
        CloseHandle(fmo);
        return 1;
    }
    
    // 4. ヘッダーを読み取る
    struct share_mem_header *h = (struct share_mem_header *)view;
    int width = h->width;
    int height = h->height;
    
    // 5. ピクセルデータにアクセス
    // ★重要★: sizeof(struct share_mem_header) ではなく、
    //          h->header_size を使用すること
    //          将来のバージョンでヘッダーが拡張される可能性があるため
    struct pixel *px = (struct pixel *)((char *)view + h->header_size);
    
    // 6. ピクセルデータを処理
    for (int y = 0; y < height; ++y) {
        for (int x = 0; x < width; ++x, ++px) {
            // ここで各ピクセルを読み取り/書き込み
            // 例: アルファ値を変更
            px->a = (uint8_t)((px->a * y) / height);
        }
    }
    
    // 7. クリーンアップ
    UnmapViewOfFile(view);
    CloseHandle(fmo);
    
    return 0;
}
```

## メモリアクセスモード

Lua から `bridge.call()` を呼び出す際、第3引数でメモリアクセスモードを指定できます。

### モードの種類

```c
enum mem_mode {
  MEM_MODE_READ = 1,    // 読み取り専用（"r"）
  MEM_MODE_WRITE = 2,   // 書き込み専用（"w"）
  MEM_MODE_DIRECT = 4,  // 直接モード（"p"）
};
```

### Lua での使用例

```lua
-- 読み取り専用: 拡張編集 → 外部プログラム
local result = require("bridge").call("program.exe", "data", "r");

-- 書き込み専用: 外部プログラム → 拡張編集
local result = require("bridge").call("program.exe", "data", "w");

-- 読み書き両方
local result = require("bridge").call("program.exe", "data", "rw");

-- 直接モード（obj.getpixeldata を呼び出さずに画像データを渡す）
local pixels, w, h = obj.getpixeldata();
local result = require("bridge").call("program.exe", "data", "rwp", pixels, w, h);
```

### モード別の動作

#### 読み取りモード（"r"）

1. bridge.dll が `obj.getpixeldata()` を呼び出す
2. 取得したピクセルデータを共有メモリにコピー
3. 外部プログラムが共有メモリからデータを読み取る
4. 拡張編集側の画像は変更されない

```c
// bridge.c の bridge_call_core 関数内
if (mem->mode & MEM_MODE_READ) {
  memcpy(v + 1, mem->buf, (size_t)(mem->width * 4 * mem->height));
}
```

#### 書き込みモード（"w"）

1. 外部プログラムが共有メモリにピクセルデータを書き込む
2. bridge.dll が共有メモリからデータを読み取る
3. `obj.putpixeldata()` を呼び出して拡張編集に反映

```c
// bridge.c の call_recv 関数内
if (rd->mem && rd->mem->mode & MEM_MODE_WRITE) {
  struct share_mem_header *const v = (struct share_mem_header *)g_view;
  memcpy(rd->mem->buf, v + 1, (size_t)(rd->mem->width * 4 * rd->mem->height));
}
```

#### 直接モード（"p"）

`obj.getpixeldata()` / `obj.putpixeldata()` を内部で呼び出さず、Lua から直接渡された画像データを使用します。これにより、複数回の `bridge.call()` で同じピクセルバッファを再利用でき、パフォーマンスが向上します。

```lua
-- 直接モードの使用例
local pixels, w, h = obj.getpixeldata();

-- 複数の処理を連続して行う場合、getpixeldata を1回だけ呼ぶ
require("bridge").call("filter1.exe", "", "rp", pixels, w, h);
require("bridge").call("filter2.exe", "", "rwp", pixels, w, h);
require("bridge").call("filter3.exe", "", "rwp", pixels, w, h);

-- 最後に結果を反映
obj.putpixeldata(pixels);
```

## データ通信プロトコル

### 標準入出力のデータ形式

bridge.dll と外部プログラム間の標準入出力は、以下のフォーマットで行われます：

```
[int32_t length][char data[length]]
```

- **length**: データの長さ（バイト数、リトルエンディアン）
- **data**: 実際のデータ

### 通信シーケンス

```
[bridge.dll]                    [外部プログラム]
    |                                   |
    |--- stdin: [length][data] -------->|  (1) コマンド送信
    |                                   |
    |                                   |  (2) 共有メモリからピクセルデータ読み取り
    |                                   |      または書き込み
    |                                   |
    |<-- stdout: [length][result] ------|  (3) 結果返信
    |                                   |
```

### サンプルコード：入出力の処理

```c
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>

int main() {
    // バイナリモードに切り替え
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    
    // 入力データの受信
    char input_buf[1024];
    int32_t input_len;
    if (fread(&input_len, sizeof(input_len), 1, stdin) != 1) {
        return 1;
    }
    if (input_len > 0 && input_len < 1024) {
        if (fread(input_buf, 1, input_len, stdin) != (size_t)input_len) {
            return 1;
        }
        input_buf[input_len] = '\0';
    }
    
    // ここで処理を行う...
    
    // 出力データの送信
    char output_buf[1024];
    int32_t output_len = sprintf(output_buf, "Processed: %s", input_buf);
    if (fwrite(&output_len, sizeof(output_len), 1, stdout) != 1) {
        return 1;
    }
    if (fwrite(output_buf, 1, output_len, stdout) != (size_t)output_len) {
        return 1;
    }
    fflush(stdout);
    
    return 0;
}
```

## プロセス管理

### プロセスのライフサイクル

bridge.dll は、各外部プログラムのプロセスを hashmap で管理しています。同じ実行ファイルパスに対しては、プロセスを再利用します。

```c
// bridge.c
static struct hashmap *g_process_map = NULL;

// キーは実行ファイルパス、値は process 構造体
struct item {
  char *key;
  size_t key_len;
  struct process *value;
};
```

### プロセスの起動

1. 実行ファイルパスで hashmap を検索
2. プロセスが見つからないか、既に終了している場合は新規起動
3. プロセスを起動し、環境変数 `BRIDGE_FMO` を設定
4. hashmap に登録

```c
// bridge.c の bridge_call_core 関数内
struct process *p = process_start(wpath, L"BRIDGE_FMO", g_mapped_file_name);
```

### プロセスの終了

外部プログラムは、以下の2つの方法で終了できます：

1. **処理後に終了**: `bridge.call()` 1回の処理が終わったら `return 0;` で終了
2. **ループで待機**: `while(1)` でループし、複数回の `bridge.call()` に対応

```c
// 方法1: 処理後に終了
int main() {
    // 1回の処理
    process_input();
    process_pixels();
    output_result();
    return 0;  // 次回の bridge.call() で再起動される
}

// 方法2: ループで待機
int main() {
    while(1) {
        // 複数回の処理に対応
        process_input();
        process_pixels();
        output_result();
    }
    return 0;
}
```

ループモードの利点：
- プロセス起動のオーバーヘッドがない
- 初期化処理（ライブラリのロードなど）を1回で済ませられる

## スレッドセーフティ

bridge.dll は、複数の Lua スレッドから同時にアクセスされる可能性があるため、mutex を使用して同期を取っています。

```c
// bridge.c
static mtx_t g_mutex = {0};

int bridge_call(...) {
  mtx_lock(&g_mutex);
  int ret = bridge_call_core(...);
  mtx_unlock(&g_mutex);
  return ret;
}
```

## パフォーマンスの考慮事項

### 共有メモリを使う利点

1. **高速なデータ転送**: メモリコピーのみで済むため、パイプやソケット通信よりも高速
2. **大容量データの効率的な転送**: フルHD (1920x1080) の画像データは約8MBですが、共有メモリなら効率的に転送可能

### パフォーマンス最適化のヒント

1. **直接モード（"p"）の使用**: 複数回の処理で `obj.getpixeldata()` を呼び出さない
2. **プロセスの再利用**: ループモードで外部プログラムを実装し、起動コストを削減
3. **必要なモードのみ指定**: 読み取り専用の場合は "r" のみを指定し、不要なメモリコピーを避ける

```lua
-- 悪い例: 毎回 getpixeldata を呼び出す
for i = 1, 100 do
    require("bridge").call("filter.exe", "", "rw")
end

-- 良い例: getpixeldata を1回だけ呼び、直接モードを使用
local px, w, h = obj.getpixeldata()
for i = 1, 100 do
    require("bridge").call("filter.exe", "", "rwp", px, w, h)
end
obj.putpixeldata(px)
```

## トラブルシューティング

### よくある問題と解決方法

#### 1. 環境変数が取得できない

**症状**: `GetEnvironmentVariableA("BRIDGE_FMO", ...)` が失敗する

**原因**: Lua から "r", "w", "rw" などのモードを指定していない

**解決**: 画像データのやり取りが必要な場合は、必ずモードを指定する

```lua
-- NG: モードを指定していない
local result = require("bridge").call("program.exe", "data");

-- OK: モードを指定
local result = require("bridge").call("program.exe", "data", "rw");
```

#### 2. ピクセルデータが正しく読めない

**症状**: 画像データが壊れて見える、または不正なメモリアクセスが発生

**原因**: ヘッダーサイズの計算が間違っている

**解決**: `h->header_size` を使用してピクセルデータの開始位置を計算する

```c
// NG: 固定サイズを使用
struct pixel *px = (struct pixel *)(view + sizeof(struct share_mem_header));

// OK: ヘッダーのサイズフィールドを使用
struct pixel *px = (struct pixel *)((char *)view + h->header_size);
```

#### 3. 書き込みモードで画像が更新されない

**症状**: "w" モードで共有メモリに書き込んだが、拡張編集に反映されない

**原因**: 
- 共有メモリには書き込んでいるが、bridge.dll が読み取る前に処理が終了している
- fflush(stdout) を忘れている

**解決**: stdout への出力後、必ず `fflush(stdout)` を呼ぶ

```c
// 結果を送信
fwrite(&output_len, sizeof(output_len), 1, stdout);
fwrite(output_buf, 1, output_len, stdout);
fflush(stdout);  // ★重要★
```

## セキュリティ上の注意事項

### 共有メモリのアクセス制御

現在の実装では、共有メモリは `FILE_MAP_ALL_ACCESS` で開かれており、同じプロセスID を知っている他のプロセスもアクセス可能です。これは、一般的な使用では問題ありませんが、機密性の高いデータを扱う場合は注意が必要です。

### プロセスの検証

外部プログラムは、環境変数 `BRIDGE_FMO` の存在を確認し、意図した方法で起動されたことを検証することを推奨します。

## 将来の拡張性

### バージョン管理

ヘッダー構造体には `version` フィールドがあり、将来的にプロトコルが拡張された際の互換性を保つために使用できます。

```c
struct share_mem_header *h = (struct share_mem_header *)view;
if (h->version != 1) {
    // 未対応のバージョン
    fprintf(stderr, "Unsupported protocol version: %u\n", h->version);
    return 1;
}
```

### ヘッダーの拡張

将来的にヘッダーに新しいフィールドを追加する場合、以下の点に注意：

1. `header_size` フィールドを更新
2. 新しいフィールドはヘッダーの末尾に追加
3. 古いバージョンのプログラムとの互換性を保つため、`header_size` を使用してピクセルデータの位置を計算

## まとめ

bridge.dll の共有メモリ機構は、以下の特徴を持っています：

- **File Mapping Object** を使用した効率的なメモリ共有
- **環境変数** による共有メモリ名の受け渡し
- **標準入出力** と組み合わせた柔軟な通信プロトコル
- **プロセスの再利用** によるパフォーマンスの最適化
- **複数のモード** (読み取り/書き込み/直接) をサポート

この仕組みを理解することで、AviUtl で高度な画像処理を行う外部プログラムを効率的に開発できます。

## 参考資料

### ソースコードファイル

- `src/bridge.h`: 共有メモリのヘッダー定義とインターフェース
- `src/bridge.c`: 共有メモリの初期化と管理
- `src/process.h`, `src/process.c`: 外部プロセスの起動と通信
- `src/luamain.c`: Lua インターフェースの実装

### Windows API ドキュメント

- [CreateFileMappingW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappingw)
- [OpenFileMappingA](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-openfilemappinga)
- [MapViewOfFile](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile)
- [UnmapViewOfFile](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-unmapviewoffile)
