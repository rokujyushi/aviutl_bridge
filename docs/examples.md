# bridge.dll 実装例集

このドキュメントでは、bridge.dll を使用した外部プログラムの実装例を紹介します。

## 目次

1. [基本的な例](#基本的な例)
2. [画像処理の例](#画像処理の例)
3. [高度な例](#高度な例)
4. [エラーハンドリング](#エラーハンドリング)

## 基本的な例

### 例1: エコープログラム

受け取ったデータをそのまま返すシンプルな例：

```c
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <windows.h>

int main() {
    // バイナリモードに設定
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    
    while (1) {
        // 入力データのサイズを読み取り
        int32_t input_len;
        if (fread(&input_len, sizeof(input_len), 1, stdin) != 1) {
            break;  // エラーまたはEOF
        }
        
        // 入力データを読み取り
        char *buffer = malloc(input_len + 1);
        if (!buffer) break;
        
        if (input_len > 0) {
            if (fread(buffer, 1, input_len, stdin) != (size_t)input_len) {
                free(buffer);
                break;
            }
        }
        buffer[input_len] = '\0';
        
        // デバッグ出力
        OutputDebugStringA("Received: ");
        OutputDebugStringA(buffer);
        OutputDebugStringA("\n");
        
        // 同じデータを返す
        if (fwrite(&input_len, sizeof(input_len), 1, stdout) != 1) {
            free(buffer);
            break;
        }
        if (input_len > 0) {
            if (fwrite(buffer, 1, input_len, stdout) != (size_t)input_len) {
                free(buffer);
                break;
            }
        }
        fflush(stdout);
        
        free(buffer);
    }
    
    return 0;
}
```

**Lua での使用:**

```lua
local result = require("bridge").call("echo.exe", "Hello, Bridge!");
-- result は "Hello, Bridge!" になる
```

### 例2: カウンタープログラム

呼び出し回数をカウントして返す例：

```c
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>

static int counter = 0;

int main() {
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    
    while (1) {
        // 入力を読み取り（使用しない）
        int32_t input_len;
        if (fread(&input_len, sizeof(input_len), 1, stdin) != 1) {
            break;
        }
        if (input_len > 0) {
            char dummy[4096];
            size_t to_read = input_len;
            while (to_read > 0) {
                size_t chunk = to_read > sizeof(dummy) ? sizeof(dummy) : to_read;
                if (fread(dummy, 1, chunk, stdin) != chunk) {
                    return 1;
                }
                to_read -= chunk;
            }
        }
        
        // カウンターをインクリメントして返す
        counter++;
        char output[64];
        int32_t output_len = sprintf(output, "Count: %d", counter);
        
        fwrite(&output_len, sizeof(output_len), 1, stdout);
        fwrite(output, 1, output_len, stdout);
        fflush(stdout);
    }
    
    return 0;
}
```

**Lua での使用:**

```lua
local bridge = require("bridge")
for i = 1, 5 do
    local result = bridge.call("counter.exe", "")
    debug_print(result)  -- "Count: 1", "Count: 2", ...
end
```

## 画像処理の例

### 例3: グレースケール変換

画像をグレースケールに変換する例：

```c
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
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
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    
    // 共有メモリ名を取得
    char fmo_name[32];
    if (GetEnvironmentVariableA("BRIDGE_FMO", fmo_name, 32) == 0) {
        return 1;
    }
    
    while (1) {
        // 入力を読み取り
        int32_t input_len;
        if (fread(&input_len, sizeof(input_len), 1, stdin) != 1) {
            break;
        }
        if (input_len > 0) {
            char dummy[4096];
            size_t to_read = input_len;
            while (to_read > 0) {
                size_t chunk = to_read > sizeof(dummy) ? sizeof(dummy) : to_read;
                if (fread(dummy, 1, chunk, stdin) != chunk) {
                    return 1;
                }
                to_read -= chunk;
            }
        }
        
        // 共有メモリを開く
        HANDLE fmo = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, fmo_name);
        if (!fmo) break;
        
        void *view = MapViewOfFile(fmo, FILE_MAP_WRITE, 0, 0, 0);
        if (!view) {
            CloseHandle(fmo);
            break;
        }
        
        // ヘッダーとピクセルデータを取得
        struct share_mem_header *h = (struct share_mem_header *)view;
        struct pixel *px = (struct pixel *)((char *)view + h->header_size);
        
        // グレースケール変換
        int total = h->width * h->height;
        for (int i = 0; i < total; ++i, ++px) {
            // 輝度計算 (ITU-R BT.601)
            uint8_t gray = (uint8_t)(
                0.299 * px->r + 0.587 * px->g + 0.114 * px->b
            );
            px->r = gray;
            px->g = gray;
            px->b = gray;
            // アルファ値はそのまま
        }
        
        UnmapViewOfFile(view);
        CloseHandle(fmo);
        
        // 結果を返す
        char output[] = "Grayscale applied";
        int32_t output_len = sizeof(output) - 1;
        fwrite(&output_len, sizeof(output_len), 1, stdout);
        fwrite(output, 1, output_len, stdout);
        fflush(stdout);
    }
    
    return 0;
}
```

**Lua での使用:**

```lua
-- 書き込みモード（"w"）を指定して、変更を反映
local result = require("bridge").call("grayscale.exe", "", "w")
```

### 例4: 明るさ調整

画像の明るさを調整する例：

```c
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <windows.h>
#include <string.h>

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

static inline uint8_t clamp(int value) {
    if (value < 0) return 0;
    if (value > 255) return 255;
    return (uint8_t)value;
}

int main() {
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    
    char fmo_name[32];
    if (GetEnvironmentVariableA("BRIDGE_FMO", fmo_name, 32) == 0) {
        return 1;
    }
    
    while (1) {
        // 明るさの値を入力から取得
        int32_t input_len;
        if (fread(&input_len, sizeof(input_len), 1, stdin) != 1) {
            break;
        }
        
        char input[256];
        if (input_len > 0 && input_len < 256) {
            if (fread(input, 1, input_len, stdin) != (size_t)input_len) {
                break;
            }
            input[input_len] = '\0';
        } else {
            break;
        }
        
        // 明るさの値を解析（-100 から +100）
        int brightness = atoi(input);
        
        // 共有メモリにアクセス
        HANDLE fmo = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, fmo_name);
        if (!fmo) break;
        
        void *view = MapViewOfFile(fmo, FILE_MAP_WRITE, 0, 0, 0);
        if (!view) {
            CloseHandle(fmo);
            break;
        }
        
        struct share_mem_header *h = (struct share_mem_header *)view;
        struct pixel *px = (struct pixel *)((char *)view + h->header_size);
        
        // 明るさ調整
        int total = h->width * h->height;
        for (int i = 0; i < total; ++i, ++px) {
            px->r = clamp((int)px->r + brightness);
            px->g = clamp((int)px->g + brightness);
            px->b = clamp((int)px->b + brightness);
        }
        
        UnmapViewOfFile(view);
        CloseHandle(fmo);
        
        // 結果を返す
        char output[64];
        int32_t output_len = sprintf(output, "Brightness adjusted by %d", brightness);
        fwrite(&output_len, sizeof(output_len), 1, stdout);
        fwrite(output, 1, output_len, stdout);
        fflush(stdout);
    }
    
    return 0;
}
```

**Lua での使用:**

```lua
-- トラックバーの値を渡す
local brightness = obj.track0  -- -100 から +100
local result = require("bridge").call(
    "brightness.exe",
    tostring(brightness),
    "rw"
)
```

### 例5: ぼかし処理（Box Blur）

単純なボックスぼかしを適用する例：

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
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
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    
    char fmo_name[32];
    if (GetEnvironmentVariableA("BRIDGE_FMO", fmo_name, 32) == 0) {
        return 1;
    }
    
    while (1) {
        // ぼかし半径を入力から取得
        int32_t input_len;
        if (fread(&input_len, sizeof(input_len), 1, stdin) != 1) {
            break;
        }
        
        char input[256];
        if (input_len > 0 && input_len < 256) {
            if (fread(input, 1, input_len, stdin) != (size_t)input_len) {
                break;
            }
            input[input_len] = '\0';
        } else {
            strcpy(input, "3");
        }
        
        int radius = atoi(input);
        if (radius < 1) radius = 1;
        if (radius > 10) radius = 10;
        
        // 共有メモリにアクセス
        HANDLE fmo = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, fmo_name);
        if (!fmo) break;
        
        void *view = MapViewOfFile(fmo, FILE_MAP_WRITE, 0, 0, 0);
        if (!view) {
            CloseHandle(fmo);
            break;
        }
        
        struct share_mem_header *h = (struct share_mem_header *)view;
        struct pixel *src = (struct pixel *)((char *)view + h->header_size);
        
        int width = h->width;
        int height = h->height;
        
        // 作業用バッファを確保
        struct pixel *dst = (struct pixel *)malloc(width * height * sizeof(struct pixel));
        if (!dst) {
            UnmapViewOfFile(view);
            CloseHandle(fmo);
            break;
        }
        
        // ボックスぼかしを適用
        for (int y = 0; y < height; ++y) {
            for (int x = 0; x < width; ++x) {
                int sum_r = 0, sum_g = 0, sum_b = 0, sum_a = 0;
                int count = 0;
                
                for (int dy = -radius; dy <= radius; ++dy) {
                    for (int dx = -radius; dx <= radius; ++dx) {
                        int nx = x + dx;
                        int ny = y + dy;
                        
                        if (nx >= 0 && nx < width && ny >= 0 && ny < height) {
                            struct pixel *p = &src[ny * width + nx];
                            sum_r += p->r;
                            sum_g += p->g;
                            sum_b += p->b;
                            sum_a += p->a;
                            count++;
                        }
                    }
                }
                
                struct pixel *d = &dst[y * width + x];
                d->r = (uint8_t)(sum_r / count);
                d->g = (uint8_t)(sum_g / count);
                d->b = (uint8_t)(sum_b / count);
                d->a = (uint8_t)(sum_a / count);
            }
        }
        
        // 結果をコピーバック
        memcpy(src, dst, width * height * sizeof(struct pixel));
        free(dst);
        
        UnmapViewOfFile(view);
        CloseHandle(fmo);
        
        // 結果を返す
        char output[64];
        int32_t output_len = sprintf(output, "Blur applied (radius=%d)", radius);
        fwrite(&output_len, sizeof(output_len), 1, stdout);
        fwrite(output, 1, output_len, stdout);
        fflush(stdout);
    }
    
    return 0;
}
```

**Lua での使用:**

```lua
local radius = 5
local result = require("bridge").call(
    "blur.exe",
    tostring(radius),
    "rw"
)
```

## 高度な例

### 例6: 外部ライブラリを使用した画像処理

OpenCV などの外部ライブラリを使用する例の構造：

```c
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <windows.h>
// #include <opencv2/opencv.hpp>  // 仮定

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
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    
    char fmo_name[32];
    if (GetEnvironmentVariableA("BRIDGE_FMO", fmo_name, 32) == 0) {
        return 1;
    }
    
    while (1) {
        // 入力パラメータを取得
        int32_t input_len;
        if (fread(&input_len, sizeof(input_len), 1, stdin) != 1) {
            break;
        }
        
        char params[1024] = {0};
        if (input_len > 0 && input_len < sizeof(params)) {
            if (fread(params, 1, input_len, stdin) != (size_t)input_len) {
                break;
            }
            params[input_len] = '\0';
        }
        
        // 共有メモリにアクセス
        HANDLE fmo = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, fmo_name);
        if (!fmo) break;
        
        void *view = MapViewOfFile(fmo, FILE_MAP_WRITE, 0, 0, 0);
        if (!view) {
            CloseHandle(fmo);
            break;
        }
        
        struct share_mem_header *h = (struct share_mem_header *)view;
        struct pixel *pixels = (struct pixel *)((char *)view + h->header_size);
        
        // OpenCV Mat に変換（仮定のコード）
        // cv::Mat image(h->height, h->width, CV_8UC4, pixels);
        // 
        // // OpenCV で処理
        // cv::GaussianBlur(image, image, cv::Size(5, 5), 0);
        // 
        // // 結果は自動的に pixels に反映される（同じメモリを参照）
        
        UnmapViewOfFile(view);
        CloseHandle(fmo);
        
        // 結果を返す
        const char *output = "Processing completed";
        int32_t output_len = strlen(output);
        fwrite(&output_len, sizeof(output_len), 1, stdout);
        fwrite(output, 1, output_len, stdout);
        fflush(stdout);
    }
    
    return 0;
}
```

### 例7: 直接モード（"p"）の活用

複数のフィルターを連続して適用する例：

**Lua スクリプト:**

```lua
-- 直接モードを使用して効率的に複数の処理を行う
local bridge = require("bridge")

-- 画像データを一度だけ取得
local pixels, w, h = obj.getpixeldata()

-- 複数のフィルターを連続適用
-- 各フィルターは共有メモリを通じて同じピクセルデータを操作
bridge.call("brightness.exe", "20", "rwp", pixels, w, h)
bridge.call("contrast.exe", "1.2", "rwp", pixels, w, h)
bridge.call("saturation.exe", "1.5", "rwp", pixels, w, h)
bridge.call("sharpen.exe", "0.3", "rwp", pixels, w, h)

-- 最後に結果を反映
obj.putpixeldata(pixels)
```

この方法の利点：
- `getpixeldata()` / `putpixeldata()` の呼び出しが最小限
- 中間結果がメモリ上に保持される
- パフォーマンスが大幅に向上

### 例8: JSONでパラメータを渡す

複雑なパラメータを JSON で渡す例：

**C プログラム（簡略化）:**

```c
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <windows.h>
// JSON パーサーライブラリを想定（例: cJSON）

int main() {
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    
    char fmo_name[32];
    GetEnvironmentVariableA("BRIDGE_FMO", fmo_name, 32);
    
    while (1) {
        // JSON パラメータを受信
        int32_t input_len;
        if (fread(&input_len, sizeof(input_len), 1, stdin) != 1) {
            break;
        }
        
        char *json_str = malloc(input_len + 1);
        if (fread(json_str, 1, input_len, stdin) != (size_t)input_len) {
            free(json_str);
            break;
        }
        json_str[input_len] = '\0';
        
        // JSON をパース（仮定）
        // cJSON *json = cJSON_Parse(json_str);
        // int brightness = cJSON_GetObjectItem(json, "brightness")->valueint;
        // double contrast = cJSON_GetObjectItem(json, "contrast")->valuedouble;
        // const char *mode = cJSON_GetObjectItem(json, "mode")->valuestring;
        
        // パラメータに基づいて処理...
        
        // 結果を JSON で返す（仮定）
        // cJSON *result = cJSON_CreateObject();
        // cJSON_AddStringToObject(result, "status", "success");
        // char *result_str = cJSON_Print(result);
        
        const char *result_str = "{\"status\":\"success\"}";
        int32_t output_len = strlen(result_str);
        fwrite(&output_len, sizeof(output_len), 1, stdout);
        fwrite(result_str, 1, output_len, stdout);
        fflush(stdout);
        
        free(json_str);
    }
    
    return 0;
}
```

**Lua での使用:**

```lua
local json = require("json")  -- JSON ライブラリを想定

local params = {
    brightness = 30,
    contrast = 1.2,
    mode = "auto"
}

local result = require("bridge").call(
    "advanced_filter.exe",
    json.encode(params),
    "rw"
)

local result_data = json.decode(result)
if result_data.status == "success" then
    debug_print("Processing succeeded")
end
```

## エラーハンドリング

### 例9: 適切なエラーハンドリング

エラーを適切に処理する例：

```c
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
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

static void send_error(const char *error_msg) {
    int32_t len = strlen(error_msg);
    fwrite(&len, sizeof(len), 1, stdout);
    fwrite(error_msg, 1, len, stdout);
    fflush(stdout);
}

static void send_success(const char *msg) {
    int32_t len = strlen(msg);
    fwrite(&len, sizeof(len), 1, stdout);
    fwrite(msg, 1, len, stdout);
    fflush(stdout);
}

int main() {
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    
    char fmo_name[32];
    if (GetEnvironmentVariableA("BRIDGE_FMO", fmo_name, 32) == 0) {
        OutputDebugStringA("ERROR: BRIDGE_FMO not set\n");
        return 1;
    }
    
    while (1) {
        // 入力を読み取り
        int32_t input_len;
        if (fread(&input_len, sizeof(input_len), 1, stdin) != 1) {
            OutputDebugStringA("ERROR: Cannot read input length\n");
            break;
        }
        
        if (input_len < 0 || input_len > 1024 * 1024) {  // 1MB 制限
            send_error("ERROR: Input too large");
            continue;
        }
        
        char *input = malloc(input_len + 1);
        if (!input) {
            send_error("ERROR: Memory allocation failed");
            continue;
        }
        
        if (input_len > 0) {
            if (fread(input, 1, input_len, stdin) != (size_t)input_len) {
                OutputDebugStringA("ERROR: Cannot read input data\n");
                free(input);
                break;
            }
        }
        input[input_len] = '\0';
        
        // 共有メモリを開く
        HANDLE fmo = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, fmo_name);
        if (!fmo) {
            OutputDebugStringA("ERROR: Cannot open file mapping\n");
            send_error("ERROR: Cannot access shared memory");
            free(input);
            continue;
        }
        
        void *view = MapViewOfFile(fmo, FILE_MAP_WRITE, 0, 0, 0);
        if (!view) {
            OutputDebugStringA("ERROR: Cannot map view\n");
            CloseHandle(fmo);
            send_error("ERROR: Cannot map shared memory");
            free(input);
            continue;
        }
        
        struct share_mem_header *h = (struct share_mem_header *)view;
        
        // バージョンチェック
        if (h->version != 1) {
            char error[128];
            sprintf(error, "ERROR: Unsupported version: %u", h->version);
            OutputDebugStringA(error);
            UnmapViewOfFile(view);
            CloseHandle(fmo);
            send_error(error);
            free(input);
            continue;
        }
        
        // サイズチェック
        if (h->width == 0 || h->height == 0 || h->width > 8192 || h->height > 8192) {
            char error[128];
            sprintf(error, "ERROR: Invalid dimensions: %ux%u", h->width, h->height);
            OutputDebugStringA(error);
            UnmapViewOfFile(view);
            CloseHandle(fmo);
            send_error(error);
            free(input);
            continue;
        }
        
        // 処理を実行
        struct pixel *pixels = (struct pixel *)((char *)view + h->header_size);
        
        // ここで実際の画像処理...
        // （この例では何もしない）
        
        UnmapViewOfFile(view);
        CloseHandle(fmo);
        
        // 成功を返す
        send_success("Processing completed successfully");
        free(input);
    }
    
    return 0;
}
```

**Lua でのエラーハンドリング:**

```lua
local bridge = require("bridge")

-- エラーハンドリングを行う
local success, result = pcall(function()
    return bridge.call("filter.exe", "params", "rw")
end)

if success then
    if string.match(result, "^ERROR:") then
        debug_print("Filter error: " .. result)
    else
        debug_print("Success: " .. result)
    end
else
    debug_print("Bridge call failed: " .. tostring(result))
end
```

## パフォーマンス測定

### 例10: 処理時間の測定

```lua
local bridge = require("bridge")

-- 処理時間を測定
local start_time = os.clock()

local result = bridge.call("heavy_filter.exe", "", "rw")

local elapsed = os.clock() - start_time
debug_print(string.format("Processing time: %.3f seconds", elapsed))
```

## まとめ

これらの例を参考に、bridge.dll を活用した高度な画像処理プログラムを開発できます。重要なポイント：

1. **バイナリモード**: stdin/stdout を必ずバイナリモードに設定
2. **エラーハンドリング**: 適切なエラーチェックとメッセージ送信
3. **効率化**: 直接モード（"p"）を使用してパフォーマンス向上
4. **デバッグ**: `OutputDebugStringA()` を活用してデバッグ情報を出力
5. **リソース管理**: 共有メモリのハンドルを必ず解放

これらのベストプラクティスに従うことで、安定した高性能な外部プログラムを実装できます。
