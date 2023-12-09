#include "bridge.h"

#include "threads.h"
#include <hashmap.h>

#include "ods.h"
#include "process.h"
#include "version.h"

struct item {
  char *key;
  size_t key_len;
  struct process *value;
};

static WCHAR g_mapped_file_name[32];
static HANDLE g_mapped_file = NULL;
static int g_bufsize = 0;
static void *g_view = NULL;
static struct hashmap *g_process_map = NULL;
static mtx_t g_mutex = {0};

static void *my_realloc(void *ptr, size_t sz, void *udata) {
  (void)udata;
  return realloc(ptr, sz);
}

static void my_free(void *ptr, void *udata) {
  (void)udata;
  free(ptr);
}

static uint64_t hash(void const *const item, uint64_t const seed0, uint64_t const seed1, void *const udata) {
  struct item const *const v = item;
  (void)udata;
  return hashmap_sip(v->key, v->key_len, seed0, seed1);
}

static int compare(void const *const a, void const *const b, void *const udata) {
  struct item const *const va = a;
  struct item const *const vb = b;
  (void)udata;
  int const r = memcmp(va->key, vb->key, va->key_len < vb->key_len ? va->key_len : vb->key_len);
  if (r != 0) {
    return r;
  }
  if (va->key_len < vb->key_len) {
    return -1;
  }
  if (va->key_len > vb->key_len) {
    return 1;
  }
  return 0;
}

static uint64_t next(uint64_t *const x) {
  uint64_t z = (*x += 0x9e3779b97f4a7c15);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
  z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
  return z ^ (z >> 31);
}

bool bridge_init(int32_t const max_width, int32_t const max_height) {
  if (max_width <= 0 || max_height <= 0) {
    return false;
  }
  uint64_t x = GetTickCount64();
  g_process_map = hashmap_new_with_allocator(
      my_realloc, my_free, sizeof(struct item), 1, next(&x), next(&x), hash, compare, NULL, NULL);
  if (!g_process_map) {
    return false;
  }
  mtx_init(&g_mutex, mtx_plain | mtx_recursive);

  int const header_size = sizeof(struct share_mem_header);
  int const body_size = max_width * 4 * max_height;
  wsprintfW(g_mapped_file_name, L"aviutl_bridge_fmo_%08x", GetCurrentProcessId());
  HANDLE mapped_file = CreateFileMappingW(
      INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, (DWORD)(header_size + body_size), g_mapped_file_name);
  if (!mapped_file) {
    return false;
  }

  void *const view = MapViewOfFile(mapped_file, FILE_MAP_WRITE, 0, 0, 0);
  if (!view) {
    CloseHandle(mapped_file);
    return false;
  }

  g_mapped_file = mapped_file;
  g_view = view;
  g_bufsize = header_size + body_size;
  struct share_mem_header *const v = view;
  v->header_size = header_size;
  v->body_size = (uint32_t)body_size;
  v->version = 1;
  v->width = (uint32_t)max_width;
  v->height = (uint32_t)max_height;
  return true;
}

bool bridge_exit(void) {
  mtx_lock(&g_mutex);

  size_t iter = 0;
  void *item;
  while (hashmap_iter(g_process_map, &iter, &item)) {
    struct item *v = item;
    process_finish(v->value);
    free(v->key);
  }
  hashmap_free(g_process_map);

  if (g_view) {
    UnmapViewOfFile(g_view);
    g_view = NULL;
  }
  if (g_mapped_file) {
    CloseHandle(g_mapped_file);
    g_mapped_file = NULL;
  }
  mtx_destroy(&g_mutex);
  return true;
}

struct recvdata {
  struct call_mem *const mem;
  void *userdata;
  void (*recv)(void *userdata, void const *const ptr, size_t const len);
};

static void call_recv(void *userdata, void const *const ptr, size_t const len) {
  struct recvdata *const rd = userdata;
  if (rd->mem && rd->mem->mode & MEM_MODE_WRITE) {
    struct share_mem_header *v = g_view;
    memcpy(rd->mem->buf, v + 1, (size_t)(rd->mem->width * 4 * rd->mem->height));
  }
  rd->recv(rd->userdata, ptr, len);
}

static int bridge_call_core(char const *const exe_path,
                            void const *const buf,
                            int32_t const len,
                            struct call_mem *const mem,
                            void (*recv)(void *userdata, void const *const ptr, size_t const len),
                            void *userdata) {
  if (g_bufsize == 0 || !g_view) {
    return ECALL_NOT_INITIALIZED;
  }
  struct item const hmkey = {
      .key = (char *)exe_path,
      .key_len = (size_t)(lstrlenA(exe_path)),
  };
  uint64_t hash = hashmap_hash(g_process_map, &hmkey);
  struct item *hmv = (struct item *)(hashmap_get_with_hash(g_process_map, &hmkey, hash));
  if (hmv) {
    if (!process_isrunning(hmv->value)) {
      // It seems process is already dead
      process_finish(hmv->value);
      free(hmv->key);
      hashmap_delete_with_hash(g_process_map, &hmkey, hash);
      hmv = NULL;
    }
  }
  if (!hmv) {
    char *newkey = malloc(hmkey.key_len);
    if (!newkey) {
      return ECALL_MEMORY_ALLOCATION_FAILED;
    }
    int buflen = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, hmkey.key, (int)hmkey.key_len, NULL, 0);
    WCHAR *wpath = malloc(sizeof(WCHAR) * (size_t)(buflen + 1));
    if (!wpath) {
      free(newkey);
      return ECALL_FAILED_TO_CONVERT_EXE_PATH;
    }
    if (MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, hmkey.key, (int)hmkey.key_len, wpath, buflen) == 0) {
      free(newkey);
      free(wpath);
      return ECALL_FAILED_TO_CONVERT_EXE_PATH;
    }
    wpath[buflen] = '\0';
    struct process *p = process_start(wpath, L"BRIDGE_FMO", g_mapped_file_name);
    if (!p) {
      free(newkey);
      free(wpath);
      return ECALL_FAILED_TO_START_PROCESS;
    }
    free(wpath);
    process_close_stderr(p);
    memcpy(newkey, hmkey.key, hmkey.key_len);
    if (!hashmap_set_with_hash(g_process_map,
                               &(struct item){
                                   .key = newkey,
                                   .key_len = hmkey.key_len,
                                   .value = p,
                               },
                               hash) &&
        hashmap_oom(g_process_map)) {
      process_finish(p);
      free(newkey);
      return ECALL_FAILED_TO_START_PROCESS;
    }
    hmv = (struct item *)(hashmap_get_with_hash(g_process_map, &hmkey, hash));
  }
  if (mem) {
    struct share_mem_header *v = g_view;
    v->width = (uint32_t)mem->width;
    v->height = (uint32_t)mem->height;
    if (mem->mode & MEM_MODE_READ) {
      memcpy(v + 1, mem->buf, (size_t)(mem->width * 4 * mem->height));
    }
  }
  if (process_write(hmv->value, buf, (size_t)len) != 0) {
    return ECALL_FAILED_TO_SEND_COMMAND;
  }
  if (process_read(hmv->value,
                   call_recv,
                   &(struct recvdata){
                       .mem = mem,
                       .userdata = userdata,
                       .recv = recv,
                   }) != 0) {
    return ECALL_FAILED_TO_RECEIVE_COMMAND;
  }
  return ECALL_OK;
}

int bridge_call(const char *exe_path,
                const void *buf,
                int32_t len,
                struct call_mem *mem,
                void (*recv)(void *userdata, void const *const ptr, size_t const len),
                void *userdata) {
  mtx_lock(&g_mutex);
  int ret = bridge_call_core(exe_path, buf, len, mem, recv, userdata);
  mtx_unlock(&g_mutex);
  return ret;
}
