#pragma once

#include <stdbool.h>
#include <wchar.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

struct process;

struct process *
process_start(WCHAR const *const exe_path, WCHAR const *const envvar_name, WCHAR const *const envvar_value);
void process_finish(struct process *const self);
void process_close_stderr(struct process *const self);
int process_read(struct process *const self,
                 void (*recv)(void *userdata, void const *const ptr, size_t const len),
                 void *userdata);
int process_write(struct process *const self, void const *const buf, size_t const len);
bool process_isrunning(struct process const *const self);
