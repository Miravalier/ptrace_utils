#include <ptrace_utils.h>

enum parameter_e {
    SP_INT,
    SP_LONG,
    SP_PTR,
    SP_SIZE_T
};

struct syscall_parameter {
    int count;
    enum parameter_e types[6];
};

struct syscall_parameter syscall_parameter_table[] = {
    {3, {SP_INT, SP_PTR, SP_SIZE_T}},   // SYS_read
    {3, {SP_INT, SP_PTR, SP_SIZE_T}},   // SYS_write
    {3, {SP_PTR, SP_INT, SP_INT}},      // SYS_open
    {1, {SP_INT}},                      // SYS_close
    {2, {SP_PTR, SP_PTR}},              // SYS_stat
    {2, {SP_INT, SP_PTR}},              // SYS_fstat
    {2, {SP_PTR, SP_PTR}},              // SYS_lstat
    {3, {SP_PTR, SP_SIZE_T, SP_INT}},   // SYS_poll
    {3, {SP_INT, SP_SIZE_T, SP_INT}},   // SYS_lseek
    {6, {SP_PTR, SP_SIZE_T, SP_INT, SP_INT, SP_INT, SP_SIZE_T}},   // SYS_mmap
    {3, {SP_PTR, SP_SIZE_T, SP_INT}},   // SYS_mprotect
    {2, {SP_PTR, SP_SIZE_T}},           // SYS_munmap
    {1, {SP_PTR}},                      // SYS_brk
    {0},                                // UNDEFINED 13
    {0},                                // UNDEFINED 14
    {0},                                // UNDEFINED 15
    {0},                                // UNDEFINED 16
    {0},                                // UNDEFINED 17
    {0},                                // UNDEFINED 18
    {0},                                // UNDEFINED 19
    {0},                                // UNDEFINED 20
    {0},                                // UNDEFINED 21
    {0},                                // UNDEFINED 22
    {0},                                // UNDEFINED 23
    {0},                                // UNDEFINED 24
    {0},                                // UNDEFINED 25
    {0},                                // UNDEFINED 26
    {0},                                // UNDEFINED 27
    {0},                                // UNDEFINED 28
    {0},                                // UNDEFINED 29
    {0},                                // UNDEFINED 30
    {0},                                // UNDEFINED 31
    {0},                                // UNDEFINED 32
    {0},                                // UNDEFINED 33
    {0},                                // UNDEFINED 34
    {0},                                // UNDEFINED 35
    {0},                                // UNDEFINED 36
    {0},                                // UNDEFINED 37
    {0},                                // UNDEFINED 38
    {0},                                // UNDEFINED 39
    {0},                                // UNDEFINED 40
    {3, {SP_INT, SP_INT, SP_INT}},      // SYS_socket
    {3, {SP_INT, SP_PTR, SP_SIZE_T}},   // SYS_connect
    {3, {SP_INT, SP_PTR, SP_PTR}},      // SYS_accept
    {0},                                // UNDEFINED 44
    {0},                                // UNDEFINED 45
    {0},                                // UNDEFINED 46
    {0},                                // UNDEFINED 47
    {0},                                // UNDEFINED 48
    {3, {SP_INT, SP_PTR, SP_SIZE_T}},   // SYS_bind
    {2, {SP_INT, SP_INT}},              // SYS_listen
    {0},                                // UNDEFINED 51
    {0},                                // UNDEFINED 52
    {0},                                // UNDEFINED 53
    {0},                                // UNDEFINED 54
    {0},                                // UNDEFINED 55
    {0},                                // UNDEFINED 56
    {0},                                // UNDEFINED 57
    {0},                                // UNDEFINED 58
    {0},                                // UNDEFINED 59
    {0},                                // UNDEFINED 60
    {0},                                // UNDEFINED 61
    {0},                                // UNDEFINED 62
    {0},                                // UNDEFINED 63
    {0},                                // UNDEFINED 64
    {0},                                // UNDEFINED 65
    {0},                                // UNDEFINED 66
    {0},                                // UNDEFINED 67
    {0},                                // UNDEFINED 68
    {0},                                // UNDEFINED 69
    {0},                                // UNDEFINED 70
    {0},                                // UNDEFINED 71
    {0},                                // UNDEFINED 72
    {0},                                // UNDEFINED 73
    {0},                                // UNDEFINED 74
    {0},                                // UNDEFINED 75
    {0},                                // UNDEFINED 76
    {0},                                // UNDEFINED 77
    {0},                                // UNDEFINED 78
    {0},                                // UNDEFINED 79
    {0},                                // UNDEFINED 80
    {0},                                // UNDEFINED 81
    {0},                                // UNDEFINED 82
    {0},                                // UNDEFINED 83
    {0},                                // UNDEFINED 84
    {0},                                // UNDEFINED 85
    {0},                                // UNDEFINED 86
    {0},                                // UNDEFINED 87
    {0},                                // UNDEFINED 88
    {0},                                // UNDEFINED 89
    {0},                                // UNDEFINED 90
    {0},                                // UNDEFINED 91
    {0},                                // UNDEFINED 92
    {0},                                // UNDEFINED 93
    {0},                                // UNDEFINED 94
    {0},                                // UNDEFINED 95
    {0},                                // UNDEFINED 96
    {0},                                // UNDEFINED 97
    {0},                                // UNDEFINED 98
    {0},                                // UNDEFINED 99
    {0},                                // UNDEFINED 100
    {0},                                // UNDEFINED 101
    {0},                                // UNDEFINED 102
    {0},                                // UNDEFINED 103
    {0},                                // UNDEFINED 104
    {0},                                // UNDEFINED 105
    {0},                                // UNDEFINED 106
    {0},                                // UNDEFINED 107
    {0},                                // UNDEFINED 108
    {0},                                // UNDEFINED 109
    {0},                                // UNDEFINED 110
    {0},                                // UNDEFINED 111
    {0},                                // UNDEFINED 112
    {0},                                // UNDEFINED 113
    {0},                                // UNDEFINED 114
    {0},                                // UNDEFINED 115
    {0},                                // UNDEFINED 116
    {0},                                // UNDEFINED 117
    {0},                                // UNDEFINED 118
    {0},                                // UNDEFINED 119
    {0},                                // UNDEFINED 120
    {0},                                // UNDEFINED 121
    {0},                                // UNDEFINED 122
    {0},                                // UNDEFINED 123
    {0},                                // UNDEFINED 124
    {0},                                // UNDEFINED 125
    {0},                                // UNDEFINED 126
    {0},                                // UNDEFINED 127
    {0},                                // UNDEFINED 128
    {0},                                // UNDEFINED 129
    {0},                                // UNDEFINED 130
    {0},                                // UNDEFINED 131
    {0},                                // UNDEFINED 132
    {0},                                // UNDEFINED 133
    {0},                                // UNDEFINED 134
    {0},                                // UNDEFINED 135
    {0},                                // UNDEFINED 136
    {0},                                // UNDEFINED 137
    {0},                                // UNDEFINED 138
    {0},                                // UNDEFINED 139
    {0},                                // UNDEFINED 140
    {0},                                // UNDEFINED 141
    {0},                                // UNDEFINED 142
    {0},                                // UNDEFINED 143
    {0},                                // UNDEFINED 144
    {0},                                // UNDEFINED 145
    {0},                                // UNDEFINED 146
    {0},                                // UNDEFINED 147
    {0},                                // UNDEFINED 148
    {0},                                // UNDEFINED 149
    {0},                                // UNDEFINED 150
    {0},                                // UNDEFINED 151
    {0},                                // UNDEFINED 152
    {0},                                // UNDEFINED 153
    {0},                                // UNDEFINED 154
    {0},                                // UNDEFINED 155
    {0},                                // UNDEFINED 156
    {0},                                // UNDEFINED 157
    {0},                                // UNDEFINED 158
    {0},                                // UNDEFINED 159
    {0},                                // UNDEFINED 160
    {0},                                // UNDEFINED 161
    {0},                                // UNDEFINED 162
    {0},                                // UNDEFINED 163
    {0},                                // UNDEFINED 164
    {0},                                // UNDEFINED 165
    {0},                                // UNDEFINED 166
    {0},                                // UNDEFINED 167
    {0},                                // UNDEFINED 168
    {0},                                // UNDEFINED 169
    {0},                                // UNDEFINED 170
    {0},                                // UNDEFINED 171
    {0},                                // UNDEFINED 172
    {0},                                // UNDEFINED 173
    {0},                                // UNDEFINED 174
    {0},                                // UNDEFINED 175
    {0},                                // UNDEFINED 176
    {0},                                // UNDEFINED 177
    {0},                                // UNDEFINED 178
    {0},                                // UNDEFINED 179
    {0},                                // UNDEFINED 180
    {0},                                // UNDEFINED 181
    {0},                                // UNDEFINED 182
    {0},                                // UNDEFINED 183
    {0},                                // UNDEFINED 184
    {0},                                // UNDEFINED 185
    {0},                                // UNDEFINED 186
    {0},                                // UNDEFINED 187
    {0},                                // UNDEFINED 188
    {0},                                // UNDEFINED 189
    {0},                                // UNDEFINED 190
    {0},                                // UNDEFINED 191
    {0},                                // UNDEFINED 192
    {0},                                // UNDEFINED 193
    {0},                                // UNDEFINED 194
    {0},                                // UNDEFINED 195
    {0},                                // UNDEFINED 196
    {0},                                // UNDEFINED 197
    {0},                                // UNDEFINED 198
    {0},                                // UNDEFINED 199
    {0},                                // UNDEFINED 200
    {0},                                // UNDEFINED 201
    {0},                                // UNDEFINED 202
    {0},                                // UNDEFINED 203
    {0},                                // UNDEFINED 204
    {0},                                // UNDEFINED 205
    {0},                                // UNDEFINED 206
    {0},                                // UNDEFINED 207
    {0},                                // UNDEFINED 208
    {0},                                // UNDEFINED 209
    {0},                                // UNDEFINED 210
    {0},                                // UNDEFINED 211
    {0},                                // UNDEFINED 212
    {0},                                // UNDEFINED 213
    {0},                                // UNDEFINED 214
    {0},                                // UNDEFINED 215
    {0},                                // UNDEFINED 216
    {0},                                // UNDEFINED 217
    {0},                                // UNDEFINED 218
    {0},                                // UNDEFINED 219
    {0},                                // UNDEFINED 220
    {0},                                // UNDEFINED 221
    {0},                                // UNDEFINED 222
    {0},                                // UNDEFINED 223
    {0},                                // UNDEFINED 224
    {0},                                // UNDEFINED 225
    {0},                                // UNDEFINED 226
    {0},                                // UNDEFINED 227
    {0},                                // UNDEFINED 228
    {0},                                // UNDEFINED 229
    {0},                                // UNDEFINED 230
    {0},                                // UNDEFINED 231
    {0},                                // UNDEFINED 232
    {0},                                // UNDEFINED 233
    {0},                                // UNDEFINED 234
    {0},                                // UNDEFINED 235
    {0},                                // UNDEFINED 236
    {0},                                // UNDEFINED 237
    {0},                                // UNDEFINED 238
    {0},                                // UNDEFINED 239
    {0},                                // UNDEFINED 240
    {0},                                // UNDEFINED 241
    {0},                                // UNDEFINED 242
    {0},                                // UNDEFINED 243
    {0},                                // UNDEFINED 244
    {0},                                // UNDEFINED 245
    {0},                                // UNDEFINED 246
    {0},                                // UNDEFINED 247
    {0},                                // UNDEFINED 248
    {0},                                // UNDEFINED 249
    {0},                                // UNDEFINED 250
    {0},                                // UNDEFINED 251
    {0},                                // UNDEFINED 252
    {0},                                // UNDEFINED 253
    {0},                                // UNDEFINED 254
    {0},                                // UNDEFINED 255
    {0},                                // UNDEFINED 256
    {0},                                // UNDEFINED 257
    {0},                                // UNDEFINED 258
    {0},                                // UNDEFINED 259
    {0},                                // UNDEFINED 260
    {0},                                // UNDEFINED 261
    {0},                                // UNDEFINED 262
    {0},                                // UNDEFINED 263
    {0},                                // UNDEFINED 264
    {0},                                // UNDEFINED 265
    {0},                                // UNDEFINED 266
    {0},                                // UNDEFINED 267
    {0},                                // UNDEFINED 268
    {0},                                // UNDEFINED 269
    {0},                                // UNDEFINED 270
    {0},                                // UNDEFINED 271
    {0},                                // UNDEFINED 272
    {0},                                // UNDEFINED 273
    {0},                                // UNDEFINED 274
    {0},                                // UNDEFINED 275
    {0},                                // UNDEFINED 276
    {0},                                // UNDEFINED 277
    {0},                                // UNDEFINED 278
    {0},                                // UNDEFINED 279
    {0},                                // UNDEFINED 280
    {0},                                // UNDEFINED 281
    {0},                                // UNDEFINED 282
    {0},                                // UNDEFINED 283
    {0},                                // UNDEFINED 284
    {0},                                // UNDEFINED 285
    {0},                                // UNDEFINED 286
    {0},                                // UNDEFINED 287
    {0},                                // UNDEFINED 288
    {0},                                // UNDEFINED 289
    {0},                                // UNDEFINED 290
    {0},                                // UNDEFINED 291
    {0},                                // UNDEFINED 292
    {0},                                // UNDEFINED 293
    {0},                                // UNDEFINED 294
    {0},                                // UNDEFINED 295
    {0},                                // UNDEFINED 296
    {0},                                // UNDEFINED 297
    {0},                                // UNDEFINED 298
    {0},                                // UNDEFINED 299
    {0},                                // UNDEFINED 300
    {0},                                // UNDEFINED 301
    {0},                                // UNDEFINED 302
    {0},                                // UNDEFINED 303
    {0},                                // UNDEFINED 304
    {0},                                // UNDEFINED 305
    {0},                                // UNDEFINED 306
    {0},                                // UNDEFINED 307
    {0},                                // UNDEFINED 308
    {0},                                // UNDEFINED 309
    {0},                                // UNDEFINED 310
    {0},                                // UNDEFINED 311
    {0},                                // UNDEFINED 312
    {0},                                // UNDEFINED 313
    {0},                                // UNDEFINED 314
    {0},                                // UNDEFINED 315
    {0},                                // UNDEFINED 316
    {0},                                // UNDEFINED 317
    {0},                                // UNDEFINED 318
    {0},                                // UNDEFINED 319
    {0},                                // UNDEFINED 320
    {0},                                // UNDEFINED 321
    {0},                                // UNDEFINED 322
    {0},                                // UNDEFINED 323
    {0},                                // UNDEFINED 324
    {0},                                // UNDEFINED 325
    {0},                                // UNDEFINED 326
    {0},                                // UNDEFINED 327
    {0},                                // UNDEFINED 328
    {0},                                // UNDEFINED 329
    {0},                                // UNDEFINED 330
    {0},                                // UNDEFINED 331
    {0},                                // UNDEFINED 332
    {0},                                // UNDEFINED 333
    {0},                                // UNDEFINED 334
    {0},                                // UNDEFINED 335
    {0},                                // UNDEFINED 336
    {0},                                // UNDEFINED 337
    {0},                                // UNDEFINED 338
    {0},                                // UNDEFINED 339
    {0},                                // UNDEFINED 340
    {0},                                // UNDEFINED 341
    {0},                                // UNDEFINED 342
    {0},                                // UNDEFINED 343
    {0},                                // UNDEFINED 344
    {0},                                // UNDEFINED 345
    {0},                                // UNDEFINED 346
    {0},                                // UNDEFINED 347
    {0},                                // UNDEFINED 348
    {0},                                // UNDEFINED 349
    {0},                                // UNDEFINED 350
    {0},                                // UNDEFINED 351
    {0},                                // UNDEFINED 352
    {0},                                // UNDEFINED 353
    {0},                                // UNDEFINED 354
    {0},                                // UNDEFINED 355
    {0},                                // UNDEFINED 356
    {0},                                // UNDEFINED 357
    {0},                                // UNDEFINED 358
    {0},                                // UNDEFINED 359
    {0},                                // UNDEFINED 360
    {0},                                // UNDEFINED 361
    {0},                                // UNDEFINED 362
    {0},                                // UNDEFINED 363
    {0},                                // UNDEFINED 364
    {0},                                // UNDEFINED 365
    {0},                                // UNDEFINED 366
    {0},                                // UNDEFINED 367
    {0},                                // UNDEFINED 368
    {0},                                // UNDEFINED 369
    {0},                                // UNDEFINED 370
    {0},                                // UNDEFINED 371
    {0},                                // UNDEFINED 372
    {0},                                // UNDEFINED 373
    {0},                                // UNDEFINED 374
    {0},                                // UNDEFINED 375
    {0},                                // UNDEFINED 376
    {0},                                // UNDEFINED 377
    {0},                                // UNDEFINED 378
    {0},                                // UNDEFINED 379
    {0},                                // UNDEFINED 380
    {0},                                // UNDEFINED 381
    {0},                                // UNDEFINED 382
    {0},                                // UNDEFINED 383
    {0},                                // UNDEFINED 384
    {0},                                // UNDEFINED 385
    {0},                                // UNDEFINED 386
    {0},                                // UNDEFINED 387
    {0},                                // UNDEFINED 388
    {0},                                // UNDEFINED 389
    {0},                                // UNDEFINED 390
    {0},                                // UNDEFINED 391
    {0},                                // UNDEFINED 392
    {0},                                // UNDEFINED 393
    {0},                                // UNDEFINED 394
    {0},                                // UNDEFINED 395
    {0},                                // UNDEFINED 396
    {0},                                // UNDEFINED 397
    {0},                                // UNDEFINED 398
    {0},                                // UNDEFINED 399
    {0},                                // UNDEFINED 400
    {0},                                // UNDEFINED 401
    {0},                                // UNDEFINED 402
    {0},                                // UNDEFINED 403
    {0},                                // UNDEFINED 404
    {0},                                // UNDEFINED 405
    {0},                                // UNDEFINED 406
    {0},                                // UNDEFINED 407
    {0},                                // UNDEFINED 408
    {0},                                // UNDEFINED 409
    {0},                                // UNDEFINED 410
    {0},                                // UNDEFINED 411
    {0},                                // UNDEFINED 412
    {0},                                // UNDEFINED 413
    {0},                                // UNDEFINED 414
    {0},                                // UNDEFINED 415
    {0},                                // UNDEFINED 416
    {0},                                // UNDEFINED 417
    {0},                                // UNDEFINED 418
    {0},                                // UNDEFINED 419
    {0},                                // UNDEFINED 420
    {0},                                // UNDEFINED 421
    {0},                                // UNDEFINED 422
    {0},                                // UNDEFINED 423
    {0},                                // UNDEFINED 424
    {0},                                // UNDEFINED 425
    {0},                                // UNDEFINED 426
    {0},                                // UNDEFINED 427
    {0},                                // UNDEFINED 428
    {0},                                // UNDEFINED 429
    {0},                                // UNDEFINED 430
    {0},                                // UNDEFINED 431
    {0},                                // UNDEFINED 432
    {0},                                // UNDEFINED 433
    {0},                                // UNDEFINED 434
    {0}                                 // UNDEFINED 435
};

bool ptrace_inject_syscall(pid_t pid, unsigned long long *result, int syscall, ...)
{
    // Get starting registers
    reg_t registers;
    if (!ptrace_get_registers(pid, &registers))
    {
        ERROR_PUTS("Failed to get registers");
        return false;
    }

    // Construct modified registers
    reg_t modified_registers = registers;
    modified_registers.gp.rax = (unsigned long long)syscall;

    // Set up syscall parameters
    unsigned long long *parameter_locations[] = {
        &modified_registers.gp.rdi,
        &modified_registers.gp.rsi,
        &modified_registers.gp.rdx,
        &modified_registers.gp.r10,
        &modified_registers.gp.r8,
        &modified_registers.gp.r9
    };
    const struct syscall_parameter *params = &syscall_parameter_table[syscall];
    va_list args;
    va_start(args, syscall);
    for (int i=0; i < params->count; i++)
    {
        unsigned long long arg;
        switch (params->types[i])
        {
            case SP_INT:
                arg = (unsigned long long)va_arg(args, int);
            break;
            case SP_LONG:
                arg = (unsigned long long)va_arg(args, long);
            break;
            case SP_PTR:
                arg = (unsigned long long)((uintptr_t)va_arg(args, void*));
            break;
            case SP_SIZE_T:
                arg = (unsigned long long)va_arg(args, size_t);
            break;
            default:
                va_end(args);
                return false;
        }
        *parameter_locations[i] = arg;
    }
    va_end(args);

    // Apply modified registers
    if (!ptrace_set_registers(pid, &modified_registers))
    {
        ERROR_PUTS("Failed to set registers");
        return false;
    }

    // Inject the shellcode
    uint8_t syscall_instructions[] = {0x0F, 0x05, 0xCC}; // syscall, int3
    if (!ptrace_inject_shellcode(pid, syscall_instructions, sizeof syscall_instructions))
    {
        ERROR_PUTS("Failed to inject shellcode");
        return false;
    }

    // Get return value
    if (result != NULL)
    {
        if (!ptrace_get_registers(pid, &modified_registers))
        {
            ERROR_PUTS("Failed to get registers");
            return false;
        }
        *result = modified_registers.gp.rax;
    }

    // Restore starting registers
    if (!ptrace_set_registers(pid, &registers))
    {
        ERROR_PUTS("Failed to restore registers");
        return false;
    }

    return true;
}

bool ptrace_inject_shellcode(pid_t pid, uint8_t *shellcode, size_t bytes)
{
    // Make sure this shellcode fits in libc entry
    if (bytes > 32)
    {
        ERROR_PRINTF("injecting too many shellcode bytes: '%zu'\n", bytes);
        return false;
    }

    // Find libc entry point
    map_t *maps = get_memory_maps(pid);
    if (maps == NULL)
    {
        ERROR_PRINTF("unable to get memory maps\n");
        return false;
    }
    uintptr_t libc_entry_point = find_libc_entry(maps);
    if (libc_entry_point == 0)
    {
        ERROR_PRINTF("unable to get libc entry point\n");
        return false;
    }
    free_memory_maps(maps);

    // Save libc instructions
    uint8_t instructions[32];
    if (!ptrace_read_memory(pid, instructions, libc_entry_point, bytes))
    {
        ERROR_PRINTF("unable to read libc entry instructions\n");
        return false;
    }
    
    // Overwrite libc instructions with shellcode
    if (!ptrace_write_memory(pid, shellcode, libc_entry_point, bytes))
    {
        ERROR_PRINTF("unable to write over libc entry instructions\n");
        return false;
    }

    // Set RIP to point to the shellcode
    reg_t registers;
    if (!ptrace_get_registers(pid, &registers))
    {
        ERROR_PRINTF("unable to get registers\n");
        return false;
    }
    registers.gp.rip = (unsigned long long)libc_entry_point;
    if (!ptrace_set_registers(pid, &registers))
    {
        ERROR_PRINTF("unable to set registers\n");
        return false;
    }

    // Wait for a breakpoint to hit in the shellcode
    if (!ptrace_continue(pid))
    {
        ERROR_PRINTF("error on shellcode inject continue\n");
        return false;
    }

    // Restore libc instructions
    if (!ptrace_write_memory(pid, instructions, libc_entry_point, bytes))
    {
        ERROR_PRINTF("error on restore libc entry memory\n");
        return false;
    }
    
    return true;
}
