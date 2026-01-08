/**
 * Frida Single DLL Hooker - 简化版
 * 用于hook单个指定DLL的所有导出函数
 * 
 * 使用方法:
 *   frida -p <PID> -l frida_single_dll_hook.js
 *   
 * 在Frida控制台中执行:
 *   hookDll("target.dll")
 */

"use strict";

// ==================== 配置 ====================
const CONFIG = {
    MAX_ARGS: 6,              // 最大参数数量
    MAX_STR_LEN: 64,          // 字符串最大长度
    
    // 日志配置
    LOG_TO_CONSOLE: true,     // 是否输出到控制台
    LOG_TO_FILE: true,        // 是否发送到文件
    LOG_BUFFER_SIZE: 200,     // 日志缓冲区大小
    
    // 过滤配置
    FILTER_ENABLED: false,
    FILTER_INCLUDE: [],
    FILTER_EXCLUDE: [],
    
    // ===== 性能优化配置 =====
    PERF_MODE: false,          // 性能模式（极简输出）
    SAFE_MODE: false,          // 安全模式（简化内存读取）-- 默认关闭，hook系统DLL时自动开启
    RATE_LIMIT: 0,             // 每秒最大日志数，0=不限制
    SAMPLE_RATE: 1.0,          // 采样率 0.0-1.0，1.0=全部记录
    SKIP_FREQUENT: true,       // 自动跳过高频函数
    FREQUENT_THRESHOLD: 50,    // 高频函数阈值
    DEDUPE_WINDOW: 200,        // 去重窗口
    SIMPLE_FORMAT: false,      // 简化格式
    
    // 自动跳过的高频/危险系统函数
    AUTO_SKIP_FUNCS: [
        // 临界区/锁
        "RtlEnterCriticalSection", "RtlLeaveCriticalSection",
        "RtlTryEnterCriticalSection", "EnterCriticalSection", "LeaveCriticalSection",
        "RtlAcquireSRWLockExclusive", "RtlReleaseSRWLockExclusive",
        "RtlAcquireSRWLockShared", "RtlReleaseSRWLockShared",
        
        // 时间/计数器
        "NtQueryPerformanceCounter", "QueryPerformanceCounter", "QueryPerformanceFrequency",
        "GetTickCount", "GetTickCount64", "NtQuerySystemTime", "GetSystemTimeAsFileTime",
        "RtlQueryPerformanceCounter", "timeGetTime",
        
        // 线程/进程ID
        "GetCurrentThreadId", "GetCurrentProcessId", "GetCurrentThread", "GetCurrentProcess",
        "NtCurrentTeb", "NtCurrentPeb",
        
        // 错误处理
        "GetLastError", "SetLastError", "RtlGetLastWin32Error", "RtlSetLastWin32Error",
        "RtlNtStatusToDosError",
        
        // TLS/FLS
        "TlsGetValue", "TlsSetValue", "FlsGetValue", "FlsSetValue",
        "RtlFlsGetValue", "RtlFlsSetValue",
        
        // 堆操作
        "HeapAlloc", "HeapFree", "HeapReAlloc", "HeapSize",
        "RtlAllocateHeap", "RtlFreeHeap", "RtlReAllocateHeap", "RtlSizeHeap",
        "NtAllocateVirtualMemory", "NtFreeVirtualMemory",
        "VirtualAlloc", "VirtualFree", "VirtualQuery", "VirtualProtect",
        "LocalAlloc", "LocalFree", "GlobalAlloc", "GlobalFree",
        "malloc", "free", "realloc", "calloc",
        
        // 原子操作
        "InterlockedIncrement", "InterlockedDecrement", "InterlockedExchange",
        "InterlockedCompareExchange", "InterlockedExchangeAdd",
        "InitializeSListHead", "RtlInterlockedFlushSList",
        "RtlInterlockedPushEntrySList", "RtlInterlockedPopEntrySList",
        
        // 字符串/内存操作
        "memcpy", "memset", "memmove", "memcmp", "memchr",
        "strlen", "wcslen", "strcpy", "wcscpy", "strncpy", "wcsncpy",
        "strcmp", "wcscmp", "strncmp", "wcsncmp", "stricmp", "wcsicmp",
        "strcat", "wcscat", "strchr", "wcschr", "strstr", "wcsstr",
        "RtlInitUnicodeString", "RtlInitAnsiString", "RtlCopyMemory",
        "RtlMoveMemory", "RtlZeroMemory", "RtlFillMemory",
        "RtlCompareMemory", "RtlEqualMemory",
        
        // 异常处理（绝对不能hook）
        "RtlUnwind", "RtlUnwindEx", "RtlVirtualUnwind", "RtlLookupFunctionEntry",
        "RtlCaptureContext", "RtlRestoreContext", "KiUserExceptionDispatcher",
        "RtlRaiseException", "RtlRaiseStatus", "NtRaiseException",
        "_CxxThrowException", "__CxxFrameHandler", "__CxxFrameHandler3",
        
        // 其他高频
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "OutputDebugStringA", "OutputDebugStringW",
        "NtQueryInformationProcess", "NtQueryInformationThread",
        "DecodePointer", "EncodePointer",
        "RtlEncodePointer", "RtlDecodePointer"
    ]
};

let callId = 0;
let logBuffer = [];
let lastFlushTime = Date.now();

// 性能统计
const perfStats = {
    totalCalls: 0,
    loggedCalls: 0,
    droppedCalls: 0,
    lastSecondCalls: 0,
    lastSecondTime: Date.now(),
    funcCallCounts: new Map(),
    lastCallTime: new Map(),
    frequentFuncs: new Set()
};

// 限流器
let rateTokens = 100;
let lastRateRefill = Date.now();

// 将跳过函数转为Set加速查找
const skipFuncSet = new Set(CONFIG.AUTO_SKIP_FUNCS);

/**
 * 安全读取字符串
 */
function readStr(ptr) {
    if (ptr.isNull()) return null;
    try {
        Memory.readU8(ptr);
        let s = ptr.readCString(CONFIG.MAX_STR_LEN);
        if (s && s.length > 0 && isPrintableStr(s)) return s;
        s = ptr.readUtf16String(CONFIG.MAX_STR_LEN);
        if (s && s.length > 0 && isPrintableStr(s)) return s;
    } catch (e) {}
    return null;
}

/**
 * 检查字符串是否可打印
 */
function isPrintableStr(str) {
    if (!str || str.length === 0) return false;
    let printable = 0;
    for (let i = 0; i < Math.min(str.length, 16); i++) {
        const c = str.charCodeAt(i);
        if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) {
            printable++;
        }
    }
    return printable / Math.min(str.length, 16) > 0.7;
}

/**
 * 将32位整数解析为IEEE 754浮点数
 */
function intToFloat(intVal) {
    const buffer = new ArrayBuffer(4);
    const intView = new Uint32Array(buffer);
    const floatView = new Float32Array(buffer);
    intView[0] = intVal >>> 0;  // 转为无符号
    return floatView[0];
}

/**
 * 将64位整数解析为IEEE 754双精度浮点数
 */
function intToDouble(low, high) {
    const buffer = new ArrayBuffer(8);
    const intView = new Uint32Array(buffer);
    const doubleView = new Float64Array(buffer);
    intView[0] = low >>> 0;
    intView[1] = high >>> 0;
    return doubleView[0];
}

/**
 * 检查浮点数是否合理
 */
function isReasonableFloat(f) {
    if (!isFinite(f)) return false;
    if (isNaN(f)) return false;
    // 排除非常小或非常大的值（可能不是有意的浮点数）
    const abs = Math.abs(f);
    if (abs === 0) return true;
    if (abs < 1e-10 || abs > 1e15) return false;
    return true;
}

/**
 * 尝试将4字节解析为ASCII字符串
 */
function tryParseAsChars(intVal) {
    const chars = [];
    let val = intVal >>> 0;
    for (let i = 0; i < 4; i++) {
        const c = val & 0xFF;
        if (c >= 32 && c < 127) {
            chars.push(String.fromCharCode(c));
        } else {
            return null;
        }
        val = val >>> 8;
    }
    // 反转因为小端序
    return chars.join('');
}

/**
 * 格式化参数 - 完整版（带安全保护）
 */
function fmtArg(arg) {
    try {
        if (arg.isNull()) {
            return "NULL (空)";
        }
        
        const ptrVal = arg.toString();
        
        // 性能模式：只显示地址
        if (CONFIG.PERF_MODE) {
            return ptrVal;
        }
        
        const results = [ptrVal];
        const types = [];
        
        // 获取数值
        let intVal;
        try {
            intVal = arg.toUInt32();
        } catch (e) {
            return ptrVal;
        }
        
        // 安全模式：简化解析，不读取内存
        if (CONFIG.SAFE_MODE) {
            // 小整数直接显示
            if (intVal <= 0xFFFF) {
                if (intVal <= 255) {
                    const c = intVal;
                    if (c >= 32 && c < 127) {
                        return `${ptrVal} (${intVal}, '${String.fromCharCode(c)}') [字符]`;
                    }
                    return `${ptrVal} (${intVal}) [字节]`;
                }
                return `${ptrVal} (${intVal}) [整数]`;
            }
            
            // 尝试解析为浮点数
            const floatVal = intToFloat(intVal);
            if (isReasonableFloat(floatVal)) {
                const rounded = Math.round(floatVal * 1000) / 1000;
                if (rounded !== 0 && Math.abs(floatVal - Math.round(floatVal)) > 0.0001) {
                    return `${ptrVal} | float: ${floatVal.toFixed(4)} [浮点数?]`;
                }
            }
            
            // 尝试解析为4个ASCII字符
            const charsStr = tryParseAsChars(intVal);
            if (charsStr) {
                return `${ptrVal} | chars: "${charsStr}" [FourCC?]`;
            }
            
            // 大整数/句柄
            if (intVal > 0x7FFFFFFF) {
                return `${ptrVal} [句柄?]`;
            }
            
            return `${ptrVal} (${intVal}) [指针?]`;
        }
        
        // === 完整模式：详细解析 ===
        
        // 1. 尝试读取为字符串指针
        try {
            const str = readStr(arg);
            if (str) {
                const displayStr = str.length > 50 ? str.substring(0, 50) + "..." : str;
                types.push("字符串指针");
                return `${ptrVal} -> "${displayStr}" [${types.join(', ')}]`;
            }
        } catch (e) {}
        
        // 2. 检测是否是有效指针
        let isValidPointer = false;
        let memBytes = null;
        try {
            if (intVal > 0x10000 && intVal < 0x7FFFFFFF) {
                Memory.readU8(arg);
                isValidPointer = true;
                
                // 读取前几个字节
                const bytes = [];
                for (let i = 0; i < 16; i++) {
                    try {
                        bytes.push(Memory.readU8(arg.add(i)).toString(16).padStart(2, '0'));
                    } catch (e) { break; }
                }
                if (bytes.length > 0) {
                    memBytes = bytes;
                }
                
                // 尝试读取二级指针
                try {
                    const ptrPtr = arg.readPointer();
                    if (!ptrPtr.isNull() && ptrPtr.toUInt32() > 0x10000) {
                        Memory.readU8(ptrPtr);
                        const innerStr = readStr(ptrPtr);
                        if (innerStr) {
                            types.push("二级指针->字符串");
                            results.push(`*ptr -> "${innerStr.substring(0, 30)}"`);
                        } else {
                            types.push("二级指针");
                            results.push(`*ptr = ${ptrPtr}`);
                        }
                    }
                } catch (e) {}
                
                types.push("指针");
            }
        } catch (e) {}
        
        // 3. 小整数直接显示十进制
        if (intVal <= 0xFFFF && !isValidPointer) {
            const signed = intVal > 0x7FFF ? intVal - 0x10000 : intVal;
            if (intVal <= 255) {
                const c = intVal;
                if (c >= 32 && c < 127) {
                    types.push("字符");
                    return `${ptrVal} (${intVal}, '${String.fromCharCode(c)}') [${types.join(', ')}]`;
                }
                types.push("字节");
            } else {
                types.push("整数");
            }
            if (signed < 0) {
                return `${ptrVal} (${intVal} / ${signed}) [${types.join(', ')}]`;
            }
            return `${ptrVal} (${intVal}) [${types.join(', ')}]`;
        }
        
        // 4. 尝试解析为浮点数
        const floatVal = intToFloat(intVal);
        if (isReasonableFloat(floatVal)) {
            const rounded = Math.round(floatVal * 1000) / 1000;
            if (rounded !== 0 && Math.abs(floatVal - Math.round(floatVal)) > 0.0001) {
                types.push("浮点数?");
                results.push(`float: ${floatVal.toFixed(4)}`);
            }
        }
        
        // 5. 尝试解析为4个ASCII字符 (FourCC等)
        const charsStr = tryParseAsChars(intVal);
        if (charsStr) {
            types.push("FourCC?");
            results.push(`chars: "${charsStr}"`);
        }
        
        // 6. 显示十进制值
        if (intVal <= 0x7FFFFFFF && !isValidPointer) {
            types.push("整数");
            results.push(`int: ${intVal}`);
        }
        
        // 7. 如果是指针，显示内存内容
        if (memBytes && memBytes.length > 0) {
            results.push(`mem: [${memBytes.slice(0, 8).join(' ')}${memBytes.length > 8 ? ' ...' : ''}]`);
        }
        
        // 8. 如果没有识别出类型
        if (types.length === 0) {
            if (intVal > 0x7FFFFFFF) {
                types.push("大整数/句柄?");
            } else {
                types.push("未知");
            }
        }
        
        return `${results.join(' | ')} [${types.join(', ')}]`;
        
    } catch (e) {
        return arg.toString() + " [解析错误]";
    }
}

/**
 * 格式化返回值 - 完整版（带安全保护）
 */
function fmtRetVal(retval) {
    try {
        if (retval.isNull()) {
            return "NULL (0) [失败/空]";
        }
        
        let intVal;
        try {
            intVal = retval.toUInt32();
        } catch (e) {
            return retval.toString();
        }
        
        // 常见返回值
        if (intVal === 0) {
            return `${retval} = 0 [FALSE/失败]`;
        }
        if (intVal === 1) {
            return `${retval} = 1 [TRUE/成功]`;
        }
        if (intVal === 0xFFFFFFFF) {
            return `${retval} = -1 [INVALID_HANDLE/错误]`;
        }
        
        // HRESULT 检查
        if (intVal >= 0x80000000) {
            const signed = intVal - 0x100000000;
            return `${retval} (${signed}) [HRESULT错误: 0x${intVal.toString(16)}]`;
        }
        
        // 性能/安全模式：不读取内存
        if (CONFIG.PERF_MODE || CONFIG.SAFE_MODE) {
            if (intVal <= 0xFFFF) {
                return `${retval} (${intVal}) [返回整数]`;
            }
            return `${retval} [返回值]`;
        }
        
        // 完整模式：检查是否是有效指针
        try {
            if (intVal > 0x10000 && intVal < 0x7FFFFFFF) {
                Memory.readU8(retval);
                const str = readStr(retval);
                if (str) {
                    return `${retval} -> "${str.substring(0, 40)}" [返回字符串指针]`;
                }
                return `${retval} [返回指针]`;
            }
        } catch (e) {}
        
        // 小整数
        if (intVal <= 0xFFFF) {
            return `${retval} (${intVal}) [返回整数]`;
        }
        
        return `${retval} (int: ${intVal}) [返回值]`;
        
    } catch (e) {
        return retval.toString() + " [解析错误]";
    }
}

// ==================== 日志系统 ====================

/**
 * 检查是否应该限流
 */
function checkRateLimit() {
    if (CONFIG.RATE_LIMIT <= 0) return false;
    
    const now = Date.now();
    const elapsed = now - lastRateRefill;
    
    // 每秒补充令牌
    if (elapsed >= 1000) {
        rateTokens = CONFIG.RATE_LIMIT;
        lastRateRefill = now;
    }
    
    if (rateTokens > 0) {
        rateTokens--;
        return false;  // 不限流
    }
    
    return true;  // 限流
}

/**
 * 检查采样
 */
function checkSample() {
    if (CONFIG.SAMPLE_RATE >= 1.0) return true;
    return Math.random() < CONFIG.SAMPLE_RATE;
}

/**
 * 检查是否是高频函数
 */
function isFrequentFunc(funcName) {
    // 静态列表 (使用Set加速)
    if (skipFuncSet.has(funcName)) {
        return true;
    }
    
    // 动态检测
    if (CONFIG.SKIP_FREQUENT && perfStats.frequentFuncs.has(funcName)) {
        return true;
    }
    
    return false;
}

/**
 * 更新函数调用统计
 */
function updateFuncStats(funcName) {
    const now = Date.now();
    
    // 更新每秒统计
    if (now - perfStats.lastSecondTime >= 1000) {
        // 检测高频函数
        if (CONFIG.SKIP_FREQUENT) {
            perfStats.funcCallCounts.forEach((count, fn) => {
                if (count >= CONFIG.FREQUENT_THRESHOLD) {
                    perfStats.frequentFuncs.add(fn);
                }
            });
        }
        perfStats.funcCallCounts.clear();
        perfStats.lastSecondCalls = 0;
        perfStats.lastSecondTime = now;
    }
    
    // 计数
    perfStats.totalCalls++;
    perfStats.lastSecondCalls++;
    const count = (perfStats.funcCallCounts.get(funcName) || 0) + 1;
    perfStats.funcCallCounts.set(funcName, count);
}

/**
 * 检查去重（相同函数短时间内只记录一次）
 */
function checkDedupe(funcName, argsHash) {
    if (CONFIG.DEDUPE_WINDOW <= 0) return true;
    
    const key = funcName + '_' + argsHash;
    const now = Date.now();
    const lastTime = perfStats.lastCallTime.get(key);
    
    if (lastTime && (now - lastTime) < CONFIG.DEDUPE_WINDOW) {
        return false;  // 重复，跳过
    }
    
    perfStats.lastCallTime.set(key, now);
    
    // 定期清理
    if (perfStats.lastCallTime.size > 1000) {
        const cutoff = now - CONFIG.DEDUPE_WINDOW * 2;
        perfStats.lastCallTime.forEach((time, k) => {
            if (time < cutoff) perfStats.lastCallTime.delete(k);
        });
    }
    
    return true;
}

/**
 * 获取时间戳
 */
function getTimestamp() {
    const now = new Date();
    return now.toISOString().replace('T', ' ').substring(0, 23);
}

/**
 * 核心日志函数 - 优化版
 */
function log(message, toFile) {
    // 输出到控制台
    if (CONFIG.LOG_TO_CONSOLE) {
        console.log(message);
    }
    
    // 发送到文件
    if (CONFIG.LOG_TO_FILE && (toFile !== false)) {
        const timestamp = getTimestamp();
        logBuffer.push(`[${timestamp}] ${message}`);
        
        // 批量发送
        const now = Date.now();
        if (logBuffer.length >= CONFIG.LOG_BUFFER_SIZE || (now - lastFlushTime) > 1000) {
            flushLog();
        }
    }
}

/**
 * 刷新日志缓冲区
 */
function flushLog() {
    if (logBuffer.length > 0) {
        send({ type: 'log', data: logBuffer.join('\n') });
        logBuffer = [];
        lastFlushTime = Date.now();
    }
}

/**
 * 简单哈希（用于去重）
 */
function simpleHash(args) {
    let hash = 0;
    for (let i = 0; i < Math.min(args.length, 3); i++) {
        try {
            hash ^= args[i].toInt32();
        } catch(e) {}
    }
    return hash.toString(16);
}

/**
 * 检查函数是否应该被过滤
 */
function shouldFilter(funcName) {
    if (!CONFIG.FILTER_ENABLED) return false;
    
    // 检查排除列表
    for (const exc of CONFIG.FILTER_EXCLUDE) {
        if (funcName.toLowerCase().includes(exc.toLowerCase())) {
            return true;
        }
    }
    
    // 检查包含列表
    if (CONFIG.FILTER_INCLUDE.length > 0) {
        for (const inc of CONFIG.FILTER_INCLUDE) {
            if (funcName.toLowerCase().includes(inc.toLowerCase())) {
                return false;
            }
        }
        return true;
    }
    
    return false;
}

/**
 * 获取参数对应的寄存器/位置名称
 * Windows x64: RCX, RDX, R8, R9, [rsp+0x20], [rsp+0x28], ...
 * Windows x86: [esp+0x4], [esp+0x8], ... (stdcall/cdecl都是栈传参)
 */
function getArgLocation(index) {
    if (Process.arch === 'x64') {
        // x64 调用约定: 前4个参数用寄存器
        const regs = ['RCX', 'RDX', 'R8', 'R9'];
        if (index < 4) {
            return regs[index];
        } else {
            // 第5个参数开始在栈上，从RSP+0x28开始（0x20是shadow space）
            const offset = 0x28 + (index - 4) * 8;
            return `[RSP+0x${offset.toString(16).toUpperCase()}]`;
        }
    } else {
        // x86 调用约定: 所有参数都在栈上
        const offset = 0x4 + index * 4;
        return `[ESP+0x${offset.toString(16).toUpperCase()}]`;
    }
}

/**
 * 记录函数调用 - 优化版
 */
function logCall(id, modName, funcName, args) {
    let log_msg;
    
    if (CONFIG.PERF_MODE || CONFIG.SIMPLE_FORMAT) {
        // 简化格式
        const argStr = args.slice(0, 3).map(a => {
            try {
                if (a.isNull()) return '0';
                return a.toString();
            } catch(e) { return '?'; }
        }).join(', ');
        log_msg = `[${id}] ${funcName}(${argStr})`;
    } else {
        // 完整格式，显示寄存器
        log_msg = `>>> [#${id}] ${modName}!${funcName}(`;
        const argStrs = [];
        for (let i = 0; i < args.length; i++) {
            const reg = getArgLocation(i);
            argStrs.push(`\n      arg${i} (${reg}): ${fmtArg(args[i])}`);
        }
        log_msg += argStrs.join(",") + "\n    )";
    }
    
    log(log_msg);
}

/**
 * 记录函数返回 - 优化版
 */
function logReturn(id, funcName, retval) {
    let log_msg;
    const retReg = Process.arch === 'x64' ? 'RAX' : 'EAX';
    
    if (CONFIG.PERF_MODE || CONFIG.SIMPLE_FORMAT) {
        try {
            const ret = retval.isNull() ? '0' : retval.toString();
            log_msg = `[${id}] ${funcName} => ${ret}`;
        } catch(e) {
            log_msg = `[${id}] ${funcName} => ?`;
        }
    } else {
        log_msg = `<<< [#${id}] ${funcName} => (${retReg}) ${fmtRetVal(retval)}\n`;
    }
    
    log(log_msg);
}

// ==================== 配置命令 ====================

/**
 * 启用/禁用控制台输出
 */
function setConsoleLog(enabled) {
    CONFIG.LOG_TO_CONSOLE = !!enabled;
    console.log(`[*] 控制台日志: ${enabled ? '开启' : '关闭'}`);
}

/**
 * 启用/禁用文件日志
 */
function setFileLog(enabled) {
    CONFIG.LOG_TO_FILE = !!enabled;
    console.log(`[*] 文件日志: ${enabled ? '开启' : '关闭'}`);
}

/**
 * 设置过滤器
 */
function setFilter(include, exclude) {
    if (include && include.length > 0) {
        CONFIG.FILTER_INCLUDE = Array.isArray(include) ? include : [include];
    }
    if (exclude && exclude.length > 0) {
        CONFIG.FILTER_EXCLUDE = Array.isArray(exclude) ? exclude : [exclude];
    }
    CONFIG.FILTER_ENABLED = true;
    console.log(`[*] 过滤器已启用`);
    console.log(`    包含: ${CONFIG.FILTER_INCLUDE.join(', ') || '全部'}`);
    console.log(`    排除: ${CONFIG.FILTER_EXCLUDE.join(', ') || '无'}`);
}

/**
 * 清除过滤器
 */
function clearFilter() {
    CONFIG.FILTER_ENABLED = false;
    CONFIG.FILTER_INCLUDE = [];
    CONFIG.FILTER_EXCLUDE = [];
    console.log(`[*] 过滤器已清除`);
}

/**
 * 只输出到文件，不输出到控制台
 */
function quietMode() {
    CONFIG.LOG_TO_CONSOLE = false;
    CONFIG.LOG_TO_FILE = true;
    console.log(`[*] 静默模式: 日志只写入文件`);
}

/**
 * 恢复正常模式
 */
function normalMode() {
    CONFIG.LOG_TO_CONSOLE = true;
    CONFIG.LOG_TO_FILE = true;
    console.log(`[*] 正常模式: 同时输出到控制台和文件`);
}

// ==================== 性能控制命令 ====================

/**
 * 启用性能模式（用于hook系统DLL）
 */
function perfMode(enabled) {
    CONFIG.PERF_MODE = enabled !== false;
    CONFIG.SIMPLE_FORMAT = CONFIG.PERF_MODE;
    CONFIG.SKIP_FREQUENT = CONFIG.PERF_MODE;
    if (CONFIG.PERF_MODE) {
        CONFIG.RATE_LIMIT = 200;
        CONFIG.LOG_TO_CONSOLE = false;
        CONFIG.SAFE_MODE = true;
    } else {
        CONFIG.RATE_LIMIT = 0;
    }
    console.log(`[*] 性能模式: ${CONFIG.PERF_MODE ? '开启' : '关闭'}`);
}

/**
 * 启用安全模式（不读取内存，防止崩溃）
 */
function safeMode(enabled) {
    CONFIG.SAFE_MODE = enabled !== false;
    console.log(`[*] 安全模式: ${CONFIG.SAFE_MODE ? '开启' : '关闭'}`);
    if (CONFIG.SAFE_MODE) {
        console.log(`    (安全模式下不解析指针内容，只显示地址)`);
    }
}

/**
 * 超级安全模式 - 用于hook系统DLL
 */
function ultraSafe() {
    CONFIG.PERF_MODE = true;
    CONFIG.SAFE_MODE = true;
    CONFIG.SIMPLE_FORMAT = true;
    CONFIG.SKIP_FREQUENT = true;
    CONFIG.RATE_LIMIT = 100;
    CONFIG.SAMPLE_RATE = 0.1;
    CONFIG.LOG_TO_CONSOLE = false;
    CONFIG.DEDUPE_WINDOW = 500;
    console.log(`[*] 超级安全模式已启用:`);
    console.log(`    - 限流: 100/秒`);
    console.log(`    - 采样: 10%`);
    console.log(`    - 去重窗口: 500ms`);
    console.log(`    - 只输出到文件`);
}

/**
 * 设置限流（每秒最大日志数）
 */
function setRateLimit(limit) {
    CONFIG.RATE_LIMIT = parseInt(limit) || 0;
    console.log(`[*] 限流: ${CONFIG.RATE_LIMIT > 0 ? CONFIG.RATE_LIMIT + '/秒' : '无限制'}`);
}

/**
 * 设置采样率
 */
function setSampleRate(rate) {
    CONFIG.SAMPLE_RATE = Math.max(0, Math.min(1, parseFloat(rate) || 1));
    console.log(`[*] 采样率: ${(CONFIG.SAMPLE_RATE * 100).toFixed(0)}%`);
}

/**
 * 启用/禁用简化格式
 */
function setSimpleFormat(enabled) {
    CONFIG.SIMPLE_FORMAT = enabled !== false;
    console.log(`[*] 简化格式: ${CONFIG.SIMPLE_FORMAT ? '开启' : '关闭'}`);
}

/**
 * 添加要跳过的函数
 */
function skipFunc(funcName) {
    if (!CONFIG.AUTO_SKIP_FUNCS.includes(funcName)) {
        CONFIG.AUTO_SKIP_FUNCS.push(funcName);
    }
    perfStats.frequentFuncs.add(funcName);
    console.log(`[*] 已添加跳过函数: ${funcName}`);
}

/**
 * 获取性能统计
 */
function getStats() {
    const dropRate = perfStats.totalCalls > 0 
        ? ((perfStats.droppedCalls / perfStats.totalCalls) * 100).toFixed(1) 
        : 0;
    
    console.log(`\n[*] 性能统计:`);
    console.log(`    总调用: ${perfStats.totalCalls}`);
    console.log(`    已记录: ${perfStats.loggedCalls}`);
    console.log(`    已丢弃: ${perfStats.droppedCalls} (${dropRate}%)`);
    console.log(`    当前秒调用: ${perfStats.lastSecondCalls}`);
    console.log(`    高频函数数: ${perfStats.frequentFuncs.size}`);
    if (perfStats.frequentFuncs.size > 0 && perfStats.frequentFuncs.size <= 20) {
        console.log(`    高频函数: ${Array.from(perfStats.frequentFuncs).join(', ')}`);
    }
    console.log(`    限流: ${CONFIG.RATE_LIMIT > 0 ? CONFIG.RATE_LIMIT + '/秒' : '无'}`);
    console.log(`    采样率: ${(CONFIG.SAMPLE_RATE * 100).toFixed(0)}%`);
}

// 已hook的地址集合，避免重复hook
const hookedAddrs = new Set();

/**
 * Hook单个DLL的所有导出函数
 * @param {string} dllName - DLL名称
 * @param {boolean} silent - 是否静默模式（批量hook时使用）
 * @returns {number} 成功hook的函数数量
 */
function hookDll(dllName, silent) {
    const module = Process.findModuleByName(dllName);
    if (!module) {
        console.log(`[-] 未找到模块: ${dllName}`);
        if (!silent) {
            console.log("[*] 已加载的模块:");
            Process.enumerateModules().forEach(m => console.log(`    ${m.name}`));
        }
        return 0;
    }
    
    console.log(`\n[*] Hooking: ${module.name} @ ${module.base}`);
    
    // 检测是否是系统DLL，自动启用性能模式
    const sysModules = ['kernel32', 'ntdll', 'user32', 'gdi32', 'advapi32', 'msvcrt', 'ucrtbase', 'kernelbase'];
    const isSysDll = sysModules.some(s => module.name.toLowerCase().includes(s));
    if (isSysDll) {
        console.log(`[!] 检测到系统DLL，自动启用安全+性能模式`);
        CONFIG.PERF_MODE = true;
        CONFIG.SAFE_MODE = true;
        CONFIG.SIMPLE_FORMAT = true;
        CONFIG.SKIP_FREQUENT = true;
        CONFIG.RATE_LIMIT = 200;
        CONFIG.LOG_TO_CONSOLE = false;
        CONFIG.SAMPLE_RATE = 0.5;
    }
    
    let count = 0;
    let skipped = 0;
    const exports = module.enumerateExports();
    
    for (const exp of exports) {
        if (exp.type !== "function") continue;
        
        // 跳过特殊函数
        if (exp.name.startsWith("Dll") || exp.name.startsWith("_") || exp.name.startsWith("?")) continue;
        
        // 避免重复hook
        const addrStr = exp.address.toString();
        if (hookedAddrs.has(addrStr)) continue;
        
        // 跳过已知高频/危险函数
        if (skipFuncSet.has(exp.name)) {
            skipped++;
            continue;
        }
        
        // 创建闭包捕获变量
        const modName = module.name;
        const funcName = exp.name;
        const funcAddr = exp.address;
        
        try {
            Interceptor.attach(funcAddr, {
                onEnter: function(args) {
                    try {
                        // === 快速检查 ===
                        
                        // 1. 更新统计
                        updateFuncStats(funcName);
                        
                        // 2. 检查是否是高频函数
                        if (isFrequentFunc(funcName)) {
                            this.skip = true;
                            perfStats.droppedCalls++;
                            return;
                        }
                        
                        // 3. 用户过滤器
                        if (shouldFilter(funcName)) {
                            this.skip = true;
                            return;
                        }
                        
                        // 4. 采样检查
                        if (!checkSample()) {
                            this.skip = true;
                            perfStats.droppedCalls++;
                            return;
                        }
                        
                        // 5. 限流检查
                        if (checkRateLimit()) {
                            this.skip = true;
                            perfStats.droppedCalls++;
                            return;
                        }
                        
                        // === 记录 ===
                        this.skip = false;
                        this.id = ++callId;
                        this.name = funcName;
                        this.mod = modName;
                        
                        // 收集参数（安全方式）
                        const argList = [];
                        for (let i = 0; i < CONFIG.MAX_ARGS; i++) {
                            try {
                                argList.push(args[i]);
                            } catch (e) { break; }
                        }
                        
                        // 去重检查
                        if (!checkDedupe(funcName, simpleHash(argList))) {
                            this.skip = true;
                            perfStats.droppedCalls++;
                            return;
                        }
                        
                        perfStats.loggedCalls++;
                        logCall(this.id, modName, funcName, argList);
                        
                    } catch (e) {
                        this.skip = true;
                    }
                },
                onLeave: function(retval) {
                    try {
                        if (this.skip) return;
                        logReturn(this.id, this.name, retval);
                    } catch (e) {
                        // 忽略
                    }
                }
            });
            hookedAddrs.add(addrStr);
            count++;
        } catch (e) {
            // 静默失败
        }
    }
    
    console.log(`[+] ${module.name}: hook ${count} 个函数, 跳过 ${skipped} 个高频函数`);
    if (isSysDll) {
        console.log(`[*] 系统DLL已启用: 安全模式, 采样50%, 限流200/秒, 只输出文件`);
        console.log(`[*] 使用 getStats() 查看统计, setFilter() 过滤函数`);
    } else {
        console.log(`[*] 普通DLL: 完整参数解析已启用`);
        console.log(`[*] 如需简化输出: perfMode(true) 或 safeMode(true)`);
    }
    return count;
}

/**
 * Hook多个DLL
 * @param {string[]} dllNames - DLL名称数组
 * 
 * 使用示例:
 *   hookDlls(["user32.dll", "ws2_32.dll", "wininet.dll"])
 *   hookDlls("user32.dll", "ws2_32.dll")  // 也支持可变参数
 */
function hookDlls(...args) {
    // 支持数组或可变参数
    let dllList = [];
    if (args.length === 1 && Array.isArray(args[0])) {
        dllList = args[0];
    } else {
        dllList = args;
    }
    
    if (dllList.length === 0) {
        console.log("[-] 请提供要hook的DLL列表");
        console.log("    用法: hookDlls(['a.dll', 'b.dll']) 或 hookDlls('a.dll', 'b.dll')");
        return;
    }
    
    console.log(`\n${"=".repeat(60)}`);
    console.log(`[*] 批量Hook ${dllList.length} 个DLL...`);
    console.log(`${"=".repeat(60)}`);
    
    let totalCount = 0;
    let successDlls = 0;
    
    for (const dll of dllList) {
        const count = hookDll(dll, true);
        if (count > 0) {
            successDlls++;
            totalCount += count;
        }
    }
    
    console.log(`\n${"=".repeat(60)}`);
    console.log(`[+] 批量Hook完成!`);
    console.log(`    成功DLL: ${successDlls}/${dllList.length}`);
    console.log(`    总函数数: ${totalCount}`);
    console.log(`${"=".repeat(60)}\n`);
}

/**
 * 按模式匹配hook多个DLL
 * @param {string} pattern - 匹配模式（支持通配符*）
 * 
 * 使用示例:
 *   hookDllsByPattern("ws2*")      // hook所有ws2开头的dll
 *   hookDllsByPattern("*net*")     // hook所有包含net的dll
 */
function hookDllsByPattern(pattern) {
    const regex = new RegExp(
        "^" + pattern.toLowerCase()
            .replace(/\*/g, ".*")
            .replace(/\?/g, ".") + "$"
    );
    
    const matchedDlls = [];
    Process.enumerateModules().forEach(m => {
        if (regex.test(m.name.toLowerCase())) {
            matchedDlls.push(m.name);
        }
    });
    
    if (matchedDlls.length === 0) {
        console.log(`[-] 没有匹配模式 "${pattern}" 的DLL`);
        return;
    }
    
    console.log(`[*] 匹配到 ${matchedDlls.length} 个DLL: ${matchedDlls.join(", ")}`);
    hookDlls(matchedDlls);
}

/**
 * 列出所有模块
 */
function listModules() {
    console.log("\n[*] 已加载模块:");
    Process.enumerateModules().forEach(m => {
        console.log(`  ${m.name.padEnd(40)} @ ${m.base}`);
    });
}

/**
 * 列出模块导出函数
 */
function listExports(dllName) {
    const m = Process.findModuleByName(dllName);
    if (!m) { console.log(`[-] 未找到: ${dllName}`); return; }
    
    console.log(`\n[*] ${m.name} 导出函数:`);
    m.enumerateExports().forEach(e => {
        if (e.type === "function") {
            console.log(`  ${e.name.padEnd(50)} @ ${e.address}`);
        }
    });
}

// 导出到全局 (兼容不同Frida版本)
const g = typeof globalThis !== 'undefined' ? globalThis : this;
g.hookDll = hookDll;
g.hookDlls = hookDlls;
g.hookDllsByPattern = hookDllsByPattern;
g.listModules = listModules;
g.listExports = listExports;
// 日志控制
g.setConsoleLog = setConsoleLog;
g.setFileLog = setFileLog;
g.setFilter = setFilter;
g.clearFilter = clearFilter;
g.quietMode = quietMode;
g.normalMode = normalMode;
g.flushLog = flushLog;
// 性能控制
g.perfMode = perfMode;
g.safeMode = safeMode;
g.ultraSafe = ultraSafe;
g.setRateLimit = setRateLimit;
g.setSampleRate = setSampleRate;
g.setSimpleFormat = setSimpleFormat;
g.skipFunc = skipFunc;
g.getStats = getStats;

// 同时通过rpc导出 (注意: Frida会自动转为小写)
rpc.exports = {
    hookdll: hookDll,
    hookdlls: function(dlls) { 
        if (Array.isArray(dlls)) {
            return hookDlls.apply(null, dlls);
        }
        return hookDll(dlls);
    },
    hookdllsbypattern: hookDllsByPattern,
    listmodules: listModules,
    listexports: listExports,
    setconsolelog: setConsoleLog,
    setfilelog: setFileLog,
    flushlog: flushLog,
    quietmode: quietMode,
    normalmode: normalMode,
    setfilter: setFilter,
    clearfilter: clearFilter,
    // 性能控制
    perfmode: perfMode,
    safemode: safeMode,
    ultrasafe: ultraSafe,
    setratelimit: setRateLimit,
    setsamplerate: setSampleRate,
    setsimpleformat: setSimpleFormat,
    skipfunc: skipFunc,
    getstats: getStats,
    // eval函数
    eval: function(code) {
        try {
            return eval(code);
        } catch (e) {
            return "Error: " + e.message;
        }
    }
};

console.log(`
╔════════════════════════════════════════════════════════════════════════════╗
║              Frida DLL Function Hooker - 高性能安全版                      ║
╠════════════════════════════════════════════════════════════════════════════╣
║  进程架构: ${Process.arch.toUpperCase().padEnd(6)} ${Process.arch === 'x64' ? '(参数: RCX,RDX,R8,R9,栈)' : '(参数: 栈)'}                         ║
╠════════════════════════════════════════════════════════════════════════════╣
║  Hook命令:                                                                 ║
║    hookDll("target.dll")              - Hook单个DLL                       ║
║    hookDlls("a.dll", "b.dll")         - Hook多个DLL                       ║
║    hookDllsByPattern("ws2*")          - 按通配符模式Hook                  ║
║                                                                            ║
║  查看命令:                                                                 ║
║    listModules()                      - 列出所有已加载模块                 ║
║    listExports("xxx.dll")             - 列出指定DLL的导出函数             ║
║                                                                            ║
║  日志控制:                                                                 ║
║    quietMode()                        - 静默模式(只写文件)                ║
║    normalMode()                       - 正常模式                          ║
║    flushLog()                         - 刷新日志缓冲区                    ║
║                                                                            ║
║  过滤器:                                                                   ║
║    setFilter(["Read","Write"], [])    - 只记录包含关键字的函数            ║
║    clearFilter()                      - 清除过滤器                        ║
║                                                                            ║
║  性能/安全控制 (Hook系统DLL必用!):                                        ║
║    ultraSafe()                        - 超级安全模式(推荐系统DLL使用)     ║
║    perfMode(true)                     - 性能模式                          ║
║    safeMode(true)                     - 安全模式(不读内存)                ║
║    setRateLimit(100)                  - 限流: 每秒最多100条               ║
║    setSampleRate(0.1)                 - 采样: 只记录10%                   ║
║    skipFunc("funcName")               - 跳过指定函数                      ║
║    getStats()                         - 查看性能统计                      ║
║                                                                            ║
║  ⚠️  Hook kernel32/ntdll等系统DLL时会自动启用安全模式                     ║
║  ⚠️  如仍然崩溃，先执行 ultraSafe() 再hook                                ║
╚════════════════════════════════════════════════════════════════════════════╝
`);

// 显示已加载模块
listModules();