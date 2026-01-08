#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Frida DLL Hooker 日志加载器
用于加载Frida脚本并将hook日志保存到文件

使用方法:
    python frida_loader.py -n 进程名 -o log.txt         # 直接附加到进程
    python frida_loader.py -p PID -o log.txt            # 通过PID附加
    python frida_loader.py -f "C:\\path\\target.exe"    # 启动并附加
    python frida_loader.py -w 进程名 -o log.txt         # 等待进程启动后附加
    python frida_loader.py -w 进程名 -t 60 -o log.txt   # 等待进程，超时60秒
    python frida_loader.py -l                           # 列出所有进程
    python frida_loader.py -l -q view                   # 列出包含view的进程
"""

import frida
import sys
import argparse
import os
from datetime import datetime
import threading
import time

class FridaHookLoader:
    def __init__(self, script_path, log_file):
        self.script_path = script_path
        self.log_file = log_file
        self.session = None
        self.script = None
        self.log_handle = None
        self.log_count = 0
        self.lock = threading.Lock()
        self.running = True
        
    def open_log(self):
        """打开日志文件"""
        self.log_handle = open(self.log_file, 'w', encoding='utf-8', buffering=1)
        self.log_handle.write(f"{'='*70}\n")
        self.log_handle.write(f"Frida Hook Log - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.log_handle.write(f"{'='*70}\n\n")
        print(f"[*] 日志文件: {os.path.abspath(self.log_file)}")
        
    def close_log(self):
        """关闭日志文件"""
        if self.log_handle:
            self.log_handle.write(f"\n{'='*70}\n")
            self.log_handle.write(f"日志结束 - 共 {self.log_count} 条记录\n")
            self.log_handle.write(f"{'='*70}\n")
            self.log_handle.close()
            print(f"\n[*] 日志已保存: {self.log_file} ({self.log_count} 条记录)")
    
    def write_log(self, data):
        """写入日志"""
        with self.lock:
            if self.log_handle:
                self.log_handle.write(data + '\n')
                self.log_count += data.count('>>>')
    
    def on_message(self, message, data):
        """处理Frida消息"""
        if message['type'] == 'send':
            payload = message['payload']
            if isinstance(payload, dict) and payload.get('type') == 'log':
                self.write_log(payload['data'])
            elif isinstance(payload, str):
                print(payload)
            else:
                print(payload)
        elif message['type'] == 'error':
            print(f"[!] Error: {message['stack']}")
    
    def on_detached(self, reason):
        """进程分离回调"""
        print(f"\n[*] 进程已分离: {reason}")
        self.running = False
    
    def load_script(self):
        """加载Frida脚本"""
        with open(self.script_path, 'r', encoding='utf-8') as f:
            script_code = f.read()
        
        self.script = self.session.create_script(script_code)
        self.script.on('message', self.on_message)
        self.script.load()
        print(f"[+] 脚本已加载: {self.script_path}")
    
    def attach_process(self, process):
        """附加到进程"""
        try:
            if isinstance(process, int):
                self.session = frida.attach(process)
                print(f"[+] 已附加到PID: {process}")
            else:
                self.session = frida.attach(process)
                print(f"[+] 已附加到进程: {process}")
            
            self.session.on('detached', self.on_detached)
            return True
        except frida.ProcessNotFoundError:
            print(f"[-] 进程未找到: {process}")
            return False
        except Exception as e:
            print(f"[-] 附加失败: {e}")
            return False
    
    def spawn_process(self, program):
        """启动并附加进程"""
        try:
            pid = frida.spawn(program)
            self.session = frida.attach(pid)
            self.session.on('detached', self.on_detached)
            print(f"[+] 已启动进程: {program} (PID: {pid})")
            return pid
        except Exception as e:
            print(f"[-] 启动失败: {e}")
            return None
    
    def resume(self, pid):
        """恢复进程执行"""
        frida.resume(pid)
        print(f"[+] 进程已恢复执行")
    
    def wait_for_process(self, process_name, timeout=0, interval=0.5):
        """
        等待进程启动
        
        Args:
            process_name: 进程名称
            timeout: 超时时间（秒），0表示无限等待
            interval: 检查间隔（秒）
        
        Returns:
            成功返回PID，超时或中断返回None
        """
        print(f"[*] 等待进程启动: {process_name}")
        print(f"[*] 按 Ctrl+C 取消等待...")
        
        start_time = time.time()
        dots = 0
        device = frida.get_local_device()
        
        while True:
            try:
                # 获取所有进程
                processes = device.enumerate_processes()
                
                # 查找匹配的进程
                for proc in processes:
                    # 精确匹配
                    if proc.name.lower() == process_name.lower():
                        print(f"\n[+] 发现进程: {proc.name} (PID: {proc.pid})")
                        return proc.pid
                    # 部分匹配
                    if process_name.lower() in proc.name.lower():
                        print(f"\n[+] 发现匹配进程: {proc.name} (PID: {proc.pid})")
                        return proc.pid
                
                # 检查超时
                if timeout > 0:
                    elapsed = time.time() - start_time
                    if elapsed >= timeout:
                        print(f"\n[-] 等待超时 ({timeout}秒)")
                        return None
                    remaining = timeout - elapsed
                    sys.stdout.write(f"\r[*] 等待中{'.' * (dots % 4):<4} (剩余 {remaining:.0f}秒)   ")
                else:
                    sys.stdout.write(f"\r[*] 等待中{'.' * (dots % 4):<4} (已等待 {time.time()-start_time:.0f}秒)   ")
                
                sys.stdout.flush()
                dots += 1
                
                time.sleep(interval)
                
            except KeyboardInterrupt:
                print("\n[*] 用户取消等待")
                return None
            except Exception as e:
                print(f"\n[-] 错误: {e}")
                return None
    
    def list_processes(self, filter_str=None):
        """列出所有进程"""
        try:
            device = frida.get_local_device()
            processes = device.enumerate_processes()
            
            print(f"\n{'='*60}")
            print(f" {'PID':<10} {'进程名':<40}")
            print(f"{'='*60}")
            
            count = 0
            for proc in sorted(processes, key=lambda x: x.name.lower()):
                if filter_str:
                    if filter_str.lower() not in proc.name.lower():
                        continue
                print(f" {proc.pid:<10} {proc.name:<40}")
                count += 1
            
            print(f"{'='*60}")
            print(f" 共 {count} 个进程")
            if filter_str:
                print(f" (过滤: {filter_str})")
            print()
            
        except Exception as e:
            print(f"[-] 获取进程列表失败: {e}")
    
    def call_rpc(self, method, *args):
        """调用RPC方法"""
        try:
            # Frida RPC方法名自动转为小写
            func = getattr(self.script.exports_sync, method.lower())
            return func(*args)
        except Exception as e:
            print(f"[-] RPC调用失败: {e}")
            return None
    
    def run_interactive(self):
        """交互模式"""
        self.print_help()
        
        while self.running:
            try:
                cmd = input("\n>>> ").strip()
                # cmd = "hooks wwsls.dll wwsl.dll intspt.dll wwclintf.dll ssleay32.dll libeay32.dll ws2_32.dll kernel32.dll".strip()
                if not cmd:
                    continue
                    
                # 解析命令
                if cmd.lower() in ('quit', 'exit', 'q'):
                    break
                elif cmd.lower() == 'help':
                    self.print_help()
                elif cmd.lower() == 'modules' or cmd.lower() == 'listmodules()':
                    self.call_rpc('listmodules')
                elif cmd.lower() == 'quiet' or cmd.lower() == 'quietmode()':
                    self.call_rpc('quietmode')
                elif cmd.lower() == 'normal' or cmd.lower() == 'normalmode()':
                    self.call_rpc('normalmode')
                elif cmd.lower() == 'flush' or cmd.lower() == 'flushlog()':
                    self.call_rpc('flushlog')
                elif cmd.lower() == 'clearfilter()' or cmd.lower() == 'clearfilter':
                    self.call_rpc('clearfilter')
                elif cmd.lower() == 'stats' or cmd.lower() == 'getstats()':
                    self.call_rpc('getstats')
                elif cmd.lower() == 'perf' or cmd.lower() == 'perfmode()':
                    self.call_rpc('perfmode', True)
                elif cmd.lower() == 'noperf':
                    self.call_rpc('perfmode', False)
                elif cmd.lower() == 'safe' or cmd.lower() == 'safemode()':
                    self.call_rpc('safemode', True)
                elif cmd.lower() == 'nosafe':
                    self.call_rpc('safemode', False)
                elif cmd.lower() == 'ultrasafe' or cmd.lower() == 'ultrasafe()':
                    self.call_rpc('ultrasafe')
                elif cmd.lower() == 'simple':
                    self.call_rpc('setsimpleformat', True)
                elif cmd.lower() == 'full':
                    self.call_rpc('setsimpleformat', False)
                elif cmd.startswith('rate ') or cmd.lower().startswith('setratelimit('):
                    rate = self.parse_int_arg(cmd)
                    if rate is not None:
                        self.call_rpc('setratelimit', rate)
                elif cmd.startswith('sample ') or cmd.lower().startswith('setsamplerate('):
                    rate = self.parse_float_arg(cmd)
                    if rate is not None:
                        self.call_rpc('setsamplerate', rate)
                elif cmd.startswith('skip ') or cmd.lower().startswith('skipfunc('):
                    func = self.parse_string_arg(cmd)
                    if func:
                        self.call_rpc('skipfunc', func)
                elif cmd.startswith('hook ') or cmd.lower().startswith('hookdll('):
                    dll = self.parse_string_arg(cmd)
                    if dll:
                        self.call_rpc('hookdll', dll)
                elif cmd.startswith('hooks ') or cmd.lower().startswith('hookdlls('):
                    dlls = self.parse_multi_args(cmd)
                    if dlls:
                        self.call_rpc('hookdlls', dlls)
                elif cmd.startswith('pattern ') or cmd.lower().startswith('hookdllsbypattern('):
                    pattern = self.parse_string_arg(cmd)
                    if pattern:
                        self.call_rpc('hookdllsbypattern', pattern)
                elif cmd.startswith('exports ') or cmd.lower().startswith('listexports('):
                    dll = self.parse_string_arg(cmd)
                    if dll:
                        self.call_rpc('listexports', dll)
                elif cmd.startswith('filter ') or cmd.lower().startswith('setfilter('):
                    inc, exc = self.parse_filter_args(cmd)
                    self.call_rpc('setfilter', inc, exc)
                else:
                    # 尝试直接eval
                    try:
                        result = self.call_rpc('eval', cmd)
                        if result and result != 'undefined':
                            print(result)
                    except:
                        print(f"[-] 未知命令: {cmd}")
                        print("    输入 'help' 查看帮助")
                    
            except EOFError:
                break
            except KeyboardInterrupt:
                print("\n[*] 收到中断信号")
                break
        
        # 刷新日志
        try:
            self.call_rpc('flushlog')
        except:
            pass
        
        self.close_log()
    
    def parse_int_arg(self, cmd):
        """解析整数参数"""
        import re
        match = re.search(r'(\d+)', cmd)
        if match:
            return int(match.group(1))
        return None
    
    def parse_float_arg(self, cmd):
        """解析浮点数参数"""
        import re
        match = re.search(r'([\d.]+)', cmd)
        if match:
            return float(match.group(1))
        return None
    
    def parse_string_arg(self, cmd):
        """解析单个字符串参数"""
        import re
        # 匹配 "xxx" 或 'xxx' 或 直接的单词
        match = re.search(r'["\']([^"\']+)["\']', cmd)
        if match:
            return match.group(1)
        # 尝试空格分隔
        parts = cmd.split(None, 1)
        if len(parts) > 1:
            return parts[1].strip('"\'() ')
        return None
    
    def parse_multi_args(self, cmd):
        """解析多个字符串参数"""
        import re
        # 匹配所有 "xxx" 或 'xxx'
        matches = re.findall(r'["\']([^"\']+)["\']', cmd)
        if matches:
            return matches
        # 尝试空格分隔
        parts = cmd.split()[1:]  # 跳过命令本身
        return [p.strip('"\'(),') for p in parts if p.strip('"\'(),')]
    
    def parse_filter_args(self, cmd):
        """解析过滤器参数: filter +Read +Write -Query"""
        import re
        include = []
        exclude = []
        
        # 检查是否是 setFilter([...], [...]) 格式
        match = re.search(r'setFilter\s*\(\s*\[(.*?)\]\s*,\s*\[(.*?)\]\s*\)', cmd)
        if match:
            inc_str, exc_str = match.groups()
            include = [s.strip().strip('"\'') for s in inc_str.split(',') if s.strip()]
            exclude = [s.strip().strip('"\'') for s in exc_str.split(',') if s.strip()]
        else:
            # filter +Read -Query 格式
            parts = cmd.split()[1:]
            for p in parts:
                p = p.strip()
                if p.startswith('+'):
                    include.append(p[1:])
                elif p.startswith('-'):
                    exclude.append(p[1:])
                else:
                    include.append(p)
        
        return include, exclude
    
    def print_help(self):
        """打印帮助信息"""
        print("""
╔══════════════════════════════════════════════════════════════════════════╗
║                    交互命令帮助                                          ║
╠══════════════════════════════════════════════════════════════════════════╣
║  Hook命令:                                                               ║
║    hook target.dll                   - Hook单个DLL                      ║
║    hooks a.dll b.dll c.dll           - Hook多个DLL                      ║
║    pattern ws2*                      - 按通配符模式Hook                 ║
║                                                                          ║
║  查看命令:                                                               ║
║    modules                           - 列出所有已加载模块                ║
║    exports target.dll                - 列出DLL导出函数                  ║
║    stats                             - 查看性能统计                     ║
║                                                                          ║
║  日志控制:                                                               ║
║    quiet                             - 静默模式(只写文件)               ║
║    normal                            - 正常模式                         ║
║    flush                             - 刷新日志缓冲区                   ║
║                                                                          ║
║  过滤器:                                                                 ║
║    filter +Read +Write               - 只记录包含关键字的               ║
║    filter -Query -Get                - 排除包含关键字的                 ║
║    clearfilter                       - 清除过滤器                       ║
║                                                                          ║
║  ⚠️ 性能/安全控制 (Hook系统DLL必用!):                                   ║
║    ultrasafe                         - 超级安全模式(强烈推荐!)          ║
║    perf / noperf                     - 开启/关闭性能模式                ║
║    safe / nosafe                     - 开启/关闭安全模式                ║
║    rate 100                          - 限流: 每秒最多100条              ║
║    sample 0.1                        - 采样: 只记录10%                  ║
║    simple / full                     - 简化/完整输出格式                ║
║    skip FuncName                     - 跳过指定函数                     ║
║                                                                          ║
║  其他:                                                                   ║
║    help                              - 显示此帮助                       ║
║    quit / exit                       - 退出                             ║
╚══════════════════════════════════════════════════════════════════════════╝
        """)


def main():
    parser = argparse.ArgumentParser(
        description='Frida DLL Hooker 日志加载器',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
    %(prog)s -n notepad.exe -o notepad_log.txt
    %(prog)s -p 1234 -o output.log
    %(prog)s -f "C:\\app\\target.exe" -o trace.txt
    %(prog)s -w view.exe -o log.txt                # 等待进程启动
    %(prog)s -w view.exe -t 60 -o log.txt          # 等待进程，超时60秒
    %(prog)s -l                                     # 列出所有进程
    %(prog)s -l -q view                            # 列出包含view的进程
        '''
    )
    
    target = parser.add_mutually_exclusive_group(required=False)
    target.add_argument('-n', '--name', help='目标进程名')
    target.add_argument('-p', '--pid', type=int, help='目标进程PID')
    target.add_argument('-f', '--file', help='要启动的可执行文件')
    target.add_argument('-w', '--wait', help='等待进程启动后附加')
    target.add_argument('-l', '--list', action='store_true', help='列出所有运行中的进程')
    
    parser.add_argument('-t', '--timeout', type=int, default=0,
                       help='等待超时时间(秒)，0=无限等待 (默认: 0)')
    parser.add_argument('-q', '--query', help='进程列表过滤关键字')
    parser.add_argument('-s', '--script', 
                       default='frida_single_dll_hook.js',
                       help='Frida脚本路径 (默认: frida_single_dll_hook.js)')
    parser.add_argument('-o', '--output',
                       default='hook_log.txt',
                       help='日志输出文件 (默认: hook_log.txt)')
    
    args = parser.parse_args()
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║           Frida DLL Hooker - Python Loader                   ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    # 列出进程模式
    if args.list:
        loader = FridaHookLoader(args.script, args.output)
        loader.list_processes(args.query)
        return
    
    # 检查是否指定了目标
    if not any([args.name, args.pid, args.file, args.wait]):
        parser.print_help()
        print("\n[-] 请指定目标: -n/--name, -p/--pid, -f/--file, 或 -w/--wait")
        sys.exit(1)
    
    # 检查脚本文件
    if not os.path.exists(args.script):
        print(f"[-] 脚本文件不存在: {args.script}")
        sys.exit(1)
    
    loader = FridaHookLoader(args.script, args.output)
    loader.open_log()
    
    # 附加或启动进程
    if args.pid:
        if not loader.attach_process(args.pid):
            sys.exit(1)
    elif args.name:
        if not loader.attach_process(args.name):
            sys.exit(1)
    elif args.wait:
        # 等待进程启动
        pid = loader.wait_for_process(args.wait, timeout=args.timeout)
        if not pid:
            sys.exit(1)
        # 短暂延迟让进程完全初始化
        print("[*] 等待进程初始化...")
        time.sleep(0.5)
        if not loader.attach_process(pid):
            sys.exit(1)
    elif args.file:
        pid = loader.spawn_process(args.file)
        if not pid:
            sys.exit(1)
        loader.load_script()
        loader.resume(pid)
        loader.run_interactive()
        return
    
    loader.load_script()
    loader.run_interactive()


if __name__ == '__main__':
    main()