# Linux 内核防御图详解 (面向安全新手)

本文档详细解释 Linux 内核防御图中的所有概念、实现原理以及攻击者如何利用这些漏洞。

## 目录

1. [漏洞类型 (Vulnerabilities)](#1-漏洞类型-vulnerabilities)
2. [利用技术 (Exploitation Techniques)](#2-利用技术-exploitation-techniques)
3. [防御技术 (Defence Technologies)](#3-防御技术-defence-technologies)
4. [漏洞检测机制 (Bug Detection Mechanisms)](#4-漏洞检测机制-bug-detection-mechanisms)

---

## 1. 漏洞类型 (Vulnerabilities)

### 1.1 栈深度溢出 (Stack Depth Overflow) - CWE-674

**概念**: 当函数递归调用过深或局部变量过大时，导致栈空间耗尽。

**实现原理**:
- Linux 内核为每个线程分配有限的内核栈空间 (通常 8KB 或 16KB)
- 每次函数调用都会在栈上分配返回地址、参数和局部变量
- 深度递归或大量局部变量会快速消耗栈空间

**攻击方式**:
```c
// 攻击示例：构造深度递归
void recursive_function(int depth) {
    char large_buffer[4096];  // 大量栈空间
    if (depth > 0) {
        recursive_function(depth - 1);  // 递归调用
    }
}
// 攻击者通过系统调用触发深度递归，导致栈溢出
```

**利用方法**:
1. 找到可以触发深度调用链的系统调用路径
2. 栈溢出后可能覆盖相邻内存区域
3. 可用于绕过安全检查或执行任意代码

---

### 1.2 整数溢出/下溢 (Int Overflow/Underflow) - CWE-190/191

**概念**: 算术运算结果超出整数类型的表示范围。

**实现原理**:
```c
// 整数溢出示例
unsigned int size = UINT_MAX;  // 4294967295
size = size + 1;                // 结果变为 0 (溢出)

// 整数下溢示例
unsigned int count = 0;
count = count - 1;              // 结果变为 UINT_MAX (下溢)
```

**攻击方式**:
```c
// 常见漏洞场景：大小检查绕过
void vulnerable_copy(size_t user_size) {
    size_t total = user_size + sizeof(header);  // 可能溢出!
    char *buf = kmalloc(total, GFP_KERNEL);     // 分配小缓冲区
    copy_from_user(buf, user_data, user_size);  // 复制大量数据 -> 堆溢出!
}
// 攻击者输入: user_size = 0xFFFFFFFF - sizeof(header) + 1
```

**利用方法**:
1. 找到整数运算后用于内存分配的代码路径
2. 构造特殊值使运算结果溢出
3. 获得比预期更小的缓冲区，后续写入造成堆溢出

---

### 1.3 Use-After-Free (UAF) - CWE-416

**概念**: 内存释放后继续使用该内存指针。

**实现原理**:
```c
struct object *obj = kmalloc(sizeof(*obj), GFP_KERNEL);
obj->data = sensitive_info;
// ... 某处释放了 obj
kfree(obj);
// ... 代码继续使用 obj (UAF!)
int value = obj->data;  // 危险：读取已释放内存
obj->callback();        // 危险：可能执行恶意代码
```

**攻击方式**:
1. **堆喷射 (Heap Spraying)**: 释放后，分配大量相同大小的对象占据该内存
2. **类型混淆**: 用不同类型的对象覆盖原内存位置
3. **函数指针劫持**: 覆盖对象中的函数指针

```c
// 攻击场景
kfree(obj);  // obj->ops 指向函数表

// 攻击者分配恶意对象占据相同内存
struct evil_obj *evil = kmalloc(sizeof(*obj), GFP_KERNEL);
evil->fake_ops = &attacker_controlled_ops;

// 后续调用触发攻击者控制的代码
obj->ops->callback(obj);  // 调用攻击者的函数!
```

**利用方法**:
1. 识别释放和使用之间的时间窗口
2. 通过堆喷射控制释放的内存内容
3. 劫持函数指针实现代码执行

---

### 1.4 Double Free - CWE-415

**概念**: 同一块内存被释放两次。

**实现原理**:
```c
void *ptr = kmalloc(size, GFP_KERNEL);
kfree(ptr);
// ... 某处又释放了 ptr
kfree(ptr);  // Double Free!
```

**攻击方式**:
- Double Free 会破坏堆分配器的内部数据结构 (freelist)
- 攻击者可以利用这种破坏实现任意内存分配

```c
// 典型攻击流程
void *A = kmalloc(size);  // A 指向块 X
kfree(A);                  // X 加入 freelist
kfree(A);                  // X 再次加入 freelist (链表被破坏)

// 后续分配
void *B = kmalloc(size);  // 返回 X
void *C = kmalloc(size);  // 也返回 X (同一块内存!)
// 攻击者控制 B 和 C 指向同一内存
```

**利用方法**:
1. 触发 Double Free 破坏 freelist
2. 获得指向同一内存的两个指针
3. 利用类型混淆或数据篡改

---

### 1.5 竞争条件 (Race Condition) - CWE-362

**概念**: 多个执行流对共享资源的并发访问导致意外行为。

**实现原理**:
```c
// TOCTOU (Time-of-Check to Time-of-Use) 漏洞
if (access(filename, R_OK) == 0) {  // 检查权限
    // --- 攻击者在此处替换文件 (符号链接攻击) ---
    fd = open(filename, O_RDONLY);   // 打开文件
    // 可能打开了不同的文件!
}
```

**攻击方式**:
```c
// 内核中的竞争条件示例
void syscall_handler(struct user_buffer *ubuf) {
    size_t len = ubuf->length;        // 第一次读取用户空间
    if (len > MAX_SIZE) return -E2BIG;
    
    // --- 攻击者在另一CPU上修改 ubuf->length ---
    
    copy_from_user(kbuf, ubuf->data, ubuf->length);  // 第二次读取用户空间
    // 可能复制超过 MAX_SIZE 的数据!
}
```

**利用方法**:
1. 创建多线程同时操作共享资源
2. 利用 CPU 时序在检查和使用之间修改数据
3. 常配合符号链接攻击或用户空间内存修改

---

### 1.6 未定义行为 (Undefined Behaviour) - CWE-758

**概念**: C 语言标准未定义的操作，编译器可以任意处理。

**实现原理**:
```c
// 未定义行为示例
int *ptr = NULL;
*ptr = 42;              // 空指针解引用

int a = INT_MAX;
a = a + 1;              // 有符号整数溢出

int arr[10];
arr[10] = 0;            // 数组越界

char *str;              // 未初始化
printf("%s", str);      // 使用未初始化变量
```

**攻击方式**:
- 编译器优化可能删除看似"安全"的检查代码
- 未定义行为可能被编译器假设为"不可能发生"

```c
// 危险：编译器可能删除空指针检查
void dangerous(int *ptr) {
    int value = *ptr;              // 解引用 ptr
    if (ptr == NULL) return;       // 编译器可能删除这个检查!
    // 因为上面已经解引用了 ptr，所以 ptr "肯定不为 NULL"
}
```

---

### 1.7 类型混淆 (Type Confusion) - CWE-843

**概念**: 将对象作为错误的类型访问。

**实现原理**:
```c
struct type_A { int data; void (*func)(void); };
struct type_B { char buffer[8]; };

void *obj = get_object();  // 返回 type_A
struct type_B *wrong = (struct type_B *)obj;  // 错误类型转换

// 写入 wrong->buffer 会覆盖 obj->func 指针!
wrong->buffer[4] = 'A';  // 破坏函数指针
```

**攻击方式**:
```c
// 在堆上制造类型混淆
kfree(obj_A);  // 释放 type_A 对象
// 立即分配相同大小的 type_B 对象
struct type_B *obj_B = kmalloc(sizeof(struct type_B), GFP_KERNEL);

// 如果残留的 type_A 指针被使用
obj_A->func();  // 调用被 obj_B 数据覆盖的"函数指针"
```

---

### 1.8 Double Fetch - CWE-367

**概念**: 从用户空间多次读取同一数据，两次读取之间数据被修改。

**实现原理**:
```c
// 内核中的 Double Fetch 漏洞
int vulnerable_syscall(struct user_data __user *udata) {
    size_t size;
    get_user(size, &udata->size);        // 第一次读取
    if (size > MAX_SIZE) return -EINVAL;  // 检查
    
    // --- 攻击者在另一个 CPU 上修改 udata->size ---
    
    char *buf = kmalloc(size, GFP_KERNEL);
    get_user(size, &udata->size);         // 第二次读取 (可能不同!)
    copy_from_user(buf, udata->data, size);  // 使用第二次的值
    // 可能导致缓冲区溢出!
}
```

**攻击方式**:
1. 创建两个线程
2. 线程1: 反复调用系统调用
3. 线程2: 反复修改用户空间数据
4. 等待时机命中检查和使用之间的窗口

---

### 1.9 内存泄漏 (Memory Leak) - CWE-401

**概念**: 分配的内存没有被正确释放。

**实现原理**:
```c
void leaky_function(void) {
    char *buf = kmalloc(1024, GFP_KERNEL);
    if (some_error_condition)
        return;  // 忘记释放 buf!
    kfree(buf);
}
```

**攻击方式**:
- 反复触发内存泄漏可以耗尽系统内存 (DoS 攻击)
- 某些情况下泄漏的内存可能包含敏感信息

---

### 1.10 信息泄露 (Info Exposure) - CWE-200

**概念**: 敏感信息被泄露给未授权方。

**实现原理**:
```c
// 栈信息泄露
void info_leak(char __user *out) {
    struct data {
        char name[16];
        int flags;      // 可能未初始化
        void *ptr;      // 可能包含内核地址!
    } d;
    
    strcpy(d.name, "test");  // 只初始化 name
    copy_to_user(out, &d, sizeof(d));  // 泄露未初始化数据!
}
```

**攻击方式**:
1. 获取内核地址可以绕过 KASLR
2. 获取栈布局可以帮助构造 ROP 链
3. 获取堆布局可以帮助堆利用

---

### 1.11 未初始化内存使用 (Uninitialized Memory Usage) - CWE-908

**概念**: 使用未初始化的内存变量。

**实现原理**:
```c
void vulnerable(void) {
    char buffer[256];    // 未初始化
    int value;           // 未初始化
    
    if (condition)
        value = 1;
    // else 分支缺失，value 可能未被初始化
    
    if (value == 1) {    // 使用可能未初始化的值!
        // ...
    }
}
```

**攻击方式**:
```c
// 利用未初始化的栈内存
// 攻击者先调用函数 A，在栈上留下特定数据
void setup_attack(void) {
    char payload[256];
    memcpy(payload, evil_data, 256);
    // 函数返回，payload 留在栈上
}

// 然后调用漏洞函数，使用上一个函数留下的栈数据
void vulnerable(void) {
    char buffer[256];    // 继承了 setup_attack 的数据!
    use(buffer);
}
```

---

### 1.12 空指针解引用 (NULL Pointer Dereference) - CWE-476

**概念**: 对空指针进行解引用操作。

**实现原理**:
```c
struct object *get_object(int id);  // 可能返回 NULL

void vulnerable(int id) {
    struct object *obj = get_object(id);
    // 缺少 NULL 检查
    obj->callback(obj);  // 如果 obj 为 NULL，崩溃!
}
```

**攻击方式**:
- 在旧内核版本中，用户可以 mmap 零地址页面
- 将零页映射为攻击者控制的内容
- 空指针解引用会读取/执行攻击者控制的数据

```c
// 历史攻击 (现代系统已防护)
mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_ANONYMOUS, -1, 0);
// 在零地址放置恶意数据结构
// 触发内核空指针解引用 -> 使用攻击者数据
```

---

### 1.13 越界访问 (Out-of-Bounds Access)

#### 堆越界 (Heap OOB) - CWE-122

```c
char *buf = kmalloc(100, GFP_KERNEL);
// 越界读取
char leak = buf[150];        // 读取相邻对象数据
// 越界写入
buf[150] = 'X';              // 覆盖相邻对象数据
```

#### 栈越界 (Stack OOB) - CWE-121

```c
void vulnerable(void) {
    char buffer[64];
    gets(buffer);            // 没有长度检查
    // 可以覆盖返回地址!
}
```

#### 全局变量越界 - CWE-119

```c
int global_array[10];
int global_secret = 12345;

int leak(int index) {
    // 如果 index >= 10，可以访问 global_secret
    return global_array[index];
}
```

**攻击方式**:
1. 越界读取: 泄露敏感信息
2. 越界写入: 修改关键数据结构
3. 栈溢出: 覆盖返回地址劫持控制流

---

### 1.14 死锁 (Deadlock) - CWE-833

**概念**: 多个线程互相等待对方持有的锁，导致永久阻塞。

```c
// 死锁示例
// 线程 A                    // 线程 B
lock(A);                     lock(B);
lock(B);  // 等待 B          lock(A);  // 等待 A
// 互相等待，永久阻塞!
```

---

### 1.15 无限循环 (Infinite Loop) - CWE-835

**概念**: 程序陷入无法退出的循环。

```c
while (user_controlled_condition) {
    // 攻击者可以让条件永远为真
    // 导致 DoS
}
```

---

### 1.16 瞬态执行漏洞 (Transient Execution Vulnerabilities) - CWE-514

**概念**: CPU 推测执行和乱序执行导致的侧信道泄露。

**Spectre/Meltdown 攻击原理**:
```c
// Spectre v1 示例
if (x < array1_size) {            // 边界检查
    y = array2[array1[x] * 256];  // 越界访问
}

// 攻击流程:
// 1. 训练 CPU 分支预测器预测条件为真
// 2. 传入越界的 x 值
// 3. CPU 推测执行越界访问 (实际不应执行)
// 4. 推测执行改变了 CPU 缓存状态
// 5. 通过缓存时序侧信道读取秘密数据
```

---

### 1.17 熵不足 (Insufficient Entropy) - CWE-331

**概念**: 随机数生成器没有足够的随机性。

```c
// 弱随机数导致可预测性
// 使用线性同余生成器 (LCG) 算法，常数来自 glibc
unsigned int weak_random(void) {
    static unsigned int seed = 0;
    // 1103515245 (乘数) 和 12345 (增量) 是 LCG 的标准参数
    // 这种算法是确定性的，容易被预测
    seed = seed * 1103515245 + 12345;  // 可预测!
    return seed;
}
```

**攻击方式**:
- 预测 ASLR 地址
- 预测网络协议序列号
- 预测加密密钥

---

## 2. 利用技术 (Exploitation Techniques)

### 2.1 控制流劫持技术

#### 2.1.1 Return Address Overwrite (返回地址覆盖)

**概念**: 通过栈溢出覆盖函数返回地址。

**栈布局图示**:
```
高地址
+----------------------+
|   调用者栈帧         |
+----------------------+
|   返回地址           | <-- 攻击目标 (被溢出覆盖)
+----------------------+
|   保存的 RBP         |
+----------------------+
|   局部变量           | <-- 缓冲区起始位置
|   (如 buffer[64])    |
+----------------------+
低地址

溢出攻击示例:
```
```c
char buf[64];
read(fd, buf, 200);  // 溢出覆盖返回地址
```

---

#### 2.1.2 ROP/JOP/COP (Return/Jump/Call Oriented Programming)

**概念**: 利用程序中已存在的代码片段 (gadget) 构造攻击。

**ROP 原理**:
```
正常执行: main() -> func_a() -> func_b() -> ret

ROP 攻击: 
栈上布置一系列返回地址:
+------------------+
| gadget1_addr     | -> pop rdi; ret
+------------------+
| "/bin/sh" 地址   | -> 作为 rdi 参数
+------------------+
| gadget2_addr     | -> call system
+------------------+

每个 gadget 以 ret 结尾，串联成任意计算
```

**JOP (Jump Oriented Programming)**:
- 使用以 jmp 结尾的 gadget
- 需要一个"dispatcher gadget"来驱动执行

**COP (Call Oriented Programming)**:
- 使用以 call 结尾的 gadget

---

#### 2.1.3 ret2usr (Return to User)

**概念**: 将内核执行流劫持到用户空间代码。

```c
// 用户空间准备恶意代码
void shellcode(void) {
    commit_creds(prepare_kernel_cred(0));  // 提权
}

// 在用户空间设置好 shellcode
// 通过漏洞将内核返回地址/函数指针改为用户空间地址
// 内核执行跳转到用户空间代码 (以 ring0 权限运行!)
```

**防御**: SMEP (Supervisor Mode Execution Prevention)

---

#### 2.1.4 ret2dir (Return to Direct-mapped Memory)

**概念**: 利用 physmap (直接映射区) 绕过 SMEP。

```
内核虚拟地址空间:
+---------------------------+
| 内核代码 (.text)          | <-- SMEP 保护
+---------------------------+
| 直接映射区 (physmap)      | <-- 映射所有物理内存
+---------------------------+  

攻击原理:
1. 用户空间分配页面，写入 shellcode
2. 该页面有对应的物理内存
3. physmap 也映射了该物理内存
4. 跳转到 physmap 中的地址执行 shellcode (绕过 SMEP)
```

---

### 2.2 堆布局控制技术

#### 2.2.1 Heap Grooming (堆布局塑造)

**概念**: 通过大量分配/释放操作使堆达到可预测状态。

```c
// 攻击步骤:
// 1. 清空 slab cache
for (int i = 0; i < 1000; i++)
    spray[i] = kmalloc(TARGET_SIZE, GFP_KERNEL);

// 2. 释放一些对象创造空洞
for (int i = 0; i < 1000; i += 2)
    kfree(spray[i]);

// 3. 触发漏洞，漏洞对象分配在空洞中
trigger_vulnerability();

// 4. 漏洞对象与攻击者控制的对象相邻
```

---

#### 2.2.2 Slab Cache Slot Reuse (Slab 缓存槽重用)

**概念**: 利用相同大小的对象分配到同一 slab cache。

```c
// 漏洞对象类型
struct victim {
    int data;
    void (*callback)(void);  // offset: 8
};  // size: 16

// 攻击者可控对象
struct controlled {
    unsigned long fake_data;
    unsigned long evil_ptr;  // 对应 callback 位置
};  // size: 16

// 释放 victim 后立即分配 controlled
// controlled 占据相同内存位置
// 修改 evil_ptr 劫持 callback
```

---

#### 2.2.3 Cross-Cache Attack (跨缓存攻击)

**概念**: 利用页面级别的内存复用在不同 slab cache 之间进行攻击。

```
攻击流程:
1. 喷射大量对象，使目标 slab cache 分配新页面
2. 释放这些对象，使页面返回页分配器
3. 从另一个 slab cache 分配，复用同一页面
4. 利用残留数据或跨 cache 的 UAF
```

---

### 2.3 数据覆盖技术

#### 2.3.1 Kernel Objects Corruption (内核对象破坏)

**概念**: 覆盖内核中的关键数据结构。

```c
// 常见攻击目标:
// 1. task_struct 中的 cred 指针
task->cred = &init_cred;  // 提升为 root 权限

// 2. file_operations 函数指针表
fops->read = evil_read;

// 3. modprobe_path 全局变量
strcpy(modprobe_path, "/tmp/evil");
// 触发模块加载 -> 执行 /tmp/evil
```

---

#### 2.3.2 Allocator Data Corruption (分配器数据破坏)

**概念**: 破坏堆分配器的内部数据结构。

```c
// SLUB freelist 攻击
// freelist 是空闲对象链表，存储在对象自身中

// 正常 freelist:
// [obj1] -> [obj2] -> [obj3] -> NULL

// 通过 UAF 覆盖 obj2 的 next 指针
// [obj1] -> [obj2] -> [攻击者控制地址] -> ???

// 下一次 kmalloc() 可能返回任意地址!
```

---

#### 2.3.3 'ops' Structures Overwrite (操作结构体覆盖)

**概念**: 覆盖内核中的函数指针表。

```c
// 内核中有大量 *_operations 结构体
struct file_operations {
    ssize_t (*read)(struct file *, char __user *, size_t, loff_t *);
    ssize_t (*write)(struct file *, const char __user *, size_t, loff_t *);
    // ...
};

// 攻击: 将函数指针改为攻击者控制的值
// 当内核调用 fops->read() 时执行恶意代码
```

---

### 2.4 其他利用技术

#### 2.4.1 Finding Kernel Objects (查找内核对象)

**概念**: 定位内核中关键数据结构的地址。

**技术**:
1. **信息泄露**: 通过漏洞泄露内核地址
2. **边信道**: 通过时序差异推断地址
3. **暴力破解**: 对 KASLR 进行猜测

---

#### 2.4.2 JIT Abuse (JIT 滥用)

**概念**: 利用即时编译器生成恶意代码。

```c
// BPF JIT 攻击
// 构造特殊的 BPF 程序
// JIT 编译后产生意外的机器码序列
// 利用这些"隐藏"的指令进行攻击
```

---

#### 2.4.3 WX Area Abuse (可写可执行区域滥用)

**概念**: 利用同时可写可执行的内存区域。

```c
// 如果某区域是 WX (可写可执行):
memcpy(wx_area, shellcode, sizeof(shellcode));  // 写入代码
((void(*)())wx_area)();                          // 执行代码
```

---

#### 2.4.4 Kernel Space Mirroring Attack (KSMA - 内核空间镜像攻击)

**概念**: 利用内核页表修改实现任意内存访问。

```
攻击原理:
1. 定位 swapper_pg_dir (内核页表)
2. 修改页表项，创建新的映射
3. 通过新映射读写任意物理内存
```

---

#### 2.4.5 Userspace Data Access (用户空间数据访问)

**概念**: 内核错误地访问用户空间数据作为内核数据。

```c
// 如果 SMAP 被绕过或未启用
struct kernel_ops *ops = (struct kernel_ops *)user_address;
ops->callback();  // 调用用户控制的函数指针
```

---

#### 2.4.6 DMA Attack (DMA 攻击)

**概念**: 通过 DMA 直接访问系统内存，绕过 CPU 和 OS。

```
攻击场景:
1. 恶意 PCIe 设备 (如 Thunderbolt 设备)
2. 被攻陷的固件
3. 恶意 DMA 请求

攻击效果:
- 直接读取物理内存 (包括内核)
- 直接修改物理内存
- 绕过所有软件安全措施
```

---

#### 2.4.7 Platform Reset Attack (平台重置攻击)

**概念**: 在系统重启时读取残留的内存数据。

```
攻击流程:
1. 目标系统运行，内存中有敏感数据
2. 强制重启 (不完全清除内存)
3. 从 USB 启动攻击者的 OS
4. 读取残留在内存中的数据 (密钥、密码等)
```

---

## 3. 防御技术 (Defence Technologies)

### 3.1 主线内核防御 (Mainline Defences) 🟢

这些是已经合并到 Linux 内核主线的安全功能。

#### 3.1.1 栈保护

##### STACKPROTECTOR (栈保护器)
```c
// 编译器在栈上放置随机值 (canary)
void function() {
    unsigned long canary = __stack_chk_guard;  // 保存 canary
    char buffer[64];
    // ... 函数代码 ...
    if (canary != __stack_chk_guard)           // 检查 canary
        __stack_chk_fail();                     // 被修改则终止
}
// 栈溢出会覆盖 canary，被检测到
```

##### VMAP_STACK (虚拟映射栈)
- 内核栈不再使用物理连续内存
- 栈末尾有 guard page，溢出触发异常而非覆盖相邻内存

##### SCHED_STACK_END_CHECK
- 在栈末尾放置魔数
- 定期检查是否被覆盖

##### THREAD_INFO_IN_TASK
- 将 thread_info 从栈底移到 task_struct
- 防止栈溢出覆盖 thread_info

##### STACKLEAK
- 系统调用返回前清除栈数据
- 防止栈信息泄露和栈残留利用

##### RANDOMIZE_KSTACK_OFFSET_DEFAULT
- 随机化栈偏移
- 使栈地址难以预测

---

#### 3.1.2 堆保护

##### SLAB_FREELIST_RANDOM
- 随机化 slab freelist 顺序
- 使堆布局难以预测

##### SLAB_FREELIST_HARDENED
- 加密 freelist 指针
- 防止 freelist 篡改攻击

##### SHUFFLE_PAGE_ALLOCATOR
- 随机化页面分配顺序
- 增加堆利用难度

##### RANDOM_KMALLOC_CACHES
- 为相同大小的分配创建多个随机缓存
- 防止跨对象攻击

##### SLAB_BUCKETS
- 按分配大小分桶
- 减少类型混淆机会

---

#### 3.1.3 内存保护

##### STRICT_{KERNEL,MODULE}_RWX
- 内核代码只读可执行
- 内核数据可读写但不可执行
- 防止代码注入

##### DEBUG_WX
- 检测并警告任何 WX 映射
- 帮助发现安全配置问题

##### HARDENED_USERCOPY
- 检查用户空间复制操作
- 防止越界访问

##### init_on_alloc / init_on_free
- 分配时清零 / 释放时清零
- 防止信息泄露和 UAF

---

#### 3.1.4 控制流保护

##### CFI_CLANG (KCFI)
- 编译器级别的控制流完整性
- 检查间接调用目标类型

##### X86_64: X86_KERNEL_IBT
- Intel IBT (Indirect Branch Tracking)
- 间接跳转必须跳转到 ENDBR 指令

##### ARM64: ARM64_BTI_KERNEL
- ARM BTI (Branch Target Identification)
- 类似 Intel IBT

##### ARM64: SHADOW_CALL_STACK
- 影子栈保护返回地址
- 返回地址单独存储，不会被栈溢出覆盖

---

#### 3.1.5 地址随机化

##### RANDOMIZE_BASE (KASLR)
- 随机化内核加载地址
- 增加利用难度

##### X86_64: RANDOMIZE_MEMORY
- 随机化直接映射区地址
- 防止 ret2dir 攻击

---

#### 3.1.6 信息泄露防护

##### kptr_restrict
```bash
# 0: 允许读取内核指针
# 1: 非特权用户看不到内核指针
# 2: 所有用户都看不到内核指针
echo 2 > /proc/sys/kernel/kptr_restrict
```

##### SECURITY_DMESG_RESTRICT
- 限制非特权用户读取 dmesg
- 防止泄露内核信息

---

#### 3.1.7 瞬态执行防御

##### CPU_MITIGATIONS
- 启用所有 CPU 漏洞缓解措施

##### X86_64: pti=on (KPTI)
- 页表隔离
- 用户态看不到内核地址空间
- 防止 Meltdown

##### X86_64: MITIGATION_*
- 各种 Spectre/MDS 缓解选项

##### mitigations=auto,nosmt
- 自动应用所有缓解
- 禁用 SMT (超线程) 防止侧信道

---

#### 3.1.8 整数溢出防护

##### REFCOUNT_FULL
- 引用计数溢出检测
- 防止通过引用计数溢出的 UAF

---

#### 3.1.9 其他防护

##### FORTIFY_SOURCE
- 编译时/运行时检查内存操作函数
- 检测缓冲区溢出

##### DEFAULT_MMAP_MIN_ADDR=65536
- 禁止映射低地址
- 防止空指针利用

##### MODULE_SIG*
- 模块签名验证
- 防止加载恶意模块

##### LOCKDOWN_LSM
- 限制内核运行时修改
- 防止 rootkit

##### IOMMU 相关选项
- DMA 隔离和过滤
- 防止 DMA 攻击

---

### 3.2 树外防御 (Out-of-tree Defences) 🔵

未合并到主线但可用的安全功能。

#### XPFO (eXclusive Page Frame Ownership)
- 用户页面不会映射在 physmap
- 彻底防止 ret2dir

#### SLAB_VIRTUAL
- 虚拟地址空间的 slab 分配
- 防止跨缓存攻击

#### SLAB_PER_SITE
- 每个分配点使用独立缓存
- 进一步隔离

---

### 3.3 商业防御 (Commercial Defences) 🔘

grsecurity/PaX 等商业解决方案提供的功能。

#### PAX_REFCOUNT
- 引用计数保护 (REFCOUNT_FULL 的前身)

#### PAX_USERCOPY
- 用户复制保护 (HARDENED_USERCOPY 的前身)

#### PAX_KERNEXEC
- 内核代码完整性保护
- W^X 强制执行

#### PAX_UDEREF
- 内核不能直接访问用户空间
- SMAP 的软件实现

#### PAX_RAP
- 细粒度 CFI
- 返回地址保护

#### GRKERNSEC_*
- 各种额外加固选项

---

### 3.4 硬件防御 (HW Defences) 🌊

依赖 CPU 硬件功能的防御。

#### SMEP (Supervisor Mode Execution Prevention)
- 阻止内核执行用户页面代码
- 防止 ret2usr

#### SMAP (Supervisor Mode Access Prevention)
- 阻止内核直接访问用户页面数据
- 防止用户数据注入

#### PXN/PAN (ARM)
- ARM 平台对应的 SMEP/SMAP

#### Intel CET
- 硬件级别的控制流执行技术
- 包括 IBT 和影子栈

#### ARM64_PTR_AUTH_KERNEL
- ARM 指针认证
- 保护返回地址和函数指针

#### ARM64_MTE (Memory Tagging Extension)
- 内存标签扩展
- 硬件级别的 UAF 和越界检测

---

## 4. 漏洞检测机制 (Bug Detection Mechanisms) 🟣

开发和测试时使用的漏洞检测工具。

### 4.1 KASAN (Kernel Address SANitizer)

**功能**: 检测堆/栈/全局变量越界访问和 UAF

**原理**:
- 为每 8 字节数据维护 1 字节影子内存
- 影子内存记录该地址是否可访问
- 每次内存访问前检查影子内存

```c
// KASAN 检测 UAF
void *ptr = kmalloc(16);
kfree(ptr);
*ptr = 0;  // KASAN: use-after-free detected!
```

### 4.2 KFENCE (Kernel Electric Fence)

**功能**: 轻量级内存错误检测

**原理**:
- 采样少量分配
- 采样的分配有 guard page
- 适合生产环境

### 4.3 KMSAN (Kernel Memory SANitizer)

**功能**: 检测未初始化内存使用

**原理**:
- 追踪内存初始化状态
- 检测使用未初始化值

### 4.4 UBSAN (Undefined Behavior SANitizer)

**功能**: 检测未定义行为

**检测内容**:
- 有符号整数溢出
- 数组越界
- 空指针解引用
- 对齐问题

### 4.5 KCSAN (Kernel Concurrency SANitizer)

**功能**: 检测数据竞争

**原理**:
- 编译器插桩
- 检测并发内存访问

### 4.6 PROVE_LOCKING

**功能**: 检测死锁和锁使用问题

**原理**:
- 跟踪锁依赖关系图
- 检测循环依赖

### 4.7 KMEMLEAK

**功能**: 检测内存泄漏

**原理**:
- 扫描内存查找孤立分配
- 报告可能的泄漏

### 4.8 slub_debug 选项

```bash
# 启动参数
slub_debug=FZPU

# F: 释放时检查 (Double Free)
# Z: Red Zoning (越界检测)
# P: Poisoning (清毒)
# U: User tracking (追踪分配者)
```

---

## 5. 概念关系总结

### 5.1 漏洞 -> 利用技术

| 漏洞类型 | 可导致的利用技术 |
|---------|----------------|
| 栈溢出 (Stack Overflow) | 返回地址覆盖 -> ROP 攻击 |
| 堆溢出 (Heap Overflow) | 内核对象破坏, 分配器数据破坏 |
| UAF (释放后使用) | 堆布局控制 -> 类型混淆 -> 函数指针劫持 |
| 整数溢出 (Integer Overflow) | 大小检查绕过 -> 缓冲区溢出 |
| 信息泄露 (Info Leak) | 绕过 KASLR -> 精确利用 |

### 5.2 防御 -> 利用技术

| 防御技术 | 阻止的利用技术 |
|---------|---------------|
| SMEP (管理模式执行保护) | 返回用户空间执行 (ret2usr) |
| SMAP (管理模式访问保护) | 用户空间数据访问 |
| KASLR (内核地址随机化) | 查找内核对象地址 |
| Canary (栈保护金丝雀) | 返回地址覆盖 |
| CFI (控制流完整性) | ROP/JOP/COP 攻击链 |
| XPFO (独占页帧所有权) | 返回直接映射区 (ret2dir) |

### 5.3 检测机制 -> 漏洞类型

| 检测机制 | 检测的漏洞 |
|---------|-----------|
| KASAN | 越界, UAF, Double Free |
| KMSAN | 未初始化内存 |
| KCSAN | 竞争条件 |
| UBSAN | 未定义行为 |
| PROVE_LOCKING | 死锁 |

---

## 6. 实际攻击流程示例

### 6.1 典型内核提权攻击

```
1. 信息收集
   - 确定内核版本
   - 查找已知漏洞或发现新漏洞

2. 漏洞触发
   - 准备利用条件
   - 触发漏洞 (如 UAF)

3. 原语构造
   - 堆喷射控制释放的内存
   - 实现任意读/写原语

4. 绕过防御
   - 信息泄露绕过 KASLR
   - ROP 绕过 SMEP
   - ... 

5. 提权
   - 修改 cred 结构
   - 或修改 modprobe_path
   - 获得 root 权限

6. 清理
   - 修复破坏的数据结构
   - 保持系统稳定
```

---

## 参考资料

- [Linux Kernel Self Protection](https://www.kernel.org/doc/html/latest/security/self-protection.html)
- [grsecurity Features](https://grsecurity.net/features.php)
- [CWE (Common Weakness Enumeration)](https://cwe.mitre.org/)
- [kernel-hardening-checker](https://github.com/a13xp0p0v/kernel-hardening-checker)

---

*本文档基于 Linux Kernel Defence Map 项目创建，旨在帮助安全初学者理解内核安全概念。*
