
[toc]
# 1.小知识点整理
<i class="fas fa-feather-alt"></i>在C语言中，数组参数是以引用形式进行传递的，也就是传址调用；而标量和常量则是按值传递的。函数对值传递参数的任何修改在函数返回时丢失。
<i class="fas fa-feather-alt"></i>C函数的参数传递规则：所有传递给函数的参数都是按值传递的。但是数组名作为参数时就会产生引用传递的效果。原因为数组名实际上是一个指向数组起始位置的指针。
<i class="fas fa-feather-alt"></i>typedef 和 #define 的区别：typedef为取别名，在编译时处理；#define仅为简单的替换，为预处理指令。
<i class="fas fa-feather-alt"></i>左值表示可寻址(location)，右值表示可读（read）。
<i class="fas fa-feather-alt"></i>当表达式中存在有符号类型和无符号类型时，所有的操作数都**自动转换为无符号类型**。
<i class="fas fa-feather-alt"></i>NULL 指针是一个定义在标准库中的值为零的常量。在大多数的操作系统上，程序不允许访问地址为 0 的内存，因为该内存是操作系统保留的。因此不会产生歧义。
<i class="fas fa-feather-alt"></i>在不同操作系统中指针大小结论：在32位操作系统下，指针是占4个字节空间大小，不管是什么数据类型；在64位操作系统下，指针是占8个字节空间大小，不管是什么数据类型。
<i class="fas fa-feather-alt"></i>除了优先级以外，下标引用和间接引用完全相同。array不必是数组名，只需是指针就可以通过下标访问。array[subscript] = \*(array+subscript)
<i class="fas fa-feather-alt"></i>联合初始化必须是联合的第一个成员类型。
<i class="fas fa-feather-alt"></i>回调函数：将函数指针作为参数传递给回调函数，回调函数将会调用指针所指向的函数。
<i class="fas fa-feather-alt"></i>转移表实质上就是函数指针数组。根据传入的下标值选择相应的函数执行。
<i class="fas fa-feather-alt"></i>任何指针类型可随意转换为void\*指针，在不确定传入类型的函数中使用void\*指针。但void\*转换为其他类型指针时必须小心。
<i class="fas fa-feather-alt"></i>文件末尾标志EOF定义为整型，它的值在任何可能出现的字符之外。

# 2.C语言程序从编写到运行历经的几个阶段
![](https://github.com/zjc0000/story_images/raw/main/小书匠/1663651116867.png)
静态链接和动态链接的区别在于：若是编译期间则是静态链接，对应的函数库就是静态链接库 (linux下为.a文件，win下为.lib文件)。速度快，占用空间大。
若是在运行时期完成，则为动态链接，对应的函数库就是动态链接库 (linux下为.so文件，win下为.dll文件)。速度慢，占用空间小。
***参考链接：***
https://blog.csdn.net/DRZ_2000/article/details/104970637

# 3.C程序内存结构
![](https://github.com/zjc0000/story_images/raw/main/小书匠/1663651238843.png)

.text：称作指令节，也叫代码节，存放程序执行的二进制文件
.rodata：称作常量节，无法直接和指令放在一起的常量，就放在 .rodata 中
.data：存放程序中初始化不为0的全局变量和静态变量
.bss：存放程序中未初始化的或者初始化为0的全局变量和静态变量
堆（手动区）：程序在运行过程中，该内存空间由程序员使用 malloc 函数开辟和 free 函数释放。
栈（自动区）：函数运行时，会自动的开辟和释放该空间，即所谓的压栈和弹栈。
***参考链接：***
https://blog.csdn.net/xiaoma_2018/article/details/118640417

# 4.链接属性
**external**:外部链接属性的标识符总表示同一个实体，如缺省情况下的全局变量。但需使用extern关键字才能访问在其他源文件定义的外部变量。可使用static关键字改变为internal链接属性。
**internal**:内部链接属性在同一个源文件指向同一个实体，不同源文件属于不同实体。
**none**:没有链接属性的标识符总是被当作独一的个体，如局部变量。

# 5.变量存储类型
四种变量存储类型：静态变量（static）、外部变量（extern）
自动变量（auto）：函数中所有的非静态局部变量，存储于栈区。
寄存器变量（register）： 一般经常被使用的的变量可以设置成寄存器变量，register 变量会被存储在寄存器中，计算速度远快于存在内存中的非 register 变量。

# 6.C语言关键字static与extern的详细解释
1. static修饰全局变量：称为静态全局变量，限定在当前源文件内使用。全局变量（隐式静态变量）与静态全局变量不同的是全局变量在其它源文件中可以通过extern声明后访问，而静态全局变量则无法访问。
2. static修饰局部变量：称为静态局部变量，储存在data区而非栈区。静态局部变量定义时，如果用户没有初始化，编译器会自动将其初始化为0，而且整个进程周期中，只定义和初始化一次，每次调用局部函数时，静态局部变量都会维持最后一次修改的值，作用域是局部代码段。
3. static修饰函数：被关键字static修饰的函数作用域是源文件，其他源文件（即使添加了对应的头文件）无法调用该函数。
4. extern修饰变量：表明该变量在其他源文件里已经被定义，此处需要使用。extern声明的变量必须是在其他源文件内的非静态的全局变量。
5. extern修饰函数：表明该函数在其他源文件里已经被定义，此处需要使用。extern声明的函数必须是在其他源文件内的非静态的函数。此方法无需添加函数声明的头文件。
***参考链接：***
https://blog.csdn.net/zhongshengxuexi_/article/details/81571287

# 7.常量指针与指针常量
const和\*谁在前谁不能修改。
int const \*p 为常量指针，可以修改指针的值，不能修改它所指向的值。
int \* const p为指针常量，指针的值不能修改，它指向的值可以修改。
int const \* const p 指针本身和指向的值都不能改变。

# 8.指针运算
指针与数运算：当一个指针和一个整数执行算数运算时，在执行前会将整数值与指针所指向类型的大小相乘。实际上移动的是整数值个指针所指向类型大小。
指针与指针运算：只有指向同一个数组中元素的两指针相减才是合法的，结果为两个指针在内存中的距离（以数组元素的长度为单位，而非字节）。
指针关系运算：只有指向同一个数组中元素的指针大小关系比较才是合法的，相等与不相等关系可以在任意指针间比较。

# 9.C语言的可变参数列表实现
类型va_list,三个宏（va_start,va_arg,va_end）
（1） 头文件stdarg.h  参数列表如下格式 float average(int n,...){}
（2） 定义一个va_list 类型的变量val，使用va_start(val,n)初始化使得val指向可变参数部分的第一个参数。
（3） 使用va_arg(val,int)访问可变参数，并将val指向下一个参数。
（4） 访问完成最后一个可变参数后调用va_end(val)结束。
需要注意：
（1） 可变参数没有声明类型，都将执行缺省参数类型。
（2） 至少需要一个命名参数指定参数数量，甚至更多参数来提供参数类型信息。


# 10.指向数组的指针和指针数组
指向数组的指针：定义方式 int martix\[3\]\[10\];   int (\*p)\[10\] = martix；
注意下标访问优先级高于间接访问符
指针数组  定义方式 int \*p\[10\];

# 11.字符串操作函数
需要着重注意是否会导致源字符串不是以NUL结尾/是否溢出
strncpy函数 char \*strncpy(char \*dst, char \*src,size_t len);
注意：若strlen(src)>len,那么dst字符串可能不是以NUL字节结尾。dst\[size-1\]='\0'语句保证dst字符串以NUL结尾。
strncat函数没有该问题，拼接它会自动添加NUL字节作为结尾。
strtok函数会修改源字符串，会将找到的第一个标记处以NUL结尾，并且保存指向这个标记的指针，因此不能同时解析两个字符串。第一个参数为NULL时会从保存的指针处继续查找标记。

# 12.函数指针、函数指针数组
int (\*f)(int);  f是一个函数指针，指向的函数参数类型为int，返回值类型为int
int (\*f\[\])(int); f是一个指针数组，指针类型是函数指针，指向的函数参数类型为int，返回值类型为int
```c
//函数名在被使用时总是由编译器将它转换为函数指针。
int f(int);
//下面两条语句的效果是一样的，&操作符只是显式说明了编译器隐式执行的任务
int (*fp)(int) = f;
int (*fp)(int) = &f;

int ans;
//同理下面三条语句效果相同
ans = f(25);
ans = (*fp)(25);
ans = fp(25);

```
# 13.C语言的命令行参数
```c
int main(int argc,char *argv[])
int main(int argc,char **argv)
```
argc : 命令行传入参数的总个数
argv : \*argv\[\]是一个指针数组，里面存放的指针指向所有的命令行参数，argv\[0\]指向程序名，argv\[1\]指向在命令行中执行程序名后的第一个字符串，argv\[2\]指向第二个。

# 14.字符串常量
字符串常量以NUL结尾，NUL为ASCII字符集中‘\0’字符的名字，作为字符串终止符，本身不是字符串的一部分。
字符串常量实际上是指针常量，编译器存储指向字符串常量第一个字符的指针。
```c
"xyz"+1   //指向字符y的指针
*"xyz"    //字符x
"xyz"[2]  //字符z
*("xyz"+4) //非法操作，指针越界
"0123456789ABCDEF"[value%16];  //10进制转16进制的一种操作
```

# 15.预处理器/宏
预定义符号：
```c
__FILE__:%s进行编译的源文件。
__LINE__:%n文件当前行号。
__DATE__:%s文件编译的日期。
__TIME__:%s文件被编译的时间。
```
#define宏定义： 替换     #undef移除一个宏定义
（1）不应在宏定义语句后加分号，若语句非常长可以将其分成几行，除最后一行外每行末尾都要加一个反斜杠。
```c
#define DEBUG_PRINT printf("File %s line %d: \
                            x = %d,y = %d,z = %d",\
                            __FILE__, __LINE__, \ 
                            x, y, z )
```
（2）所有用于对数值表达式进行求值的宏定义都应该加上括号，避免在使用宏时由于参数中的操作符或邻近的操作符之间产生错误结果。
```c
#define DOUBLE(X)  ( (X) + (X) )
#define SQUARE(X)  ( (X) * (X) )
```
（3）将宏参数插入到字符串常量中。
```c
a.通过相邻字符串自动拼接的特性
#define PRINT(FORMAT, VALUE) \
            printf("The value is " FORMAT " \n", VALUE)
PRINT("%d", x);

b.#FORMAT 被预处理器翻译为 "FORMAT"
#define PRINT(FORMAT, VALUE) \
            printf("The value is" #FORMAT " \n", VALUE)
PRINT(%d, x);

c.##用于将其两边的符号连接成一个符号，允许宏定义从分离的文本片段创建标识符
#define ADD_TO_SUN(sum_number, value) \
        sum ## sum_number += value
ADD_TO_SUM(5, 25);  --->   sum5 += 25;
```
（4）宏和函数的不同之处
![](https://github.com/zjc0000/story_images/raw/main/小书匠/1663652074915.png)

# 16.信号
（1）标准定义的信号
![](https://raw.githubusercontent.com/zjc0000/story_images/main/小书匠/1664966754999.png)
（2）相关函数
```c
//调用该函数引发参数所指定的信号
int raise(int sig);
//信号处理函数
//第一个参数为需要处理的信号
//第二个参数为函数指针，指向你希望为这个信号设置的信号处理函数
//函数返回值为函数指针，指向该信号触发以前的处理函数，用于程序恢复
void ( *signal( int sig, void ( * handler )( int )))( int );
```
（3）volatie数据
信号可能在任何时候发生，所以由信号处理函数修改的变量的值可能在任何时候发生改变。
```c
//在普通情况下，第一个测试和第二个测试具有相同的结果，如果信号处理函数修改了这个变量，第二个测试结果可能不同。
if(value){
	printf("TRUE\n");
}else{
	printf("FALSE\n");
}
if(value){
	printf("TRUE\n");
}else{
	printf("FALSE\n");
}
//然而除非value被声明为volatie，编译器会优化成下面这段代码，这显然不是我们想要的。
if(value){
	printf("TRUE\n");
	printf("TRUE\n");
}else{
	printf("FALSE\n");
	printf("FALSE\n");
}
```