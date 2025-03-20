# 文件加密与认证系统

这是一个基于Java的文件加密与认证系统，旨在提供安全的文件存储和访问控制。项目使用椭圆曲线加密技术（通过Bouncy Castle库实现）确保数据的机密性，并通过认证服务器管理用户身份和密钥。客户端可以上传加密文件到本地模拟的S3存储，并通过Web界面查看加密文件的内容或解密后的内容。

## 项目概述

本项目的核心功能包括：
- **用户注册和认证**：用户可以通过ID和密码注册或登录。
- **文件加密和上传**：客户端将文件加密后上传到本地存储。
- **文件下载和解密**：支持查看加密文件内容（控制台输出）或解密后的内容（Web页面展示）。
- **Web界面**：提供直观的用户交互界面，用于认证、文件管理和内容查看。

项目采用客户端-服务器架构，使用Spark Java框架构建Web服务器，并模拟Amazon S3的本地存储。

## 技术栈

- **Java 8+**：核心编程语言。
- **Bouncy Castle**：用于椭圆曲线加密。
- **Spark Java**：轻量级Web框架。
- **Gson**：JSON序列化和反序列化。
- **Apache Commons IO**：文件操作工具。

## 项目结构

项目包含以下主要文件和模块：

- **`AuthServer.java`**：认证服务器，负责用户注册、密钥管理和认证。
- **`Client.java`**：客户端，处理文件加密、上传、下载和解密。
- **`LocalS3Client.java`**：本地S3存储模拟客户端。
- **`Utils.java`**：工具类，提供密码哈希和密钥派生功能。
- **`SimpleEcCurve.java`**：椭圆曲线加密工具类。
- **`ApiController.java`**：API控制器，定义Web端点（如认证、上传、查看）。
- **`WebServer.java`**：Web服务器入口，启动Spark服务并提供静态文件。
- **`E2seMain.java`**：项目主入口，支持命令行启动。
- **`Constants.java`**：常量定义（如默认路径、端口等）。
- **`HMacKDF.java`**：基于HMAC的密钥派生函数。
- **`EncThread.java`**：多线程文件加密。
- **`StreamDecThread.java`**：多线程文件解密。
- **`index.html`**：Web界面，提供用户交互页面。
- **`app.js`**：前端JavaScript脚本，处理用户操作和API调用。

## 安装和配置

### 前提条件
- **Java 8或更高版本**：确保已安装JDK。
- **Maven**：用于依赖管理（可选，若手动添加JAR包则无需Maven）。
- **Git**：用于克隆仓库。

### 安装步骤
1. **克隆项目仓库**：
   ```bash
   git clone https://github.com/your-username/your-repo.git
   cd your-repo
   ```

2. **安装依赖**：
   - 如果使用Maven，在项目根目录运行：
     ```bash
     mvn install
     ```
   - 或者手动下载以下依赖并添加到项目：
     - Bouncy Castle (`bcprov-jdk15on`)
     - Spark Java (`spark-core`)
     - Gson (`gson`)
     - Apache Commons IO (`commons-io`)

3. **配置环境**：
   - 确保`DataFile`目录存在，用于存储上传的文件和本地S3数据：
     ```bash
     mkdir DataFile
     ```
   - 可选：修改`Constants.java`中的配置，例如服务器地址（默认`localhost`）、端口（默认`8080`）等。

4. **编译项目**：
   ```bash
   mvn compile
   ```

## 使用指南

### 启动项目
1. **启动认证服务器**：
   在终端运行：
   ```bash
   java -cp target/classes org.example.E2seMain authserver
   ```
   这将启动`AuthServer`，监听用户注册和认证请求。

2. **启动Web服务器**：
   在另一个终端运行：
   ```bash
   java -cp target/classes org.example.WebServer
   ```
   Web服务器将运行在`http://localhost:8080`。

### 使用Web界面
1. **访问界面**：
   打开浏览器，访问`http://localhost:8080`。

2. **用户注册或登录**：
   - 在“用户认证”部分输入`用户ID`和`密码`，点击“认证”按钮。
   - 若用户未注册，将自动注册；若已注册，则验证密码。

3. **查询已注册用户**：
   - 点击“查询已注册用户”按钮，查看所有注册用户的ID。

4. **上传文件**：
   - 在“上传并加密文件”部分选择文件，点击“上传”按钮。
   - 文件将被加密并存储到本地S3模拟存储。

5. **查看文件**：
   - 点击“查看（控制台）”按钮，加密文件内容将输出到服务器控制台。
   - 点击“查看解密内容”按钮，解密后的文件内容将显示在Web页面上。

### 示例
假设用户ID为`testuser`，密码为`password123`：
1. 输入`testuser`和`password123`，点击“认证”。
2. 选择文件`example.txt`，点击“上传”。
3. 点击“查看解密内容”，页面将显示`example.txt`的原始内容。

## API端点
以下是主要的API端点（由`ApiController.java`定义）：
- **`POST /api/authenticate`**：用户认证或注册。
- **`POST /api/upload`**：上传并加密文件。
- **`POST /api/view`**：查看加密文件内容（控制台输出）。
- **`GET /api/registeredUsers`**：获取已注册用户列表。
- **`POST /api/viewDecrypted`**：查看解密后的文件内容。

## 贡献指南

欢迎为本项目做出贡献！您可以通过以下方式参与：
- 提交Bug报告或功能建议。
- 改进文档、添加示例。
- 优化代码性能或安全性。

### 贡献步骤
1. Fork本仓库。
2. 创建新分支：
   ```bash
   git checkout -b feature/your-feature
   ```
3. 提交修改：
   ```bash
   git commit -am 'Add your feature'
   ```
4. 推送分支：
   ```bash
   git push origin feature/your-feature
   ```
5. 创建Pull Request。

## 注意事项
- 确保在生产环境中使用安全的密码和密钥管理策略。
- 当前项目使用本地文件系统模拟S3存储，可扩展为真实AWS S3服务。
- Web界面和API未实现HTTPS，建议在公网部署时添加SSL支持。
