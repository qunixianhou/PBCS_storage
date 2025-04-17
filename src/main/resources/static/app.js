document.addEventListener('DOMContentLoaded', () => {
    // DOM 元素
    const elements = {
        userId: document.getElementById('userId'),
        passphrase: document.getElementById('passphrase'),
        authBtn: document.getElementById('authBtn'),
        checkUsersBtn: document.getElementById('checkUsersBtn'),
        userList: document.getElementById('userList'),
        fileInput: document.getElementById('fileInput'),
        uploadBtn: document.getElementById('uploadBtn'),
        uploadProgress: document.getElementById('uploadProgress'),
        viewEncryptedBtn: document.getElementById('viewEncryptedBtn'),
        viewDecryptedBtn: document.getElementById('viewDecryptedBtn'),
        contentDisplay: document.getElementById('contentDisplay'),
        imagePreview: document.getElementById('imagePreview'),
        result: document.getElementById('result'),
        showLogsBtn: document.getElementById('showLogsBtn'),
        clearLogsBtn: document.getElementById('clearLogsBtn'),
        backendLogs: document.getElementById('backendLogs')
    };

    // 状态管理
    let state = {
        isAuthenticated: false,
        currentUserId: null,
        ws: null
    };

    // UI 工具函数
    const ui = {
        showResult(message, isError = false) {
            elements.result.textContent = message;
            elements.result.className = `alert ${isError ? 'alert-danger' : 'alert-success'}`;
            elements.result.style.display = 'block';
            setTimeout(() => { elements.result.style.display = 'none'; }, 5000);
        },
        clearContent() {
            elements.contentDisplay.textContent = '';
            elements.imagePreview.style.display = 'none';
        }
    };

    // WebSocket 模块
    const websocket = {
        connect() {
            state.ws = new WebSocket('ws://localhost:8080/logs');
            state.ws.onmessage = (event) => {
                const logEntry = `[${new Date().toLocaleTimeString()}] ${event.data}\n`;
                elements.backendLogs.textContent += logEntry;
                elements.backendLogs.scrollTop = elements.backendLogs.scrollHeight;
            };
            state.ws.onerror = (error) => {
                console.error('WebSocket 错误:', error);
                ui.showResult('日志连接错误', true);
            };
            state.ws.onclose = () => {
                console.log('WebSocket 关闭，重连中...');
                setTimeout(websocket.connect, 5000);
            };
        }
    };
    websocket.connect();

    // 认证模块
    const auth = {
        async authenticate() {
            const userId = elements.userId.value.trim();
            const passphrase = elements.passphrase.value.trim();
            if (!userId || !passphrase) {
                ui.showResult('用户ID和密码不能为空', true);
                return;
            }
            ui.showResult('认证中...');
            try {
                const response = await fetch('/api/authenticate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: `userId=${encodeURIComponent(userId)}&passphrase=${encodeURIComponent(passphrase)}`
                });
                const data = await response.json();
                if (response.ok) {
                    state.isAuthenticated = true;
                    state.currentUserId = userId;
                    ui.showResult(data.message);
                } else {
                    ui.showResult(data.message, true);
                }
            } catch (error) {
                ui.showResult('认证失败: ' + error.message, true);
            }
        }
    };
    elements.authBtn.addEventListener('click', auth.authenticate);

    // 用户查询模块
    const users = {
        async checkUsers() {
            ui.showResult('查询中...');
            try {
                const response = await fetch('/api/registeredUsers', {
                    method: 'GET',
                    headers: { 'Accept': 'application/json' }
                });
                const data = await response.json();
                if (response.ok) {
                    elements.userList.innerHTML = data.length > 0
                        ? data.map(user => `<p class="mb-1">${user}</p>`).join('')
                        : '<p>暂无注册用户</p>';
                    ui.showResult(data.length > 0 ? `发现 ${data.length} 个用户` : '无注册用户');
                } else {
                    ui.showResult(data.message, true);
                }
            } catch (error) {
                ui.showResult('查询失败: ' + error.message, true);
            }
        }
    };
    elements.checkUsersBtn.addEventListener('click', users.checkUsers);

    // 文件上传模块
    const upload = {
        async uploadFile() {
            if (!state.isAuthenticated) {
                ui.showResult('请先认证', true);
                return;
            }
            const file = elements.fileInput.files[0];
            if (!file) {
                ui.showResult('请选择文件', true);
                return;
            }
            ui.showResult('上传中...');
            const formData = new FormData();
            formData.append('file', file);
            const xhr = new XMLHttpRequest();
            xhr.upload.onprogress = (event) => {
                if (event.lengthComputable) {
                    const percent = (event.loaded / event.total) * 100;
                    elements.uploadProgress.querySelector('.progress-bar').style.width = `${percent}%`;
                    elements.uploadProgress.style.display = 'block';
                }
            };
            xhr.open('POST', `/api/upload?userId=${encodeURIComponent(state.currentUserId)}&passphrase=${encodeURIComponent(elements.passphrase.value)}`);
            xhr.setRequestHeader('X-File-Name', encodeURIComponent(file.name));
            xhr.onload = () => {
                const data = JSON.parse(xhr.responseText);
                elements.uploadProgress.style.display = 'none';
                ui.showResult(data.message, xhr.status !== 200);
            };
            xhr.onerror = () => {
                elements.uploadProgress.style.display = 'none';
                ui.showResult('上传失败', true);
            };
            xhr.send(formData);
        }
    };
    elements.uploadBtn.addEventListener('click', upload.uploadFile);

    // 文件查看模块
    const view = {
        async viewEncrypted() {
            if (!state.isAuthenticated) {
                ui.showResult('请先认证', true);
                return;
            }
            ui.clearContent();
            ui.showResult('获取加密文件...');
            try {
                const response = await fetch('/api/view', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: `userId=${encodeURIComponent(state.currentUserId)}&passphrase=${encodeURIComponent(elements.passphrase.value)}`
                });
                if (response.ok) {
                    const blob = await response.blob();
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'encrypted_file.bin';
                    a.click();
                    URL.revokeObjectURL(url);
                    ui.showResult('加密文件已下载');
                } else {
                    const data = await response.json();
                    ui.showResult(data.message, true);
                }
            } catch (error) {
                ui.showResult('获取失败: ' + error.message, true);
            }
        },
        async viewDecrypted() {
            if (!state.isAuthenticated) {
                ui.showResult('请先认证', true);
                return;
            }
            ui.clearContent();
            ui.showResult('解密中...');
            try {
                const response = await fetch('/api/viewDecrypted', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: `userId=${encodeURIComponent(state.currentUserId)}&passphrase=${encodeURIComponent(elements.passphrase.value)}`
                });
                if (!response.ok) {
                    const data = await response.json();
                    ui.showResult(data.message, true);
                    return;
                }
                const blob = await response.blob();
                const contentType = response.headers.get('Content-Type');
                const fileName = response.headers.get('X-File-Name') || 'unknown';
                if (contentType.startsWith('image/')) {
                    elements.imagePreview.src = URL.createObjectURL(blob);
                    elements.imagePreview.style.display = 'block';
                    ui.showResult('图片解密成功');
                } else if (contentType === 'text/plain') {
                    elements.contentDisplay.textContent = await blob.text();
                    ui.showResult('文本解密成功');
                } else {
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = fileName;
                    a.click();
                    URL.revokeObjectURL(url);
                    ui.showResult('文件解密成功，已下载');
                }
            } catch (error) {
                ui.showResult('解密失败: ' + error.message, true);
            }
        }
    };
    elements.viewEncryptedBtn.addEventListener('click', view.viewEncrypted);
    elements.viewDecryptedBtn.addEventListener('click', view.viewDecrypted);

    // 日志模块
    const logs = {
        show() {
            const offcanvas = new bootstrap.Offcanvas(document.getElementById('logOffcanvas'));
            offcanvas.show();
        },
        clear() {
            elements.backendLogs.textContent = '';
        }
    };
    elements.showLogsBtn.addEventListener('click', logs.show);
    elements.clearLogsBtn.addEventListener('click', logs.clear);
});