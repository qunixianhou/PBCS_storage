document.addEventListener('DOMContentLoaded', () => {
    console.log('页面已加载');

    const resultDiv = document.getElementById('result');
    const decryptedContentDiv = document.getElementById('decryptedContent');
    const backendLogsDiv = document.getElementById('backendLogs');
    const backendWindow = document.getElementById('backendWindow');
    const authBtn = document.getElementById('authBtn');
    const uploadBtn = document.getElementById('uploadBtn');
    const viewBtn = document.getElementById('viewBtn');
    const viewDecryptedBtn = document.getElementById('viewDecryptedBtn');
    const checkUsersBtn = document.getElementById('checkUsersBtn');
    const userListDiv = document.getElementById('userList');
    const showBackendBtn = document.getElementById('showBackendBtn');
    const closeBackendBtn = document.getElementById('closeBackendBtn');

    let isAuthenticated = false;
    let currentUserId = null;

    // WebSocket 连接
    let ws = new WebSocket('ws://localhost:8080/logs');
    ws.onmessage = (event) => {
        backendLogsDiv.textContent += event.data + '\n';
        backendLogsDiv.scrollTop = backendLogsDiv.scrollHeight; // 自动滚动到底部
    };
    ws.onerror = (error) => console.error('WebSocket 错误:', error);
    ws.onclose = () => console.log('WebSocket 连接关闭');

    function showResult(message, isError = false) {
        resultDiv.textContent = message;
        resultDiv.className = isError ? 'error' : 'success';
    }

    // 显示/隐藏后台窗口
    showBackendBtn.addEventListener('click', () => {
        backendWindow.style.display = 'block';
    });
    closeBackendBtn.addEventListener('click', () => {
        backendWindow.style.display = 'none';
    });

    authBtn.addEventListener('click', async () => {
        const userId = document.getElementById('userId').value;
        const passphrase = document.getElementById('passphrase').value;

        if (!userId || !passphrase) {
            showResult('请输入用户ID和密码', true);
            return;
        }

        showResult('正在处理...');
        try {
            const response = await fetch('/api/authenticate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `userId=${encodeURIComponent(userId)}&passphrase=${encodeURIComponent(passphrase)}`
            });
            const data = await response.json();
            if (response.ok) {
                isAuthenticated = true;
                currentUserId = userId;
                showResult(data.message);
            } else {
                showResult(data.message, true);
            }
        } catch (error) {
            showResult('认证错误: ' + error.message, true);
        }

        if (response.ok) {
            isAuthenticated = true;
            currentUserId = userId;
            showResult(data.message);
            // 检查 WebSocket 状态并重新连接
            if (ws.readyState === WebSocket.CLOSED || ws.readyState === WebSocket.CLOSING) {
                console.log('Reconnecting WebSocket...');
                ws = new WebSocket('ws://localhost:8080/logs');
                ws.onmessage = (event) => {
                    backendLogsDiv.textContent += event.data + '\n';
                    backendLogsDiv.scrollTop = backendLogsDiv.scrollHeight;
                };
                ws.onerror = (error) => console.error('WebSocket 错误:', error);
                ws.onclose = () => console.log('WebSocket 连接关闭');
            }
        }
    });

    checkUsersBtn.addEventListener('click', async () => {
        showResult('正在查询...');
        try {
            const response = await fetch('/api/registeredUsers', {
                method: 'GET',
                headers: { 'Accept': 'application/json' }
            });
            const users = await response.json();
            if (response.ok) {
                userListDiv.innerHTML = users.length > 0
                    ? users.map(user => `<p>${user}</p>`).join('')
                    : '<p>暂无注册用户</p>';
                showResult(users.length > 0 ? '查询成功，发现 ' + users.length + ' 个用户' : '查询成功，无注册用户');
            } else {
                showResult(users.message, true);
            }
        } catch (error) {
            showResult('查询错误: ' + error.message, true);
        }
    });

    uploadBtn.addEventListener('click', async () => {
        if (!isAuthenticated) {
            showResult('请先认证', true);
            return;
        }

        const fileInput = document.getElementById('fileInput');
        const file = fileInput.files[0];

        if (!file) {
            showResult('请选择文件', true);
            return;
        }

        showResult('正在上传和加密...');
        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch(`/api/upload?userId=${encodeURIComponent(currentUserId)}&passphrase=${encodeURIComponent(document.getElementById('passphrase').value)}`, {
                method: 'POST',
                body: formData,
                headers: { 'X-File-Name': file.name }
            });
            const data = await response.json();
            showResult(data.message, !response.ok);
        } catch (error) {
            showResult('上传错误: ' + error.message, true);
        }
    });

    viewBtn.addEventListener('click', async () => {
        if (!isAuthenticated) {
            showResult('请先认证', true);
            return;
        }
        const passphrase = document.getElementById('passphrase').value;
        console.log('Viewing encrypted file with passphrase:', passphrase); // 添加调试日志
        showResult('正在查看加密内容...');
        decryptedContentDiv.textContent = ''; // 清空之前的内容
        try {
            const response = await fetch('/api/view', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `userId=${encodeURIComponent(currentUserId)}&passphrase=${encodeURIComponent(document.getElementById('passphrase').value)}`
            });
            if (response.ok) {
                const encryptedText = await response.text(); // 获取加密内容
                decryptedContentDiv.textContent = encryptedText; // 显示加密内容
                showResult('加密内容查看成功');
            } else {
                const data = await response.json();
                showResult(data.message, true);
            }
        } catch (error) {
            showResult('查看错误: ' + error.message, true);
        }
    });

    viewDecryptedBtn.addEventListener('click', async () => {
        if (!isAuthenticated) {
            showResult('请先认证', true);
            return;
        }

        showResult('正在解密并查看文件内容...');
        decryptedContentDiv.textContent = '';
        try {
            const response = await fetch('/api/viewDecrypted', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `userId=${encodeURIComponent(currentUserId)}&passphrase=${encodeURIComponent(document.getElementById('passphrase').value)}`
            });
            if (response.ok) {
                const decryptedText = await response.text();
                decryptedContentDiv.textContent = decryptedText;
                showResult('解密查看成功');
            } else {
                const data = await response.json();
                showResult(data.message, true);
            }
        } catch (error) {
            showResult('解密查看错误: ' + error.message, true);
        }
    });
});