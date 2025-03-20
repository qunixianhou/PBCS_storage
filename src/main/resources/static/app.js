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
    const imagePreview = document.getElementById('imagePreview');
    let ws = new WebSocket('ws://localhost:8080/logs');
    let isAuthenticated = false;
    let currentUserId = null;

    ws.onmessage = (event) => {
        const logEntry = `[${new Date().toLocaleTimeString()}] ${event.data}`;
        backendLogsDiv.textContent += logEntry + '\n';
        backendLogsDiv.scrollTop = backendLogsDiv.scrollHeight;
    };
    ws.onerror = (error) => console.error('WebSocket Error:', error);
    ws.onclose = () => console.log('WebSocket Connection Closed');

    function showResult(message, isError = false) {
        resultDiv.textContent = message;
        resultDiv.className = isError ? 'error' : 'success';
    }

    showBackendBtn.addEventListener('click', () => backendWindow.style.display = 'block');
    closeBackendBtn.addEventListener('click', () => backendWindow.style.display = 'none');

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
                headers: { 'X-File-Name': encodeURIComponent(file.name) } // 编码文件名
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
        showResult('正在查看加密内容...');
        decryptedContentDiv.textContent = '';
        imagePreview.style.display = 'none';
        try {
            const response = await fetch('/api/view', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `userId=${encodeURIComponent(currentUserId)}&passphrase=${encodeURIComponent(document.getElementById('passphrase').value)}`
            });
            if (response.ok) {
                const blob = await response.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'encrypted_file.bin'; // 下载加密文件
                a.click();
                URL.revokeObjectURL(url);
                showResult('加密内容已下载');

                // 可选：显示十六进制（调试用）
                const reader = new FileReader();
                reader.onload = () => {
                    const arrayBuffer = reader.result;
                    const bytes = new Uint8Array(arrayBuffer);
                    let hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
                    decryptedContentDiv.textContent = hex.substring(0, 1000) + (hex.length > 1000 ? '...' : ''); // 限制长度
                };
                reader.readAsArrayBuffer(blob);
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
        imagePreview.style.display = 'none';
        try {
            const response = await fetch('/api/viewDecrypted', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `userId=${encodeURIComponent(currentUserId)}&passphrase=${encodeURIComponent(document.getElementById('passphrase').value)}`
            });
            if (!response.ok) {
                const data = await response.json();
                showResult(data.message, true);
                return;
            }

            const blob = await response.blob();
            const contentType = response.headers.get('Content-Type');
            const fileName = response.headers.get('X-File-Name') || 'unknown';

            console.log('Content-Type:', contentType); // 调试
            console.log('File Name:', fileName);       // 调试
            console.log('Blob Size:', blob.size);      // 调试

            if (contentType.startsWith('image/')) {
                const url = URL.createObjectURL(blob);
                imagePreview.src = url;
                imagePreview.onload = () => {
                    console.log('Image loaded successfully');
                    URL.revokeObjectURL(url); // 释放内存
                };
                imagePreview.onerror = () => {
                    console.error('Failed to load image');
                    showResult('图片加载失败', true);
                };
                imagePreview.style.display = 'block';
                showResult('图片解密查看成功');
            } else if (contentType === 'text/plain') {
                const text = await blob.text();
                decryptedContentDiv.textContent = text;
                showResult('文本解密查看成功');
            } else {
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = fileName;
                a.click();
                URL.revokeObjectURL(url);
                showResult('文件解密成功，已下载');
            }
        } catch (error) {
            showResult('解密查看错误: ' + error.message, true);
            console.error('Fetch error:', error);
        }
    });
});