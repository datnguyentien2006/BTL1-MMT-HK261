"use strict";
let currentTarget = null;
let sessionId = sessionStorage.getItem("session_id") || "";
let statusPending = false;
let statusData = null;
let activeTransfer = null;
let uploadPreparing = false;
const pageId = crypto.randomUUID();
let pageLeaving = false;
// Lấy phần tử giao diện theo ID để dùng trong các thao tác cập nhật DOM.
const element = id => document.getElementById(id);

// Hiển thị thông báo lỗi thao tác; truyền chuỗi rỗng để xóa thông báo.
function errorMessage(message = "") { element("action-error").textContent = message; }
// Xóa trạng thái phiên hiện tại và đưa giao diện về màn hình đăng nhập.
function showLogin() {
    sessionId = "";
    sessionStorage.removeItem("session_id");
    statusData = null;
    activeTransfer = null;
    uploadPreparing = false;
    element("upload-button").disabled = false;
    element("send-button").disabled = false;
    element("chat-screen").classList.add("hidden");
    element("login-screen").classList.remove("hidden");
    element("chat-messages").replaceChildren();
    element("progress-container").classList.add("hidden");
}
// Gọi API bằng GET hoặc POST, gửi token phiên và chuyển phản hồi lỗi thành exception.
async function api(path, body, token = sessionId) {
    const headers = {"X-Session-ID": token, "X-Page-ID": pageId};
    const options = {headers, cache: "no-store"};
    if (body !== undefined) {
        headers["Content-Type"] = "application/json";
        options.method = "POST";
        options.body = JSON.stringify(body);
    }
    const response = await fetch(path, options);
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);
    return result;
}
// Đăng nhập bằng tên đã nhập, lưu token trong tab hiện tại và tải trạng thái phiên.
async function login() {
    const button = element("login-button");
    if (button.disabled) return;
    button.disabled = true;
    element("login-error").classList.add("hidden");
    try {
        const result = await api('/api/login', {username: element("login-username").value.trim()}, "");
        sessionId = result.session_id;
        sessionStorage.setItem("session_id", sessionId);
        currentTarget = null;
        errorMessage();
        await fetchStatus();
    } catch (err) {
        element("login-error").textContent = err.message;
        element("login-error").classList.remove("hidden");
    } finally { button.disabled = false; }
}
// Đưa giao diện về màn hình đăng nhập và yêu cầu máy chủ đóng phiên cũ.
async function logout() {
    const token = sessionId;
    showLogin();
    try { await api('/api/logout', {}, token); }
    catch (err) { console.error(err); }
}
// Cho phép nhấn Enter ở ô tên người dùng để đăng nhập.
function handleLoginKey(event) { if (event.key === 'Enter') login(); }
// Cho phép nhấn Enter ở ô soạn tin để gửi tin nhắn.
function handleChatKey(event) { if (event.key === 'Enter') sendMessage(); }
// Chọn người nhận hoặc phòng chat chung rồi hiển thị cuộc trò chuyện tương ứng.
function selectTarget(target) {
    currentTarget = target;
    errorMessage();
    if (statusData) render(statusData);
}
// Cập nhật danh sách peer, tin nhắn của cuộc trò chuyện đang chọn và tiến độ truyền file.
function render(data) {
    element("username-display").textContent = data.username;
    element("current-target").textContent = currentTarget === null ? 'Chat chung' : currentTarget;
    element("peer-count").textContent = data.peers.length;
    const list = element("peer-list");
    list.replaceChildren();
    for (const peer of [{user: null}, ...data.peers]) {
        const item = document.createElement('li');
        item.className = 'peer-item' + (peer.user === currentTarget ? ' active' : '');
        item.textContent = peer.user === null ? 'Chat chung (Broadcast)' :
            peer.user + (peer.user === data.username ? ' (Bạn)' : '');
        if (peer.user !== null) {
            const address = document.createElement('small');
            address.className = 'peer-address';
            address.textContent = `IP: ${peer.ip} · UDP: ${peer.udp_port}`;
            item.append(address);
        }
        item.onclick = () => selectTarget(peer.user);
        list.append(item);
    }
    const box = element("chat-messages");
    const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 60;
    box.replaceChildren();
    const messages = data.messages.filter(message => currentTarget === null ? message.type === 'broadcast' :
        message.type !== 'broadcast' &&
        ((message.sender === data.username && message.target === currentTarget) ||
         (message.sender === currentTarget && message.target === data.username)));
    if (!messages.length) {
        const empty = document.createElement('div');
        empty.className = 'empty-chat-state';
        empty.textContent = 'Chưa có tin nhắn trong cuộc trò chuyện này.';
        box.append(empty);
    }
    for (const message of messages) {
        const mine = message.sender === data.username;
        const wrapper = document.createElement('div');
        wrapper.className = 'msg-wrapper ' + (mine ? 'me' : 'other');
        const meta = document.createElement('div');
        meta.className = 'msg-meta';
        meta.textContent = `${message.sender} • ${message.time}`;
        const bubble = document.createElement('div');
        bubble.className = 'msg-bubble ' + (mine ? 'me' : 'other');
        if (message.type === 'file' && message.file_id) {
            const button = document.createElement('button');
            button.textContent = 'Tải file: ' + message.filename;
            button.onclick = () => downloadFile(message.file_id, message.filename);
            bubble.append(button);
        } else {
            bubble.textContent = message.type === 'file' ? 'Đã gửi file: ' + message.filename : message.content;
        }
        if (message.delivery && Object.keys(message.delivery.failed).length) {
            const failure = document.createElement('div');
            failure.textContent = 'Chưa gửi được tới: ' + Object.keys(message.delivery.failed).join(', ');
            bubble.append(failure);
        }
        wrapper.append(meta, bubble);
        box.append(wrapper);
    }
    if (atBottom) box.scrollTop = box.scrollHeight;
    const transfer = data.transfers.find(item => item.id === activeTransfer) || data.transfers.at(-1);
    if (transfer) {
        element("progress-container").classList.remove("hidden");
        element("progress-filename").textContent = transfer.filename;
        const percent = transfer.total ? Math.floor(transfer.sent * 100 / transfer.total) :
            (transfer.state === 'done' ? 100 : 0);
        element("progress-percent").textContent = `${percent}%`;
        element("progress-bar").style.width = `${percent}%`;
        element("progress-state").textContent = ({queued:'Đang chờ',sending:'Đang gửi',
            verifying:'Đang kiểm tra',done:'Hoàn tất',error:'Lỗi'})[transfer.state];
        element("upload-button").disabled = uploadPreparing || ['queued','sending','verifying'].includes(transfer.state);
        if (transfer.state === 'error') errorMessage(transfer.error);
    }
}
// Lấy trạng thái mới, tránh yêu cầu trùng và bỏ phản hồi thuộc phiên đã thay đổi.
async function fetchStatus() {
    if (!sessionId || statusPending || pageLeaving) return false;
    statusPending = true;
    const token = sessionId;
    try {
        const data = await api('/api/status');
        if (token !== sessionId) return false;
        if (!data.logged_in) {
            showLogin();
            element("login-error").textContent = 'Phiên đã đóng. Vui lòng đăng nhập lại.';
            element("login-error").classList.remove("hidden");
            return false;
        }
        element("login-screen").classList.add("hidden");
        element("chat-screen").classList.remove("hidden");
        element("connection-status").textContent = 'Đã kết nối';
        statusData = data;
        render(data);
        return true;
    } catch (err) {
        element("connection-status").textContent = 'Mất kết nối tới web bridge';
        errorMessage(err.message);
        return false;
    } finally { statusPending = false; }
}
// Gửi nội dung đang soạn đến đích đã chọn và cập nhật lịch sử hoặc lỗi giao tin.
async function sendMessage() {
    const button = element("send-button");
    const input = element("message-input");
    if (button.disabled || !input.value.trim()) return;
    button.disabled = true;
    errorMessage();
    try {
        const result = await api('/api/send', {target: currentTarget, message: input.value});
        if (!result.success) errorMessage('Không gửi được tới: ' + Object.keys(result.failed).join(', '));
        input.value = '';
        await fetchStatus();
    } catch (err) { errorMessage(err.message); }
    finally { button.disabled = false; }
}
// Kiểm tra file/người nhận, chuyển nội dung sang base64 và tạo công việc upload qua API.
async function uploadFile() {
    const file = element("file-input").files[0];
    if (!file) return errorMessage('Vui lòng chọn file.');
    if (currentTarget === null) return errorMessage('Chọn một người nhận trước khi gửi file.');
    if (file.size > 16 * 1024 * 1024) return errorMessage('Giới hạn tải lên qua web là 16 MiB.');
    const button = element("upload-button");
    if (button.disabled) return;
    const token = sessionId;
    const target = currentTarget;
    uploadPreparing = true;
    button.disabled = true;
    errorMessage();
    try {
        const bytes = new Uint8Array(await file.arrayBuffer());
        if (token !== sessionId) return;
        let binary = '';
        for (let i = 0; i < bytes.length; i += 32768) binary += String.fromCharCode(...bytes.subarray(i, i + 32768));
        const result = await api('/api/upload', {target, filename: file.name, filedata: btoa(binary)}, token);
        if (token !== sessionId) return;
        activeTransfer = result.transfer_id;
        uploadPreparing = false;
        element("file-input").value = '';
        await fetchStatus();
    } catch (err) {
        if (token === sessionId) { errorMessage(err.message); button.disabled = false; }
    } finally { if (token === sessionId) uploadPreparing = false; }
}
// Tải file bằng token phiên, tạo liên kết tải xuống và giải phóng URL tạm sau khi dùng.
async function downloadFile(id, filename) {
    try {
        const response = await fetch('/api/download/' + encodeURIComponent(id),
            {headers: {'X-Session-ID': sessionId}});
        if (!response.ok) throw new Error('Không thể tải file.');
        const url = URL.createObjectURL(await response.blob());
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = filename;
        anchor.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) { errorMessage(err.message); }
}
// A single recursive poll, scheduled after completion: no overlap or duplicate timers.
async function pollStatus() {
    // Chờ lượt cập nhật hiện tại xong rồi hẹn lượt tiếp theo sau một giây để tránh chạy chồng.
    await fetchStatus();
    setTimeout(pollStatus, 1000);
}
pollStatus();

// Báo trang đã rời đi; thời gian chờ phía máy chủ giúp tải lại trang không bị đăng xuất.
window.addEventListener('pagehide', () => {
    pageLeaving = true;
    if (!sessionId) return;
    const body = JSON.stringify({session_id: sessionId, page_id: pageId});
    if (!navigator.sendBeacon('/api/detach', new Blob([body], {type: 'application/json'}))) {
        fetch('/api/detach', {method: 'POST', body,
            headers: {'Content-Type': 'application/json'}, keepalive: true}).catch(() => {});
    }
});

// Nối lại phiên khi quay về trang từ bộ nhớ lịch sử của trình duyệt.
window.addEventListener('pageshow', () => {
    pageLeaving = false;
    fetchStatus();
});
