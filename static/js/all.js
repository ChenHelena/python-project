let selectedRole = 'customer';

// 函数来选择角色
function selectRole(role) {
  selectedRole = role;

  // 更新选中的 Tab 样式
  const tabs = document.querySelectorAll('.nav-link.active');
  tabs.forEach(tab => tab.classList.remove('active'));
  
  // 查找当前角色对应的 activeTab
  // const activeTab = document.querySelector(`.nav-link[onclick="selectRole('${role}')"]`);
  const activeTab = document.querySelector(`.nav-link[data-role="${role}"]`);
  if (activeTab) { // 确保 activeTab 存在
    activeTab.classList.add('active');
  } else {
    console.error('Active tab 找不到：' + role); // 添加错误日志
  }

  // 使用 console.log 来查看选择的角色
  console.log('选择的角色是：' + selectedRole);
}

function handleGoogleAuth(action) {
    try {
        console.log('当前选择的角色:', selectedRole);
        if (!selectedRole) {
            displayFlashMessage('danger', '身份不明');
            return;
        }

        // 根据 action 确定跳转的 URL
        const url = `/${action}/google?role=${encodeURIComponent(selectedRole)}`;
        console.log('重定向 URL:', url);
        window.location.href = url;  // 跳转到后端的登录或注册 URL
    } catch (error) {
        console.error('处理 Google 认证过程中出错:', error);
    }
}

// 用法示例
function registerWithGoogle() {
    handleGoogleAuth('register');
}

function loginWithGoogle() {
    handleGoogleAuth('login');
}

// 用于显示 Flash 消息的函数
function displayFlashMessage(type, message) {
  const flashContainer = document.getElementById('flash-messages');
  if (flashContainer) {
    const flashMessage = document.createElement('div');
    flashMessage.className = `alert alert-${type} alert-dismissible fade show`; //category 決定訊息的樣式（例如 alert-success 或 alert-danger），message 是實際的內容
    flashMessage.innerHTML = `${message}<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>`;
    flashContainer.appendChild(flashMessage);
    setTimeout(() => flashMessage.remove(), 5000);  // 5秒后移除消息
  }
}