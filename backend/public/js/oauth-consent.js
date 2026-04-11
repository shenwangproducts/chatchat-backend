document.addEventListener('DOMContentLoaded', () => {
  const container = document.getElementById('oauth-data');
  if (!container) return;
  
  // ดึงค่าตัวแปรจาก Data Attributes ที่ฝังมาจาก Backend
  const clientId = container.dataset.clientId;
  const redirectUri = container.dataset.redirectUri;
  const state = container.dataset.state;
  const scope = container.dataset.scope;

  const token = localStorage.getItem('chatchat_oauth_token');
  if (token) { 
    document.getElementById('consent-section').style.display = 'block'; 
  } else { 
    document.getElementById('login-section').style.display = 'block'; 
  }

  // ทำงานเมื่อกดปุ่ม "เข้าสู่ระบบ"
  document.getElementById('btnLogin')?.addEventListener('click', async () => {
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const errorDiv = document.getElementById('login-error');
    errorDiv.style.display = 'none';

    try {
      const res = await fetch('/api/login', { 
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' }, 
        body: JSON.stringify({ email, password }) 
      });
      const data = await res.json();
      if (data.success) {
        localStorage.setItem('chatchat_oauth_token', data.authToken);
        document.getElementById('login-section').style.display = 'none';
        document.getElementById('consent-section').style.display = 'block';
      } else { 
        errorDiv.innerText = data.error || 'เข้าสู่ระบบไม่สำเร็จ'; 
        errorDiv.style.display = 'block'; 
      }
    } catch (e) { 
      errorDiv.innerText = 'ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์ได้'; 
      errorDiv.style.display = 'block'; 
    }
  });

  // ฟังก์ชันส่วนกลางเมื่อกดยืนยัน (อนุญาต หรือ ปฏิเสธ)
  const submitConsent = async (approved) => {
    const token = localStorage.getItem('chatchat_oauth_token');
    try {
      const res = await fetch('/api/oauth/authorize', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
        body: JSON.stringify({ client_id: clientId, redirect_uri: redirectUri, state: state, scope: scope, approved })
      });
      
      if (res.status === 401) {
        localStorage.removeItem('chatchat_oauth_token');
        document.getElementById('consent-section').style.display = 'none';
        document.getElementById('login-section').style.display = 'block';
        return;
      }
      
      const data = await res.json();
      if (data.success && data.redirect_url) { 
        window.location.href = data.redirect_url; 
      } else { 
        alert(data.error || 'เกิดข้อผิดพลาดในการประมวลผล'); 
      }
    } catch (e) { 
      alert('ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์ได้'); 
    }
  };

  // ทำงานเมื่อกด "อนุญาต" หรือ "ปฏิเสธ"
  document.getElementById('btnAllow')?.addEventListener('click', () => submitConsent(true));
  document.getElementById('btnDeny')?.addEventListener('click', () => submitConsent(false));
});