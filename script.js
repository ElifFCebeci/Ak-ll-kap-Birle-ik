  // --- Ortak / global ---
    const API_BASE_URL = window.location.origin;
    const DOOR_MODES = {1:'Otomatik Mod',2:'Manuel Mod',3:'Serbest Mod',4:'Pasif Mod',5:'Test Modu'};
    // GÜNCELLEME: TechnicalStaff buradan kaldırıldı.
    const AUTH_LEVELS = { 'SuperAdmin':3,'Admin':2,'User':1 ,'TechnicalStaff':4 };
    
    // Varsayılan yetki 0 (TechnicalStaff/Visitor) veya null olmalı
    let currentRoleID = 0; 
    let currentUserName = null; // Veri gelene kadar null
    let currentUserRoleName = null; 
    let globalDoorsData = []; // Demo veri yok, API'den dolacak
    let currentSelectedGroup = null;
    let tempEmail = ''; // kayıt/reset için

    // --- TÜRKÇE KARAKTER DÜZELTME YARDIMCISI (GLOBAL) ---
    function trToEn(text) {
        if (!text) return "";
        const charMap = {
            'ç': 'c', 'Ç': 'C', 'ğ': 'g', 'Ğ': 'G',
            'ı': 'i', 'I': 'I', 'İ': 'I', 'i': 'i',
            'ö': 'o', 'Ö': 'O', 'ş': 's', 'Ş': 'S',
            'ü': 'u', 'Ü': 'U'
        };
        return String(text).replace(/[çÇğĞıİöÖşŞüÜ]/g, (s) => charMap[s] || s);
    }


async function fetchUserData() {
    try {
        const token = sessionStorage.getItem('token'); 
        if (!token) throw new Error("No token found");

        const res = await fetch(`${API_BASE_URL}/api/auth/me`, {
            method: 'GET',
            headers: { 'Authorization': 'Bearer ' + token }
        });

        if (res.ok) {
            const data = await res.json();
            currentUserName = data.name;
            // Ham rol ismini alıyoruz (örn: 'user', 'USER', 'Admin' vs.)
            const rawRole = data.role; 

            // --- HARF DÜZELTME MEKANİZMASI ---
            // İlk harfi büyüt, gerisini küçült (örn: 'user' -> 'User')
            let normalizedRole = rawRole.charAt(0).toUpperCase() + rawRole.slice(1).toLowerCase();
            
            // Özel durumlar (Bitişik yazılanlar vs.)
            if(normalizedRole === 'Superadmin') normalizedRole = 'SuperAdmin';
            if(normalizedRole === 'Technicalstaff') normalizedRole = 'TechnicalStaff';

            currentUserRoleName = normalizedRole; // Ekrana düzgün yazsın
            currentRoleID = AUTH_LEVELS[normalizedRole] || 0; 
            
            console.log(`Rol Algılandı: ${rawRole} -> Çevrildi: ${normalizedRole} (ID: ${currentRoleID})`);

            updateHeaderInfo(); 
            updateSidebarVisibility(); // Menüyü tekrar çizdir
            checkAdminButtonVisibility();

        } else {
            doSignOut();
        }
    } catch (err) {
        console.error("Kullanıcı verisi alınamadı", err);
        currentRoleID = 0; 
        doSignOut(); 
    }
}

// *** DEĞİŞİKLİK BURADA: localStorage -> sessionStorage ***
async function fetchDoorsData() {
    try {
        console.log("📡 Sunucudan kapı verileri isteniyor...");
        
        const token = sessionStorage.getItem('token');
        if(!token) return doSignOut();

        const res = await fetch(`${API_BASE_URL}/api/doors/status/all`, {
             headers: { 'Authorization': 'Bearer ' + token }
        });
        
        if (!res.ok) {
            throw new Error(`HTTP Hatası: ${res.status}`);
        }

        const rawData = await res.json();
        const doorsArray = rawData.doors || rawData;

        console.log("📦 Sunucudan Gelen Ham Veri:", rawData);

        // --- YENİ VE KESİN ÇÖZÜM: HEARTBEAT ÜZERİNDEN ---
        globalDoorsData = doorsArray.map(d => {
            // CRITICAL: Tüm kapılar için aynı mantık
            // 1. Önce heartbeatstatus'e bak (ESP ve DB kapıları için)
            // 2. Sonra onlinedb'ye bak
            // 3. Sonra online alanına bak
            
            let isOnline = false;
            
            // DEBUG: Server'dan gelen tüm online bilgilerini logla
            console.log(`🔍 Kapı ${d.doorid || d.DoorID}:`, {
                heartbeatstatus: d.heartbeatstatus,
                onlinedb: d.onlinedb,
                online: d.online,
                doorname: d.doorname || d.DoorName
            });
            
            // 1. HEARTBEATSTATUS (Öncelikli)
            if (d.heartbeatstatus !== undefined) {
                isOnline = d.heartbeatstatus === true || d.heartbeatstatus === 1;
                console.log(`✅ Kapı ${d.doorid || d.DoorID}: heartbeatstatus = ${d.heartbeatstatus} → online = ${isOnline}`);
            }
            // 2. ONLINEDB (Database'den)
            else if (d.onlinedb !== undefined) {
                isOnline = d.onlinedb === true || d.onlinedb === 1;
                console.log(`✅ Kapı ${d.doorid || d.DoorID}: onlinedb = ${d.onlinedb} → online = ${isOnline}`);
            }
            // 3. ONLINE (Direkt alan)
            else if (d.online !== undefined) {
                isOnline = d.online === true || d.online === 1;
                console.log(`✅ Kapı ${d.doorid || d.DoorID}: online = ${d.online} → online = ${isOnline}`);
            }
            // 4. HİÇBİRİ YOKSA: Varsayılan false
            else {
                console.log(`⚠️  Kapı ${d.doorid || d.DoorID}: Hiçbir online bilgisi yok, false varsayılıyor`);
            }

            return {
                DoorID: d.doorid || d.DoorID,
                DoorName: d.doorname || d.DoorName || 'İsimsiz Kapı',
                GroupName: (d.GroupName && d.GroupName !== 'null') ? d.GroupName : (d.groupname || 'Genel'),
                Mode: d.doormodemodeid || d.DoorModeModeID || d.Mode || d.currentmodeid || 1,
                Online: isOnline, // ✅ HEARTBEAT ÜZERİNDEN
                OpenSpeed: d.speedopen || d.Speed || d.SpeedOpen || 50,
                CloseSpeed: d.speedclose || d.SpeedClose || 50,
                WaitTime: d.waittime || d.WaitTime || 5,
                Access: d.Access || { EntryFree: false, EntryAuth: false, ExitFree: false, ExitAuth: false },
                MaintenanceLogs: d.MaintenanceLogs || [],
                ModeLogs: d.ModeLogs || [],
                PassiveState: d.PassiveState || 'CLOSED',
                TestCycle: d.TestCycle || { OpenTime: 5, CloseTime: 5 },
                
                // YENİ EKLENDİ: Gerçek verileri de kaydet
                RealData: {
                    speedopen: d.speedopen,
                    speedclose: d.speedclose,
                    waittime: d.waittime,
                    mode: d.doormodemodeid || d.mode,
                    status: d.status,
                    sensorLeft: d.SensorLeft,
                    sensorRight: d.SensorRight,
                    passiveState: d.PassiveState
                }
            };
        });
        
        console.log("✅ Frontend Kapıları:", globalDoorsData.map(d => ({
            id: d.DoorID,
            name: d.DoorName,
            mode: d.Mode,
            online: d.Online,
            speed: d.OpenSpeed,
            wait: d.WaitTime
        })));
        
        // ✅ GÜNCELLEME SONRASI ZORLA RENDER
        if (typeof updateAllDoorStatuses === 'function') {
            updateAllDoorStatuses();
        }
        
        // ✅ DOOR MANAGEMENT PANEL'İNİ DE GÜNCELLE
        if (document.getElementById('door-management-panel')?.style.display === 'block') {
            updateMgmtTargetSelect();
        }

        return globalDoorsData;

    } catch (err) {
        console.error("❌ Kapı verileri çekilemedi:", err);
        return [];
    }
}
        
    function getLocalISOString(){
        const now=new Date(); now.setMinutes(now.getMinutes()-now.getTimezoneOffset()); return now.toISOString().slice(0,16);
    }

    function showIfExists(id, display){
        const el = document.getElementById(id);
        if(el) el.style.display = display || 'block';
    }
    function hideIfExists(id){
        const el = document.getElementById(id);
        if(el) el.style.display = 'none';
    }

  
    function switchPanel(panelName) {
    // ============================================================
    // 1. LAYOUT YÖNETİMİ (Giriş Ekranı mı? Uygulama mı?)
    // ============================================================
    
    // Herkese açık (Auth) sayfalar listesi
    const authPanels = ["login", "register", "verify", "forgot", "reset"];
    
    // HTML'deki Ana Kapsayıcılar
    const authContainer = document.getElementById('auth-wrapper-container');
    const appLayout = document.getElementById('main-app-layout');
    const logModal = document.getElementById('log-modal');

    // Açık modalları kapat
    if (logModal) logModal.style.display = 'none';
    if (typeof closeAddDoorModal === 'function') closeAddDoorModal(); 

    // --- SENARYO A: GİRİŞ/KAYIT EKRANLARI İSTENİYORSA ---
    if (authPanels.includes(panelName)) {
        // Uygulama arayüzünü (Sidebar + Content) tamamen gizle
        if (appLayout) appLayout.style.display = 'none';
        
        // Auth kapsayıcısını aç
        if (authContainer) authContainer.style.display = 'block';

        // Tüm auth alt panellerini (login, register vb.) gizle
        document.querySelectorAll('.auth-wrapper').forEach(el => el.style.display = 'none');

        // Sadece istenen auth panelini aç
        const target = document.getElementById(`panel-${panelName}`);
        if (target) target.style.display = "flex";
        
        return; // İşlem bitti, fonksiyondan çık.
    }

    // --- SENARYO B: UYGULAMA İÇİ PANELLER İSTENİYORSA ---
    
    // Auth ekranını gizle, Ana Uygulamayı (Sidebar + Content) aç
    if (authContainer) authContainer.style.display = 'none';
    if (appLayout) appLayout.style.display = 'flex'; 

    // Sidebar'daki butonları kullanıcının yetkisine göre güncelle
    if (typeof updateSidebarVisibility === "function") {
        updateSidebarVisibility();
    }

    // ============================================================
    // 2. ROL TABANLI ERİŞİM KONTROLÜ (RBAC)
    // ============================================================
    // currentRoleID: SuperAdmin(3), Admin(2), User(1), TechnicalStaff(4)

    // --- KURAL 1: TEKNİK PERSONEL (ID: 4) ---
    // Teknik personel SADECE 'maintenance' görebilir.
    if (currentRoleID === 4) {
        if (panelName !== 'maintenance') {
            return switchPanel('maintenance');
        }
    }

    // --- KURAL 2: DİĞER ROLLERİN KISITLAMALARI ---
    
    // SuperAdmin (3) değilse -> Dashboard YASAK
    if (panelName === 'dashboard' && currentRoleID < 3) {
        return switchPanel('doors'); 
    }

    // Admin (2) veya SuperAdmin (3) değilse -> Takvimleme YASAK
    if (panelName === 'scheduler' && currentRoleID < 2) {
        return switchPanel('doors');
    }

    // SuperAdmin (3) değilse -> Gruplar YASAK
    if (panelName === 'groups' && currentRoleID !== 3) {
        return switchPanel('doors');
    }

    // SuperAdmin (3) veya Teknik Personel (4) değilse -> Bakım YASAK
    if (panelName === 'maintenance' && currentRoleID !== 3 && currentRoleID !== 4) {
        return switchPanel('doors');
    }

    // SuperAdmin (3) değilse -> Kullanıcılar (Users) YASAK
    if (panelName === 'users' && currentRoleID !== 3) {
        return switchPanel('doors');
    }

    // ============================================================
    // 3. İÇERİK DEĞİŞTİRME (Sadece sağ taraf değişecek)
    // ============================================================

    // Önce içerik alanındaki TÜM panelleri gizle
    const contentPanels = [
        'dashboard-panel', 
        'door-management-panel', 
        'scheduler-panel', 
        'group-management-panel', 
        'maintenance-panel',
        'users-panel',
        'assignments-panel'
    ];
    
    contentPanels.forEach(id => {
        const el = document.getElementById(id);
        if(el) el.style.display = 'none';
    });

    // İstenen paneli aç ve ilgili verileri yükle
    if (panelName === 'dashboard') {
        showIfExists('dashboard-panel', 'block');
        fetchDoorsData();
    } 

    else if (panelName === 'doors') {
        showIfExists('door-management-panel', 'block');

        // --- USER İSE "GRUP SEÇ" SEÇENEĞİNİ SİL ---
        const targetTypeSelect = document.getElementById('mgmt-target-type');
        
        if (targetTypeSelect) {
            if (currentRoleID === 1) {
                targetTypeSelect.innerHTML = `
                    <option value="all">TÜM KAPILARIM</option>
                    <option value="door">KAPI SEÇ</option>
                `;
            } else {
                // EĞER ADMİN İSE: Hepsi görünsün
                targetTypeSelect.innerHTML = `
                    <option value="all">TÜM TESİS</option>
                    <option value="group">GRUP SEÇ</option>
                    <option value="door">KAPI SEÇ</option>
                `;
            }
        }
        if (typeof updateMgmtTargetSelect === 'function') updateMgmtTargetSelect();
        
        // User ise ve henüz hedef seçilmediyse 'all' yap ki boş gelmesin
        if (currentRoleID === 1 && targetTypeSelect.value === 'group') {
             targetTypeSelect.value = 'all';
             if (typeof updateMgmtTargetSelect === 'function') updateMgmtTargetSelect();
        }

        fetchDoorsData();
    }

    else if (panelName === 'scheduler') {
        showIfExists('scheduler-panel', 'block');
        if (typeof updateTargetSelect === 'function') updateTargetSelect();
        if (typeof updateSchedulerSettingsUI === 'function') updateSchedulerSettingsUI();
        
        // --- TARİH AYARLARI ---
        const minTime = getLocalISOString();
        const maxTime = "2099-12-31T23:59"; 

        const schedStart = document.getElementById('sched-start');
        const schedEnd = document.getElementById('sched-end');

        if (schedStart) { schedStart.min = minTime; schedStart.max = maxTime; }
        if (schedEnd) { schedEnd.min = minTime; schedEnd.max = maxTime; }
        
        // Eğer kapı listesi boşsa çek
        if(globalDoorsData.length === 0) fetchDoorsData();

        // 🟢 YENİ EKLENEN KISIM: LİSTEYİ YENİLE 🟢
        // Takvim ekranı açılınca veritabanındaki kayıtları çekip listeler
        if (typeof fetchSchedules === 'function') fetchSchedules();
    }

    else if (panelName === 'groups') {
        showIfExists('group-management-panel', 'block');
        fetchDoorsData().then(() => {
            if (typeof renderGroupManagementUI === 'function') renderGroupManagementUI();
        });
    }
    else if (panelName === 'maintenance') {
        showIfExists('maintenance-panel', 'block');
        fetchDoorsData().then(() => {
            if (typeof renderMaintenancePanel === 'function') renderMaintenancePanel();
        });
    }
    else if (panelName === 'users') {
        showIfExists('users-panel', 'block');
        if (typeof fetchUsersData === 'function') fetchUsersData();
    }
    else if (panelName === 'assignments') {
        showIfExists('assignments-panel', 'block');
        fetchAssignableUsers(); 
        if(globalDoorsData.length === 0) fetchDoorsData(); 
    }
}

// Sidebar'daki linkleri yetkiye göre göster/gizle
function updateSidebarVisibility() {
    // HTML'deki Sidebar Butonlarının ID'leri
    const btnDash = document.getElementById('nav-btn-dashboard');
    const btnDoors = document.getElementById('nav-btn-doors');
    const btnSched = document.getElementById('nav-btn-scheduler');
    const btnGroups = document.getElementById('nav-btn-groups');
    const btnMaint = document.getElementById('nav-btn-maintenance');
    const btnUsers = document.getElementById('nav-btn-users'); // <-- YENİ EKLENDİ
    const btnAssignments = document.getElementById('nav-btn-assignments'); // <-- ID'yi seç

    // Sidebar kullanıcı bilgisini güncelle
    const userLabel = document.getElementById('sidebar-user-name');
    const roleLabel = document.getElementById('sidebar-user-role');
    if(userLabel) userLabel.innerText = currentUserName || 'Kullanıcı';
    if(roleLabel) roleLabel.innerText = currentUserRoleName || 'Yetkisiz';

    // 1. Önce Hepsini Gizle (Temizlik)
    // Listeye btnUsers da eklendi
    [btnDash, btnDoors, btnSched, btnGroups, btnMaint, btnUsers, btnAssignments].forEach(btn => { // btnAssignments ekle
    if(btn) btn.style.display = 'none';
    });

    // 2. Yetkiye Göre Aç

    // --- ÖZEL DURUM: TEKNİK PERSONEL (ID: 4) ---
    // Sadece Bakım butonunu görür, başka hiçbir şeyi görmez.
    if (currentRoleID === 4) {
        if(btnMaint) btnMaint.style.display = 'flex'; 
        return; // Fonksiyondan çık, diğer kontrolleri yapma.
    }

    // --- STANDART HİYERARŞİ (ID: 1, 2, 3) ---

    // User(1), Admin(2), SuperAdmin(3) -> Kapıları Görür
    if (currentRoleID >= 1 && btnDoors) {
        btnDoors.style.display = 'flex';
    }

    // Admin(2) ve SuperAdmin(3) -> Takvimlemeyi Görür
    if (currentRoleID >= 2 && btnSched) {
        btnSched.style.display = 'flex';
    }

    // Sadece SuperAdmin(3) -> Dashboard, Gruplar, Bakım ve Kullanıcıları Görür
    if (currentRoleID === 3) {
        if(btnDash) btnDash.style.display = 'flex';
        if(btnGroups) btnGroups.style.display = 'flex';
        if(btnMaint) btnMaint.style.display = 'flex';
        if(btnUsers) btnUsers.style.display = 'flex'; 
        if(btnAssignments) btnAssignments.style.display = 'flex';// <-- YENİ: Sadece SuperAdmin
    }
}


    function updateHeaderInfo(){
        const displayName = currentUserName || 'Ziyaretçi';
        const displayRole = currentUserRoleName || 'Misafir'; 

        const htmlContent = `
            <span>
                <i class="fas fa-user-circle"></i> 
                <strong style="color:var(--neon-blue)">${displayName}</strong>
            </span>
            <span style="background:rgba(255,255,255,0.06); padding:6px 10px; border-radius:6px; font-size:0.85rem; margin-left:8px;">
                ${displayRole}
            </span>`;

        ['header-info-dashboard','header-info-doors','header-info-scheduler','header-info-groups','header-info-maintenance', 'header-info-users'].forEach(id => {
            const el = document.getElementById(id); 
            if(el) el.innerHTML = htmlContent;
        });
    }

    // *** DEĞİŞİKLİK BURADA: localStorage -> sessionStorage ***
    async function handleLogin(){
        const email = document.getElementById('login-email').value;
        const password = document.getElementById('login-password').value;
        
        if(!email || !password) return alert("E-posta ve şifre girin.");

        try{
            const res = await fetch(`${API_BASE_URL}/api/auth/login`, {
                method: 'POST',  
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password })
            });
            
            const data = await res.json();
            
            if(data.status === 'success'){
                if(data.token) {
                    sessionStorage.setItem('token', data.token);
                    console.log("✔️ Yeni Token Başarıyla sessionStorage'a kaydedildi.");
                }

                alert("Giriş Başarılı!");

                if (data.user) {
                    currentUserName = data.user.name;
                    currentUserRoleName = data.user.role; 
                    currentRoleID = AUTH_LEVELS[currentUserRoleName] || 0; 

                    updateHeaderInfo(); 
                    checkAdminButtonVisibility(); 
                } else {
                    await fetchUserData(); 
                }

                switchPanel('dashboard');
                fetchDoorsData(); 

            } else {
                alert(data.message || 'Giriş başarısız. Bilgileri kontrol edin.');
            }

        } catch(err){
            console.error("❌ Login Hatası:", err); 
            alert("Sunucuya bağlanılamadı.");
        }
    }

    async function handleRegister(){
        const firstname = document.getElementById('reg-name').value.trim();
        const surname = document.getElementById('reg-surname').value.trim();
        const email = document.getElementById('reg-email').value.trim();
        const password = document.getElementById('reg-pass').value;

        if(!firstname || !surname || !email || !password) {
            return alert("Lütfen ad, soyad, e-posta ve şifre alanlarını eksiksiz doldurun.");
        }

        try{
            const res = await fetch(`${API_BASE_URL}/api/auth/register`, {
                method: 'POST', 
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ firstname, surname, email, password })
            });
            
            const data = await res.json();
            
            if(data.status === 'success'){
                tempEmail = email; 
                alert("Kayıt başarılı! E-posta adresinize gelen doğrulama kodunu giriniz.");
                switchPanel('verify');
            } else {
                alert(data.message || 'Kayıt işlemi başarısız oldu.');
            }
        } catch(err){ 
            console.error("Kayıt Hatası:", err); 
            alert("Sunucuya bağlanılamadı. Lütfen daha sonra tekrar deneyin."); 
        }
    }

    async function handleVerify(){
        const code = document.getElementById('verify-code').value.trim();

        if(!code) return alert("Lütfen doğrulama kodunu giriniz.");

        if(!tempEmail) {
            alert("Oturum süresi doldu veya sayfa yenilendi. Lütfen tekrar kayıt olun.");
            switchPanel('register');
            return;
        }

        try{
            const res = await fetch(`${API_BASE_URL}/api/auth/verify`, {
                method: 'POST', 
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: tempEmail, code })
            });

            const data = await res.json();

            if(data.status === 'success'){
                alert("Hesap başarıyla doğrulandı! Giriş yapabilirsiniz.");
                tempEmail = ''; 
                switchPanel('login');
            } else {
                alert(data.message || 'Doğrulama başarısız. Kodu kontrol edin.');
            }
        } catch(err){ 
            console.error("Verify Hatası:", err); 
            alert("Sunucuya erişilemedi. Lütfen daha sonra tekrar deneyin."); 
        }
    }

    async function handleForgot(){
        const email = document.getElementById('forgot-email').value;
        if(!email) return alert("E-posta girin.");

        try{
            const res = await fetch(`${API_BASE_URL}/api/auth/forgot-password`, {
                method: 'POST', 
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });

            const data = await res.json();

            if(data.status === 'success'){
                tempEmail = email; 
                alert("Sıfırlama kodu mailinize gönderildi.");
                switchPanel('reset');
            } 
            else {
                alert(data.message || 'İşlem başarısız.');
            }
        } catch(err){ 
            console.error("Forgot Password Hatası:", err); 
            alert("Sunucu hatası."); 
        }
    }

    async function handleReset(){
        const code = document.getElementById('reset-code').value;
        const newPassword = document.getElementById('reset-pass').value;

        if(!code || !newPassword) return alert("Lütfen kod ve yeni şifre alanlarını doldurun.");

        if (!tempEmail) {
            alert("Oturum süresi doldu. Lütfen 'Şifremi Unuttum' işlemini baştan başlatın.");
            switchPanel('forgot'); 
            return;
        }

        try{
            const res = await fetch(`${API_BASE_URL}/api/auth/reset-password`, {
                method: 'POST', 
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: tempEmail, code, newPassword })
            });

            const data = await res.json();

            if(data.status === 'success'){
                alert("Şifreniz başarıyla değiştirildi! Yeni şifrenizle giriş yapabilirsiniz.");
                tempEmail = ''; 
                switchPanel('login');
            } 
            else {
                alert(data.message || 'Şifre sıfırlama başarısız. Kodu kontrol edin.');
            }
        } catch(err){ 
            console.error("Reset Password Hatası:", err); 
            alert("Sunucu hatası."); 
        }
    }


    function doSignOut(){ 
        sessionStorage.removeItem('token');
        window.location.reload(); 
    }

    // Settings panel HTML (PRO fonksiyonu)
    function getSettingsPanelHTML(door){
        const mode = parseInt(door.Mode);
        const id = door.DoorID; 

        // HTML KODUNU STRING OLARAK HAZIRLIYORUZ (Backtick kullanarak)
        let html = `<div class="settings-panel">`;

        switch(mode){
      // script.js içinde getSettingsPanelHTML fonksiyonunun Case 1 kısmını bununla değiştir:

// script.js -> getSettingsPanelHTML fonksiyonu -> Case 1 güncellemesi

case 1: // OTOMATİK MOD
    html += `
    <strong style="display:block; text-align:center; margin-bottom:5px; color:var(--neon-blue);">OTOMATİK AYARLAR</strong>
    
    <div style="display:flex; gap:5px;">
        <div style="flex:1">
            <label style="font-size:0.7rem; color:var(--neon-blue);">Açma Hızı</label>
            <input type="number" id="auto-open-${id}" value="${door.OpenSpeed}" min="10" max="100" style="padding:6px;" />
        </div>
        <div style="flex:1">
            <label style="font-size:0.7rem; color:var(--neon-blue);">Kapama Hızı</label>
            <input type="number" id="auto-close-${id}" value="${door.CloseSpeed}" min="10" max="100" style="padding:6px;" />
        </div>
    </div>
    <div style="margin-bottom:8px;">
        <label style="font-size:0.7rem; color:var(--neon-blue);">Açık Kalma (Sn)</label>
        <input type="number" id="auto-wait-${id}" value="${door.WaitTime}" min="0" max="30" style="padding:6px;" />
    </div>
    
    <label style="font-size:0.7rem; color:var(--neon-blue);">GEÇİŞ SENSÖRLERİ:</label>
    <div class="sensor-grid">
        <label class="checkbox-item">
            <input type="checkbox" id="sens-entry-free-${id}" 
                   onchange="handleSensorMutex(this, 'sens-entry-auth-${id}')"
                   ${door.Access.EntryFree ? 'checked' : ''} /> Serbest Giriş
        </label>
        <label class="checkbox-item">
            <input type="checkbox" id="sens-entry-auth-${id}" 
                   onchange="handleSensorMutex(this, 'sens-entry-free-${id}')"
                   ${door.Access.EntryAuth ? 'checked' : ''} /> Yetkili Giriş
        </label>

        <label class="checkbox-item">
            <input type="checkbox" id="sens-exit-free-${id}" 
                   onchange="handleSensorMutex(this, 'sens-exit-auth-${id}')"
                   ${door.Access.ExitFree ? 'checked' : ''} /> Serbest Çıkış
        </label>
        <label class="checkbox-item">
            <input type="checkbox" id="sens-exit-auth-${id}" 
                   onchange="handleSensorMutex(this, 'sens-exit-free-${id}')"
                   ${door.Access.ExitAuth ? 'checked' : ''} /> Yetkili Çıkış
        </label>
    </div>`;
    break;
            case 2: // MANUEL MOD
                html += `
                <strong style="display:block; text-align:center; margin-bottom:5px; color:var(--neon-orange);">MANUEL KONTROL</strong>
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-top:8px;">
                    <button class="btn-primary" onclick="controlDoor(${id}, 'OPEN')" style="font-size:0.85rem;"><i class="fas fa-door-open"></i> AÇ</button>
                    <button class="btn-primary" onclick="controlDoor(${id}, 'CLOSE')" style="font-size:0.85rem; border-color:var(--neon-red); color:var(--neon-red);"><i class="fas fa-door-closed"></i> KAPAT</button>
                </div>`;
                break;

            case 3: // SERBEST MOD
                html += `<div style="text-align:center; padding:10px;"><i class="fas fa-hand-paper" style="font-size:2rem; color:var(--neon-green); margin-bottom:10px;"></i><p style="margin:0; color:var(--neon-green);">SERBEST MOD</p><p style="font-size:0.8rem; color:#ccc;">Ayar yok. Kapı serbest.</p></div>`;
                break;

            case 4: // PASİF MOD
                html += `
                <strong style="display:block; text-align:center; margin-bottom:5px; color:var(--neon-red);">PASİF DURUMU</strong>
                <label style="font-size:0.7rem; color:var(--neon-blue);">Kapı Konumu:</label>
                <select id="passive-select-${id}" style="margin-bottom:0; padding:6px;">
                    <option value="OPEN" ${door.PassiveState === 'OPEN' ? 'selected' : ''}>SÜREKLİ AÇIK</option>
                    <option value="CLOSED" ${door.PassiveState === 'CLOSED' ? 'selected' : ''}>SÜREKLİ KAPALI</option>
                </select>`;
                break;

            case 5: // TEST MODU
                html += `
                <strong style="display:block; text-align:center; margin-bottom:5px; color:var(--neon-purple);">TEST PARAMETRELERİ</strong>
                <div style="display:flex; gap:6px;">
                    <div style="flex:1">
                        <label style="font-size:0.7rem; color:var(--neon-blue);">Açık (Sn)</label>
                        <input type="number" id="test-open-${id}" value="${door.TestCycle ? door.TestCycle.OpenTime : 5}" style="padding:6px;" />
                    </div>
                    <div style="flex:1">
                        <label style="font-size:0.7rem; color:var(--neon-blue);">Kapalı (Sn)</label>
                        <input type="number" id="test-close-${id}" value="${door.TestCycle ? door.TestCycle.CloseTime : 5}" style="padding:6px;" />
                    </div>
                </div>`;
                break;
        }

        if(mode !== 2 && mode !== 3){
            html += `<button class="btn-success" style="width:100%; margin-top:10px; font-size:0.85rem;" onclick="applySettings(${id})"><i class="fas fa-save"></i> AYARLARI KAYDET</button></div>`;
        } else {
            html += `</div>`;
        }
        
        return html;
    }
        
    function updateMgmtTargetSelect(){
        const type = document.getElementById('mgmt-target-type').value;
        const targetSelect = document.getElementById('mgmt-target-id');
        
        targetSelect.innerHTML = '';

        const reportArea = document.getElementById('report-buttons-area');
        const groupDashboard = document.getElementById('group-action-dashboard');

        if(type === 'door'){
            globalDoorsData.forEach(d => { 
                let opt = document.createElement('option'); 
                opt.value = d.DoorID; 
                opt.innerText = d.DoorName; 
                targetSelect.appendChild(opt); 
            });
            
            if(reportArea) reportArea.style.display = 'block';
            if(groupDashboard) groupDashboard.style.display = 'none';

        } else if(type === 'group'){
            const groups = [...new Set(globalDoorsData.map(d => d.GroupName))];
            
            groups.forEach(g => { 
                let opt = document.createElement('option'); 
                opt.value = g; 
                opt.innerText = g; 
                targetSelect.appendChild(opt); 
            });
            
            if(reportArea) reportArea.style.display = 'block';
            
            renderGroupDashboard();

        } else {
            targetSelect.innerHTML = '<option value="all">Tümü</option>';
            
            if(reportArea) reportArea.style.display = 'none';
            if(groupDashboard) groupDashboard.style.display = 'none';
        }
    }
    

function updateAllDoorStatuses(){
    const filterType = document.getElementById('mgmt-target-type').value;
    const filterValue = document.getElementById('mgmt-target-id').value;
    const list = document.getElementById('door-list');
    
    // Eğer liste elementi yoksa (başka sayfadaysak) işlemi durdur
    if(!list) return;

    list.innerHTML = '';

    // grup dashboard kontrolü
    if(filterType === 'group'){ 
        currentSelectedGroup = filterValue; 
        if (typeof renderGroupDashboard === 'function') renderGroupDashboard(); 
    } else { 
        const gad = document.getElementById('group-action-dashboard'); 
        if(gad) gad.style.display = 'none'; 
        currentSelectedGroup = null; 
    }

    globalDoorsData.forEach(d => {
        let show=false;
        if(filterType === 'all') show=true;
        else if(filterType === 'group' && d.GroupName === filterValue) show=true;
        else if(filterType === 'door' && d.DoorID.toString() === filterValue) show=true;
        if(!show) return;

        // --- İKON VE RENK AYARLARI ---
        let modeClass='', iconClass='';
        
        // Varsayılan metinler (Admin için)
        let statusText = DOOR_MODES[d.Mode]; 

        switch(d.Mode){
            case 1: modeClass='mode-auto'; iconClass='fa-robot'; break;
            case 2: modeClass='mode-manual'; iconClass='fa-hand-paper'; break; // Admin: Manuel
            case 3: modeClass='mode-free'; iconClass='fa-door-open'; break;
            case 4: modeClass='mode-passive'; iconClass='fa-power-off'; break; // Admin: Pasif
            case 5: modeClass='mode-test'; iconClass='fa-tools'; break;
        }

        // --- ÖZEL USER AYARI (BURASI YENİ) ---
        // Eğer User ise (Role 1), Otomatik olsa bile "MANUEL MOD" yazsın.
        if (currentRoleID === 1) {
            if (d.Mode == 4) {
                // Kilitli ise
                statusText = "PASİF MOD"; 
                iconClass = "fa-power-off"; 
            } else {
                // Diğer durumlarda (Açık veya Otomatik) hep MANUEL MOD yazsın
                statusText = "MANUEL MOD"; 
                iconClass = "fa-hand-paper"; 
            }
        }

        const card = document.createElement('div'); 
        card.className = `door-card ${modeClass}`;
        if(!d.Online) card.style.opacity = '0.6';

        let html = `
            <div class="door-header">
                <div><span class="door-name">${d.DoorName}</span><span class="door-sub" style="display:block;font-size:0.8rem;color:var(--text-muted)">ID: ${d.DoorID} | ${d.GroupName}</span></div>
                <i class="fas ${iconClass}" style="font-size:1.4rem; color:rgba(255,255,255,0.5);"></i>
            </div>
            
            <div class="status-icon-container"><i class="fas ${iconClass}"></i></div>
            
            <div class="status-text-big">${statusText}</div>
            
            ${!d.Online ? '<div style="text-align:center; color:var(--neon-red);">(OFFLINE)</div>' : '' }
        `;

        // --- YETKİ KONTROLLERİ ---
        
        if (d.Online) {
            // SENARYO 1: ADMİN VE SUPERADMİN (Tam Yetki - Full Panel)
            if (currentRoleID >= 2) {
                html += getSettingsPanelHTML(d); 
                html += `<div style="margin-top:10px; border-top:1px solid rgba(255,255,255,0.06); padding-top:8px;">
                            <label style="font-size:0.8rem; color:#aaa;">MODU DEĞİŞTİR:</label>
                            <select onchange="changeDoorMode(${d.DoorID}, this.value)" style="width:100%; padding:8px; margin-top:6px;">
                                ${Object.entries(DOOR_MODES).map(([k,v])=>`<option value="${k}" ${k==d.Mode?'selected':''}>${v}</option>`).join('')}
                            </select>
                         </div>`;
            } 
            
            // SENARYO 2: STANDART USER (Sadece AÇ / KAPAT)
            else if (currentRoleID === 1) {
                html += `
                <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid rgba(255,255,255,0.1);">
                    
                    <div style="display: flex; gap: 10px;">
                        <button class="btn-primary" style="flex:1; padding:15px; font-size:1rem; font-weight:bold; display:flex; flex-direction:column; align-items:center; gap:5px;" onclick="changeDoorMode(${d.DoorID}, 2)">
                            <i class="fas fa-door-open" style="font-size:1.5rem;"></i>
                            KAPIYI AÇ
                        </button>
                        
                        <button class="btn-danger" style="flex:1; padding:15px; font-size:1rem; font-weight:bold; display:flex; flex-direction:column; align-items:center; gap:5px;" onclick="changeDoorMode(${d.DoorID}, 4)">
                            <i class="fas fa-lock" style="font-size:1.5rem;"></i>
                            KAPIYI KAPAT
                        </button>
                    </div>

                </div>
                `;
            }
        }

        card.innerHTML = html;
        list.appendChild(card);
    });
} 


async function changeDoorMode(id, val) {
    const newMode = parseInt(val);
    const token = sessionStorage.getItem('token');

    if(!token) {
        alert("Oturum süresi dolmuş. Lütfen tekrar giriş yapın.");
        return switchPanel('login');
    }

    // ÖNCE OPTIMISTIC UPDATE (hemen göster)
    const oldDoors = [...globalDoorsData];
    const doorIndex = globalDoorsData.findIndex(d => d.DoorID === id);
    if (doorIndex !== -1) {
        globalDoorsData[doorIndex] = {
            ...globalDoorsData[doorIndex],
            Mode: newMode,
            updating: true // Loading göstergesi için
        };
        
        // HEMEN RENDER ET
        if (typeof updateAllDoorStatuses === 'function') {
            updateAllDoorStatuses();
        }
    }

    try {
        const res = await fetch(`${API_BASE_URL}/api/doors/${id}/settings`, {
            method: 'PUT',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token 
            },
            body: JSON.stringify({ 
                Mode: newMode,
                // Diğer değerleri koru
                Speed: globalDoorsData.find(d => d.DoorID === id)?.OpenSpeed || 50,
                WaitTime: globalDoorsData.find(d => d.DoorID === id)?.WaitTime || 5
            })
        });

        const data = await res.json();

        if(data.status === 'success'){
            console.log('✅ Mod değişikliği başarılı:', data);
            
            // VERİTABANINDAN TAZE VERİ ÇEK
            await fetchDoorsData();
            
            // BAŞARI MESAJI
            const modeName = DOOR_MODES[newMode] || 'Bilinmeyen Mod';
            alert(`✅ Kapı modu "${modeName}" olarak güncellendi!`);
        } else {
            // HATA DURUMUNDA ESKİ VERİYE DÖN
            globalDoorsData = oldDoors;
            if (typeof updateAllDoorStatuses === 'function') {
                updateAllDoorStatuses();
            }
            alert('❌ Mod değiştirme başarısız: ' + (data.message || 'Bilinmeyen hata'));
        }

    } catch(err) {
        console.error("❌ Mod Değiştirme Hatası:", err);
        // HATA DURUMUNDA ESKİ VERİYE DÖN
        globalDoorsData = oldDoors;
        if (typeof updateAllDoorStatuses === 'function') {
            updateAllDoorStatuses();
        }
        alert('❌ Sunucu hatası. Lütfen tekrar deneyin.');
    } finally {
        // Loading göstergesini kaldır
        if (doorIndex !== -1) {
            globalDoorsData[doorIndex].updating = false;
        }
    }
}
// script.js -> applySettings fonksiyonu

async function applySettings(doorId) {
    const token = sessionStorage.getItem('token');
    if (!token) return alert("Oturum hatası.");

    // 1. Kapının Mevcut Modunu Bul
    const door = globalDoorsData.find(d => d.DoorID === doorId);
    if (!door) return;

    const currentMode = parseInt(door.Mode);
    let payload = { Mode: currentMode }; 

    // ============================================================
    // MODA GÖRE VERİ OKUMA
    // ============================================================

    // --- MOD 1: OTOMATİK ---
    if (currentMode === 1) {
        const speedOpenInput = document.getElementById(`auto-open-${doorId}`);
        const speedCloseInput = document.getElementById(`auto-close-${doorId}`);
        const waitTimeInput = document.getElementById(`auto-wait-${doorId}`);

        if (!speedOpenInput || !speedCloseInput || !waitTimeInput) return;

        payload.SpeedOpen = parseInt(speedOpenInput.value);
        payload.SpeedClose = parseInt(speedCloseInput.value);
        payload.WaitTime = parseInt(waitTimeInput.value);

        // Sensör Değerlerini Okuyoruz
        const entryFree = document.getElementById(`sens-entry-free-${doorId}`)?.checked || false;
        const entryAuth = document.getElementById(`sens-entry-auth-${doorId}`)?.checked || false;
        const exitFree = document.getElementById(`sens-exit-free-${doorId}`)?.checked || false;
        const exitAuth = document.getElementById(`sens-exit-auth-${doorId}`)?.checked || false;

        // ⭐⭐⭐ VALIDASYON KONTROLÜ (YENİ) ⭐⭐⭐
        // Giriş tarafında en az biri seçili olmalı
        const hasEntry = entryFree || entryAuth;
        // Çıkış tarafında en az biri seçili olmalı
        const hasExit = exitFree || exitAuth;

        if (!hasEntry || !hasExit) {
            // Uyarı ver ve işlemi durdur (Backend'e gönderme)
            return alert("⚠️ Otomatik Mod Hatası:\nLütfen hem İÇ hem de DIŞ taraf için en az bir sensör seçiniz!");
        }
        // ⭐⭐⭐ VALIDASYON BİTİŞ ⭐⭐⭐

        payload.Access = {
            EntryFree: entryFree,
            EntryAuth: entryAuth,
            ExitFree: exitFree,
            ExitAuth: exitAuth
        };
    }

    // --- MOD 4: PASİF ---
    else if (currentMode === 4) {
        const passiveSelect = document.getElementById(`passive-select-${doorId}`);
        if (passiveSelect) {
            payload.PassiveState = passiveSelect.value; 
        }
    }

    // --- MOD 5: TEST ---
    else if (currentMode === 5) {
        const tOpen = document.getElementById(`test-open-${doorId}`);
        const tClose = document.getElementById(`test-close-${doorId}`);
        
        if(tOpen && tClose) {
            payload.TestCycle = {
                OpenTime: parseInt(tOpen.value),
                CloseTime: parseInt(tClose.value)
            };
        }
    }

    // ============================================================
    // BACKEND'E GÖNDER (Değişiklik Yok)
    // ============================================================
    try {
        const res = await fetch(`${API_BASE_URL}/api/doors/${doorId}/settings`, {
            method: 'PUT',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token 
            },
            body: JSON.stringify(payload)
        });

        const data = await res.json();
        
        if (data.status === 'success') {
            let msg = "Ayarlar kaydedildi.";
            if (payload.PassiveState) {
                const stateTr = payload.PassiveState === 'OPEN' ? 'SÜREKLİ AÇIK' : 'SÜREKLİ KAPALI';
                msg = `Kapı durumu "${stateTr}" olarak güncellendi.`;
            }
            alert("✅ " + msg);
            fetchDoorsData(); 
        } else {
            alert("❌ Hata: " + data.message);
        }
    } catch (err) {
        console.error(err);
        alert("Sunucu hatası.");
    }
}
    // script.js -> updateSchedulerSettingsUI FONKSİYONUNU BUNUNLA DEĞİŞTİR

function updateSchedulerSettingsUI(){
    const mode = parseInt(document.getElementById('sched-mode').value);
    const container = document.getElementById('sched-dynamic-settings');
    let html = '';
    
    switch(mode){
        case 1: // OTOMATİK MOD
            html = `
            <div class="settings-panel">
                <strong style="display:block; text-align:center; color:var(--neon-blue); margin-bottom:10px;">OTOMATİK AYARLAR</strong>
                
                <div style="display:flex; gap:10px; margin-bottom:10px;">
                    <div style="flex:1">
                        <label style="font-size:0.75rem; color:var(--neon-blue); display:block; margin-bottom:4px;">Açılma Hızı</label>
                        <input type="number" id="sched-auto-open" value="50" style="padding:8px;" />
                    </div>
                    <div style="flex:1">
                        <label style="font-size:0.75rem; color:var(--neon-blue); display:block; margin-bottom:4px;">Kapanma Hızı</label>
                        <input type="number" id="sched-auto-close" value="50" style="padding:8px;" />
                    </div>
                </div>
                
                <div style="margin-bottom:15px;">
                    <label style="font-size:0.75rem; color:var(--neon-blue); display:block; margin-bottom:4px;">Açık Kalma Süresi (Sn)</label>
                    <input type="number" id="sched-auto-wait" value="5" style="padding:8px;" />
                </div>

                <label style="font-size:0.75rem; color:#aaa; display:block; margin-bottom:5px;">SENSÖR VE YETKİ AYARLARI:</label>
                <div class="sensor-grid">
                    <label class="checkbox-tile tile-entry">
                        <input type="checkbox" id="sched-sens-1" onchange="handleSensorMutex(this, 'sched-sens-2')" /> 
                        <span>Serbest Gir</span>
                    </label>
                    <label class="checkbox-tile tile-entry">
                        <input type="checkbox" id="sched-sens-2" onchange="handleSensorMutex(this, 'sched-sens-1')" /> 
                        <span>Yetkili Gir</span>
                    </label>
                    <label class="checkbox-tile tile-exit">
                        <input type="checkbox" id="sched-sens-3" onchange="handleSensorMutex(this, 'sched-sens-4')" /> 
                        <span>Serbest Çık</span>
                    </label>
                    <label class="checkbox-tile tile-exit">
                        <input type="checkbox" id="sched-sens-4" onchange="handleSensorMutex(this, 'sched-sens-3')" /> 
                        <span>Yetkili Çık</span>
                    </label>
                </div>
            </div>`;
            break;

        case 4: // PASİF MOD
            html = `<div class="settings-panel"><strong style="color:var(--neon-red)">PASİF DURUMU</strong><select id="sched-passive-state" style="margin-top:6px; padding:8px;"><option value="CLOSED">SÜREKLİ KAPALI</option><option value="OPEN">SÜREKLİ AÇIK</option></select></div>`;
            break;
        case 5: // TEST MODU
            html = `<div class="settings-panel"><strong style="color:var(--neon-purple)">TEST DÖNGÜSÜ</strong><div style="display:flex; gap:8px; margin-top:8px;"><input type="number" id="sched-test-open" placeholder="Açık Süre (sn)" value="5" /><input type="number" id="sched-test-close" placeholder="Kapalı Süre (sn)" value="5" /></div></div>`;
            break;
        default:
            html = `<div style="padding:10px; color:#aaa; font-size:0.9rem;">Bu mod için ek ayar gerekmez.</div>`;
    }
    container.innerHTML = html;
}

    function updateTargetSelect(){
        const type = document.getElementById('sched-target-type').value;
        const targetSelect = document.getElementById('sched-target-id');
        
        targetSelect.innerHTML = '';

        if(type === 'door'){
            globalDoorsData.forEach(door => { 
                const opt = document.createElement('option'); 
                opt.value = door.DoorID; 
                opt.innerText = door.DoorName; 
                targetSelect.appendChild(opt); 
            });
        } else {
            const groups = [...new Set(globalDoorsData.map(d => d.GroupName))];
            groups.forEach(g => { 
                const opt = document.createElement('option'); 
                opt.value = g; 
                opt.innerText = g; 
                targetSelect.appendChild(opt); 
            });
        }
    }

    function toggleRecurrenceUI(){
        const recurType = document.getElementById('sched-recur-type').value;
        const stdDates = document.getElementById('sched-standard-dates');
        const recurOpts = document.getElementById('sched-recurrence-options');
        const daySelect = document.getElementById('sched-recur-day-week');
        
        if(recurType === 'none'){ 
            stdDates.style.display='flex'; 
            recurOpts.style.display='none'; 
        } else { 
            stdDates.style.display='none'; 
            recurOpts.style.display='flex'; 
            if(recurType==='weekly'){ 
                daySelect.style.display='block'; 
            } else { 
                daySelect.style.display='none'; 
            } 
        }
    }

    // script.js -> addSchedule fonksiyonunun GÜNCELLENMİŞ HALİ

// script.js -> addSchedule FONKSİYONUNU TAMAMEN BUNUNLA DEĞİŞTİR

// =========================================================
// script.js -> addSchedule FONKSİYONUNUN EN GÜNCEL HALİ
// (Validasyonlar + Çakışma Uyarısı Dahil)
// =========================================================

// script.js -> addSchedule FONKSİYONUNUN EN TEMİZ HALİ

async function addSchedule() {
    const type = document.getElementById('sched-target-type').value;
    const target = document.getElementById('sched-target-id').value;
    const mode = parseInt(document.getElementById('sched-mode').value);
    const recurType = document.getElementById('sched-recur-type').value;
    const now = new Date();

    let payload = {
        targetType: type,
        targetId: target,
        mode: mode,
        recurrenceType: recurType,
        settings: {} 
    };

    // 1. AYARLARI OKU (Otomatik, Pasif vb.)
    if (mode === 1) { // OTO
        const elOpen = document.getElementById('sched-auto-open');
        const elClose = document.getElementById('sched-auto-close');
        const elWait = document.getElementById('sched-auto-wait');
        if (elOpen && elOpen.value) payload.settings.SpeedOpen = parseInt(elOpen.value);
        if (elClose && elClose.value) payload.settings.SpeedClose = parseInt(elClose.value);
        if (elWait && elWait.value) payload.settings.WaitTime = parseInt(elWait.value);

        const s1 = document.getElementById('sched-sens-1').checked;
        const s2 = document.getElementById('sched-sens-2').checked;
        const s3 = document.getElementById('sched-sens-3').checked;
        const s4 = document.getElementById('sched-sens-4').checked;
        
        if ((!s1 && !s2) || (!s3 && !s4)) {
            return alert("⚠️ Lütfen Giriş ve Çıkış sensörlerinden en az birini seçiniz!");
        }
        payload.settings.Access = { EntryFree: s1, EntryAuth: s2, ExitFree: s3, ExitAuth: s4 };

    } else if (mode === 4) { // PASİF
        const elPassive = document.getElementById('sched-passive-state');
        if (elPassive) payload.settings.PassiveState = elPassive.value; 
    }

    // 2. TARİH VE SAAT KONTROLLERİ
    if (recurType === 'none') {
        // --- TEK SEFERLİK ---
        const startVal = document.getElementById('sched-start').value;
        const endVal = document.getElementById('sched-end').value;

        if (!startVal || !endVal) return alert("Lütfen başlangıç ve bitiş tarihlerini eksiksiz giriniz.");
        const startDate = new Date(startVal);
        const endDate = new Date(endVal);

        if (startDate < now) return alert("⚠️ HATA: Başlangıç tarihi şu anki zamandan önce olamaz!");
        if (endDate <= startDate) return alert("⚠️ HATA: Bitiş tarihi, başlangıç tarihinden sonra olmalıdır!");

        payload.startTime = startVal;
        payload.endTime = endVal;

    } else {
        // --- HAFTALIK ---
        const tStart = document.getElementById('sched-time-start').value;
        const tEnd = document.getElementById('sched-time-end').value;

        if (!tStart || !tEnd) return alert("Lütfen saat aralığını giriniz.");
        if (tEnd <= tStart) return alert("⚠️ HATA: Bitiş saati, başlangıç saatinden sonra olmalıdır!");

        payload.startTime = tStart;
        payload.endTime = tEnd;

        const daySel = document.getElementById('sched-recur-day-week');
        payload.recurrenceValue = daySel.value; 
    }

    // 3. BACKEND İSTEĞİ
    const token = sessionStorage.getItem('token');
    if (!token) return alert("Oturum hatası.");

    try {
        const res = await fetch(`${API_BASE_URL}/api/scheduler/add`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
            body: JSON.stringify(payload)
        });

        const data = await res.json();
        
        if (data.status === 'success') {
            
            if (data.hasWarning || (data.message && data.message.includes('⚠️'))) {
                alert("✅ İŞLEM BAŞARILI!\n\nSistem notu:\n" + data.message);
            } else {
                alert("✅ Zamanlama Başarıyla Kaydedildi!");
            }

            // ⭐ ESKİ MANUEL HTML OLUŞTURMA KODLARI TAMAMEN SİLİNDİ ⭐
            // Yerine sadece bu satır eklendi:
            await fetchSchedules(); 

        } else {
            alert("❌ Hata: " + data.message);
        }
    } catch (err) {
        console.error("Scheduler Hatası:", err);
        alert("Sunucu hatası.");
    }
}
// script.js -> deleteSchedule FONKSİYONUNUN GÜNCELLENMİŞ HALİ

// script.js -> deleteSchedule FONKSİYONUNUN YENİ HALİ

async function deleteSchedule(id, isBatch = false) {
    // 1. SESSİZ MOD KONTROLÜ: 
    // Eğer toplu silme (isBatch=true) yapılıyorsa onay istemeden geç.
    // Eğer tekil silme (isBatch=false) yapılıyorsa onay iste.
    if (!isBatch && !confirm("Bu zamanlamayı silmek istediğinize emin misiniz?")) return;

    const token = sessionStorage.getItem('token');
    
    try {
        const res = await fetch(`${API_BASE_URL}/api/scheduler/delete/${id}`, {
            method: 'DELETE',
            headers: { 'Authorization': 'Bearer ' + token }
        });
        const data = await res.json();
        
        if (data.status === 'success') {
            
            // 2. BAŞARI DURUMU:
            // Sadece tekil silme yapıyorsak mesaj ver ve listeyi yenile.
            // Toplu silmede bunları 'deleteBatch' fonksiyonu en sonda yapacak.
            if (!isBatch) {
                alert("Silindi.");
                await fetchSchedules(); 
            }
            
        } else {
            // Hata varsa konsola yaz, tekil işlemse ekrana bas
            console.error("Silinemedi ID:" + id, data.message);
            if (!isBatch) alert("Silinemedi: " + data.message);
        }
    } catch (err) { 
        console.error(err); 
        if (!isBatch) alert("Hata."); 
    }
}

    function renderGroupDashboard(){
        const dashboard = document.getElementById('group-action-dashboard');
        const groupName = document.getElementById('mgmt-target-id')?.value || null;
        if(!groupName || groupName === 'all'){ if(dashboard) dashboard.style.display='none'; return; }
        if(dashboard) dashboard.style.display='block';
        document.getElementById('selected-group-title').innerText = groupName;
        const membersList = document.getElementById('group-members-container');
        membersList.innerHTML = '';
        const doorsInGroup = globalDoorsData.filter(d => d.GroupName === groupName);
        doorsInGroup.forEach(d=>{
            let statusColor = d.Online ? 'var(--neon-green)' : 'var(--neon-red)';
            let item = document.createElement('div'); item.className='mini-door-item';
            item.innerHTML = `<span style="display:flex; align-items:center; gap:10px;"><i class="fas fa-circle" style="font-size:0.6rem; color:${statusColor}"></i> ${d.DoorName}</span><span style="color:var(--text-muted); font-size:0.8rem;">${DOOR_MODES[d.Mode]}</span>`;
            membersList.appendChild(item);
        });
        updateGroupBulkSettingsUI();
    }

    function updateGroupBulkSettingsUI(){
        const mode = parseInt(document.getElementById('grp-bulk-mode-select').value);
        const container = document.getElementById('grp-bulk-dynamic-settings');
        let html = '';
        switch(mode){
            // ... updateGroupBulkSettingsUI fonksiyonu içi ...
// ... updateGroupBulkSettingsUI fonksiyonu içinde Case 1 ...

case 1:
    html = `<div class="settings-panel" style="margin-top:0;">
        <div style="display:flex; gap:8px; margin-bottom:8px;">
            <div style="flex:1"><label style="font-size:0.8rem;color:var(--neon-blue)">Açma Hızı</label><input id="grp-auto-open" type="number" value="60" style="padding:8px;" /></div>
            <div style="flex:1"><label style="font-size:0.8rem;color:var(--neon-blue)">Kapama Hızı</label><input id="grp-auto-close" type="number" value="40" style="padding:8px;" /></div>
        </div>
        <div style="margin-bottom:8px;"><label style="font-size:0.8rem;color:var(--neon-blue)">Açık Kalma (Sn)</label><input id="grp-auto-wait" type="number" value="5" style="padding:8px;" /></div>
        
        <label style="font-size:0.8rem;color:var(--neon-blue)">SENSÖRLER (Varsayılan Boş):</label>
        <div class="sensor-grid">
            <label class="checkbox-item">
                <input id="grp-sens-1" type="checkbox" onchange="handleSensorMutex(this, 'grp-sens-2')" /> Serbest Gir
            </label>
            <label class="checkbox-item">
                <input id="grp-sens-2" type="checkbox" onchange="handleSensorMutex(this, 'grp-sens-1')" /> Yetkili Gir
            </label>
            <label class="checkbox-item">
                <input id="grp-sens-3" type="checkbox" onchange="handleSensorMutex(this, 'grp-sens-4')" /> Serbest Çık
            </label>
            <label class="checkbox-item">
                <input id="grp-sens-4" type="checkbox" onchange="handleSensorMutex(this, 'grp-sens-3')" /> Yetkili Çık
            </label>
        </div>
    </div>`;
    break;
// ...

            case 2:
                html = `<div style="text-align:center; padding:18px; color:#aaa;"><i class="fas fa-hand-paper" style="font-size:2rem;"></i><br>Kapılar manuel kontrole alınacak.</div>`;
                break;
            case 3:
                html = `<div style="text-align:center; padding:18px; color:var(--neon-green);"><i class="fas fa-door-open" style="font-size:2rem;"></i><br>Kapılar serbest bırakılacak.</div>`;
                break;
            case 4:
                html = `<div class="settings-panel"><label style="font-size:0.8rem; color:var(--neon-red)">PASİF KONUMU:</label><select id="grp-passive-state" style="margin-top:6px; padding:8px;"><option value="CLOSED">SÜREKLİ KAPALI</option><option value="OPEN">SÜREKLİ AÇIK</option></select></div>`;
                break;
            case 5:
                html = `<div class="settings-panel"><div style="display:flex; gap:8px;"><div style="flex:1"><label style="font-size:0.8rem;color:var(--neon-purple)">Açık Süre (sn)</label><input id="grp-test-open" type="number" value="5" style="padding:8px;" /></div><div style="flex:1"><label style="font-size:0.8rem;color:var(--neon-purple)">Kapalı Süre (sn)</label><input id="grp-test-close" type="number" value="5" style="padding:8px;" /></div></div></div>`;
                break;
        }
        container.innerHTML = html;
    }

    // script.js -> applyGroupBulkActionWithSettings fonksiyonu (GÜNCELLENMİŞ HALİ)

async function applyGroupBulkActionWithSettings(){
    const groupName = currentSelectedGroup;
    if(!groupName) return alert('Lütfen işlem yapılacak grubu seçin.');
    
    const token = sessionStorage.getItem('token');
    if(!token) return alert("Oturum hatası. Lütfen giriş yapın.");

    const mode = parseInt(document.getElementById('grp-bulk-mode-select').value);

    // ============================================================
    // ⭐ YENİ EKLENEN KISIM: SENSÖR VALIDASYONU ⭐
    // ============================================================
    if (mode === 1) { // Sadece Otomatik Modda Kontrol Et
        const entryFree = document.getElementById('grp-sens-1').checked;
        const entryAuth = document.getElementById('grp-sens-2').checked;
        const exitFree = document.getElementById('grp-sens-3').checked;
        const exitAuth = document.getElementById('grp-sens-4').checked;

        const hasEntry = entryFree || entryAuth;
        const hasExit = exitFree || exitAuth;

        if (!hasEntry || !hasExit) {
            return alert("⚠️ Grup İşlemi Hatası:\nLütfen toplu güncelleme için hem İÇ hem de DIŞ taraf sensörlerinden en az birini seçiniz!");
        }
    }
    // ============================================================

    if(!confirm(`"${groupName}" grubundaki TÜM kapılar güncellenecek.\nBu işlem geri alınamaz. Onaylıyor musunuz?`)) return;

    let settingsPayload = {};

    switch(mode){
        case 1: // OTOMATİK MOD
            settingsPayload = {
                SpeedOpen: document.getElementById('grp-auto-open').value, 
                SpeedClose: document.getElementById('grp-auto-close').value, 
                WaitTime: document.getElementById('grp-auto-wait').value,
                Access: {
                    EntryFree: document.getElementById('grp-sens-1').checked,
                    EntryAuth: document.getElementById('grp-sens-2').checked,
                    ExitFree: document.getElementById('grp-sens-3').checked,
                    ExitAuth: document.getElementById('grp-sens-4').checked
                }
            };
            break;
        case 4: 
            settingsPayload = {
                PassiveState: document.getElementById('grp-passive-state').value
            };
            break;
        case 5: 
            settingsPayload = {
                TestCycle: {
                    OpenTime: document.getElementById('grp-test-open').value,
                    CloseTime: document.getElementById('grp-test-close').value
                }
            };
            break;
    }

    try {
        const res = await fetch(`${API_BASE_URL}/api/groups/apply-settings`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token
            },
            body: JSON.stringify({
                groupName: groupName,
                targetMode: mode,
                settings: settingsPayload
            })
        });

        const data = await res.json();

        if(data.status === 'success'){
            alert(`İşlem Başarılı!\n"${groupName}" grubundaki kapılar güncellendi.`);
            fetchDoorsData(); 
        } else {
            alert(data.message || 'Toplu güncelleme sırasında bir hata oluştu.');
        }

    } catch(err){
        console.error("Bulk Action Hatası:", err);
        alert("Sunucuya ulaşılamadı. Ayarlar kaydedilemedi.");
    }
}
    function renderGroupManagementUI(){
        const groupSelect = document.getElementById('group-select-action');
        const existingGroups = [...new Set(globalDoorsData.map(d=>d.GroupName))].filter(g=>g!=='Genel');
        
        while(groupSelect.options.length>1) groupSelect.remove(1);
        
        existingGroups.forEach(g=>{ const opt=document.createElement('option'); opt.value=g; opt.innerText=`GRUP: ${g}`; groupSelect.appendChild(opt); });
        
        const selectionContainer = document.getElementById('group-selection-list');
        selectionContainer.innerHTML = '';
        
        globalDoorsData.forEach(door=>{
            const item = document.createElement('label'); item.className='checkbox-item'; item.style.justifyContent='space-between';
            const currentGroupBadge = `<span style="font-size:0.7rem; color:var(--text-muted); border:1px solid #555; padding:2px 6px; border-radius:4px;">${door.GroupName}</span>`;
            item.innerHTML = `<span>${door.DoorName} (ID: ${door.DoorID})</span><div style="display:flex; align-items:center; gap:10px;">${currentGroupBadge}<input type="checkbox" class="door-group-checkbox" value="${door.DoorID}" style="width:18px; height:18px;" /></div>`;
            selectionContainer.appendChild(item);
        });
        
        renderExistingGroups(); 
        toggleGroupInput();
    }

    function toggleGroupInput(){
        const val = document.getElementById('group-select-action').value;
        const inputContainer = document.getElementById('new-group-input-container');
        if(val === 'new'){ inputContainer.style.display='block'; } else { inputContainer.style.display='none'; }
    }

    function renderExistingGroups(){
        const container = document.getElementById('existing-groups-list'); container.innerHTML = '';
        const groups = [...new Set(globalDoorsData.map(d=>d.GroupName))];
        groups.forEach(groupName=>{
            const doorsInGroup = globalDoorsData.filter(d=>d.GroupName===groupName);
            const card = document.createElement('div'); card.className='door-card'; card.style.width='100%'; card.style.borderColor='var(--neon-purple)';
            let doorsListHTML = '';
            if(groupName !== 'Genel') doorsListHTML = doorsInGroup.map(d=>`<li style="color:#ddd; font-size:0.85rem; display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">${d.DoorName}<i class="fas fa-times-circle" style="color:var(--neon-red); cursor:pointer;" onclick="removeDoorFromGroup(${d.DoorID})" title="Gruptan Çıkar"></i></li>`).join('');
            else doorsListHTML = doorsInGroup.map(d=>`<li style="color:#ddd; font-size:0.85rem;">${d.DoorName}</li>`).join('');
            const dissolveButton = groupName !== 'Genel' ? `<div class="card-actions" style="margin-top:10px;"><button class="btn-card-action" onclick="dissolveGroup('${groupName}')" style="border-color:var(--neon-red); color:var(--neon-red);"><i class="fas fa-trash"></i> GRUBU BOZ</button></div>` : '';
            card.innerHTML = `<div class="door-header"><span class="door-name" style="font-size:1.05rem;">${groupName}</span><span style="font-size:0.85rem; color:var(--neon-blue);">${doorsInGroup.length} Kapı</span></div><ul style="padding-left:18px; margin:10px 0;">${doorsListHTML}</ul>${dissolveButton}`;
            container.appendChild(card);
        });
    }

    async function saveGroupChanges(){
        const action = document.getElementById('group-select-action').value;
        let groupName = "";

        if(action === 'new'){ 
            groupName = document.getElementById('new-group-name').value.trim(); 
            if(!groupName) return alert("Lütfen geçerli bir grup adı giriniz!"); 
        } else {
            groupName = action;
        }

        const checkboxes = document.querySelectorAll('.door-group-checkbox:checked');
        if(checkboxes.length === 0) return alert("Lütfen gruba eklenecek en az bir kapı seçiniz!");

        const selectedIds = Array.from(checkboxes).map(cb => parseInt(cb.value));

        const conflicts = [];
        selectedIds.forEach(id => { 
            const door = globalDoorsData.find(d => d.DoorID === id); 
            if(door && door.GroupName && door.GroupName !== 'Genel' && door.GroupName !== groupName) {
                conflicts.push(`${door.DoorName} (Mevcut Grup: ${door.GroupName})`);
            }
        });

        if(conflicts.length > 0) {
            return alert(`DİKKAT! Seçilen bazı kapılar zaten başka gruplara ait:\n\n- ${conflicts.join('\n- ')}\n\nLütfen önce bu kapıları eski gruplarından çıkarın.`);
        }

        const token = sessionStorage.getItem('token');
        if(!token) return alert("Oturum hatası.");

        try {
            const res = await fetch(`${API_BASE_URL}/api/groups/save`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + token 
                },
                body: JSON.stringify({
                    groupName: groupName,
                    doorIds: selectedIds
                })
            });

            const data = await res.json();

            if(data.status === 'success'){
                alert(`İşlem Başarılı! "${groupName}" grubu güncellendi.`);

                if(action === 'new') {
                    document.getElementById('new-group-name').value = '';
                    document.getElementById('group-select-action').value = 'new';
                }
                
                toggleGroupInput();

                fetchDoorsData().then(() => {
                    renderGroupManagementUI();
                });

            } else {
                alert(data.message || 'Grup kaydetme başarısız.');
            }

        } catch(err){
            console.error("Grup Kayıt Hatası:", err);
            alert("Sunucu hatası.");
        }
    }

    async function removeDoorFromGroup(doorId){
        if(!confirm('Bu kapıyı gruptan çıkarmak istediğinize emin misiniz?\nKapı otomatik olarak "Genel" grubuna taşınacaktır.')) return;

        const token = sessionStorage.getItem('token');
        if(!token) return alert("Oturum hatası. Lütfen giriş yapın.");

        try {
            const res = await fetch(`${API_BASE_URL}/api/groups/remove-door`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + token
                },
                body: JSON.stringify({ doorId: doorId })
            });

            const data = await res.json();

            if(data.status === 'success'){
                fetchDoorsData().then(() => {
                    renderGroupManagementUI();
                });
            } else {
                alert(data.message || 'Kapı gruptan çıkarılamadı.');
            }

        } catch(err){
            console.error("Grup Çıkarma Hatası:", err);
            alert("Sunucu hatası.");
        }
    }

    async function dissolveGroup(groupName){
        if(!confirm(`"${groupName}" grubunu kalıcı olarak silmek istiyor musunuz?\n\nBu gruptaki tüm kapılar otomatik olarak 'Genel' grubuna aktarılacaktır.`)) return;

        const token = sessionStorage.getItem('token');
        if(!token) return alert("Oturum hatası. Lütfen giriş yapın.");

        try {
            const res = await fetch(`${API_BASE_URL}/api/groups/delete`, {
                method: 'POST', 
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + token
                },
                body: JSON.stringify({ groupName: groupName })
            });

            const data = await res.json();

            if(data.status === 'success'){
                alert(`"${groupName}" grubu başarıyla silindi ve kapılar 'Genel' grubuna taşındı.`);
                fetchDoorsData().then(() => {
                    renderGroupManagementUI();
                });
            } else {
                alert(data.message || 'Grup silme işlemi başarısız.');
            }

        } catch(err){
            console.error("Grup Silme Hatası:", err);
            alert("Sunucu hatası.");
        }
    }

    
    function renderMaintenancePanel(){
        const list = document.getElementById('maintenance-door-list'); 
        list.innerHTML = '';

        globalDoorsData.forEach(d => {
            const card = document.createElement('div'); 
            card.className = 'door-card'; 
            card.style.borderColor = 'var(--neon-orange)'; 
            card.style.width = '300px';

            let lastMaintDate = "Kayıt Yok";
            
            if(d.MaintenanceLogs && d.MaintenanceLogs.length > 0){ 
                const sorted = [...d.MaintenanceLogs].sort((a,b) => new Date(b.date) - new Date(a.date)); 
                
                const dateObj = new Date(sorted[0].date);
                lastMaintDate = dateObj.toLocaleDateString('tr-TR') + ' ' + dateObj.toLocaleTimeString('tr-TR', {hour: '2-digit', minute:'2-digit'});
            }

            const safeDoorName = d.DoorName.replace(/'/g, "\\'");

            let html = `
                <div class="door-header">
                    <div>
                        <span class="door-name">${d.DoorName}</span>
                        <span class="door-sub" style="display:block;font-size:0.85rem;color:var(--text-muted)">ID: ${d.DoorID} | ${d.GroupName}</span>
                    </div>
                    <i class="fas fa-tools" style="font-size:1.2rem; color:var(--neon-orange)"></i>
                </div>
                <div style="text-align:center; margin:14px 0;">
                    <span style="display:block; color:#aaa; font-size:0.9rem;">SON BAKIM TARİHİ</span>
                    <span style="font-size:1rem; color:white;">${lastMaintDate}</span>
                </div>
                <div class="card-actions">
                    <button class="btn-card-action" style="border-color:var(--neon-orange); color:var(--neon-orange);" onclick="viewLogs(${d.DoorID}, '${safeDoorName}')">
                        <i class="fas fa-file-medical"></i> KAYITLARI YÖNET
                    </button>
                </div>`;
                
            card.innerHTML = html; 
            list.appendChild(card);
        });
    }

    function viewLogs(doorId, doorName){
        const logModal = document.getElementById('log-modal'); 
        const logContent = document.getElementById('log-content'); 
        const door = globalDoorsData.find(d=>d.DoorID===doorId);
        
        if(!door) return alert('Kapı bulunamadı.');
        
        let html = `<div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--neon-blue); padding-bottom:8px; margin-bottom:12px;"><h3 style="margin:0;"><i class="fas fa-tools"></i> BAKIM KAYITLARI: <span style="color:var(--neon-blue)">${doorName}</span></h3><div style="display:flex; gap:8px;"><button class="btn-success" onclick="downloadMaintenancePDF(${doorId}, '${doorName.replace(/'/g,"\\'")}')"><i class="fas fa-file-pdf"></i> PDF</button><button class="btn-primary" onclick="downloadMaintenanceXML(${doorId}, '${doorName.replace(/'/g,"\\'")}')"><i class="fas fa-file-code"></i> XML</button></div></div>
            <div class="settings-panel" style="background:rgba(255,255,255,0.03); border:1px solid #444;"><strong style="color:var(--neon-green)">+ YENİ BAKIM KAYDI EKLE</strong>
            <div style="display:grid; grid-template-columns: 1fr 1fr 1fr auto; gap:8px; margin-top:10px; align-items:center;">
                <input type="text" id="maint-person" placeholder="Bakım Yapan Kişi" />
                <input type="datetime-local" id="maint-date" value="${getLocalISOString()}" />
                <select id="maint-type"><option>Rutin Kontrol</option><option>Arıza Onarım</option><option>Parça Değişimi</option></select>
                <button class="btn-primary" onclick="addMaintenanceRecord(${doorId})">EKLE</button>
            </div></div>
            <div style="margin-top:14px;"><h4 style="color:#aaa;">GEÇMİŞ KAYITLAR</h4>${renderMaintenanceList(door.MaintenanceLogs)}</div>`;
        logContent.innerHTML = html; logModal.style.display='flex';
    }

    // SCRIPT.JS (renderMaintenanceList fonksiyonunu bununla değiştirin)

function renderMaintenanceList(logs){
    if(!logs || logs.length===0) return '<div style="text-align:center; padding:20px; color:#666;">Henüz kayıt bulunmamaktadır.</div>';
    
    logs.sort((a,b)=> new Date(b.date)-new Date(a.date));
    
    let tableHTML = `<table style="width:100%; border-collapse:collapse; font-size:0.9rem;">
            <thead>
                <tr>
                    <th style="padding:8px; border-bottom:1px solid rgba(255,255,255,0.06); text-align:left;">Tarih</th>
                    <th style="padding:8px; border-bottom:1px solid rgba(255,255,255,0.06); text-align:left;">Tür</th>
                    <th style="padding:8px; border-bottom:1px solid rgba(255,255,255,0.06); text-align:left;">Personel</th>
                </tr>
            </thead>
            <tbody>`;
            
    logs.forEach(log=>{ 
        let color = log.type.includes('Arıza') ? 'var(--neon-red)' : 'var(--neon-green)';
        
        let dateObj = new Date(log.date);
        // DÜZELTME: toLocaleString ile tam tarih ve saat gösterimi
        let dateStr = dateObj.toLocaleDateString('tr-TR') + ' ' + dateObj.toLocaleTimeString('tr-TR', {hour: '2-digit', minute:'2-digit'});

        tableHTML += `
            <tr>
                <td style="padding:8px;">${dateStr}</td>
                <td style="padding:8px;color:${color};font-weight:700;">${log.type}</td>
                <td style="padding:8px;">${log.person}</td>
            </tr>`; 
    });
    
    tableHTML += `</tbody></table>`; 
    return tableHTML;
}

    // SCRIPT.JS (addMaintenanceRecord fonksiyonunu bununla değiştirin)

async function addMaintenanceRecord(doorId){
    const person = document.getElementById('maint-person').value.trim();
    // YENİ: datetime-local'dan tam zaman damgasını al
    const date = document.getElementById('maint-date').value; 
    const type = document.getElementById('maint-type').value;

    if(!person || !date) return alert('Lütfen tüm alanları doldurunuz.');
    // API'a gönderilen date artık tam TIMESTAMP formatında: YYYY-MM-DDTHH:MM

    const token = sessionStorage.getItem('token');
    if(!token) return alert("Oturum hatası. Lütfen giriş yapın.");

    try {
        const res = await fetch(`${API_BASE_URL}/api/maintenance/add`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token },
            body: JSON.stringify({
                doorId: doorId,
                person: person,
                date: date, // YENİ: Tam zaman damgasını gönder
                type: type
            })
        });

        // ... (Diğer kısımlar aynı kalacak) ...
        const data = await res.json();
        if(data.status === 'success'){
             alert('Bakım kaydı başarıyla eklendi!');
             await fetchDoorsData(); 
             const updatedDoor = globalDoorsData.find(d => d.DoorID === doorId);
             if(updatedDoor){
                 // Modalı yenilemek için
                 viewLogs(doorId, updatedDoor.DoorName);
                 renderMaintenancePanel();
             }
         } else {
             alert(data.message || 'Kayıt eklenemedi.');
         }
    } catch(err){
         console.error("Bakım Kaydı Hatası:", err);
         alert("Sunucu hatası.");
    }
}

    // SCRIPT.JS (downloadMaintenancePDF fonksiyonunu bununla değiştirin)

function downloadMaintenancePDF(doorId, doorName){
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    
    const door = globalDoorsData.find(d=>d.DoorID===doorId);
    if(!door || !door.MaintenanceLogs || door.MaintenanceLogs.length===0) return alert('İndirilecek kayıt bulunamadı.');
    
    doc.setFontSize(16); 
    doc.text(trToEn(`KAPI BAKIM RAPORU: ${doorName}`), 14, 22);
    
    doc.setFontSize(10); 
    doc.text(`Rapor Tarihi: ${new Date().toLocaleDateString()}`, 14, 30);
    
    const tableData = door.MaintenanceLogs
        .sort((a,b)=> new Date(b.date)-new Date(a.date))
        .map(l => {
            let dateObj = new Date(l.date);
            // DÜZELTME: toLocaleString ile tam tarih ve saat gösterimi
            // trToEn ile Türkçe karakterler dönüştürülürken, toLocaleString'in çıktısı UTF-8 kalabilir.
            // Bu nedenle, toLocaleString çıktısını direk kullanmak yerine manuel formatı kullanalım.
            const dateStr = dateObj.toLocaleDateString('tr-TR') + ' ' + dateObj.toLocaleTimeString('tr-TR', {hour: '2-digit', minute:'2-digit'});
            
            return [
                trToEn(dateStr), // PDF'e uygun ASCII formatına çevir
                trToEn(l.type), 
                trToEn(l.person)
            ];
        });

    doc.autoTable({ 
        head:[['Tarih','Islem Turu','Personel']], 
        body: tableData, 
        startY:40, 
        theme:'grid' ,
        // Türkçe karakter desteği için font ayarı (eğer font yüklenmediyse düzgün çalışmayabilir, ancak trToEn ile deniyoruz)
        headStyles: { font: 'helvetica', fontStyle: 'bold' },
        styles: { font: 'helvetica' }
    });
    
    doc.save(`bakim_${trToEn(doorName).replace(/\s+/g,'_')}.pdf`);
}
    function downloadMaintenanceXML(doorId, doorName){
        const door = globalDoorsData.find(d=>d.DoorID===doorId);
        if(!door || !door.MaintenanceLogs || door.MaintenanceLogs.length===0) return alert('İndirilecek kayıt bulunamadı.');
        downloadXML(`bakim_${doorName.replace(/\s+/g,'_')}.xml`, 'MaintenanceLogs', door.MaintenanceLogs);
    }

    function downloadXML(filename, rootNode, dataArray){
        let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
        xml += `<${rootNode}>\n`;
        dataArray.forEach(item=>{
            xml += '  <entry>\n';
            for(const [key,value] of Object.entries(item)){
                let val = value;
                if(typeof value === 'object' && value !== null) val = JSON.stringify(value);
                xml += `    <${key}>${String(val).replace(/&/g,'&amp;').replace(/</g,'&lt;')}</${key}>\n`;
            }
            xml += '  </entry>\n';
        });
        xml += `</${rootNode}>`;
        const blob = new Blob([xml], { type:'application/xml' });
        const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href=url; a.download=filename; document.body.appendChild(a); a.click(); document.body.removeChild(a);
    }

    function downloadHistory(type) {
        const filterType = document.getElementById('mgmt-target-type').value;
        const filterValue = document.getElementById('mgmt-target-id').value;
        
        let targetName = "";
        let logsToExport = [];

        // 1. KAPI FİLTRESİ
        if (filterType === 'door') {
            const door = globalDoorsData.find(d => d.DoorID == filterValue);
            
            if (!door) return alert('Lütfen geçerli bir kapı seçin.');
            
            targetName = door.DoorName;
            logsToExport = door.ModeLogs || [];
        } 
        // 2. GRUP FİLTRESİ
        else if (filterType === 'group') {
            targetName = filterValue + " Grubu";
            
            globalDoorsData.forEach(d => {
                if (d.GroupName === filterValue && d.ModeLogs && d.ModeLogs.length > 0) {
                    d.ModeLogs.forEach(log => {
                        logsToExport.push({
                            ...log,
                            DoorName: d.DoorName 
                        });
                    });
                }
            });
        } 
        else {
            return alert('Geçmiş indirmek için Kapı veya Grup seçin.');
        }

        // KAYIT KONTROLÜ
        if (logsToExport.length === 0) {
            return alert('Bu seçim için geçmiş kaydı bulunamadı.');
        }

        // TARİHE GÖRE SIRALA (Yeniden eskiye)
        logsToExport.sort((a, b) => new Date(b.Date) - new Date(a.Date));

        const safeFileName = `gecmis_${trToEn(targetName).replace(/\s+/g, '_')}`;

        // XML İNDİRME
        if (type === 'xml') {
            downloadXML(`${safeFileName}.xml`, 'HistoryLogs', logsToExport);
        } 
        // PDF İNDİRME
        else {
            const { jsPDF } = window.jspdf;
            const doc = new jsPDF();

            doc.setFont("helvetica", "bold");
            doc.setFontSize(16);
            doc.text(trToEn(`MOD GECMISI RAPORU: ${targetName}`), 14, 22);
            
            doc.setFont("helvetica", "normal");
            doc.setFontSize(10);
            doc.text(`Tarih: ${new Date().toLocaleDateString()}`, 14, 28);

            const headers = [['Tarih', 'Eski Mod', 'Yeni Mod', 'Kullanici']];
            
            if (filterType === 'group') {
                headers[0].unshift('Kapi Adi'); // Kapı Adı -> Kapi Adi
            }

            const tableData = logsToExport.map(log => {
                // script.js >> downloadHistory fonksiyonu içinde, logsToExport.map döngüsünün içindeki dateStr hesaplama kısmını bununla değiştirin.

const dateStr = (() => {
    // 1. log.Date yoksa veya tanımsızsa, hemen çıkış yap
    if (!log.Date) return '-';

    // 2. DB'den gelen string'i Date objesine çevir
    const rawDate = new Date(log.Date);
    
    // 3. Tarih objesi geçerli değilse (NaN), PDF'i bozmamak için eski (yanlış saatli) formatı geri döndür.
    if (isNaN(rawDate.getTime())) {
         return log.Date.replace('T', ' ').substring(0, 16); 
    }

    // 4. Tarayıcının yerel saatine göre saat ve tarih bileşenlerini çek ve formatla
    const year = rawDate.getFullYear();
    const month = String(rawDate.getMonth() + 1).padStart(2, '0'); // Ay 0'dan başlar, +1 eklenir
    const day = String(rawDate.getDate()).padStart(2, '0');
    const hours = String(rawDate.getHours()).padStart(2, '0');
    const minutes = String(rawDate.getMinutes()).padStart(2, '0');

    // 5. İstenen formatı (YYYY-MM-DD HH:MM) oluştur
    return `${year}-${month}-${day} ${hours}:${minutes}`;
})(); // <-- Bu bir IIFE'dir, tüm geçici değişkenleri kendi içinde tutar.

// Bu noktadan sonra, let row = [..., dateStr, ...]; satırı yeni, doğru saati kullanacaktır.
                
                const oldModeStr = DOOR_MODES[log.OldMode] || 'Bilinmiyor';
                const newModeStr = DOOR_MODES[log.NewMode] || 'Bilinmiyor';

                let row = [
                    dateStr, 
                    trToEn(oldModeStr), 
                    trToEn(newModeStr), 
                    trToEn(log.User)
                ];

                if (filterType === 'group') {
                    row.unshift(trToEn(log.DoorName || '-'));
                }
                return row;
            });

            doc.autoTable({
                head: headers,
                body: tableData,
                startY: 36,
                theme: 'grid',
                styles: { fontSize: 9 },
                headStyles: { fillColor: [41, 128, 185] }
            });

            doc.save(`${safeFileName}.pdf`);
        }
    }

    function checkAdminButtonVisibility() {
        const adminPanel = document.getElementById('superadmin-controls');
        // Yeni eklediğimiz kart
        const adminCard = document.getElementById('admin-user-card');

        if (currentRoleID === 3) { // 3 = SuperAdmin
            if(adminPanel) adminPanel.style.display = 'block';
            if(adminCard) adminCard.style.display = 'block'; // Kartı aç
        } else {
            if(adminPanel) adminPanel.style.display = 'none';
            if(adminCard) adminCard.style.display = 'none'; // Kartı kapa
        }
    }

    function addNewDoorUI() {
        document.getElementById('new-door-name-input').value = '';
        document.getElementById('new-door-ip-input').value = '';
        
        document.getElementById('add-door-modal').style.display = 'flex';
    }

    function closeAddDoorModal() {
        document.getElementById('add-door-modal').style.display = 'none';
    }

    async function saveNewDoorFromModal() {
        const doorName = document.getElementById('new-door-name-input').value.trim();
        const ipAddress = document.getElementById('new-door-ip-input').value.trim();

        if (!doorName || !ipAddress) {
            return alert("Lütfen Kapı Adı ve IP Adresi alanlarını doldurunuz.");
        }

        const ipRegex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        if (!ipRegex.test(ipAddress)) {
            return alert("Geçersiz IP adresi formatı!");
        }

        const token = sessionStorage.getItem('token');
        if (!token) return alert("Oturum hatası. Lütfen tekrar giriş yapın.");

        try {
            const res = await fetch(`${API_BASE_URL}/api/doors/add`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + token
                },
                body: JSON.stringify({ doorName, ipAddress })
            });

            const data = await res.json();

            if (data.status === 'success') {
                alert("✅ " + data.message);
                closeAddDoorModal(); 
                
                await fetchDoorsData(); 

                renderGroupManagementUI(); 
                
            } else {
                alert("❌ Hata: " + data.message);
            }
        } catch (err) {
            console.error(err);
            alert("Sunucu ile iletişim hatası.");
        }
    }

    // =========================================================
    // KULLANICI YÖNETİM FONKSİYONLARI (YENİ EKLENEN)
    // =========================================================

    async function fetchUsersData() {
        const token = sessionStorage.getItem('token');
        if (!token) return;

        try {
            const res = await fetch(`${API_BASE_URL}/api/users/list`, {
                headers: { 'Authorization': 'Bearer ' + token }
            });
            const data = await res.json();

            if (data.status === 'success') {
                renderUserTable(data.users);
            } else {
                alert(data.message);
                switchPanel('dashboard');
            }
        } catch (err) {
            console.error("Kullanıcı çekme hatası:", err);
        }
    }


    function renderUserTable(users) {
    const tbody = document.getElementById('users-table-body');
    tbody.innerHTML = '';

    // Rollerin ID karşılıkları
    const roles = [
        { id: 1, name: 'User' },
        { id: 2, name: 'Admin' },
        { id: 3, name: 'SuperAdmin' }
        // TechnicalStaff (ID:4) listeye koymuyoruz, çünkü manuel seçilemez.
    ];

    users.forEach(user => {
        const tr = document.createElement('tr');
        tr.style.borderBottom = '1px solid rgba(255,255,255,0.1)';
        
        // --- 1. TEKNİK PERSONEL KONTROLÜ (YENİ) ---
        // Eğer kullanıcı TechnicalStaff (4) ise Select kutusu kilitli olsun.
        const isTechnical = (user.rolesroleid === 4);
        const disabledAttr = isTechnical ? 'disabled' : '';
        const disabledStyle = isTechnical ? 'opacity:0.5; cursor:not-allowed;' : '';

        // Select Box oluşturma
        let roleOptions = '';
        if (isTechnical) {
            // Sadece tek bir kilitli seçenek ekle
            roleOptions = `<option value="4" selected>TechnicalStaff</option>`;
        } else {
            // Diğer rolleri listele
            roles.forEach(r => {
                const selected = (user.rolesroleid === r.id) ? 'selected' : '';
                roleOptions += `<option value="${r.id}" ${selected}>${r.name}</option>`;
            });
        }

        // --- 2. DURUM (AKTİF/PASİF) İKONU (YENİ) ---
        const statusIcon = user.status ? 'fa-check-circle' : 'fa-times-circle';
        const statusColor = user.status ? 'var(--neon-green)' : 'var(--neon-red)';
        const statusText = user.status ? 'Aktif' : 'Pasif';

        tr.innerHTML = `
            <td style="padding:10px;">#${user.userid}</td>
            <td style="padding:10px;">${user.userfirstname} ${user.usersurname}</td>
            <td style="padding:10px; color:var(--text-muted);">${user.email}</td>
            <td style="padding:10px;"><span style="color:var(--neon-blue)">${user.rolename || 'Tanımsız'}</span></td>
            
            <td style="padding:10px; text-align:center;">
                <button onclick="toggleUserStatus(${user.userid})" 
                        style="background:none; border:none; cursor:pointer; font-size:1.2rem; color:${statusColor};" 
                        title="${statusText} - Değiştirmek için tıkla">
                    <i class="fas ${statusIcon}"></i>
                </button>
            </td>

            <td style="padding:10px;">
                <select id="role-select-${user.userid}" style="padding:5px; margin:0; width:100%; ${disabledStyle}" ${disabledAttr}>
                    ${roleOptions}
                </select>
            </td>

            <td style="padding:10px; text-align:center;">
                <button class="btn-primary" 
                        style="padding:5px 10px; font-size:0.8rem; ${disabledStyle}" 
                        onclick="updateUserRole(${user.userid})" ${disabledAttr}>
                    <i class="fas fa-save"></i>
                </button>
            </td>
        `;
        tbody.appendChild(tr);
      });
    }

    async function updateUserRole(targetUserId) {
        const selectBox = document.getElementById(`role-select-${targetUserId}`);
        const newRoleId = parseInt(selectBox.value);

        if(!confirm(`Kullanıcı (ID: ${targetUserId}) yetkisi güncellenecek. Onaylıyor musunuz?`)) return;

        const token = sessionStorage.getItem('token');
        try {
            const res = await fetch(`${API_BASE_URL}/api/users/update-role`, {
                method: 'PUT',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + token 
                },
                body: JSON.stringify({ targetUserId, newRoleId })
            });
            const data = await res.json();

            if (data.status === 'success') {
                alert('Yetki başarıyla güncellendi!');
                fetchUsersData(); // Tabloyu yenile
            } else {
                alert('Hata: ' + data.message);
            }
        } catch (err) {
            console.error(err);
            alert('Sunucu hatası.');
        }
    }


    async function toggleUserStatus(targetUserId) {
    if(!confirm('Bu kullanıcının Aktif/Pasif durumunu değiştirmek istediğinize emin misiniz?')) return;

    const token = sessionStorage.getItem('token');
    try {
        const res = await fetch(`${API_BASE_URL}/api/users/toggle-status`, {
            method: 'PUT',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token 
            },
            body: JSON.stringify({ targetUserId })
        });
        const data = await res.json();

        if (data.status === 'success') {
            // Tabloyu yenile ki ikonun rengi değişsin
            fetchUsersData(); 
        } else {
            alert('Hata: ' + data.message);
        }
    } catch (err) {
        console.error(err);
        alert('Sunucu hatası.');
    }
   }

    window.onload = async () => {
        const token = sessionStorage.getItem('token');
        
        if (token) {
            await fetchUserData(); 
            
            if (currentUserName) {
                switchPanel('dashboard');
                fetchDoorsData();
            } else {
                switchPanel('login');
            }
        } else {
            switchPanel('login');
        }

        const loader = document.getElementById('app-loader');
        if(loader) {
            loader.style.opacity = '0'; 
            setTimeout(() => { loader.style.display = 'none'; }, 300); 
        }
    };

// =========================================================
// KAPI YETKİLENDİRME (DB + TABLO GÖRÜNÜMÜ)
// =========================================================

// 1. Kullanıcıları Veritabanından Çek ve Tabloya Yaz
// =========================================================
// script.js -> fetchAssignableUsers FONKSİYONUNU BUL VE BUNUNLA DEĞİŞTİR
// =========================================================

// =========================================================
// script.js -> fetchAssignableUsers FONKSİYONUNU BUNUNLA GÜNCELLE
// =========================================================

async function fetchAssignableUsers() {
    const token = sessionStorage.getItem('token');
    const tbody = document.getElementById('assignments-table-body');
    if (!tbody) return;

    // Yükleniyor animasyonu (colspan sayısını 7 yaptık çünkü yeni sütun ekledik)
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:30px; color:#aaa;">Veriler Yükleniyor...</td></tr>';

    try {
        const res = await fetch(`${API_BASE_URL}/api/assignments/users`, {
            headers: { 'Authorization': 'Bearer ' + token }
        });
        const data = await res.json();

        tbody.innerHTML = ''; // Tabloyu temizle

        if (data.status === 'success' && data.users.length > 0) {
            data.users.forEach(u => {
                const tr = document.createElement('tr');
                
                // Rol Rengi Ayarlama
                let roleStyle = 'color: white;';
                if(u.rolename === 'SuperAdmin') roleStyle = 'color: var(--neon-red); font-weight:bold;';
                else if(u.rolename === 'Admin') roleStyle = 'color: var(--neon-purple); font-weight:bold;';
                else if(u.rolename === 'TechnicalStaff') roleStyle = 'color: var(--neon-orange);';
                else if(u.rolename === 'User') roleStyle = 'color: var(--neon-green);';

                // E-posta alanı yoksa placeholder koy
                const email = u.email || 'Belirtilmemiş';

                // Kapı Verileri
                const count = u.door_count;
                const countColor = count > 0 ? 'var(--neon-green)' : '#aaa';
                const countText = count > 0 ? `${count}` : '0';
                
                // Kapı İsimleri Listesi (Boşsa tire koy)
                // Eğer çok uzunsa sığması için fontu küçültüyoruz
                const doorNamesList = u.door_names ? u.door_names : '<span style="color:#555;">-</span>';

                tr.innerHTML = `
                    <td style="padding:15px;">#${u.userid}</td>
                    <td style="padding:15px; font-weight:600;">${u.userfirstname} ${u.usersurname}</td>
                    <td style="padding:15px; color:#aaa;">${email}</td>
                    <td style="padding:15px; ${roleStyle}">${u.rolename}</td>
                    
                    <td style="padding:15px; text-align:center;">
                        <span style="background:rgba(255,255,255,0.1); padding:4px 10px; border-radius:4px; color:${countColor}; font-weight:bold;">
                            ${countText}
                        </span>
                    </td>

                    <td style="padding:15px; font-size:0.85rem; color:#ccc; max-width: 300px; line-height: 1.4;">
                        ${doorNamesList}
                    </td>

                    <td style="padding:15px; text-align:right;">
                        <button class="btn-action-cyan" onclick="openAssignmentModal(${u.userid}, '${u.userfirstname} ${u.usersurname}')">
                            DÜZENLE
                        </button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        } else {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:20px;">Listelenecek kullanıcı bulunamadı.</td></tr>';
        }

    } catch (err) {
        console.error("Tablo Hatası:", err);
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--neon-red);">Sunucu hatası! Veriler alınamadı.</td></tr>';
    }
}
// =========================================================
// TAKVİM VERİLERİNİ SUNUCUDAN ÇEK VE LİSTELE
// =========================================================
// =========================================================
// TAKVİM VERİLERİNİ ÇEK, BATCH_ID İLE GRUPLA VE LİSTELE
// =========================================================
// script.js -> fetchSchedules FONKSİYONUNUN DÜZELTİLMİŞ HALİ

async function fetchSchedules() {
    const token = sessionStorage.getItem('token');
    if (!token) return;

    try {
        const res = await fetch(`${API_BASE_URL}/api/scheduler/list`, {
            headers: { 'Authorization': 'Bearer ' + token }
        });
        const resp = await res.json();

        const list = document.getElementById('schedule-list');
        if (!list) return;
        
        list.innerHTML = ''; 

        if (resp.status === 'success' && resp.data) {
            
            // 1. GRUPLAMA MANTIĞI
            const groups = {};
            resp.data.forEach(task => {
                const groupKey = task.batch_id || `single-${task.scheduleid}`;
                if (!groups[groupKey]) groups[groupKey] = [];
                groups[groupKey].push(task);
            });

            // 2. KARTLARI OLUŞTUR
            Object.values(groups).forEach(batchTasks => {
                const mainTask = batchTasks[0];
                let isGroup = !!mainTask.batch_id; 
                
                let cardTitle = "";
                let cardClass = isGroup ? "mode-test" : "mode-auto"; 
                let cardId = `card-batch-${mainTask.batch_id || mainTask.scheduleid}`;

                if (isGroup) {
                    let groupName = "Bilinmeyen Grup";
                    if (mainTask.schedulename && mainTask.schedulename.includes('GRUP:')) {
                        groupName = mainTask.schedulename.split('(')[0].replace('GRUP:', '').trim();
                    }
                    cardTitle = `<i class="fas fa-layer-group"></i> GRUP: <span style="color:var(--neon-purple)">${groupName}</span>`;
                } else {
                    cardTitle = `<i class="fas fa-door-closed"></i> KAPI: <span style="color:var(--neon-blue)">${mainTask.doorname}</span>`;
                }

                const card = document.createElement('div');
                card.id = cardId;
                card.className = `door-card ${cardClass}`;
                card.style.marginBottom = "20px";

                let cardHTML = `
                    <h3 style="font-size:1rem; margin:0 0 10px 0; border-bottom:1px solid #444; padding-bottom:5px; display:flex; justify-content:space-between;">
                        <span>${cardTitle}</span>
                        ${isGroup ? '<button class="btn-xs" onclick="deleteBatch(\''+mainTask.batch_id+'\')" style="background:#333; border:1px solid #555; font-size:0.7rem; color:#fff; cursor:pointer; padding:2px 8px; border-radius:4px;">TÜMÜNÜ SİL</button>' : ''}
                    </h3>
                    <div class="schedule-entries">`;

                batchTasks.forEach(task => {
                    // Zaman Metni
                    let timeString = "";
                    if (task.recurrencetype === 'weekly') {
                        const dayMap = {1:'Pazartesi', 2:'Salı', 3:'Çarşamba', 4:'Perşembe', 5:'Cuma', 6:'Cumartesi', 7:'Pazar'};
                        const daysArr = task.activedays ? task.activedays.split(',') : [];
                        const dayNames = daysArr.map(d => dayMap[d]).join(', ');
                        
                        const tStart = new Date(task.starttime).toLocaleTimeString('tr-TR', {hour:'2-digit', minute:'2-digit'});
                        const tEnd = new Date(task.endtime).toLocaleTimeString('tr-TR', {hour:'2-digit', minute:'2-digit'});
                        timeString = `<span style="color:var(--neon-orange); font-weight:bold;">${dayNames}</span> <span style="color:#ccc;">${tStart}-${tEnd}</span>`;
                    } else {
                        // ⭐ DÜZELTME BURADA YAPILDI ⭐
                        // Bitiş saati için de 'month' ve 'day' parametreleri eklendi.
                        
                        const tStart = new Date(task.starttime).toLocaleString('tr-TR', {month:'numeric', day:'numeric', hour:'2-digit', minute:'2-digit'});
                        const tEnd = new Date(task.endtime).toLocaleString('tr-TR', {month:'numeric', day:'numeric', hour:'2-digit', minute:'2-digit'});
                        
                        // Örn: 19/12 14:47 -> 28/12 14:47
                        timeString = `<span style="color:white; font-weight:bold;">${tStart}</span> <span style="color:#aaa;">-> ${tEnd}</span>`;
                    }

                    const modeName = DOOR_MODES[task.doormodemodeid] || 'Mod ' + task.doormodemodeid;
                    let noteHtml = task.note ? `<div style="font-size:0.75rem; color:#888; font-style:italic; margin-left:10px;">Not: ${task.note}</div>` : '';
                    
                    let rowTitle = isGroup ? `<span style="color:var(--neon-blue); font-weight:bold; margin-right:10px;">${task.doorname}</span>` : '';

                    cardHTML += `
                        <div id="sched-item-${task.scheduleid}" style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid rgba(255,255,255,0.05); padding:8px 0;">
                            <div>
                                <div style="font-size:0.9rem;">${rowTitle} ${timeString}</div>
                                <div style="font-size:0.8rem; color:#aaa; display:flex; align-items:center;">
                                    <i class="fas fa-cog" style="margin-right:5px;"></i> ${modeName}
                                    ${noteHtml}
                                </div>
                            </div>
                            <button class="btn-danger" style="padding:5px 10px; font-size:0.8rem;" onclick="deleteSchedule(${task.scheduleid})" title="Bu görevi sil">
                                <i class="fas fa-trash"></i>
                            </button>
                        </div>
                    `;
                });

                cardHTML += `</div>`; 
                card.innerHTML = cardHTML;
                list.appendChild(card);
            });
        }
    } catch (err) {
        console.error("Takvim Listeleme Hatası:", err);
    }
}
// script.js -> deleteBatch FONKSİYONUNUN GÜNCELLENMİŞ HALİ

async function deleteBatch(batchId) {
    // 1. Sadece EN BAŞTA tek bir onay iste
    if (!confirm("Bu gruptaki TÜM görevleri silmek istediğinize emin misiniz?")) return;
    
    const card = document.getElementById(`card-batch-${batchId}`);
    if (!card) return;
    
    // Kullanıcıya işlemin başladığını hissettirmek için kartı soluklaştır
    card.style.opacity = '0.5';
    card.style.pointerEvents = 'none';

    const items = card.querySelectorAll('[id^="sched-item-"]');

    // 2. Döngü içinde "Sessiz Mod" (true) ile sil
    for (let item of items) {
        const id = item.id.replace('sched-item-', '');
        
        // DİKKAT: İkinci parametre olarak 'true' gönderiyoruz.
        // Bu sayede deleteSchedule fonksiyonu onay istemeden ve uyarı vermeden siler.
        await deleteSchedule(id, true); 
    }

    // 3. İşlem tamamen bitince listeyi yenile ve tek mesaj göster
    await fetchSchedules();
    alert("Grup başarıyla silindi.");
}
// =========================================================
// YENİ MODAL MANTIĞI (TRANSFER LIST) - BURADAN BAŞLA
// =========================================================

let currentAssignmentUserId = null;
let tempAuthorizedSet = new Set(); // Yapılan değişiklikleri RAM'de tutacağız

// 3. Modalı Aç ve Listeleri Hazırla
async function openAssignmentModal(userId, userName) {
    currentAssignmentUserId = userId;
    document.getElementById('modal-user-name').innerText = userName;
    
    const modal = document.getElementById('assignment-modal');
    modal.style.display = 'flex';
    
    // Yükleniyor mesajı koyalım
    document.getElementById('authorized-doors-list').innerHTML = '<div style="padding:10px; color:#aaa;">Veriler yükleniyor...</div>';
    document.getElementById('available-doors-list').innerHTML = '';

    const token = sessionStorage.getItem('token');

    // A. Tüm Kapıları Getir (Eğer boşsa çek)
    if (globalDoorsData.length === 0) await fetchDoorsData();

    // B. Kullanıcının Mevcut Yetkilerini Getir (Backend'den)
    try {
        const res = await fetch(`${API_BASE_URL}/api/assignments/by-user/${userId}`, {
            headers: { 'Authorization': 'Bearer ' + token }
        });
        const data = await res.json();
        
        if(data.status === 'success') {
            // Gelen yetkili ID'lerini Set yapısına atıyoruz
            tempAuthorizedSet = new Set(data.doorIds);
            
            // Listeleri Çiz
            renderAssignmentLists();
        }
    } catch(e) { 
        console.error(e); 
        alert("Yetki verileri alınamadı.");
        closeAssignmentModal();
    }
}

// YARDIMCI: Listeleri Ekrana Basan Fonksiyon
function renderAssignmentLists() {
    const authList = document.getElementById('authorized-doors-list');
    const availList = document.getElementById('available-doors-list');
    
    authList.innerHTML = '';
    availList.innerHTML = '';

    if (globalDoorsData.length === 0) {
        availList.innerHTML = '<p style="padding:10px;">Sistemde tanımlı kapı yok.</p>';
        return;
    }

    // Kapıları isme göre sıralayalım (A-Z)
    const sortedDoors = [...globalDoorsData].sort((a,b) => a.DoorName.localeCompare(b.DoorName));

    sortedDoors.forEach(door => {
        // Bu kapı şu anki yetki kümesinde var mı?
        const isAuthorized = tempAuthorizedSet.has(door.DoorID);

        // HTML Şablonu
        const itemDiv = document.createElement('div');
        itemDiv.className = 'transfer-item';
        
        const infoHTML = `
            <div style="display:flex; flex-direction:column;">
                <span style="font-weight:bold; color:white;">${door.DoorName}</span>
                <span style="font-size:0.75rem; color:#aaa;">${door.GroupName || 'Genel'} (ID: ${door.DoorID})</span>
            </div>
        `;

        if (isAuthorized) {
            // --- ÜST LİSTE (Yetkili) -> Çıkartma Butonu (-) ---
            itemDiv.innerHTML = `
                ${infoHTML}
                <button class="btn-icon-small btn-remove" onclick="toggleDoorPermission(${door.DoorID}, false)" title="Yetkiyi Kaldır">
                    <i class="fas fa-minus"></i>
                </button>
            `;
            authList.appendChild(itemDiv);
        } else {
            // --- ALT LİSTE (Eklenebilir) -> Ekleme Butonu (+) ---
            itemDiv.innerHTML = `
                ${infoHTML}
                <button class="btn-icon-small btn-add" onclick="toggleDoorPermission(${door.DoorID}, true)" title="Yetki Ekle">
                    <i class="fas fa-plus"></i>
                </button>
            `;
            availList.appendChild(itemDiv);
        }
    });

    // Boş durum mesajları
    if (authList.children.length === 0) authList.innerHTML = '<div style="padding:10px; color:#555; font-style:italic;">Yetkili olduğu kapı yok.</div>';
    if (availList.children.length === 0) availList.innerHTML = '<div style="padding:10px; color:#555; font-style:italic;">Tüm kapılara yetkisi var.</div>';
}

// YARDIMCI: Yetki Ekle/Çıkar İşlemi (RAM üzerinde)
function toggleDoorPermission(doorId, shouldAdd) {
    if (shouldAdd) {
        tempAuthorizedSet.add(doorId);
    } else {
        tempAuthorizedSet.delete(doorId);
    }
    // Listeyi hemen yeniden çiz (Anlık tepki)
    renderAssignmentLists();
}

// 4. Modalı Kapat
function closeAssignmentModal() {
    document.getElementById('assignment-modal').style.display = 'none';
    currentAssignmentUserId = null;
    tempAuthorizedSet.clear();
}

// 5. Kaydetme İşlemi (Backend'e Gönder)
async function saveAssignmentsFromModal() {
    if (!currentAssignmentUserId) return;

    // Set'i Array'e çevirip sunucuya yolluyoruz
    const finalDoorIds = Array.from(tempAuthorizedSet);

    const token = sessionStorage.getItem('token');
    
    // Butonu kitle
    const btn = document.querySelector('#assignment-modal .btn-primary');
    const orgHTML = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> KAYDEDİLİYOR...';
    btn.disabled = true;

    try {
        const res = await fetch(`${API_BASE_URL}/api/assignments/save`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + token
            },
            body: JSON.stringify({
                targetUserId: currentAssignmentUserId,
                selectedDoorIds: finalDoorIds
            })
        });

        const data = await res.json();
        if (data.status === 'success') {
            alert("✅ Yetkiler başarıyla güncellendi!");
            closeAssignmentModal();
            fetchAssignableUsers(); // Ana tabloyu güncelle
        } else {
            alert("❌ Hata: " + data.message);
        }
    } catch (err) {
        console.error(err);
        alert("Sunucu hatası.");
    } finally {
        btn.innerHTML = orgHTML;
        btn.disabled = false;
    }
}

//----GOOGLE İLE GİRİŞ İÇİN --------
document.addEventListener("DOMContentLoaded", function () {

    // Google login butonu sayfada var mı?
    const googleBtn = document.getElementById("google-login-btn");
    if (!googleBtn) return; // login ekranı değilse çık

    // Google'ı başlat
    google.accounts.id.initialize({
        client_id: "45497727874-566k4a566l6ll4fb0jlmbpuuhu8b9p3b.apps.googleusercontent.com",
        callback: handleGoogleLogin
    });

    // Butonu çiz
    google.accounts.id.renderButton(googleBtn, {
        theme: "outline",
        size: "large",
        text: "continue_with",
        shape: "pill"
    });
});


//YENİ Google callback fonksiyonu
function handleGoogleLogin(response) {
    console.log("GOOGLE TOKEN:", response.credential);

    fetch("http://localhost:3000/api/auth/google", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        credentials: "include",
        body: JSON.stringify({
            token: response.credential
        })
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === "success") {

            // kritik satır 
            sessionStorage.setItem("token", data.token);

            //AKIŞI window.onload'a BIRAK
            location.reload();

        } else {
            alert("Google giriş başarısız");
        }
    })
    .catch(err => console.error(err));
}
// --- SENSÖR ÇAKIŞMASINI ÖNLEYEN YARDIMCI FONKSİYON ---
// Bir sensör seçilince, aynı taraftaki diğer sensörü kapatır.
function handleSensorMutex(currentCheckbox, partnerId) {
    if (currentCheckbox.checked) {
        const partner = document.getElementById(partnerId);
        if (partner) {
            partner.checked = false;
        }
    }
}
