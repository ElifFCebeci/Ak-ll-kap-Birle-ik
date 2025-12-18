// =========================================================
// SERVER.JS – FULL AUTH + GOOGLE + MQTT + LOGLAMA + GRUPLAR
// =========================================================

const express = require('express');
const mqtt = require('mqtt');
const path = require('path');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Pool } = require('pg');
const { OAuth2Client } = require('google-auth-library');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');   // mail ile giriş için kütüpane eklendi.

// =========================================================
// 1. AYARLAR
// =========================================================
const PORT = 3000;
const MQTT_BROKER = 'mqtt://broker.emqx.io';
const API_PREFIX_DOORS = '/api/doors';
const API_PREFIX_AUTH = '/api/auth';
const API_PREFIX_GROUPS = '/api/groups';
const API_PREFIX_SCHED = '/api/scheduler';
const API_PREFIX_MAINT = '/api/maintenance';
const MQTT_TOPIC_COMMAND_PREFIX = 'kapi/';
const JWT_SECRET = 'SüperGizliAnahtarKelime2025';
const GOOGLE_CLIENT_ID = "45497727874-566k4a566l6ll4fb0jlmbpuuhu8b9p3b.apps.googleusercontent.com";
const DB_CONFIG = {
    // db.js veya server.js içinde bağlantı kodundan hemen önce:
    user: 'postgres',
    host: 'localhost',
    database: 'albayrak_db',
    password: '634638',
    port: 5432,
};

const MAIL_TRANSPORTER = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'ozgeks.fb@gmail.com', // Kendi mailin
        pass: 'gdub urfz huxg jkja' // 16 haneli kodun
    }
});

const app = express();
const pool = new Pool(DB_CONFIG);
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);
const mqttClient = mqtt.connect(MQTT_BROKER);

// *** CORS GÜNCELLEMESİ ***
app.use(cors({
    origin: true,
    credentials: true
}));

app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

let allDoorStatuses = {};

const verificationCodes = {}; 


// =========================================================
// 2. YARDIMCI FONKSİYONLAR
// =========================================================

function generateCode() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}


// --- YARDIMCI DOĞRULAMA FONKSİYONLARI ---

// 1. Email Format Kontrolü 
function validateEmail(email) {
    // e-posta formatı: birseyler@birseyler.com
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(String(email).toLowerCase());
}

// 2. Şifre Politikası
function checkPasswordPolicy(password) {
    // Regex: En az 6 karakter, en az 1 harf, 1 rakam, 1 özel karakter
    const re = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])[A-Za-z\d!@#$%^&*(),.?":{}|<>]{6,}$/;
    
    if (!re.test(password)) {
        return "Şifreniz harf, rakam ve özel karakter içermeli!";
    }
    return null; 
}

async function verifyGoogleToken(token) {
    try {
        const ticket = await googleClient.verifyIdToken({ idToken: token, audience: GOOGLE_CLIENT_ID, });
        return ticket.getPayload();
    } catch (error) { return null; }
}

async function getRoleNameById(roleId) {
    try {
        const roleResult = await pool.query('SELECT "rolename" FROM "roles" WHERE "roleid" = $1', [roleId]);
        return roleResult.rows.length > 0 ? roleResult.rows[0].rolename : 'Bilinmiyor';
    } catch (error) { return 'HATA'; }
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!req.cookies || !req.cookies.session_id) {
        console.log("LOG: İstek geldi ama Session Cookie yok (Tarayıcı kapatılmış olabilir).");
        return res.status(401).json({ message: 'Oturum kapalı. Lütfen tekrar giriş yapın.' });
    }

    if (token == null) return res.sendStatus(401);
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

async function getDoorModeLogs(doorId) {
    try {
        const logsResult = await pool.query(
            `SELECT
                t1.oldstatus, 
                t1.newstatus, 
                t1.timestamp,
                CASE
                    WHEN t2.userfirstname IS NOT NULL THEN t2.userfirstname || ' ' || t2.usersurname
                    ELSE 'Sistem/MQTT'
                END AS username
            FROM doorstatuslogs AS t1
            LEFT JOIN users AS t2 ON t1.usersuserid = t2.userid
            WHERE t1.doorsdoorid = $1 
            ORDER BY t1.timestamp DESC LIMIT 50`,
            [doorId]
        );

        return logsResult.rows.map(log => {
            let rawNew = log.newstatus || '';
            let rawOld = log.oldstatus || '';

            const parseModeToID = (val) => {
                if (!val) return 0;
                val = val.toString();
                if (val.startsWith('Mod: ')) return parseInt(val.split(': ')[1]);
                const lowerVal = val.toLowerCase();
                if (lowerVal.includes('oto')) return 1;
                if (lowerVal.includes('manuel')) return 2;
                if (lowerVal.includes('serbest')) return 3;
                if (lowerVal.includes('pasif')) return 4;
                if (lowerVal.includes('test')) return 5;
                return 0;
            };

            return {
                Date: log.timestamp,
                OldMode: parseModeToID(rawOld),
                NewMode: parseModeToID(rawNew),
                User: log.username
            };
        });

    } catch (error) {
        console.error(`Log Hatası (Kapı ${doorId}):`, error.message);
        return [];
    }
}

// --- YENİ EKLENEN BAKIM LOGLARI FONKSİYONU ---
async function getMaintenanceLogs(doorId) {
    try {
        const res = await pool.query(
            // lastmaintenancedate artık TIMESTAMP türünde (saati de içeriyor)
            `SELECT lastmaintenancedate, maintenancetype, faultrecord 
             FROM doormaintenancelog 
             WHERE doorsdoorid = $1 
             ORDER BY lastmaintenancedate DESC LIMIT 10`,
            [doorId]
        );
        return res.rows.map(row => ({
            // Date türünü ISO formatında döndürüyoruz ki Frontend doğru şekilde işlesin
            date: new Date(row.lastmaintenancedate).toISOString(), 
            type: row.maintenancetype,
            person: row.faultrecord 
        }));
    } catch (e) { return []; }
}

// =========================================================
// 3. MQTT
// =========================================================

const MQTT_TOPICS = {
  // Kapıdan Gelenler
  DOOR_STATUS: 'albayrak/doors/+/status',
  DOOR_HEARTBEAT: 'albayrak/doors/+/heartbeat',
  DOOR_SENSOR: 'albayrak/doors/+/sensor',
  DOOR_COMMAND_RESPONSE: 'albayrak/doors/+/command_response',
  
  // Sunucudan Gönderilenler
  DOOR_COMMAND: 'albayrak/doors/+/command',
  DOOR_CONFIG: 'albayrak/doors/+/config',
  GROUP_COMMAND: 'albayrak/groups/+/command',
  
  // Sistem Topic'leri
  SYSTEM_ALERT: 'albayrak/system/alerts',
  EMERGENCY: 'albayrak/system/emergency'
};

mqttClient.on('connect', () => {
    console.log('✅ MQTT Broker\'a bağlandı.');
    
    // TÜM albayrak topic'lerini dinle
    mqttClient.subscribe('albayrak/#', { qos: 1 }, (err) => {
        if (err) {
            console.log('❌ Abone olamadı:', err);
        } else {
            console.log('📡 Tüm albayrak topic\'leri dinleniyor...');
        }
    });
    
    // Ayrıca ESP'nin gönderdiği spesifik topic'lere de abone ol
    mqttClient.subscribe('albayrak/doors/+/status');
    mqttClient.subscribe('albayrak/doors/+/heartbeat');
    mqttClient.subscribe('albayrak/doors/+/sensor');
    
    console.log('🔍 Debug: Topic subscription tamam');
});

mqttClient.on('message', async (topic, message) => {
    // HER GELEN MESAJI GÖRÜNTÜLE
    console.log(`🔔 MQTT MESAJ ALINDI!`);
    console.log(`   Topic: ${topic}`);
    console.log(`   Message: ${message.toString()}`);
    console.log(`   Length: ${message.length} bytes`);
    
    try {
        const data = JSON.parse(message.toString());
        console.log(`   Parsed JSON:`, JSON.stringify(data, null, 2));
        
        if (topic.includes('/status')) {
            console.log(`   🚪 Kapı durumu işleniyor...`);
            await handleDoorStatus(topic, data);
        } else if (topic.includes('/heartbeat')) {
            console.log(`   💓 Heartbeat işleniyor...`);
            await handleHeartbeat(topic, data);
        } else if (topic.includes('/sensor')) {
            console.log(`   📡 Sensör verisi işleniyor...`);
            await handleSensorData(topic, data);
        }
    } catch (error) {
        console.error('❌ JSON parse hatası:', error.message);
        console.log('   Raw message:', message.toString());
    }
});


// =========================================================
// MQTT MESAJ İŞLEYİCİ FONKSİYONLARI
// =========================================================

async function handleDoorStatus(topic, data) {
    const doorId = data.doorID;
    
    console.log(`🚪 handleDoorStatus: Kapı ${doorId} bağlandı`);
    
    // 1. ÖNCE allDoorStatuses BELLEĞİNİ GÜNCELLE
    if (!allDoorStatuses[doorId]) {
        allDoorStatuses[doorId] = { DoorID: doorId };
        console.log(`🆕 Yeni kapı algılandı: ${doorId}`);
    }
    
    // ESP'den gelen verileri allDoorStatuses'e kaydet
    allDoorStatuses[doorId] = {
        ...allDoorStatuses[doorId],
        DoorID: doorId,
        DoorName: `ESP Kapı ${doorId}`,
        Status: data.status || 'CLOSED',
        Mode: data.mode || 1,
        Speed: data.speed || 50,
        WaitTime: data.waitTime || 5,
        Online: true,  // MQTT'den mesaj geliyorsa KESİNLİKLE online
        LastUpdate: new Date().toISOString(),
        SensorLeft: data.sensorFree || true,
        SensorRight: data.sensorAuthorized || true,
        PassiveState: data.passiveState || 'CLOSED',
        IPAddress: 'ESP8266',
        isESP: true
    };
    
    console.log(`✅ Kapı ${doorId} güncellendi - ONLINE:`, allDoorStatuses[doorId].Online);
    
    // 2. VERİTABANINDA KAPININ VAR OLUP OLMADIĞINI KONTROL ET
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        const doorCheck = await client.query('SELECT doorid FROM doors WHERE doorid = $1', [doorId]);
        
        if (doorCheck.rows.length === 0) {
            // YENİ KAPISI - DATABASE'E EKLE
            console.log(`📝 Database'e yeni kapı ekleniyor: ${doorId}`);
            
            // 2A. KAPIYI DOORS TABLOSUNA EKLE
            await client.query(
                `INSERT INTO doors (
                    doorid, doorname, ipadress, doormodemodeid, 
                    passivestate, heartbeatstatus, lastupdate
                ) VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)`,
                [
                    doorId,
                    `ESP Kapı ${doorId}`,
                    'ESP8266',
                    data.mode || 1,
                    data.passiveState || 'CLOSED',
                    true  // heartbeatstatus = true
                ]
            );
            console.log(`✅ Database: Kapı ${doorId} eklendi`);
            
            // 2B. KAPI AYARLARINI EKLE (doorsettings)
            await client.query(
                `INSERT INTO doorsettings (doorsdoorid, speedopen, speedclose, waittime) 
                 VALUES ($1, $2, $3, $4)`,
                [
                    doorId,
                    data.speed || 50,
                    data.speed || 40,  // Kapanma hızı (varsayılan)
                    data.waitTime || 5
                ]
            );
            console.log(`✅ Database: Kapı ${doorId} ayarları eklendi`);
            
            // 2C. SENSÖRLERİ EKLE (doorsensor)
            await client.query(
                `INSERT INTO doorsensor (doorsdoorid, sensorside, sensortype, isenable) 
                 VALUES 
                 ($1, 'İç Taraf', 'Serbest', $2),
                 ($1, 'Dış Taraf', 'Yetkili', $3)`,
                [
                    doorId,
                    data.sensorFree || true,
                    data.sensorAuthorized || true
                ]
            );
            console.log(`✅ Database: Kapı ${doorId} sensörleri eklendi`);
            
            // 2D. SUPERADMIN'E OTOMATİK YETKİ VER (isteğe bağlı)
            try {
                // Tüm SuperAdmin kullanıcıları bul (RoleID = 3)
                const superAdmins = await client.query(
                    'SELECT userid FROM users WHERE rolesroleid = 3'
                );
                
                for (const admin of superAdmins.rows) {
                    await client.query(
                        `INSERT INTO users_doors_permission (doorsdoorid, useruserid, permission) 
                         VALUES ($1, $2, TRUE) 
                         ON CONFLICT (doorsdoorid, useruserid) DO NOTHING`,
                        [doorId, admin.userid]
                    );
                }
                console.log(`✅ Database: SuperAdmin'lere yetki verildi`);
            } catch (permError) {
                console.log(`⚠️  Yetki verme hatası: ${permError.message}`);
                // Kritik değil, devam et
            }
            
            // 2E. LOG KAYDI EKLE
            await client.query(
                `INSERT INTO doorstatuslogs (
                    doorsdoorid, oldstatus, newstatus, timestamp, usersuserid, severity
                ) VALUES ($1, 'Sistem', 'Yeni ESP Kapısı Eklendi', CURRENT_TIMESTAMP, NULL, 'Info')`,
                [doorId]
            );
            
            // 2F. SYSTEM LOG KAYDI
            await client.query(
                `INSERT INTO systemlogs (action, timestamp, severity, usersuserid) 
                 VALUES ($1, CURRENT_TIMESTAMP, 'Info', NULL)`,
                [`YENI_ESP_KAPISI: Kapı ${doorId} otomatik eklendi`]
            );
            
        } else {
            // ⭐⭐⭐ MEVCUT KAPI - SADECE GÜNCELLE ⭐⭐⭐
            console.log(`📝 Database: Mevcut kapı ${doorId} güncelleniyor`);
            
            await client.query(
                `UPDATE doors SET 
                 doormodemodeid = $1,
                 passivestate = $2,
                 heartbeatstatus = TRUE,
                 lastupdate = CURRENT_TIMESTAMP
                 WHERE doorid = $3`,
                [data.mode || 1, data.passiveState || 'CLOSED', doorId]
            );
            
            // Ayarları güncelle
            await client.query(
                `UPDATE doorsettings SET 
                 speedopen = COALESCE($1, speedopen),
                 waittime = COALESCE($2, waittime)
                 WHERE doorsdoorid = $3`,
                [data.speed, data.waitTime, doorId]
            );
        }
        
        await client.query('COMMIT');
        console.log(`✅ Database işlemleri tamamlandı: Kapı ${doorId}`);
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error(`❌ Database hatası (Kapı ${doorId}):`, error.message);
        
        // Tablo yoksa oluştur (sadece development için)
        if (error.message.includes('relation') && error.message.includes('does not exist')) {
            console.log(`⚠️  Tablo eksik `);
        }
    } finally {
        client.release();
    }
    
    // 3. DURUM LOGU EKLE (sadece status değiştiyse)
    if (data.status && allDoorStatuses[doorId].previousStatus !== data.status) {
        try {
            await pool.query(
                `INSERT INTO doorstatuslogs (doorsdoorid, oldstatus, newstatus, timestamp, usersuserid) 
                 VALUES ($1, $2, $3, CURRENT_TIMESTAMP, NULL)`,
                [doorId, allDoorStatuses[doorId].previousStatus || 'UNKNOWN', data.status]
            );
            
            allDoorStatuses[doorId].previousStatus = data.status;
            
        } catch (logError) {
            console.error(`❌ Durum log hatası:`, logError.message);
        }
    }
}

async function handleHeartbeat(topic, data) {
    const doorId = data.doorID;
    const isAlive = data.alive === true || data.alive === 'true' || data.alive === 1;
    
    console.log(`💓 Heartbeat Kapı ${doorId}:`, isAlive ? 'ALIVE' : 'DEAD');
    
    // allDoorStatuses'i güncelle
    if (allDoorStatuses[doorId]) {
        allDoorStatuses[doorId].Online = isAlive;
        allDoorStatuses[doorId].lastHeartbeat = Date.now();
        allDoorStatuses[doorId].LastUpdate = new Date().toISOString();
    }
    
    // Veritabanını güncelle
    try {
        await pool.query(
            `UPDATE doors SET 
             heartbeatstatus = $1, 
             lastupdate = CURRENT_TIMESTAMP 
             WHERE doorid = $2`,
            [isAlive, doorId]
        );
    } catch (error) {
        console.error(`❌ Heartbeat kayıt hatası:`, error.message);
    }
}

async function handleSensorData(topic, data) {
    const doorId = data.doorID;
    
    console.log(`📡 Sensör verisi Kapı ${doorId}:`, data.sensorType, '=', data.sensorStatus);
    
    // Sensör durumunu güncelle
    if (allDoorStatuses[doorId]) {
        if (data.sensorType === 'free') {
            allDoorStatuses[doorId].SensorLeft = data.sensorStatus;
        } else if (data.sensorType === 'authorized') {
            allDoorStatuses[doorId].SensorRight = data.sensorStatus;
        }
    }
    
    // Sensör logu ekle
    try {
        await pool.query(
            `INSERT INTO systemlogs (action, timestamp, severity, usersuserid) 
             VALUES ($1, CURRENT_TIMESTAMP, 'INFO', NULL)`,
            [`SENSOR_UPDATE: Kapı ${doorId} - ${data.sensorType} = ${data.sensorStatus}`]
        );
    } catch (error) {
        // Tablo yoksa hata verme
    }
}

// Yardımcı fonksiyon
function extractDoorIdFromTopic(topic) {
    const match = topic.match(/albayrak\/doors\/(\d+)\//);
    return match ? parseInt(match[1]) : null;
}

// =========================================================
// 4. API: AUTH
// =========================================================

// --- KAYIT OL (REGISTER) ROTASI ---

app.post(`${API_PREFIX_AUTH}/register`, async (req, res) => {
    const { firstname, surname, email, password } = req.body;
    
    // YENİ EKLENEN: EMAİL FORMAT KONTROLÜ ---
    // Eğer mail formatı bozuksa (örn: "ahmet" yazdıysa) direkt hata dönüyor.
    if (!validateEmail(email)) {
        return res.json({ status: 'error', message: 'Lütfen geçerli bir e-posta adresi giriniz!' });
    }

    // 1. Şifre Politikası Kontrolü (Hata varsa direkt dön)
    const passwordError = checkPasswordPolicy(password);
    if (passwordError) {
        return res.status(400).json({ status: 'error', message: passwordError });
    }

    try {
        // 2. ÖNCE DB KONTROLÜ (Boşuna kod üretmeyelim)
        // Bu mail adresi veritabanında var mı?
        const existing = await pool.query('SELECT * FROM "users" WHERE "email" = $1', [email]);
        
        if (existing.rows.length > 0) {
            // Eğer kullanıcı var VE hesabı onaylıysa -> HATA FIRLAT
            if (existing.rows[0].isverified) {
                return res.json({ status: 'error', message: 'Bu e-posta adresi ile kayıtlı bir kullanıcı zaten var!' });
            }
            
            // Kullanıcı var ama "isverified = FALSE" ise (onaylamamışsa) -> Aşağı devam etsin, kodu tekrar atalım.
        }

        // 3. Kod Üret ve RAM'e Yaz
        const code = generateCode();
        verificationCodes[email] = code;

        // 4. Veritabanı İşlemleri (Insert veya Update)
        if (existing.rows.length > 0) {
            // Kayıt var ama onaysızdı -> Bilgileri güncelle (şifreyi vs. değiştirmiş olabilir)
            await pool.query('UPDATE "users" SET "userfirstname"=$1, "usersurname"=$2, "userpassword"=$3 WHERE "email"=$4', 
            [firstname, surname, password, email]);
        } else {
            // Hiç kayıt yok -> Sıfırdan yeni kayıt oluştur
            await pool.query(
                `INSERT INTO "users" ("userfirstname", "usersurname", "email", "userpassword", "rolesroleid", "status", "isverified", "createdat") 
                 VALUES ($1, $2, $3, $4, 1, 'TRUE', 'FALSE', CURRENT_TIMESTAMP)`,
                [firstname, surname, email, password]
            );
        }

        // 5. Mail Gönder
        const mailOptions = {
            from: 'KAPI SİSTEMİ',
            to: email,
            subject: 'Hesap Doğrulama Kodu',
            text: `Merhaba ${firstname},\n\nKAPI YÖNETİM SİSTEMİNE GİRİŞ İÇİN KODUNUZ: ${code}`
        };

        if (typeof MAIL_TRANSPORTER !== 'undefined') {
            MAIL_TRANSPORTER.sendMail(mailOptions, (err) => {
                if (err) {
                    console.error("Mail Hatası:", err);
                    // Hata olsa bile kayıt yaptık diyelim, kullanıcı tekrar dener
                    return res.json({ status: 'success', message: 'Kayıt alındı ancak mail gönderilemedi. Lütfen tekrar deneyin.' });
                }
                res.json({ status: 'success', message: 'Kayıt başarılı! Doğrulama kodu mailinize gönderildi.' });
            });
        } else {
            console.log("UYARI: Mail ayarları yok. Konsol Kodu: " + code);
            res.json({ status: 'success', message: 'Kayıt başarılı. (Mail ayarı olmadığı için kod konsola yazıldı)' });
        }

    } catch (err) {
        console.error("Kayıt Hatası Detayı:", err);
        res.status(500).json({ status: 'error', message: 'Sunucu hatası: ' + err.message });
    }
});

// --- EKSİK OLAN VERIFY (DOĞRULAMA) ROTASI ---
app.post(`${API_PREFIX_AUTH}/verify`, async (req, res) => {
    const { email, code } = req.body; 

    try {
        // Kullanıcı db'de var mı diye bakıyoruz
        const result = await pool.query('SELECT * FROM "users" WHERE "email" = $1', [email]);
        if (result.rows.length === 0) {
            return res.json({ status: 'error', message: 'Kullanıcı bulunamadı.' });
        }

        // RAM'deki kodu kontrol et
        const serverCode = verificationCodes[email];

        // Gelen kod ile RAM'deki kod eşleşiyor mu?
        if (serverCode && String(serverCode) === String(code)) {
            
            // Kod doğruysa hesabı onayla
            await pool.query('UPDATE "users" SET "isverified" = $1 WHERE "email" = $2', ['TRUE', email]);
            
            // İş bittiği için RAM'den silebilirsin kanka yer kaplamasın
            delete verificationCodes[email];
            
            res.json({ status: 'success', message: 'Hesap başarıyla doğrulandı.' });
        } else {
            res.json({ status: 'error', message: 'Hatalı veya süresi dolmuş doğrulama kodu!' });
        }

    } catch (err) {
        console.error("Doğrulama Hatası:", err);
        res.status(500).json({ status: 'error', message: 'Sunucu hatası: ' + err.message });
    }
});

//--- ŞİFRE SIFIRLAMA BÖLÜMÜ --- 

// 1. Şifre Sıfırlama Kodu Gönder
app.post(`${API_PREFIX_AUTH}/forgot-password`, async (req, res) => {
    const { email } = req.body;

    try {
        // Kullanıcı var mı bak
        const userCheck = await pool.query('SELECT * FROM "users" WHERE "email" = $1', [email]);
        if (userCheck.rows.length === 0) {
            return res.json({ status: 'error', message: 'Bu mail adresi sistemde kayıtlı değil.' });
        }

        // Kod üret ve RAM'e kaydet
        const code = generateCode();
        verificationCodes[email] = code;

        // Mail at
        const mailOptions = {
            from: 'KAPI SİSTEMİ',
            to: email,
            subject: 'Şifre Sıfırlama Kodu',
            text: `Şifrenizi sıfırlamak için kodunuz: ${code}`
        };

        if (typeof MAIL_TRANSPORTER !== 'undefined') {
            MAIL_TRANSPORTER.sendMail(mailOptions, (err) => {
                if (err) {
                    console.error("Mail Hatası:", err);
                    // Hata olsa bile güvenlik için gönderildi diyelim veya hata dönelim, sana kalmış
                    return res.json({ status: 'error', message: 'Mail gönderilemedi.' });
                }
                res.json({ status: 'success', message: 'Sıfırlama kodu mailinize gönderildi.' });
            });
        } else {
            // Mail ayarı yoksa konsola yaz (Test için)
            console.log(`[TEST] Şifre Sıfırlama Kodu (${email}): ${code}`);
            res.json({ status: 'success', message: 'Kod gönderildi (Konsola bak).' });
        }

    } catch (err) {
        console.error("Forgot Password Hatası:", err);
        res.status(500).json({ status: 'error', message: 'Sunucu hatası.' });
    }
});

// 2. Yeni Şifreyi Kaydet
app.post(`${API_PREFIX_AUTH}/reset-password`, async (req, res) => {
    const { email, code, newPassword } = req.body;

    try {
        // RAM'deki kod ile eşleşiyor mu?
        const serverCode = verificationCodes[email];

        if (!serverCode || String(serverCode) !== String(code)) {
            return res.json({ status: 'error', message: 'Hatalı veya süresi dolmuş kod!' });
        }

        // Şifre kurallarına uyuyor mu?
        const passwordError = checkPasswordPolicy(newPassword);
        if (passwordError) {
            return res.json({ status: 'error', message: passwordError });
        }

        // Şifreyi güncelle
        await pool.query('UPDATE "users" SET "userpassword" = $1 WHERE "email" = $2', [newPassword, email]);

        // Kodu sil (tek kullanımlık olsun)
        delete verificationCodes[email];

        res.json({ status: 'success', message: 'Şifreniz başarıyla değiştirildi. Giriş yapabilirsiniz.' });

    } catch (err) {
        console.error("Reset Password Hatası:", err);
        res.status(500).json({ status: 'error', message: 'Sunucu hatası.' });
    }
});

app.post(`${API_PREFIX_AUTH}/google`, async (req, res) => {
    const { token } = req.body;

    // 1. Google Token Doğrulama
    const googleUser = await verifyGoogleToken(token);
    if (!googleUser) return res.status(401).json({ status: 'error', message: 'Geçersiz Token' });
    
    const { sub: googleId, email, given_name, family_name } = googleUser;

    // İsim boş gelirse varsayılan ata
    const safeName = given_name || 'Google';
    const safeSurname = family_name || 'User';

    const client = await pool.connect();

    try {
        await client.query('BEGIN'); // İşlem bütünlüğü için transaction başlat

        // 2. Kullanıcı var mı kontrol et
        let result = await client.query('SELECT * FROM "users" WHERE "email" = $1', [email]);
        let user;

        if (result.rows.length > 0) {
            // A) KULLANICI ZATEN VAR
            user = result.rows[0];

            // Eğer hesap doğrulanmamışsa Google ile girdiği için doğrula
            if (!user.isverified) {
                await client.query('UPDATE "users" SET "isverified" = TRUE WHERE "userid" = $1', [user.userid]);
                user.isverified = true;
            }

            // Google ID bağlantısını kontrol et (Daha önce bağlanmadıysa ekle)
            const loginCheck = await client.query('SELECT * FROM "userlogins" WHERE "usersuserid" = $1 AND "oauthprovider" = $2', [user.userid, 'Google']);
            if (loginCheck.rows.length === 0) {
                await client.query('INSERT INTO "userlogins" ("oauthprovider", "oauthid", "usersuserid") VALUES ($1, $2, $3)', ['Google', googleId, user.userid]);
            }

        } else {
            // B) KULLANICI YOK -> YENİ KAYIT OLUŞTUR
            // Not: Varsayılan Rol ID = 2 (Admin) olarak ayarlı, isterseniz 1 (User) yapabilirsiniz.
            const insertRes = await client.query(
                `INSERT INTO "users" ("userfirstname", "usersurname", "email", "isverified", "status", "createdat", "rolesroleid") 
                 VALUES ($1, $2, $3, 'TRUE', 'TRUE', CURRENT_TIMESTAMP, 1) RETURNING *`, 
                [safeName, safeSurname, email]
            );
            user = insertRes.rows[0];

            // UserLogins tablosuna bağla
            await client.query(
                `INSERT INTO "userlogins" ("oauthprovider", "oauthid", "usersuserid") VALUES ($1, $2, $3)`, 
                ['Google', googleId, user.userid]
            );
        }

        // ============================================================
        // 📝 LOGLAMA EKLENDİ: Google girişi veritabanına yazılıyor
        // ============================================================
        await client.query(
            'INSERT INTO UserLogs (Action, UsersUserID) VALUES ($1, $2)',
            ['Sisteme Giriş Yapıldı (Google)', user.userid]
        );
        console.log(`Log Eklendi: Kullanıcı ${user.userid} Google ile giriş yaptı.`);
        // ============================================================

        await client.query('COMMIT'); // İşlemleri onayla

        // 3. Token Oluştur ve Gönder
        const roleName = await getRoleNameById(user.rolesroleid);
        const jwtToken = jwt.sign({ id: user.userid, role: user.rolesroleid }, JWT_SECRET, { expiresIn: '12h' });
        
        res.cookie('session_id', 'active', { httpOnly: true });

        res.json({ status: 'success', token: jwtToken, user: { name: user.userfirstname, role: roleName } });

    } catch (err) {
        await client.query('ROLLBACK'); // Hata olursa işlemleri geri al
        console.error("Google Login Hatası:", err);
        res.status(500).json({ status: 'error', message: 'Sunucu hatası' });
    } finally {
        client.release(); // Bağlantıyı havuza iade et
    }
});
app.post(`${API_PREFIX_AUTH}/login`, async (req, res) => {
    const { email, password } = req.body;
    
    // --- YENİ EKLENEN: Girişte mail formatı kontrolü ---
    if (!validateEmail(email)) {
        return res.status(400).json({ status: 'error', message: 'Geçersiz e-posta formatı!' });
    }

    try {
        const result = await pool.query('SELECT * FROM "users" WHERE "email" = $1', [email]);
        if (result.rows.length === 0) return res.status(401).json({ status: 'error', message: 'Bulunamadı.' });
        const user = result.rows[0];

        // EĞER KULLANICI ONAYLI DEĞİLSE HATA VER (Güvenlik için eklendi)
        if (user.isverified === false) {
            return res.status(401).json({ status: 'error', message: 'Lütfen önce mailinize gelen kod ile hesabınızı doğrulayın!' });
        }

        // Şifre Kontrolü
        if (!user.userpassword || user.userpassword !== password) return res.status(401).json({ status: 'error', message: 'Hatalı şifre.' });
        
        // ============================================================
        // 📝 LOGLAMA EKLENDİ: Başarılı giriş veritabanına yazılıyor
        // ============================================================
        await pool.query(
            'INSERT INTO UserLogs (Action, UsersUserID) VALUES ($1, $2)',
            ['Sisteme Giriş Yapıldı', user.userid]
        );
        console.log(`Log Eklendi: Kullanıcı ${user.userid} giriş yaptı.`);
        // ============================================================

        const roleName = await getRoleNameById(user.rolesroleid);
        const jwtToken = jwt.sign({ id: user.userid, role: user.rolesroleid }, JWT_SECRET, { expiresIn: '12h' });

        res.cookie('session_id', 'active', { httpOnly: true });

        res.json({ status: 'success', token: jwtToken, user: { name: user.userfirstname, role: roleName } });
    } catch (err) { 
        console.error("Login Hatası:", err);
        res.status(500).json({ status: 'error' }); 
    }
});
app.post(`${API_PREFIX_AUTH}/logout`, (req, res) => {
    res.clearCookie('session_id');
    res.json({ status: 'success', message: 'Çıkış yapıldı.' });
});

app.get(`${API_PREFIX_AUTH}/me`, authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM "users" WHERE "userid" = $1', [req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ message: 'User not found' });
        const user = result.rows[0];
        const roleName = await getRoleNameById(user.rolesroleid);
        res.json({ name: user.userfirstname + ' ' + user.usersurname, role: roleName, roleId: user.rolesroleid });
    } catch (err) { res.status(500).send('Error'); }
});

// =========================================================
// 5. API: KAPILAR (DOORS)
// =========================================================


app.get(`${API_PREFIX_DOORS}/status/all`, authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const userRole = req.user.role;

    try {
        let dbResult;
        let doorIdsWithPermission = [];

        // 1. ÖNCE: Kullanıcının erişim yetkisi olan kapıları belirle
        if (userRole === 3) {
            // SuperAdmin: TÜM kapılara erişebilir
            const allDoors = await pool.query('SELECT doorid FROM doors ORDER BY doorid ASC');
            doorIdsWithPermission = allDoors.rows.map(row => row.doorid);
            
            // Ortak Sütunlar
            const selectColumns = `
                SELECT d.doorid, d.doorname, d.ipadress, d.heartbeatstatus,
                       dg.groupname, dm.modename, dm.modeid AS currentmodeid,
                       ds.speedopen, ds.waittime, d.passivestate 
            `;
            
            const querySuper = `
                ${selectColumns}
                FROM doors d
                LEFT JOIN doorgroups dg ON d.doorgroupsgroupid = dg.groupid
                LEFT JOIN doorsettings ds ON ds.doorsdoorid = d.doorid
                LEFT JOIN doormode dm ON d.doormodemodeid = dm.modeid
                WHERE d.doorid = ANY($1::int[])
                ORDER BY d.doorid ASC;
            `;
            
            dbResult = await pool.query(querySuper, [doorIdsWithPermission]);
            
        } else {
            // Normal kullanıcı veya Admin: İZİNLİ olduğu kapılara erişebilir
            const userPermissions = await pool.query(
                'SELECT doorsdoorid FROM users_doors_permission WHERE useruserid = $1 AND permission = TRUE',
                [userId]
            );
            
            doorIdsWithPermission = userPermissions.rows.map(row => row.doorsdoorid);
            
            if (doorIdsWithPermission.length === 0) {
                console.log(`⚠️ Kullanıcı ${userId} için yetkili kapı bulunamadı`);
                return res.json({ doors: [] });
            }
            
            const selectColumns = `
                SELECT d.doorid, d.doorname, d.ipadress, d.heartbeatstatus,
                       dg.groupname, dm.modename, dm.modeid AS currentmodeid,
                       ds.speedopen, ds.waittime, d.passivestate 
            `;
            
            const queryUser = `
                ${selectColumns}
                FROM doors d
                LEFT JOIN doorgroups dg ON d.doorgroupsgroupid = dg.groupid
                LEFT JOIN doorsettings ds ON ds.doorsdoorid = d.doorid
                LEFT JOIN doormode dm ON d.doormodemodeid = dm.modeid
                WHERE d.doorid = ANY($1::int[])
                ORDER BY d.doorid ASC;
            `;
            
            dbResult = await pool.query(queryUser, [doorIdsWithPermission]);
        }

        console.log(`🔍 Kullanıcı ${userId} için ${doorIdsWithPermission.length} kapı yetkisi var`);
        
        // 2. VERİTABANINDAKİ KAPILARI İŞLE
        // ... app.get status/all rotasının içi ...

        const doorsWithLogsPromises = dbResult.rows.map(async db => {
            const liveStatus = allDoorStatuses[db.doorid] || {};
            const isESP = (db.ipadress === 'ESP8266' || liveStatus.isESP === true);

            // Logları getir
            const modeLogs = await getDoorModeLogs(db.doorid);
            const maintLogs = await getMaintenanceLogs(db.doorid);
            
            // ⭐ YENİ: Sensör Ayarlarını Getir ⭐
            const sensors = await getDoorSensors(db.doorid);

            // ONLINE DURUMU BELİRLE
            let onlineStatus;
            if (liveStatus.Online !== undefined) {
                onlineStatus = liveStatus.Online;
            } else if (db.heartbeatstatus !== undefined) {
                onlineStatus = db.heartbeatstatus;
            } else {
                onlineStatus = false;
            }

            return {
                doorid: db.doorid, 
                doorname: db.doorname, 
                GroupName: db.groupname,
                online: onlineStatus,
                heartbeatstatus: db.heartbeatstatus,
                isESP: isESP,
                Status: liveStatus.Status || 'CLOSED',
                Mode: liveStatus.Mode || db.currentmodeid,
                Speed: liveStatus.Speed || db.speedopen,
                WaitTime: liveStatus.WaitTime || db.waittime,
                SensorLeft: liveStatus.SensorLeft || 1, 
                SensorRight: liveStatus.SensorRight || 1,
                PassiveState: db.passivestate || 'CLOSED',
                IPAddress: db.ipadress,
                
                ModeLogs: modeLogs, 
                MaintenanceLogs: maintLogs,
                
                // ⭐ BURAYA EKLENDİ ⭐
                Access: sensors 
            };
        });

        let combinedDoors = await Promise.all(doorsWithLogsPromises);

        // 3. DEBUG İÇİN LOG
        console.log('🔍 API Yanıtı - Kapılar:');
        combinedDoors.forEach(door => {
            console.log(`   - Kapı ${door.doorid}: "${door.doorname}" | ESP: ${door.isESP} | Online: ${door.online} | DB Heartbeat: ${door.heartbeatstatus}`);
        });

        // 4. allDoorStatuses'de olan ama DB'de olmayan ESP kapıları için (sadece SuperAdmin)
        if (userRole === 3) {
            const dbDoorIds = new Set(dbResult.rows.map(door => door.doorid));
            
            for (const doorId in allDoorStatuses) {
                const doorIdNum = parseInt(doorId);
                const espDoor = allDoorStatuses[doorId];
                
                // ESP kapısı var ama DB'de yoksa (henüz kaydedilmemişse)
                if (!dbDoorIds.has(doorIdNum) && espDoor.isESP) {
                    console.log(`🔧 ESP Kapı ${doorId} (DB'de yok) API'ye ekleniyor...`);
                    
                    const modeLogs = await getDoorModeLogs(doorIdNum);
                    const maintLogs = await getMaintenanceLogs(doorIdNum);
                    
                    combinedDoors.push({
                        doorid: doorIdNum,
                        doorname: espDoor.DoorName || `ESP Kapı ${doorId}`,
                        GroupName: null,
                        online: espDoor.Online !== undefined ? espDoor.Online : true,
                        heartbeatstatus: true,
                        isESP: true,
                        Status: espDoor.Status || 'CLOSED',
                        Mode: espDoor.Mode || 1,
                        Speed: espDoor.Speed || 50,
                        WaitTime: espDoor.WaitTime || 5,
                        SensorLeft: espDoor.SensorLeft || 1,
                        SensorRight: espDoor.SensorRight || 1,
                        PassiveState: espDoor.PassiveState || 'CLOSED',
                        IPAddress: 'ESP8266',
                        ModeLogs: modeLogs,
                        MaintenanceLogs: maintLogs
                    });
                }
            }
        }

        // Kapıları sırala
        combinedDoors.sort((a, b) => a.doorid - b.doorid);

        res.json({ 
            status: 'success',
            doors: combinedDoors,
            count: combinedDoors.length
        });

    } catch (err) {
        console.error("❌ Kapı Listeleme Hatası:", err);
        res.status(500).json({ 
            status: 'error', 
            message: 'DB Hatası: ' + err.message 
        });
    }
});

app.put(`${API_PREFIX_DOORS}/:id/settings`, authenticateToken, async (req, res) => {
    const doorId = req.params.id;
    const { Mode, SpeedOpen, SpeedClose, WaitTime, Access, PassiveState, TestCycle } = req.body;
    const userId = req.user.id;

    console.log(`🚨 AYAR GÜNCELLEME İSTEĞİ (Kapı: ${doorId}):`);
    console.log(`- Body:`, req.body);

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // 1. MEVCUT VERİYİ GETİR (Eski durumu loglamak için lazım)
        const currentDataRes = await client.query(`
            SELECT d.doormodemodeid, d.passivestate, ds.speedopen, ds.speedclose, ds.waittime 
            FROM doors d 
            LEFT JOIN doorsettings ds ON d.doorid = ds.doorsdoorid 
            WHERE d.doorid = $1`, [doorId]);

        let current = {};

        if (currentDataRes.rows.length === 0) {
            // Kapı yoksa oluştur (ESP kapısı için)
            console.log(`📝 Kapı ${doorId} yok, oluşturuluyor...`);
            await client.query(
                `INSERT INTO doors (doorid, doorname, ipadress, doormodemodeid, passivestate, heartbeatstatus, lastupdate) 
                 VALUES ($1, $2, $3, $4, $5, TRUE, CURRENT_TIMESTAMP)`,
                [doorId, `Kapı ${doorId}`, '192.168.1.100', Mode || 1, 'IDLE']
            );
            current = { doormodemodeid: 1, passivestate: 'IDLE', speedopen: 50, speedclose: 40, waittime: 5 };
        } else {
            current = currentDataRes.rows[0];
        }

        // 2. HEDEF MOD VE PASİF DURUM MANTIĞI
        const targetMode = Mode !== undefined ? parseInt(Mode) : current.doormodemodeid;
        
        let finalPassiveState = 'IDLE';

        // SADECE PASİF MOD (4) İSE DURUMU KABUL ET
        if (targetMode === 4) {
            // Yeni durum geldiyse al, yoksa eskiyi koru, o da yoksa CLOSED yap
            finalPassiveState = PassiveState || current.passivestate || 'CLOSED';
            
            // Eğer eski durum IDLE ise ve yeni bir şey gelmediyse varsayılan CLOSED olsun
            if (finalPassiveState === 'IDLE') finalPassiveState = 'CLOSED';
        } else {
            // Diğer tüm modlarda (Manuel, Oto, Test vb.) durum IDLE olmalı
            finalPassiveState = 'IDLE';
        }

        // 3. DOORS TABLOSUNU GÜNCELLE
        await client.query(
            'UPDATE doors SET doormodemodeid = $1, passivestate = $2, lastupdate = CURRENT_TIMESTAMP WHERE doorid = $3', 
            [targetMode, finalPassiveState, doorId]
        );

        // ==================================================================
        // ⭐ DÜZELTİLEN KISIM: LOGLAMA MANTIĞI ⭐
        // ==================================================================
        
        // Sadece mod veya durum değiştiyse log at
        if (targetMode !== current.doormodemodeid || finalPassiveState !== current.passivestate) {
            const modeNames = { 1:'Oto', 2:'Manuel', 3:'Serbest', 4:'Pasif', 5:'Test' };
            
            // A. Eski durumu metne çevir (Örn: "Oto (IDLE)")
            const oldModeName = modeNames[current.doormodemodeid] || `Mod ${current.doormodemodeid}`;
            const oldStatusText = `${oldModeName} (${current.passivestate || 'IDLE'})`;

            // B. Yeni durumu metne çevir (Örn: "Pasif (CLOSED)")
            const newModeName = modeNames[targetMode] || `Mod ${targetMode}`;
            const newStatusText = `${newModeName} (${finalPassiveState})`;

            // C. Log tablosuna yaz
            await client.query(
                `INSERT INTO doorstatuslogs (doorsdoorid, oldstatus, newstatus, timestamp, usersuserid, severity) 
                 VALUES ($1, $2, $3, CURRENT_TIMESTAMP, $4, 'Info')`,
                [doorId, oldStatusText, newStatusText, userId]
            );
        }
        // ==================================================================

        // 4. DOOR SETTINGS (HIZ/SÜRE) GÜNCELLE (UPSERT)
        const newSpeedOpen = SpeedOpen !== undefined ? SpeedOpen : current.speedopen;
        const newSpeedClose = SpeedClose !== undefined ? SpeedClose : current.speedclose;
        const newWaitTime = WaitTime !== undefined ? WaitTime : current.waittime;
        
        await client.query(`
            INSERT INTO doorsettings (doorsdoorid, speedopen, speedclose, waittime)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (doorsdoorid) 
            DO UPDATE SET 
                speedopen = EXCLUDED.speedopen,
                speedclose = EXCLUDED.speedclose,
                waittime = EXCLUDED.waittime
        `, [doorId, newSpeedOpen || 50, newSpeedClose || 40, newWaitTime || 5]);

        // 5. SENSÖRLERİ GÜNCELLE (EĞER ACCESS VERİSİ GELDİYSE)
        if (Access) {
            console.log(`📝 Sensörler Veritabanına Yazılıyor: Kapı ${doorId}`);
            
            const sensorMap = [
                { key: 'EntryFree', side: 'İç Taraf', type: 'Serbest' },
                { key: 'EntryAuth', side: 'İç Taraf', type: 'Yetkili' },
                { key: 'ExitFree',  side: 'Dış Taraf', type: 'Serbest' },
                { key: 'ExitAuth',  side: 'Dış Taraf', type: 'Yetkili' }
            ];

            for (const s of sensorMap) {
                if (Access[s.key] !== undefined) {
                    await client.query(
                        `UPDATE doorsensor 
                         SET isenable = $1 
                         WHERE doorsdoorid = $2 AND sensorside = $3 AND sensortype = $4`,
                        [Access[s.key], doorId, s.side, s.type]
                    );
                }
            }
        }

        await client.query('COMMIT');

        // 6. MQTT GÖNDER
        const mqttPayload = {
            Mode: targetMode,
            PassiveState: finalPassiveState,
            SpeedOpen: newSpeedOpen,
            SpeedClose: newSpeedClose,
            WaitTime: newWaitTime,
            Access: Access,
            TestCycle: TestCycle
        };

        const topic = `${MQTT_TOPIC_COMMAND_PREFIX}${doorId}/settings_update`;
        mqttClient.publish(topic, JSON.stringify(mqttPayload), { qos: 1, retain: false });
        console.log(`📤 MQTT Gönderildi: ${topic} ->`, mqttPayload);

        // 7. FRONTEND'E CEVAP
        res.json({ 
            status: 'success', 
            message: 'Ayarlar güncellendi.', 
            finalMode: targetMode,
            finalState: finalPassiveState 
        });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Ayar Güncelleme Hatası:", err);
        res.status(500).json({ status: 'error', message: err.message });
    } finally {
        client.release();
    }
});

app.post(`${API_PREFIX_DOORS}/add`, authenticateToken, async (req, res) => {
    if (req.user.role !== 3) {
        return res.status(403).json({ status: 'error', message: 'Yetkisiz işlem! Sadece SuperAdmin kapı ekleyebilir.' });
    }

    const { doorName, ipAddress } = req.body;

    if (!doorName || !ipAddress) {
        return res.status(400).json({ status: 'error', message: 'Kapı adı ve IP adresi zorunludur.' });
    }

    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        const insertRes = await client.query(
            `INSERT INTO doors ("doorname", "ipadress", "doormodemodeid", "passivestate", "heartbeatstatus", "lastupdate") 
             VALUES ($1, $2, 1, 'CLOSED', '0', CURRENT_TIMESTAMP) 
             RETURNING doorid`,
            [doorName, ipAddress]
        );

        const newDoorId = insertRes.rows[0].doorid;

        await client.query(
            `INSERT INTO doorsettings (doorsdoorid, speedopen, waittime) VALUES ($1, 50, 5)`,
            [newDoorId]
        );

        await client.query(
            `INSERT INTO doorstatuslogs (doorsdoorid, oldstatus, newstatus, timestamp, usersuserid) 
             VALUES ($1, 'Sistem', 'Yeni Kapı Eklendi', CURRENT_TIMESTAMP, $2)`,
            [newDoorId, req.user.id]
        );

        await client.query('COMMIT');
        res.json({ status: 'success', message: 'Yeni kapı başarıyla eklendi.', doorId: newDoorId });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Kapı Ekleme Hatası:", err);
        res.status(500).json({ status: 'error', message: 'Veritabanı hatası: ' + err.message });
    } finally {
        client.release();
    }
});

// =========================================================
// 6. API: GRUPLAR
// =========================================================

app.post(`${API_PREFIX_GROUPS}/save`, authenticateToken, async (req, res) => {
    const { groupName, doorIds } = req.body;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        let groupRes = await client.query('SELECT groupid FROM doorgroups WHERE groupname = $1', [groupName]);
        let groupId;
        if (groupRes.rows.length === 0) {
            const newGrp = await client.query('INSERT INTO doorgroups (groupname) VALUES ($1) RETURNING groupid', [groupName]);
            groupId = newGrp.rows[0].groupid;
        } else {
            groupId = groupRes.rows[0].groupid;
        }
        for (const doorId of doorIds) {
            await client.query('UPDATE doors SET doorgroupsgroupid = $1 WHERE doorid = $2', [groupId, doorId]);
        }
        await client.query('COMMIT');
        res.json({ status: 'success', message: 'Grup güncellendi.' });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ status: 'error' });
    } finally { client.release(); }
});

app.post(`${API_PREFIX_GROUPS}/remove-door`, authenticateToken, async (req, res) => {
    const { doorId } = req.body;
    try {
        await pool.query('UPDATE doors SET doorgroupsgroupid = NULL WHERE doorid = $1', [doorId]);
        res.json({ status: 'success' });
    } catch (err) { res.status(500).json({ status: 'error' }); }
});

app.post(`${API_PREFIX_GROUPS}/delete`, authenticateToken, async (req, res) => {
    const { groupName } = req.body;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const grp = await client.query('SELECT groupid FROM doorgroups WHERE groupname = $1', [groupName]);
        if (grp.rows.length > 0) {
            const gid = grp.rows[0].groupid;
            await client.query('UPDATE doors SET doorgroupsgroupid = NULL WHERE doorgroupsgroupid = $1', [gid]);
            await client.query('DELETE FROM doorgroups WHERE groupid = $1', [gid]);
        }
        await client.query('COMMIT');
        res.json({ status: 'success' });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(500).json({ status: 'error' });
    } finally { client.release(); }
});

app.post(`${API_PREFIX_GROUPS}/apply-settings`, authenticateToken, async (req, res) => {
    const { groupName, targetMode, settings } = req.body;
    const userId = req.user.id;
    
    const modeNames = { 1: 'Otomatik Mod', 2: 'Manuel Mod', 3: 'Serbest Mod', 4: 'Pasif Mod', 5: 'Test Modu' };
    const newModeText = modeNames[targetMode] || 'Bilinmiyor';

    try {
        const doorsRes = await pool.query(
            `SELECT d.doorid, d.doormodemodeid 
             FROM doors d 
             JOIN doorgroups dg ON d.doorgroupsgroupid = dg.groupid 
             WHERE dg.groupname = $1`, 
            [groupName]
        );
        
        if (doorsRes.rows.length === 0) return res.json({ status: 'error', message: 'Bu grupta kapı yok.' });

        for (const door of doorsRes.rows) {
            const doorId = door.doorid;
            const currentModeID = door.doormodemodeid; 
            const oldModeText = modeNames[currentModeID] || 'Bilinmiyor';

            // 1. Kapı Modunu Güncelle
            await pool.query('UPDATE doors SET doormodemodeid = $1 WHERE doorid = $2', [targetMode, doorId]);
            
            // 2. Log Kaydı
            await pool.query(
                `INSERT INTO doorstatuslogs (doorsdoorid, oldstatus, newstatus, timestamp, usersuserid) 
                 VALUES ($1, $2, $3, CURRENT_TIMESTAMP, $4)`, 
                [doorId, oldModeText, newModeText, userId]
            );

            // =======================================================
            // >>> DÜZELTİLEN KISIM BAŞLANGICI <<<
            // =======================================================
            
            // Hız ve Bekleme Süresi Kontrolü
            // Eğer 'Speed' geldiyse hem open hem close'a uygula.
            // Eğer özel olarak SpeedOpen/Close geldiyse onları kullan.
            const valSpeedOpen = settings.SpeedOpen !== undefined ? settings.SpeedOpen : (settings.Speed !== undefined ? settings.Speed : null);
            const valSpeedClose = settings.SpeedClose !== undefined ? settings.SpeedClose : (settings.Speed !== undefined ? settings.Speed : null);
            const valWaitTime = settings.WaitTime !== undefined ? settings.WaitTime : null;

            if (valSpeedOpen !== null || valSpeedClose !== null || valWaitTime !== null) {
                // Not: Yeni kapı eklenirken varsayılan kayıt oluştuğu için UPDATE yeterlidir.
                // Ancak garanti olsun diye (kayıt silinmişse) UPSERT mantığı (Varsa Update Yoksa Insert) uygulanabilir.
                // Şimdilik sizin yapınıza uygun UPDATE yapıyoruz ama speedclose EKLENDİ.

                await pool.query(
                   `UPDATE doorsettings 
                    SET speedopen = COALESCE($1, speedopen), 
                        speedclose = COALESCE($2, speedclose),  -- BURASI EKLENDİ
                        waittime = COALESCE($3, waittime) 
                    WHERE doorsdoorid = $4`, 
                   [valSpeedOpen, valSpeedClose, valWaitTime, doorId]
                );
            }
            // =======================================================
            // ⭐ YENİ EKLENEN KISIM: GRUP SENSÖR GÜNCELLEMESİ ⭐
            // =======================================================
            if (settings.Access) {
                const sensorMap = [
                    { key: 'EntryFree', side: 'İç Taraf', type: 'Serbest' },
                    { key: 'EntryAuth', side: 'İç Taraf', type: 'Yetkili' },
                    { key: 'ExitFree',  side: 'Dış Taraf', type: 'Serbest' },
                    { key: 'ExitAuth',  side: 'Dış Taraf', type: 'Yetkili' }
                ];

                for (const s of sensorMap) {
                    if (settings.Access[s.key] !== undefined) {
                        await pool.query(
                            `UPDATE doorsensor 
                             SET isenable = $1 
                             WHERE doorsdoorid = $2 AND sensorside = $3 AND sensortype = $4`,
                            [settings.Access[s.key], doorId, s.side, s.type]
                        );
                    }
                }
            }
            // =======================================================
            // ⭐ BİTİŞ ⭐
            // =======================================================
            // =======================================================
            // >>> DÜZELTİLEN KISIM BİTİŞİ <<<
            // =======================================================

            const topic = `${MQTT_TOPIC_COMMAND_PREFIX}${doorId}/settings_update`;
            // MQTT Payload'ına da düzgün gitmesi için:
            const payload = { Mode: targetMode, ...settings };
            mqttClient.publish(topic, JSON.stringify(payload), { qos: 1, retain: false });
            
            if (allDoorStatuses[doorId]) { 
                allDoorStatuses[doorId] = { ...allDoorStatuses[doorId], Mode: targetMode, ...settings }; 
            }
        }
        res.json({ status: 'success', message: 'Toplu işlem tamamlandı.' });
    } catch (err) { 
        console.error("Grup Ayar Hatası:", err);
        res.status(500).json({ status: 'error', message: 'Sunucu hatası.' }); 
    }
});

app.get(`${API_PREFIX_GROUPS}/:groupName/logs`, authenticateToken, async (req, res) => {
    const { groupName } = req.params;
    try {
        const doorsRes = await pool.query(
            `SELECT d.doorid, d.doorname FROM doors d 
             JOIN doorgroups dg ON d.doorgroupsgroupid = dg.groupid 
             WHERE dg.groupname = $1`, 
            [groupName]
        );
        
        const doorIds = doorsRes.rows.map(r => r.doorid);

        if (doorIds.length === 0) {
            return res.json([]);
        }

        const allLogsPromises = doorIds.map(doorId => getDoorModeLogs(doorId));
        let allLogsArrays = await Promise.all(allLogsPromises);
        
        let combinedLogs = allLogsArrays.flat().map((log, index) => {
             return log;
        });

        combinedLogs.sort((a, b) => new Date(b.Date) - new Date(a.Date));

        res.json(combinedLogs);
    } catch (err) {
        console.error(`Grup ${groupName} logları çekilirken hata:`, err);
        res.status(500).json({ status: 'error', message: 'Sunucu hatası.' });
    }
});
// =========================================================
// MEVCUT ZAMANLAMALARI LİSTELEME ROTASI (EKLENECEK KOD)
// =========================================================
app.get(`${API_PREFIX_SCHED}/list`, authenticateToken, async (req, res) => {
    try {
        const client = await pool.connect();
        
        // DÜZELTME: 'doorgroups' tablosuna olan JOIN kaldırıldı.
        // Artık sadece kapı ismini çekiyoruz.
        const result = await client.query(`
            SELECT 
                s.*,
                d.doorname
            FROM schedule s
            LEFT JOIN doors d ON s.doorsdoorid = d.doorid
            WHERE s.isactive = TRUE
            ORDER BY s.scheduleid DESC
        `);
        client.release();

        res.json({ status: 'success', data: result.rows });
    } catch (err) {
        console.error("Takvim Listeleme Hatası:", err);
        res.status(500).json({ status: 'error', message: 'Veriler çekilemedi.' });
    }
});

// =========================================================
// ZAMANLAMA SİLME (TOPLU/GRUP SİLME DESTEKLİ)
// =========================================================
// =========================================================
// ZAMANLAMA SİLME (TOPLU/GRUP SİLME DESTEKLİ)
// =========================================================
// server.js -> DELETE Rotasının Düzeltilmiş Hali

app.delete(`${API_PREFIX_SCHED}/delete/:id`, authenticateToken, async (req, res) => {
    const id = req.params.id;
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // 1. Önce silinmek istenen hedef kaydı bul
        const checkRes = await client.query(
            'SELECT * FROM schedule WHERE scheduleid = $1',
            [id]
        );

        if (checkRes.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.json({ status: 'error', message: 'Kayıt bulunamadı.' });
        }

        const targetRecord = checkRes.rows[0];

        // ⭐ DÜZELTME BURADA YAPILDI ⭐
        // Eski kodda "batch_id varsa hepsini seç" diyorduk.
        // Artık sadece İSTENEN KAYDI listeye ekliyoruz.
        const recordsToDelete = [targetRecord];

        console.log(`🗑 SİLME İŞLEMİ: ID ${id} siliniyor. (Kapı: ${targetRecord.doorsdoorid})`);

        // 3. Geri döndürme (Revert) işlemleri
        const modeNames = { 1: 'Oto', 2: 'Manuel', 3: 'Serbest', 4: 'Pasif', 5: 'Test' };

        for (const rec of recordsToDelete) {
            // Eğer görev şu an AKTİF ise ve yedeği varsa, kapıyı eski ayarlarına döndür
            if (rec.currentstatus === 'ACTIVE' && rec.snapshotdata) {
                console.log(` ↪ Kapı ${rec.doorsdoorid} ayarları geri yükleniyor...`);

                const oldData = rec.snapshotdata;
                const currentModeName = modeNames[rec.doormodemodeid] || `Mod ${rec.doormodemodeid}`;
                const revertModeName = modeNames[oldData.Mode] || `Mod ${oldData.Mode}`;

                // A. Modu geri al
                if (oldData.Mode !== undefined) {
                    if (oldData.PassiveState) {
                        await client.query(
                            'UPDATE doors SET doormodemodeid = $1, passivestate = $2 WHERE doorid = $3',
                            [oldData.Mode, oldData.PassiveState, rec.doorsdoorid]
                        );
                    } else {
                        await client.query(
                            'UPDATE doors SET doormodemodeid = $1 WHERE doorid = $2',
                            [oldData.Mode, rec.doorsdoorid]
                        );
                    }
                }

                // B. Hız ve süreleri geri al
                await client.query(
                    `UPDATE doorsettings SET 
                        speedopen = COALESCE($1, speedopen),
                        speedclose = COALESCE($2, speedclose),
                        waittime = COALESCE($3, waittime)
                     WHERE doorsdoorid = $4`,
                    [
                        oldData.SpeedOpen,
                        oldData.SpeedClose,
                        oldData.WaitTime,
                        rec.doorsdoorid
                    ]
                );

                // C. Log at
                await client.query(
                    `INSERT INTO doorstatuslogs 
                     (doorsdoorid, oldstatus, newstatus, timestamp, severity) 
                     VALUES ($1, $2, $3, CURRENT_TIMESTAMP, 'Warning')`,
                    [
                        rec.doorsdoorid,
                        `${currentModeName} (İptal)`,
                        `${revertModeName} (Geri Yüklendi)`
                    ]
                );

                // D. MQTT ile cihaza bildir
                const topic = `${MQTT_TOPIC_COMMAND_PREFIX}${rec.doorsdoorid}/settings_update`;
                const payload = {
                    Mode: oldData.Mode,
                    SpeedOpen: oldData.SpeedOpen,
                    SpeedClose: oldData.SpeedClose,
                    WaitTime: oldData.WaitTime,
                    PassiveState: oldData.PassiveState
                };

                mqttClient.publish(topic, JSON.stringify(payload), { qos: 1, retain: false });
            }

            // 4. Kaydı sil
            await client.query(
                'DELETE FROM schedule WHERE scheduleid = $1',
                [rec.scheduleid]
            );
        }

        await client.query('COMMIT');
        res.json({ status: 'success', message: 'Zamanlama silindi.' });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('Takvim Silme Hatası:', err);
        res.status(500).json({
            status: 'error',
            message: 'Silme işlemi sırasında hata oluştu.'
        });
    } finally {
        client.release();
    }
});
// =========================================================
// 8. API: MAINTENANCE (BAKIM - DB BAĞLANTILI - GÜNCELLENDİ)
// =========================================================

app.post(`${API_PREFIX_MAINT}/add`, authenticateToken, async (req, res) => {
    const { doorId, person, date, type } = req.body;
    
    // YENİ: date (tam zaman damgası) parametresini kullanıyoruz
    if (!doorId || !person || !date || !type) {
        return res.status(400).json({ status: 'error', message: 'Tüm alanlar zorunludur.' });
    }

    try {
        // Personel adını FaultRecord alanına kaydetmeye devam ediyoruz.
        // sp_add_maintenance_log prosedürünü YENİ haliyle çağırıyoruz.
        await pool.query('CALL sp_add_maintenance_log($1, $2, $3, $4)', [doorId, person, type, date]);
        
        res.json({ status: 'success' });
    } catch (err) {
        console.error("Bakım Kaydı Hatası:", err);
        res.status(500).json({ status: 'error', message: 'Veritabanı hatası.' });
    }
});
// =========================================================
// 10. API: KULLANICI YÖNETİMİ (SÜPER ADMIN ÖZEL)
// =========================================================

// Tüm kullanıcıları listele
app.get('/api/users/list', authenticateToken, async (req, res) => {
    // Sadece Süper Admin (Role ID 3) görebilsin
    if (req.user.role !== 3) {
        return res.status(403).json({ status: 'error', message: 'Yetkisiz Erişim!' });
    }

    try {
        const result = await pool.query(`
            SELECT u.userid, u.userfirstname, u.usersurname, u.email, u.rolesroleid, u.status, r.rolename 
            FROM users u
            LEFT JOIN roles r ON u.rolesroleid = r.roleid
            ORDER BY u.userid ASC
        `);
        res.json({ status: 'success', users: result.rows });
    } catch (err) {
        console.error("Kullanıcı Listesi Hatası:", err);
        res.status(500).json({ status: 'error', message: 'Veritabanı hatası' });
    }
});

// Kullanıcı Durumunu Değiştir (Aktif/Pasif Yapma)
app.put('/api/users/toggle-status', authenticateToken, async (req, res) => {
    if (req.user.role !== 3) {
        return res.status(403).json({ status: 'error', message: 'Yetkisiz Erişim!' });
    }

    const { targetUserId } = req.body;

    // Kendini pasife almasını engelleyelim
    if (parseInt(targetUserId) === req.user.id) {
        return res.status(400).json({ status: 'error', message: 'Kendi hesabınızı pasife alamazsınız.' });
    }

    try {
        // Mevcut durumu tersine çevir (NOT status)
        await pool.query('UPDATE users SET status = NOT status WHERE userid = $1', [targetUserId]);
        res.json({ status: 'success', message: 'Kullanıcı durumu güncellendi.' });
    } catch (err) {
        console.error("Durum Değiştirme Hatası:", err);
        res.status(500).json({ status: 'error', message: 'Veritabanı hatası' });
    }
});

// Kullanıcı Rolünü Güncelle
app.put('/api/users/update-role', authenticateToken, async (req, res) => {
    if (req.user.role !== 3) {
        return res.status(403).json({ status: 'error', message: 'Yetkisiz Erişim!' });
    }
    const { targetUserId, newRoleId } = req.body;
    
    if (parseInt(targetUserId) === req.user.id) {
        return res.status(400).json({ status: 'error', message: 'Kendi yetkinizi değiştiremezsiniz.' });
    }
    try {
        await pool.query('UPDATE users SET rolesroleid = $1 WHERE userid = $2', [newRoleId, targetUserId]);
        res.json({ status: 'success', message: 'Kullanıcı yetkisi güncellendi.' });
    } catch (err) {
        console.error("Rol Güncelleme Hatası:", err);
        res.status(500).json({ status: 'error', message: 'Güncelleme hatası' });
    }
});



// =========================================================
// 11. API: KAPI ATAMA (ASSIGNMENTS) 
// =========================================================
// =========================================================
// server.js -> /api/assignments/users ROTASINI BUL VE BUNUNLA DEĞİŞTİR
// =========================================================

// 1. Kapı yetkisi verilebilecek kullanıcıları listele (Roller, Sayılar ve Kapı İsimleri Dahil)
app.get('/api/assignments/users', authenticateToken, async (req, res) => {
    if (req.user.role !== 3) return res.sendStatus(403); // Sadece SuperAdmin

    try {
        // Rolü 1(User) veya 2(Admin) olanları getir.
        // STRING_AGG: PostgreSQL'de kapı isimlerini virgülle birleştirir.
        const query = `
            SELECT 
                u.userid, 
                u.userfirstname, 
                u.usersurname, 
                u.email, 
                r.rolename,
                COUNT(d.doorid) as door_count,
                STRING_AGG(d.doorname, ', ') as door_names
            FROM users u
            LEFT JOIN roles r ON u.rolesroleid = r.roleid
            LEFT JOIN users_doors_permission udp ON u.userid = udp.useruserid AND udp.permission = TRUE
            LEFT JOIN doors d ON udp.doorsdoorid = d.doorid
            WHERE u.rolesroleid IN (1, 2)
            GROUP BY u.userid, u.userfirstname, u.usersurname, u.email, r.rolename
            ORDER BY u.userid ASC
        `;

        const result = await pool.query(query);
        
        // door_count string olarak dönebilir (Postgres bigint), int'e çevirelim
        const users = result.rows.map(user => ({
            ...user,
            door_count: parseInt(user.door_count || 0)
        }));

        res.json({ status: 'success', users: users });
    } catch (err) {
        console.error("Assignment User List Hatası:", err);
        res.status(500).json({ status: 'error', message: err.message });
    }
});

// 2. Bir kullanıcının yetkili olduğu kapıları getir
// =========================================================
// server.js -> KAPI ATAMA BÖLÜMÜNE EKLE (EKSİK OLAN KISIM)
// =========================================================

// 2. Bir kullanıcının yetkili olduğu kapıları getir
app.get('/api/assignments/by-user/:userId', authenticateToken, async (req, res) => {
    // Sadece SuperAdmin bu veriyi görebilir
    if (req.user.role !== 3) return res.sendStatus(403);

    const { userId } = req.params;
    try {
        const result = await pool.query(
            'SELECT doorsdoorid FROM users_doors_permission WHERE useruserid = $1 AND permission = TRUE', 
            [userId]
        );
        
        // Sadece ID'lerden oluşan bir dizi döndür: [1, 5, 8] gibi
        const authorizedDoorIds = result.rows.map(r => r.doorsdoorid);
        
        res.json({ status: 'success', doorIds: authorizedDoorIds });
    } catch (err) {
        console.error("Yetki Getirme Hatası:", err);
        res.status(500).json({ status: 'error', message: err.message });
    }
});

// 3. Yetkileri Kaydet (Eskileri Sil -> Yenileri Ekle)
app.post('/api/assignments/save', authenticateToken, async (req, res) => {
    if (req.user.role !== 3) return res.sendStatus(403);

    const { targetUserId, selectedDoorIds } = req.body;
    const client = await pool.connect();

    try {
        await client.query('BEGIN');

        // A. Önce bu kullanıcıya ait eski tüm yetkileri sil (Temiz sayfa)
        await client.query('DELETE FROM users_doors_permission WHERE useruserid = $1', [targetUserId]);

        // B. Seçilen yeni kapıları tek tek ekle
        if (selectedDoorIds && selectedDoorIds.length > 0) {
            for (const doorId of selectedDoorIds) {
                await client.query(
                    `INSERT INTO users_doors_permission (doorsdoorid, useruserid, permission) 
                     VALUES ($1, $2, TRUE)`,
                    [doorId, targetUserId]
                );
            }
        }

        await client.query('COMMIT');
        res.json({ status: 'success', message: 'Yetkiler veritabanına kaydedildi.' });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error("Yetki Kayıt Hatası:", err);
        res.status(500).json({ status: 'error', message: 'Veritabanı hatası.' });
    } finally {
        client.release();
    }
});
// =========================================================
// 12. OTOMATİK ZAMANLAYICI (GÜNCELLENMİŞ & UYUMLU)
// =========================================================

// =========================================================
// 12. OTOMATİK ZAMANLAYICI (FINAL - SQL UYUMLU & LOG DÜZELTMELİ & PASİF DURUM DESTEKLİ)
// =========================================================

setInterval(async () => {
    try {
        // 1. Veritabanı Fonksiyonunu Çağır
        // Bu fonksiyon NULL hatası vermiyor, UserID ve Pasif Durum dahil tüm bilgileri getiriyor.
        const result = await pool.query('SELECT * FROM sp_get_pending_schedules()');
        
        // Yapılacak iş yoksa çık
        if (result.rows.length === 0) return;

        console.log(`⏰ ZAMANLAYICI TETİKLENDİ: ${result.rows.length} işlem uygulanıyor...`);
        
        // Loglarda güzel görünmesi için mod isimleri
        const modeNames = { 1: 'Oto', 2: 'Manuel', 3: 'Serbest', 4: 'Pasif', 5: 'Test' };

        for (const task of result.rows) {
            // SQL fonksiyonundan dönen sütun isimleri (hepsi küçük harf)
            const { targetdoorid, actiontype, modeid, speedopen, speedclose, waittime, userid, targetpassive } = task;

            // --- 1. ESKİ DURUMU ÖĞREN (Loglama İçin) ---
            let oldStatusText = 'Bilinmiyor';
            try {
                const oldRes = await pool.query('SELECT doormodemodeid FROM doors WHERE doorid = $1', [targetdoorid]);
                if(oldRes.rows.length > 0) {
                    const oldID = oldRes.rows[0].doormodemodeid;
                    oldStatusText = modeNames[oldID] || `Mod ${oldID}`;
                }
            } catch(e) { console.error("Eski mod okuma hatası", e); }

            // Yeni durum metni
            const newStatusText = modeNames[modeid] || `Mod ${modeid}`;
            const actionLabel = actiontype === 'START' ? 'BAŞLADI' : 'BİTTİ';

            console.log(`   └-> Kapı ${targetdoorid}: ${actionLabel} | ${oldStatusText} -> ${newStatusText} | User: ${userid}`);

            // -------------------------------------------------
            // 2. MQTT PAKETİNİ HAZIRLA VE GÖNDER
            // -------------------------------------------------
            let payloadObj = { Mode: modeid };
            
            // Eğer Pasif Durum (OPEN/CLOSED) varsa pakete ekle
            if (targetpassive) payloadObj.PassiveState = targetpassive;

            // Eğer veritabanından hız/süre ayarı geldiyse pakete ekle
            if (speedopen !== null) payloadObj.SpeedOpen = speedopen;
            if (speedclose !== null) payloadObj.SpeedClose = speedclose;
            if (waittime !== null) payloadObj.WaitTime = waittime;
            
            const payloadJSON = JSON.stringify(payloadObj);
            const topic = `${MQTT_TOPIC_COMMAND_PREFIX}${targetdoorid}/settings_update`;
            mqttClient.publish(topic, payloadJSON, { qos: 1, retain: false });

            // -------------------------------------------------
            // 3. VERİTABANI GÜNCELLEMELERİ (DB Sync)
            // -------------------------------------------------
            
            // A. Kapı Modunu Güncelle (Doors tablosu)
            // Eğer Pasif Durum geldiyse onu da güncelle
            if (targetpassive) {
                await pool.query('UPDATE doors SET doormodemodeid = $1, passivestate = $2 WHERE doorid = $3', 
                    [modeid, targetpassive, targetdoorid]);
            } else {
                await pool.query('UPDATE doors SET doormodemodeid = $1 WHERE doorid = $2', 
                    [modeid, targetdoorid]);
            }

            // B. Hız ve Süre Ayarlarını Güncelle (DoorSettings tablosu - UPSERT)
            // Eğer hız verisi geldiyse settings tablosunu da güncelle ki panelde doğru görünsün
            if (speedopen !== null || speedclose !== null || waittime !== null) {
                await pool.query(`
                    INSERT INTO doorsettings (doorsdoorid, speedopen, speedclose, waittime)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (doorsdoorid) 
                    DO UPDATE SET 
                        speedopen = COALESCE($2, doorsettings.speedopen),
                        speedclose = COALESCE($3, doorsettings.speedclose),
                        waittime = COALESCE($4, doorsettings.waittime)
                `, [targetdoorid, speedopen || 50, speedclose || 40, waittime || 5]);
            }

            // C. Log Kaydı At (DoorStatusLogs tablosu)
            // OldStatus: Temiz eski mod ismi
            // NewStatus: Yeni mod ismi + Zamanlayıcı notu
            // UserID: SQL'den gelen ID (Artık NULL değil)
            await pool.query(
                `INSERT INTO doorstatuslogs (doorsdoorid, oldstatus, newstatus, timestamp, usersuserid, severity) 
                 VALUES ($1, $2, $3, CURRENT_TIMESTAMP, $4, 'Info')`, 
                [
                    targetdoorid, 
                    oldStatusText, 
                    `${newStatusText} (Zamanlayıcı: ${actiontype})`, 
                    userid
                ]
            );
        }

    } catch (err) {
        console.error("❌ Zamanlayıcı Döngü Hatası:", err.message);
    }
}, 60000); // 60 Saniyede bir kontrol et (Test için 5000 yapabilirsin)
// =========================================================
// SERVER BAŞLANGIÇ KONTROLLERİ
// =========================================================
async function initializeDatabase() {
    console.log('🔍 Veritabanı başlangıç kontrolleri yapılıyor...');   
    try {
        // 1. ROLLER KONTROLÜ
        const rolesCheck = await pool.query('SELECT COUNT(*) FROM roles');
        if (rolesCheck.rows[0].count == 0) {
            console.log('⚙️  Roller tablosu boş, örnek veriler ekleniyor...');
            await pool.query(`
                INSERT INTO Roles (RoleName) VALUES 
                ('User'), ('Admin'), ('SuperAdmin'), ('TechnicalStaff');
            `);
        }

        // 2. MODLAR KONTROLÜ
        const modesCheck = await pool.query('SELECT COUNT(*) FROM doormode');
        if (modesCheck.rows[0].count == 0) {
            console.log('⚙️  Kapı modları boş, örnek veriler ekleniyor...');
            await pool.query(`
                INSERT INTO DoorMode (ModeName) VALUES 
                ('Oto'), ('Manuel'), ('Serbest'), ('Pasif'), ('Test');
            `);
        }

        // 3. VARSYALAN KAPILAR KONTROLÜ (ESKİ VERİLERİ TEMİZLEMEYECEK)
        const doorsCheck = await pool.query('SELECT COUNT(*) FROM doors');
        console.log(`📊 Veritabanında ${doorsCheck.rows[0].count} kapı bulunuyor`);

        // 4. SUPERADMIN KONTROLÜ
        const superAdminCheck = await pool.query(
            'SELECT COUNT(*) FROM users WHERE rolesroleid = 3 AND email = $1',
            ['sukru@aldoor.com']
        );
        
        if (superAdminCheck.rows[0].count == 0) {
            console.log('⚙️  SuperAdmin kullanıcısı ekleniyor...');
            await pool.query(`
                INSERT INTO Users (UserFirstname, UserSurname, Email, UserPassword, RolesRoleID, IsVerified, Status) 
                VALUES ('Şükrü', 'Görgülü', 'sukru@aldoor.com', '1234', 3, TRUE, TRUE)
                ON CONFLICT (email) DO NOTHING;
            `);
        }

        console.log('✅ Veritabanı başlangıç kontrolleri tamamlandı');

    } catch (error) {
        console.error('❌ Veritabanı başlangıç hatası:', error.message);
    }
}
// =========================================================
// 7. API: SCHEDULER (TIMESTAMP + BATCH ID + KESİN ÇAKIŞMA)
// =========================================================
app.post(`${API_PREFIX_SCHED}/add`, authenticateToken, async (req, res) => {
    const { targetType, targetId, mode, recurrenceType, startTime, endTime, recurrenceValue, settings } = req.body;
    const userId = req.user.id;

    // Grup silme işlemi için benzersiz bir kimlik oluşturuyoruz
    const batchId = `${Date.now()}-${Math.floor(Math.random() * 10000)}`;

    console.log(`\n🔵 [SCHEDULER] Yeni İstek (${batchId}): ${targetType} ID:${targetId} | ${startTime} -> ${endTime}`);

    const client = await pool.connect();
    
    try {
        await client.query('BEGIN');

        // 1. ZAMAN HESAPLAMALARI
        // ---------------------------------------------------------
        
        // A) Tam Zaman Damgası (Milisaniye) - Tek Seferlik ve Çok Günlü Kontrolü İçin
        const reqStartMs = new Date(startTime).getTime();
        const reqEndMs = new Date(endTime).getTime();

        // B) Dakika Hesabı - Haftalık ve Karışık Kontroller İçin
        // (00:00 -> 0, 14:30 -> 870)
        const getMinutes = (dateObj) => {
            return (dateObj.getHours() * 60) + dateObj.getMinutes();
        };

        // C) DB Kayıt Formatları (TIMESTAMP Uyumu)
        let dbStartTime = startTime;
        let dbEndTime = endTime;
        let sqlDate = null;
        let activeDays = null;

        if (recurrenceType === 'none') {
            // Tek Seferlik: Zaten tam tarih formatında (2025-12-16T14:30)
            sqlDate = startTime.split('T')[0]; 
        } else {
            // Haftalık: Frontend sadece saat gönderir ("14:30").
            // TIMESTAMP sütununa kaydetmek için başına dummy tarih ekliyoruz.
            dbStartTime = `2000-01-01 ${startTime}`; 
            dbEndTime = `2000-01-01 ${endTime}`;
            activeDays = String(recurrenceValue);
        }

        const sOpen = settings?.SpeedOpen ? parseInt(settings.SpeedOpen) : null;
        const sClose = settings?.SpeedClose ? parseInt(settings.SpeedClose) : null;
        const sWait = settings?.WaitTime ? parseInt(settings.WaitTime) : null;
        const sPassive = settings?.PassiveState || null;

        // 2. HEDEF KAPI LİSTESİ
        let targetDoorIds = [];
        if (targetType === 'group') {
            const grpRes = await client.query('SELECT groupid FROM doorgroups WHERE groupname = $1', [targetId]);
            if (grpRes.rows.length > 0) {
                const doors = await client.query('SELECT doorid FROM doors WHERE doorgroupsgroupid = $1', [grpRes.rows[0].groupid]);
                targetDoorIds = doors.rows.map(d => d.doorid);
            }
        } else {
            targetDoorIds = [parseInt(targetId)];
        }

        // 3. 🛑 SIKI ÇAKIŞMA KONTROLÜ
        // ---------------------------------------------------------
        for (const tDoorId of targetDoorIds) {
            // Veritabanından TIMESTAMP olarak çekiyoruz (pg otomatik Date objesine çevirir)
            const existingTasks = await client.query(
                `SELECT scheduleid, schedulename, 
                        starttime, endtime, 
                        recurrencetype, activedays
                 FROM schedule 
                 WHERE doorsdoorid = $1 AND isactive = TRUE`,
                [tDoorId]
            );

            for (const task of existingTasks.rows) {
                const dbRecur = task.recurrencetype || 'none';
                
                // DB Zamanlarını Hazırla
                const taskStartMs = new Date(task.starttime).getTime();
                const taskEndMs = new Date(task.endtime).getTime();

                // --- SENARYO 1: TEK SEFERLİK vs TEK SEFERLİK (Çok Günlü Dahil) ---
                if (recurrenceType === 'none' && dbRecur === 'none') {
                    // Tarih fark etmeksizin zaman aralıkları kesişiyor mu?
                    if (reqStartMs < taskEndMs && reqEndMs > taskStartMs) {
                        await client.query('ROLLBACK');
                        console.log(`❌ ÇAKIŞMA: ${new Date(reqStartMs)} <-> ${new Date(taskEndMs)}`);
                        return res.json({ 
                            status: 'error', 
                            message: `ÇAKIŞMA!\nKapı ID: ${tDoorId}\n"${task.schedulename}" görevi bu tarih aralığını kullanıyor.` 
                        });
                    }
                }

                // --- SENARYO 2: HAFTALIK vs HAFTALIK ---
                else if (recurrenceType !== 'none' && dbRecur !== 'none') {
                    // Sadece dakikalara bak (Tarih önemsiz)
                    // İki taraf da haftalık olduğu için 2000-01-01 bazlı karşılaştırma güvenlidir
                    const reqMinStart = getMinutes(new Date(`2000-01-01 ${startTime}`));
                    const reqMinEnd = getMinutes(new Date(`2000-01-01 ${endTime}`));
                    const taskMinStart = getMinutes(new Date(task.starttime));
                    const taskMinEnd = getMinutes(new Date(task.endtime));

                    if (String(task.activedays) === String(activeDays)) {
                        if (reqMinStart < taskMinEnd && reqMinEnd > taskMinStart) {
                            await client.query('ROLLBACK');
                            return res.json({ 
                                status: 'error', 
                                message: `ÇAKIŞMA!\nKapı ID: ${tDoorId}\nGün: ${activeDays}. Gün dolu.` 
                            });
                        }
                    }
                }

                // --- SENARYO 3: KARIŞIK (Haftalık vs Tek Seferlik) ---
                else {
                    let conflict = false;
                    
                    // A) Yeni=Tek, Mevcut=Haftalık
                    if (recurrenceType === 'none' && dbRecur !== 'none') {
                        const dateObj = new Date(startTime);
                        let dayIndex = dateObj.getDay(); 
                        if (dayIndex === 0) dayIndex = 7; // Pazar düzeltmesi

                        if (String(task.activedays) === String(dayIndex)) {
                            // Gün tutuyor, saat aralığına bak (Dakika bazlı)
                            const reqMinStart = getMinutes(dateObj);
                            // Çok günlü ise bitiş saati sonraki günlerde olabilir ama
                            // basitlik için başlangıç gününün saatlerine bakıyoruz veya
                            // kesin çakışma için bitiş saati kontrolü:
                            const reqMinEnd = getMinutes(new Date(endTime)); 
                            
                            const taskMinStart = getMinutes(new Date(task.starttime));
                            const taskMinEnd = getMinutes(new Date(task.endtime));

                            if (reqMinStart < taskMinEnd && reqMinEnd > taskMinStart) conflict = true;
                        }
                    }
                    // B) Yeni=Haftalık, Mevcut=Tek
                    else if (recurrenceType !== 'none' && dbRecur === 'none') {
                        const dateObj = new Date(task.starttime);
                        let dayIndex = dateObj.getDay();
                        if (dayIndex === 0) dayIndex = 7;

                        if (String(activeDays) === String(dayIndex)) {
                            const reqMinStart = getMinutes(new Date(`2000-01-01 ${startTime}`));
                            const reqMinEnd = getMinutes(new Date(`2000-01-01 ${endTime}`));
                            
                            const taskMinStart = getMinutes(dateObj);
                            const taskMinEnd = getMinutes(new Date(task.endtime));

                            if (reqMinStart < taskMinEnd && reqMinEnd > taskMinStart) conflict = true;
                        }
                    }

                    if (conflict) {
                        await client.query('ROLLBACK');
                        return res.json({ status: 'error', message: `ÇAKIŞMA!\nKapı ID: ${tDoorId}\n"${task.schedulename}" görevi bu zaman diliminde çalışıyor.` });
                    }
                }
            }
        }

        // 4. KAYIT İŞLEMİ (BATCH ID DESTEKLİ)
        // ---------------------------------------------------------
        const insertQuery = `
            INSERT INTO schedule 
            (schedulename, starttime, endtime, activedays, isactive, specificdate, 
             usersuserid, doorsdoorid, doormodemodeid, 
             recurrencetype, TargetSpeedOpen, TargetSpeedClose, TargetWaitTime, targetpassivestate, batch_id)
            VALUES ($1, $2, $3, $4, TRUE, $5, $6, $7,$8, $9, $10, $11, $12, $13, $14)
            RETURNING scheduleid
        `;

        let lastInsertId = 0;

        for (const tDoorId of targetDoorIds) {
            let namePrefix = (targetType === 'group') ? `GRUP: ${targetId}` : `KAPI: ${tDoorId}`;
            let name = `${namePrefix} (${mode === 1 ? 'OTO' : 'MOD '+mode})`;
            
            // batchId parametresini ($14) sorguya ekliyoruz
            const resInsert = await client.query(insertQuery, [
                name, dbStartTime, dbEndTime, activeDays, sqlDate, userId, tDoorId, 
                mode, recurrenceType, sOpen, sClose, sWait, sPassive, batchId
            ]);
            
            lastInsertId = resInsert.rows[0].scheduleid;
        }

        await client.query('COMMIT');
        console.log(`✅ BAŞARILI: Zamanlama eklendi. (BatchID: ${batchId})`);
        
        // Son eklenen ID'yi dönüyoruz (Frontend tek kapı eklediyse silme butonu için lazım)
        res.json({ status: 'success', message: "Zamanlama eklendi.", id: lastInsertId });

    } catch (err) {
        await client.query('ROLLBACK');
        console.error("❌ Takvim Ekleme Hatası:", err);
        res.status(500).json({ status: 'error', message: 'Sunucu hatası: ' + err.message });
    } finally {
        client.release();
    }
});
// =========================================================
// 9. BAŞLAT
// =========================================================
app.listen(PORT, async () => {
    console.log(`🚀 Sunucu çalışıyor: http://localhost:${PORT}`);
    
    try {
        // Veritabanı bağlantısını test et
        const dbTest = await pool.query('SELECT NOW()');
        console.log("✅ Veritabanı Bağlantısı Başarılı!");
        
        // Başlangıç kontrollerini çalıştır
        await initializeDatabase();
        
        // Tüm kapıları kontrol et
        const doors = await pool.query('SELECT doorid, doorname, ipadress, heartbeatstatus FROM doors ORDER BY doorid');
        console.log(`📊 Veritabanında ${doors.rows.length} kapı mevcut:`);
        doors.rows.forEach(door => {
            console.log(`   - Kapı ${door.doorid}: "${door.doorname}" (IP: ${door.ipadress}, Online: ${door.heartbeatstatus})`);
        });
        
    } catch (err) {
        console.error("❌ Veritabanı Bağlantı Hatası:", err.message);
    }
});
// --- SENSÖR VERİLERİNİ OKUMA YARDIMCISI ---
async function getDoorSensors(doorId) {
    try {
        const res = await pool.query('SELECT sensortype, sensorside, isenable FROM doorsensor WHERE doorsdoorid = $1', [doorId]);
        
        // Varsayılan hepsi FALSE (Kapalı)
        let access = { EntryFree: false, EntryAuth: false, ExitFree: false, ExitAuth: false };
        
        res.rows.forEach(r => {
            if (r.sensorside === 'İç Taraf' && r.sensortype === 'Serbest') access.EntryFree = r.isenable;
            if (r.sensorside === 'İç Taraf' && r.sensortype === 'Yetkili') access.EntryAuth = r.isenable;
            if (r.sensorside === 'Dış Taraf' && r.sensortype === 'Serbest') access.ExitFree = r.isenable;
            if (r.sensorside === 'Dış Taraf' && r.sensortype === 'Yetkili') access.ExitAuth = r.isenable;
        });
        return access;
    } catch (e) {
        console.error("Sensör okuma hatası:", e);
        return { EntryFree: false, EntryAuth: false, ExitFree: false, ExitAuth: false };
    }
}

// =========================================================
// DB GÜNCELLEME (EN ALTTA TEK BİR KERE OLMALI)
// =========================================================
async function autoUpdateDatabase() {
    const client = await pool.connect();
    try {
        console.log("⚙️  Veritabanı şeması kontrol ediliyor...");
        
        // 1. schedule tablosuna eksik sütunu ekle
        await client.query(`
            ALTER TABLE schedule 
            ADD COLUMN IF NOT EXISTS targetpassivestate VARCHAR(20) DEFAULT NULL;
        `);
        console.log("✅ Sütun Kontrolü: 'targetpassivestate' sütunu hazır.");

    } catch (err) {
        console.error("❌ Veritabanı güncelleme hatası:", err.message);
    } finally {
        client.release();
    }
}

// Sunucu başlamadan önce çalıştır
autoUpdateDatabase();
