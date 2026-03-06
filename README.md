# Daly Alpha VIP Admin Package

هذه النسخة تُبقي **مفتاح Gemini مخفيًا على الخادم** وتضيف **لوحة إدارة داخلية** على `/admin` لإنشاء أكواد VIP القصيرة وإلغاءها وتحرير الأجهزة المرتبطة بها.

## ما الجديد في هذه النسخة
- الواجهة الأساسية `public/index.html` تستخدم **Activation Code** بدل إدخال Google API Key.
- مفتاح Gemini الحقيقي يبقى داخل `.env` على الخادم فقط.
- لوحة إدارة رسومية على:
  - `http://localhost:3000/admin`
- تدعم لوحة الإدارة:
  - إنشاء كود جديد
  - نسخ الكود فور إنشائه
  - عرض كل الأكواد الحالية
  - إلغاء أي كود
  - تحرير جهاز معيّن من كود معيّن إذا غيّر المستخدم هاتفه
- أضفت أيضًا ملفات التشغيل الناقصة:
  - `package.json`
  - `.env.example`
  - `scripts/vip-codes.js`
  - `lib/vip-store.js`

## التثبيت
```bash
npm install
```

## الإعداد الأولي
انسخ ملف البيئة المثال:
```bash
cp .env.example .env
```

ثم عدّل القيم المهمة:
```env
GEMINI_API_KEY=YOUR_REAL_GOOGLE_AI_STUDIO_KEY
ADMIN_PASSWORD=YOUR_STRONG_ADMIN_PASSWORD
```

## التشغيل
```bash
npm start
```

التطبيق الرئيسي:
```text
http://localhost:3000
```

لوحة الإدارة:
```text
http://localhost:3000/admin
```

## كيف تستخدم لوحة الإدارة
1. افتح `/admin`
2. سجّل الدخول بكلمة مرور الإدارة من `.env`
3. أنشئ كودًا جديدًا
4. انسخ الكود وأرسله لصديقك
5. صديقك يفعّل VIP من داخل الواجهة الرئيسية بالكود القصير فقط

> ملاحظة مهمة: **الكود الكامل لا يُخزَّن في قاعدة البيانات بعد الإنشاء**. لذلك انسخه فور ظهوره في لوحة الإدارة.

## أوامر سطر الأوامر ما زالت متاحة
إنشاء كود:
```bash
npm run create-code -- --label "Ahmad" --uses 1 --days 90 --notes "iPhone"
```

عرض الأكواد:
```bash
npm run list-codes
```

إلغاء كود:
```bash
npm run revoke-code -- CODE_ID_HERE
```

تحرير جهاز من كود:
```bash
npm run remove-device -- CODE_ID_HERE DEVICE_ID_HERE
```

## ملفاتك الثابتة الأخرى
انسخ ملفاتك الأصلية إلى `public/` إذا لم تكن موجودة، مثل:
- `camp.png`
- `sniper.png`
- `fighter.png`
- `cavalry.png`
- `manifest.json`
- `sw.js`

## ملاحظات أمان مهمة
- لا تضع مفتاح Gemini داخل `index.html` أو JavaScript في المتصفح.
- اجعل `ADMIN_PASSWORD` قويًا وطويلًا.
- لو كنت تستخدم HTTPS وخادمًا حقيقيًا، غيّر:
```env
COOKIE_SECURE=1
```
- لو كان الخادم خلف reverse proxy مثل Nginx أو Cloudflare، فعّل:
```env
TRUST_PROXY=1
```

## قاعدة البيانات
سيتم إنشاء ملف البيانات تلقائيًا هنا:
```text
./data/vip-db.json
```

يحفظ هذا الملف:
- Hash الأكواد
- الجلسات النشطة
- ربط الكود بالأجهزة
- جلسات لوحة الإدارة

## بنية المشروع
```text
public/
  index.html
  admin.html
lib/
  vip-store.js
scripts/
  vip-codes.js
server.js
package.json
.env.example
README.md
```
