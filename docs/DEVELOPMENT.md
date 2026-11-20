# راهنمای توسعه Developersia AI

## پیش‌نیازها

- Node.js نسخه 22 یا جدیدتر
- npm نسخه 10 یا جدیدتر
- PostgreSQL نسخه 16
- PHP 8.1+ و WordPress 6.5+ برای تست افزونه
- دامنه و HTTPS برای محیط عمومی

## راه‌اندازی محلی

1. مخزن را clone کنید و وارد پوشه پروژه شوید.
2. فایل نمونه را کپی کنید:

   ```bash
   cp .env.example .env
   ```

3. مقادیر محرمانه را تولید و در فایل `.env` قرار دهید:

   ```bash
   openssl rand -base64 48
   openssl rand -hex 32
   ```

   خروجی اول برای `JWT_SECRET` و خروجی دوم برای `ENCRYPTION_KEY` است. کلید رمزنگاری باید دقیقاً ۶۴ نویسه هگزادسیمال باشد.

4. PostgreSQL را اجرا کنید و `DATABASE_URL` را تنظیم کنید.
5. وابستگی‌ها و دیتابیس را آماده کنید:

   ```bash
   npm install
   npx prisma generate
   npm run db:migrate
   npm run db:seed
   ```

6. سرور را اجرا کنید:

   ```bash
   npm run dev
   ```

سلامت سرویس از مسیر `/health` قابل بررسی است.

## ساخت حساب مدیر اولیه

در `.env` مقدارهای `ADMIN_EMAIL` و `ADMIN_PASSWORD` را تعیین کنید. رمز عبور باید حداقل ۱۴ کاراکتر باشد. سپس `npm run db:seed` را اجرا کنید. Seed در صورت وجود ایمیل، رمز عبور را به‌روزرسانی و نقش حساب را مدیر می‌کند.

## ساخت کد اتصال وردپرس

پس از ساخت حساب مدیر:

```bash
npm run pair:code -- --email admin@example.com --ttl-minutes 15
```

کد فقط یک بار نمایش داده می‌شود و حداکثر ۶۰ دقیقه اعتبار دارد. آن را در تنظیمات افزونه WordPress وارد کنید.

## نصب افزونه وردپرس

فایل اصلی افزونه در مسیر زیر است:

`plugins/developersia-ai/developersia-ai.php`

برای ساخت ZIP نصب وردپرس:

```bash
cd plugins
zip -r developersia-ai-connector-0.1.0.zip developersia-ai
```

در پیشخوان وردپرس به افزونه‌ها ← افزودن افزونه ← بارگذاری افزونه بروید و فایل ZIP را نصب و فعال کنید. سپس از تنظیمات ← Developersia AI، آدرس API و کد اتصال را وارد کنید.

## دستورات بررسی

```bash
npm run typecheck
npm test
npm run build
php -l plugins/developersia-ai/developersia-ai.php
```

## نکته مهم

برای محیط تولید از HTTPS، PostgreSQL مدیریت‌شده، پشتیبان‌گیری منظم، محدودسازی دسترسی شبکه و مدیریت امن secretها استفاده کنید. فایل `.env` نباید وارد Git شود.
