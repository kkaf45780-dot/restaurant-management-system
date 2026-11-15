import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
import express, { type NextFunction, type Request, type Response } from 'express';
import { createServer as createViteServer } from 'vite';
import { DEFAULT_RESTAURANT_ID } from './src/data/restaurant.ts';
import { evaluateRestaurantHours } from './src/lib/hours.ts';
import {
  ROLE_PERMISSIONS,
  hasPermission,
  type AdminTabPermission,
} from './src/lib/permissions.ts';
import { calculateOrderTotals } from './src/lib/pricing.ts';
import { buildWhatsAppOrderUrl } from './src/lib/whatsapp.ts';
import { runReceptionistChat } from './src/server/geminiReceptionist.ts';
import {
  UPLOADS_DIR,
  adjustItemStock,
  appendActivityLog,
  createOrder,
  deleteBranch,
  deleteCategory,
  deleteCoupon,
  deleteDeliveryZone,
  deleteEmployee,
  deleteMenuItem,
  findEmployeeByEmail,
  findOrderByIdempotencyKey,
  findOrderByNumberOrId,
  findOrdersByPhone,
  getLocalAdminPassword,
  getRestaurantBundle,
  incrementCouponUsage,
  isSupabaseBackendActive,
  listActivityLogs,
  listAiLogs,
  listCoupons,
  listEmployees,
  listInventoryMovements,
  listNotifications,
  listOrders,
  markNotificationsRead,
  rateOrder,
  reorderMenuItems,
  setLocalAdminPassword,
  updateOrderStatus,
  updateRestaurant,
  uploadImageAsset,
  upsertBranch,
  upsertCategory,
  upsertCoupon,
  upsertDeliveryZone,
  upsertEmployee,
  upsertMenuItem,
} from './src/server/store.ts';
import type {
  Coupon,
  DeliveryZone,
  Employee,
  EmployeeRole,
  FulfillmentType,
  MenuCategory,
  MenuItem,
  Order,
  OrderDraftItem,
  OrderStatus,
  RestaurantBranch,
  ServiceConfigStatus,
} from './src/types/restaurant.ts';

dotenv.config();

const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET =
  process.env.ADMIN_SESSION_SECRET || 'meshweyat-elhara-local-session-secret-2026';

// Production deployments must not use the public demo credentials or a predictable session key.
if (process.env.NODE_ENV === 'production') {
  const missingSecurityVars = ['ADMIN_PASSWORD', 'ADMIN_SESSION_SECRET'].filter(
    (name) => !process.env[name]?.trim()
  );
  if (missingSecurityVars.length > 0) {
    throw new Error(
      `Missing required production environment variables: ${missingSecurityVars.join(', ')}`
    );
  }
  if (process.env.ADMIN_PASSWORD === 'Admin@1234') {
    throw new Error('Set a unique ADMIN_PASSWORD before deploying this public application.');
  }
  if (process.env.ADMIN_SESSION_SECRET === 'meshweyat-elhara-local-session-secret-2026') {
    throw new Error('Set a unique ADMIN_SESSION_SECRET before deploying this public application.');
  }
}

// In-memory sliding-window rate limiter for AI chat
const chatRateMap = new Map<string, number[]>();
function checkChatRateLimit(ip: string): boolean {
  const now = Date.now();
  const windowMs = 60_000;
  const maxRequests = 25;
  const recent = (chatRateMap.get(ip) ?? []).filter((ts) => now - ts < windowMs);
  if (recent.length >= maxRequests) return false;
  recent.push(now);
  chatRateMap.set(ip, recent);
  return true;
}

interface AdminRequest extends Request {
  adminEmail?: string;
  adminRole?: EmployeeRole;
}

const VALID_ROLES: EmployeeRole[] = ['owner', 'manager', 'cashier', 'kitchen'];

function signLocalAdminToken(email: string, role: EmployeeRole = 'owner'): string {
  const payload = Buffer.from(
    JSON.stringify({ email, role, exp: Date.now() + 1000 * 60 * 60 * 24 * 7 })
  ).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `local.${payload}.${sig}`;
}

function verifyLocalAdminToken(token: string): { email: string; role: EmployeeRole } | null {
  if (!token.startsWith('local.')) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [, payload, sig] = parts;
  const expectedSig = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(payload)
    .digest('base64url');
  if (sig !== expectedSig) return null;
  try {
    const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf-8')) as {
      email: string;
      role?: EmployeeRole;
      exp: number;
    };
    if (decoded.exp < Date.now()) return null;
    const role: EmployeeRole =
      decoded.role && VALID_ROLES.includes(decoded.role) ? decoded.role : 'owner';
    return { email: decoded.email, role };
  } catch {
    return null;
  }
}

async function resolveRoleForEmail(email: string): Promise<EmployeeRole> {
  const expectedOwner = (process.env.ADMIN_EMAIL || 'admin@hara-grill.eg').toLowerCase();
  if (email.trim().toLowerCase() === expectedOwner) return 'owner';
  const emp = await findEmployeeByEmail(DEFAULT_RESTAURANT_ID, email);
  return emp?.role ?? 'owner';
}

async function verifyAdminRequest(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';

  if (!token) {
    res.status(401).json({ error: 'غير مصرح لك بالوصول. يُرجى تسجيل الدخول كمدير أولاً.' });
    return;
  }

  const supabaseUrl = process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL;
  const supabaseKey =
    process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.VITE_SUPABASE_ANON_KEY;

  if (supabaseUrl && supabaseKey && !token.startsWith('local.')) {
    try {
      const sb = createClient(supabaseUrl, supabaseKey);
      const { data, error } = await sb.auth.getUser(token);
      if (!error && data.user) {
        const userEmail = data.user.email ?? 'admin';
        (req as AdminRequest).adminEmail = userEmail;
        (req as AdminRequest).adminRole = await resolveRoleForEmail(userEmail);
        next();
        return;
      }
    } catch {
      // Fall through
    }
  }

  const localAdmin = verifyLocalAdminToken(token);
  if (localAdmin) {
    (req as AdminRequest).adminEmail = localAdmin.email;
    (req as AdminRequest).adminRole = localAdmin.role;
    next();
    return;
  }

  res.status(401).json({ error: 'انتهت جلسة المدير أو بيانات الدخول غير صالحة.' });
}

function requirePermission(...allowed: AdminTabPermission[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const role: EmployeeRole = (req as AdminRequest).adminRole || 'owner';
    if (allowed.some((perm) => hasPermission(role, perm))) {
      next();
      return;
    }
    res.status(403).json({
      error: 'ليس لديك صلاحية تنفيذ هذا الإجراء بدورك الوظيفي الحالي.',
    });
  };
}

function getServiceConfigStatus(): ServiceConfigStatus {
  const geminiConfigured = Boolean(
    process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'MY_GEMINI_API_KEY'
  );
  const supabaseUrl = process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL;
  const supabaseAnon = process.env.VITE_SUPABASE_ANON_KEY;
  const supabaseConfigured = Boolean(supabaseUrl && supabaseAnon);

  return {
    geminiConfigured,
    supabaseConfigured,
    storageMode: isSupabaseBackendActive() ? 'supabase' : 'local',
    authMode: supabaseConfigured ? 'supabase' : 'local',
    demoAdminEmail: process.env.ADMIN_EMAIL || 'admin@hara-grill.eg',
  };
}

async function startServer(): Promise<void> {
  const app = express();
  app.use(express.json({ limit: '10mb' }));

  if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
  }
  app.use('/uploads', express.static(UPLOADS_DIR));

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, service: 'moazzaf-almatam' });
  });

  app.get('/api/config/status', (_req, res) => {
    res.json(getServiceConfigStatus());
  });

  // Public Restaurant Bundle + Computed Hours
  app.get('/api/restaurant/:slug?', async (req, res) => {
    try {
      const slugOrId = req.params.slug || DEFAULT_RESTAURANT_ID;
      const bundle = await getRestaurantBundle(slugOrId);
      const hoursStatus = evaluateRestaurantHours(bundle.restaurant);
      res.json({ bundle, hoursStatus });
    } catch (err) {
      console.error('Error loading restaurant:', err);
      res.status(500).json({ error: 'تعذر تحميل بيانات المطعم حالياً، يُرجى المحاولة لاحقاً.' });
    }
  });

  // Public Coupon Validation
  app.post('/api/coupons/validate', async (req, res) => {
    try {
      const {
        restaurantId = DEFAULT_RESTAURANT_ID,
        code,
        items = [],
        deliveryZoneId = '',
        fulfillmentType = 'delivery',
      } = req.body ?? {};
      const bundle = await getRestaurantBundle(restaurantId);
      const calc = calculateOrderTotals(
        items as OrderDraftItem[],
        bundle.items,
        deliveryZoneId,
        bundle.deliveryZones,
        {
          fulfillmentType: fulfillmentType as FulfillmentType,
          couponCode: code,
          coupons: bundle.activeCoupons,
        }
      );
      if (!calc.appliedCoupon) {
        res.status(400).json({
          valid: false,
          error: calc.couponError || 'كود الخصم غير صالح.',
        });
        return;
      }
      res.json({
        valid: true,
        coupon: calc.appliedCoupon,
        discountAmount: calc.discountAmount,
        totals: calc,
      });
    } catch {
      res.status(500).json({ error: 'تعذر التحقق من كود الخصم حالياً.' });
    }
  });

  // Public Order Tracking & Customer History Lookup
  app.get('/api/orders/track', async (req, res) => {
    try {
      const restaurantId = String(req.query.restaurantId || DEFAULT_RESTAURANT_ID);
      const orderNumber = String(req.query.orderNumber || '').trim();
      const phone = String(req.query.phone || '').trim();

      if (orderNumber) {
        const order = await findOrderByNumberOrId(restaurantId, orderNumber);
        if (!order) {
          res.status(404).json({ error: 'لم يتم العثور على طلب بهذا الرقم.' });
          return;
        }
        res.json({ order });
        return;
      }

      if (phone) {
        const orders = await findOrdersByPhone(restaurantId, phone);
        res.json({ orders });
        return;
      }

      res.status(400).json({ error: 'يُرجى إدخال رقم الطلب أو رقم الهاتف.' });
    } catch {
      res.status(500).json({ error: 'تعذر البحث عن الطلب حالياً.' });
    }
  });

  // Public Order Rating (available after delivery)
  app.post('/api/orders/:orderNumber/rate', async (req, res) => {
    try {
      const { restaurantId = DEFAULT_RESTAURANT_ID, rating, comment = '' } = req.body ?? {};
      const numRating = Math.trunc(Number(rating));
      if (!Number.isFinite(numRating) || numRating < 1 || numRating > 5) {
        res.status(400).json({ error: 'يُرجى اختيار تقييم من 1 إلى 5 نجوم.' });
        return;
      }
      const updated = await rateOrder(
        String(restaurantId),
        req.params.orderNumber,
        numRating,
        String(comment || '')
      );
      if (!updated) {
        res.status(404).json({ error: 'لم يتم العثور على الطلب.' });
        return;
      }
      res.json({ order: updated });
    } catch (err) {
      res.status(400).json({
        error: err instanceof Error ? err.message : 'تعذر تسجيل التقييم حالياً.',
      });
    }
  });

  // Public AI Receptionist Chat with Rate Limiting
  app.post('/api/chat', async (req, res) => {
    try {
      const clientIp = req.ip || req.socket.remoteAddress || 'unknown';
      if (!checkChatRateLimit(clientIp)) {
        res.status(429).json({
          error: 'تم إرسال رسائل كثيرة في وقت قصير. يُرجى الانتظار دقيقة ثم المحاولة مرة أخرى.',
        });
        return;
      }

      const {
        restaurantId = DEFAULT_RESTAURANT_ID,
        message,
        history = [],
        orderDraft = {
          items: [],
          fulfillmentType: 'delivery',
          deliveryZoneId: '',
          customerName: '',
          customerPhone: '',
          customerAddress: '',
          notes: '',
        },
      } = req.body ?? {};

      if (!message || typeof message !== 'string' || !message.trim()) {
        res.status(400).json({ error: 'يُرجى كتابة رسالة قبل الإرسال.' });
        return;
      }

      const bundle = await getRestaurantBundle(restaurantId);
      const result = await runReceptionistChat({
        bundle,
        userMessage: message.trim(),
        history: Array.isArray(history) ? history : [],
        currentDraft: {
          fulfillmentType: 'delivery',
          ...orderDraft,
        },
      });

      res.json(result);
    } catch (err) {
      console.error('Chat endpoint error:', err);
      res.status(500).json({
        error: 'حدث خطأ أثناء معالجة الرسالة، يمكنك التواصل معنا مباشرة عبر واتساب.',
      });
    }
  });

  // Public Order Creation (Always computes prices and totals programmatically in TypeScript)
  app.post('/api/orders', async (req, res) => {
    try {
      const {
        restaurantId = DEFAULT_RESTAURANT_ID,
        items = [],
        fulfillmentType = 'delivery',
        deliveryZoneId = '',
        branchId = '',
        couponCode = '',
        customerName,
        customerPhone,
        customerAddress = '',
        notes = '',
        idempotencyKey = '',
      } = req.body ?? {};

      const bundle = await getRestaurantBundle(restaurantId);

      // Duplicate order submission guard
      if (idempotencyKey && typeof idempotencyKey === 'string') {
        const existing = await findOrderByIdempotencyKey(bundle.restaurant.id, idempotencyKey);
        if (existing) {
          const whatsappUrl = buildWhatsAppOrderUrl(
            bundle.restaurant.whatsappNumber,
            existing,
            bundle.restaurant.name,
            bundle.restaurant.systemSettings.currencyLabel
          );
          res.status(200).json({ order: existing, whatsappUrl, deduplicated: true });
          return;
        }
      }

      const hoursStatus = evaluateRestaurantHours(bundle.restaurant);
      if (!hoursStatus.isOpen && !bundle.restaurant.systemSettings.allowOrdersWhenClosed) {
        res.status(400).json({
          error: `عذراً، المطعم مغلق حالياً. ${hoursStatus.nextOpenText ? `نفتح ${hoursStatus.nextOpenText}.` : ''}`,
        });
        return;
      }

      if (!Array.isArray(items) || items.length === 0) {
        res.status(400).json({ error: 'سلة الطلبات فارغة. أضف صنفاً واحداً على الأقل.' });
        return;
      }

      if (!customerName || !String(customerName).trim()) {
        res.status(400).json({ error: 'يُرجى إدخال اسم العميل.' });
        return;
      }

      const cleanPhone = String(customerPhone || '').trim();
      if (!cleanPhone || cleanPhone.replace(/[^\d]/g, '').length < 8) {
        res.status(400).json({ error: 'يُرجى إدخال رقم هاتف صحيح للتواصل.' });
        return;
      }

      const cleanFulfillment: FulfillmentType =
        fulfillmentType === 'pickup' ? 'pickup' : 'delivery';

      if (cleanFulfillment === 'delivery' && (!customerAddress || !String(customerAddress).trim())) {
        res.status(400).json({ error: 'يُرجى إدخال العنوان بالتفصيل.' });
        return;
      }

      const calc = calculateOrderTotals(
        items as OrderDraftItem[],
        bundle.items,
        deliveryZoneId,
        bundle.deliveryZones,
        {
          fulfillmentType: cleanFulfillment,
          couponCode: String(couponCode || ''),
          coupons: bundle.activeCoupons,
        }
      );

      if (calc.unavailableItemNames.length > 0) {
        res.status(400).json({
          error: `بعض الأصناف لم تعد متوفرة حالياً: ${calc.unavailableItemNames.join('، ')}`,
        });
        return;
      }

      if (calc.outOfStockItemNames.length > 0) {
        res.status(400).json({
          error: `الكمية المطلوبة غير متوفرة في المخزون لـ: ${calc.outOfStockItemNames.join('، ')}`,
        });
        return;
      }

      if (calc.validItems.length === 0) {
        res.status(400).json({ error: 'لم يتم العثور على أصناف صالحة في الطلب.' });
        return;
      }

      if (cleanFulfillment === 'delivery' && !calc.deliveryZone) {
        res.status(400).json({
          error: 'منطقة التوصيل المختارة غير متاحة حالياً. يُرجى اختيار منطقة متاحة.',
        });
        return;
      }

      if (cleanFulfillment === 'delivery' && calc.belowZoneMinimum && calc.deliveryZone) {
        res.status(400).json({
          error: `الحد الأدنى للطلب في منطقة ${calc.deliveryZone.name} هو ${calc.deliveryZone.minOrderAmount} ${bundle.restaurant.systemSettings.currencyLabel}.`,
        });
        return;
      }

      const matchedBranch =
        bundle.branches.find((b) => b.id === branchId && b.isOpen) ??
        bundle.branches.find((b) => b.isOpen) ??
        bundle.branches[0];

      const nowIso = new Date().toISOString();
      const orderNumber = String(Math.floor(10000 + Math.random() * 89999));
      const newOrder: Order = {
        id: `ord_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
        orderNumber,
        restaurantId: bundle.restaurant.id,
        customerName: String(customerName).trim(),
        customerPhone: cleanPhone,
        fulfillmentType: cleanFulfillment,
        deliveryZoneId: calc.deliveryZone?.id ?? '',
        deliveryZoneName:
          cleanFulfillment === 'pickup' ? 'استلام من الفرع' : calc.deliveryZone?.name ?? '',
        branchId: matchedBranch?.id,
        branchName: matchedBranch?.name ?? bundle.restaurant.name,
        customerAddress:
          cleanFulfillment === 'pickup'
            ? `استلام من: ${matchedBranch?.address ?? bundle.restaurant.address}`
            : String(customerAddress).trim(),
        notes: String(notes || '').trim(),
        items: calc.validItems,
        subtotal: calc.subtotal,
        discountAmount: calc.discountAmount,
        couponCode: calc.appliedCoupon?.code,
        deliveryFee: calc.deliveryFee,
        total: calc.total,
        paymentMethod: 'cash_on_delivery',
        paymentStatus: 'pending',
        estimatedDeliveryText:
          cleanFulfillment === 'pickup'
            ? '٢٠ - ٣٠ دقيقة للاستلام'
            : calc.deliveryZone?.estimatedMinutes ?? '٣٠ - ٤٥ دقيقة',
        stockDeducted: false,
        idempotencyKey: idempotencyKey ? String(idempotencyKey) : undefined,
        status: 'received',
        statusHistory: [{ status: 'received', timestamp: nowIso }],
        createdAt: nowIso,
        updatedAt: nowIso,
      };

      const savedOrder = await createOrder(newOrder);
      if (calc.appliedCoupon) {
        await incrementCouponUsage(bundle.restaurant.id, calc.appliedCoupon.code);
      }

      const whatsappUrl = buildWhatsAppOrderUrl(
        bundle.restaurant.whatsappNumber,
        savedOrder,
        bundle.restaurant.name,
        bundle.restaurant.systemSettings.currencyLabel
      );

      res.status(201).json({ order: savedOrder, whatsappUrl: whatsappUrl || '' });
    } catch (err) {
      console.error('Create order error:', err);
      res.status(500).json({ error: 'حدث خطأ غير متوقع أثناء تسجيل الطلب. حاول مرة أخرى.' });
    }
  });

  // =========================================================
  // Admin Auth & Protected Endpoints (/api/admin/*)
  // =========================================================

  app.post('/api/admin/login', async (req, res) => {
    try {
      const { email, password } = req.body ?? {};
      const cleanEmail = String(email || '').trim().toLowerCase();
      const cleanPass = String(password || '');
      const expectedEmail = (process.env.ADMIN_EMAIL || 'admin@hara-grill.eg').toLowerCase();
      const expectedPassword = getLocalAdminPassword();

      if (cleanEmail === expectedEmail && cleanPass === expectedPassword) {
        const role: EmployeeRole = 'owner';
        const token = signLocalAdminToken(expectedEmail, role);
        res.json({ token, email: expectedEmail, role, permissions: ROLE_PERMISSIONS[role] });
        return;
      }

      const employee = await findEmployeeByEmail(DEFAULT_RESTAURANT_ID, cleanEmail);
      if (employee && cleanPass === expectedPassword) {
        const token = signLocalAdminToken(employee.email, employee.role);
        res.json({
          token,
          email: employee.email,
          role: employee.role,
          permissions: ROLE_PERMISSIONS[employee.role],
        });
        return;
      }

      res.status(401).json({ error: 'البريد الإلكتروني أو كلمة المرور غير صحيحة.' });
    } catch {
      res.status(500).json({ error: 'تعذر التحقق من بيانات الدخول حالياً.' });
    }
  });

  app.get('/api/admin/me', verifyAdminRequest, (req, res) => {
    const adminReq = req as AdminRequest;
    const role: EmployeeRole = adminReq.adminRole || 'owner';
    res.json({
      authenticated: true,
      email: adminReq.adminEmail,
      role,
      permissions: ROLE_PERMISSIONS[role],
    });
  });

  app.get('/api/admin/overview', verifyAdminRequest, async (req, res) => {
    try {
      const restaurantId = String(req.query.restaurantId || DEFAULT_RESTAURANT_ID);
      const [
        bundle,
        orders,
        aiLogs,
        coupons,
        inventoryMovements,
        employees,
        activityLogs,
        notifications,
      ] = await Promise.all([
        getRestaurantBundle(restaurantId),
        listOrders(restaurantId),
        listAiLogs(restaurantId),
        listCoupons(restaurantId),
        listInventoryMovements(restaurantId),
        listEmployees(restaurantId),
        listActivityLogs(restaurantId),
        listNotifications(restaurantId),
      ]);
      const hoursStatus = evaluateRestaurantHours(bundle.restaurant);
      res.json({
        bundle,
        hoursStatus,
        orders,
        aiLogs,
        coupons,
        inventoryMovements,
        employees,
        activityLogs,
        notifications,
        configStatus: getServiceConfigStatus(),
      });
    } catch (err) {
      console.error('Admin overview error:', err);
      res.status(500).json({ error: 'تعذر تحميل بيانات لوحة التحكم.' });
    }
  });

  app.put(
    '/api/admin/restaurant',
    verifyAdminRequest,
    requirePermission('settings', 'ai', 'system'),
    async (req, res) => {
      try {
        const { restaurantId = DEFAULT_RESTAURANT_ID, ...patch } = req.body ?? {};
        const updated = await updateRestaurant(restaurantId, patch);
        const hoursStatus = evaluateRestaurantHours(updated);
        await appendActivityLog({
          id: `act_${Date.now()}`,
          restaurantId,
          actorName: (req as AdminRequest).adminEmail || 'المدير',
          action: 'تحديث إعدادات المطعم',
          details: 'تم تعديل معلومات المطعم أو المواعيد أو إعدادات المساعد الذكي.',
          createdAt: new Date().toISOString(),
        });
        res.json({ restaurant: updated, hoursStatus });
      } catch (err) {
        console.error('Update restaurant error:', err);
        res.status(500).json({ error: 'تعذر حفظ بيانات المطعم.' });
      }
    }
  );

  app.post(
    '/api/admin/categories',
    verifyAdminRequest,
    requirePermission('menu'),
    async (req, res) => {
      try {
        const body = req.body ?? {};
        const cat: MenuCategory = {
          id: body.id || `cat_${Date.now()}`,
          restaurantId: body.restaurantId || DEFAULT_RESTAURANT_ID,
          name: String(body.name || '').trim(),
          description: String(body.description || '').trim(),
          sortOrder: Number(body.sortOrder ?? 99),
        };
        if (!cat.name) {
          res.status(400).json({ error: 'اسم القسم مطلوب.' });
          return;
        }
        const saved = await upsertCategory(cat);
        res.json({ category: saved });
      } catch {
        res.status(500).json({ error: 'تعذر حفظ القسم.' });
      }
    }
  );

  app.delete(
    '/api/admin/categories/:id',
    verifyAdminRequest,
    requirePermission('menu'),
    async (req, res) => {
      try {
        const restaurantId = String(req.query.restaurantId || DEFAULT_RESTAURANT_ID);
        await deleteCategory(restaurantId, req.params.id);
        res.json({ ok: true });
      } catch {
        res.status(500).json({ error: 'تعذر حذف القسم.' });
      }
    }
  );

  app.post(
    '/api/admin/items',
    verifyAdminRequest,
    requirePermission('menu'),
    async (req, res) => {
      try {
        const body = req.body ?? {};
        const price = Number(body.price);
        if (!String(body.name || '').trim() || !Number.isFinite(price) || price < 0) {
          res.status(400).json({ error: 'يُرجى إدخال اسم الصنف وسعر صحيح.' });
          return;
        }
        const item: MenuItem = {
          id: body.id || `item_${Date.now()}_${Math.random().toString(36).slice(2, 5)}`,
          restaurantId: body.restaurantId || DEFAULT_RESTAURANT_ID,
          categoryId: String(body.categoryId),
          name: String(body.name).trim(),
          description: String(body.description || '').trim(),
          price,
          imageUrl: String(body.imageUrl || ''),
          isAvailable: body.isAvailable !== false,
          isPopular: Boolean(body.isPopular),
          stockQuantity: Math.max(0, Math.floor(Number(body.stockQuantity ?? 40))),
          lowStockThreshold: Math.max(1, Math.floor(Number(body.lowStockThreshold ?? 8))),
          sizes: Array.isArray(body.sizes) ? body.sizes : [],
          extras: Array.isArray(body.extras) ? body.extras : [],
          sortOrder: Number(body.sortOrder ?? 99),
        };
        const saved = await upsertMenuItem(item);
        res.json({ item: saved });
      } catch {
        res.status(500).json({ error: 'تعذر حفظ الصنف.' });
      }
    }
  );

  app.post(
    '/api/admin/items/reorder',
    verifyAdminRequest,
    requirePermission('menu'),
    async (req, res) => {
      try {
        const { restaurantId = DEFAULT_RESTAURANT_ID, orderedIds = [] } = req.body ?? {};
        if (!Array.isArray(orderedIds)) {
          res.status(400).json({ error: 'بيانات الترتيب غير صالحة.' });
          return;
        }
        await reorderMenuItems(restaurantId, orderedIds);
        res.json({ ok: true });
      } catch {
        res.status(500).json({ error: 'تعذر حفظ ترتيب الأصناف.' });
      }
    }
  );

  app.delete(
    '/api/admin/items/:id',
    verifyAdminRequest,
    requirePermission('menu'),
    async (req, res) => {
      try {
        const restaurantId = String(req.query.restaurantId || DEFAULT_RESTAURANT_ID);
        await deleteMenuItem(restaurantId, req.params.id);
        res.json({ ok: true });
      } catch {
        res.status(500).json({ error: 'تعذر حذف الصنف.' });
      }
    }
  );

  app.post(
    '/api/admin/inventory/adjust',
    verifyAdminRequest,
    requirePermission('inventory'),
    async (req, res) => {
    try {
      const {
        restaurantId = DEFAULT_RESTAURANT_ID,
        itemId,
        delta,
        reason = 'تعديل مخزون يدوي',
      } = req.body ?? {};
      const numDelta = Math.trunc(Number(delta));
      if (!itemId || !Number.isFinite(numDelta) || numDelta === 0) {
        res.status(400).json({ error: 'يُرجى تحديد الصنف وكمية التعديل.' });
        return;
      }
      const updated = await adjustItemStock({
        restaurantId,
        itemId: String(itemId),
        delta: numDelta,
        reason: String(reason).trim() || 'تعديل مخزون يدوي',
      });
      if (!updated) {
        res.status(404).json({ error: 'الصنف غير موجود.' });
        return;
      }
      res.json({ item: updated });
    } catch {
      res.status(500).json({ error: 'تعذر تعديل المخزون.' });
    }
  });

  app.post(
    '/api/admin/delivery-zones',
    verifyAdminRequest,
    requirePermission('delivery'),
    async (req, res) => {
      try {
        const body = req.body ?? {};
        const fee = Number(body.fee);
        const minOrderAmount = Math.max(0, Number(body.minOrderAmount ?? 0));
        if (!String(body.name || '').trim() || !Number.isFinite(fee) || fee < 0) {
          res.status(400).json({ error: 'يُرجى إدخال اسم المنطقة ورسوم توصيل صحيحة.' });
          return;
        }
        const zone: DeliveryZone = {
          id: body.id || `zone_${Date.now()}`,
          restaurantId: body.restaurantId || DEFAULT_RESTAURANT_ID,
          name: String(body.name).trim(),
          fee,
          minOrderAmount,
          estimatedMinutes: String(body.estimatedMinutes || '٣٠ - ٤٥ دقيقة').trim(),
          isActive: body.isActive !== false,
        };
        const saved = await upsertDeliveryZone(zone);
        res.json({ zone: saved });
      } catch {
        res.status(500).json({ error: 'تعذر حفظ منطقة التوصيل.' });
      }
    }
  );

  app.delete(
    '/api/admin/delivery-zones/:id',
    verifyAdminRequest,
    requirePermission('delivery'),
    async (req, res) => {
      try {
        const restaurantId = String(req.query.restaurantId || DEFAULT_RESTAURANT_ID);
        await deleteDeliveryZone(restaurantId, req.params.id);
        res.json({ ok: true });
      } catch {
        res.status(500).json({ error: 'تعذر حذف منطقة التوصيل.' });
      }
    }
  );

  app.post(
    '/api/admin/branches',
    verifyAdminRequest,
    requirePermission('delivery'),
    async (req, res) => {
      try {
        const body = req.body ?? {};
        if (!String(body.name || '').trim()) {
          res.status(400).json({ error: 'يُرجى إدخال اسم الفرع.' });
          return;
        }
        const branch: RestaurantBranch = {
          id: body.id || `br_${Date.now()}`,
          restaurantId: body.restaurantId || DEFAULT_RESTAURANT_ID,
          name: String(body.name).trim(),
          address: String(body.address || '').trim(),
          phone: String(body.phone || '').trim(),
          hoursText: String(body.hoursText || '١٢:٠٠ م - ١٢:٠٠ ص').trim(),
          isOpen: body.isOpen !== false,
        };
        const saved = await upsertBranch(branch);
        res.json({ branch: saved });
      } catch {
        res.status(500).json({ error: 'تعذر حفظ بيانات الفرع.' });
      }
    }
  );

  app.delete(
    '/api/admin/branches/:id',
    verifyAdminRequest,
    requirePermission('delivery'),
    async (req, res) => {
      try {
        const restaurantId = String(req.query.restaurantId || DEFAULT_RESTAURANT_ID);
        await deleteBranch(restaurantId, req.params.id);
        res.json({ ok: true });
      } catch {
        res.status(500).json({ error: 'تعذر حذف الفرع.' });
      }
    }
  );

  app.post(
    '/api/admin/coupons',
    verifyAdminRequest,
    requirePermission('coupons'),
    async (req, res) => {
      try {
        const body = req.body ?? {};
        const val = Number(body.discountValue);
        if (!String(body.code || '').trim() || !Number.isFinite(val) || val <= 0) {
          res.status(400).json({ error: 'يُرجى إدخال كود الخصم وقيمة خصم صحيحة.' });
          return;
        }
        const coupon: Coupon = {
          id: body.id || `cpn_${Date.now()}`,
          restaurantId: body.restaurantId || DEFAULT_RESTAURANT_ID,
          code: String(body.code).trim().toUpperCase(),
          description: String(body.description || '').trim(),
          discountType: body.discountType === 'fixed' ? 'fixed' : 'percentage',
          discountValue: val,
          minOrderAmount: Math.max(0, Number(body.minOrderAmount ?? 0)),
          maxDiscountAmount: body.maxDiscountAmount ? Number(body.maxDiscountAmount) : undefined,
          validFrom: String(body.validFrom || '2026-01-01'),
          validUntil: String(body.validUntil || '2027-12-31'),
          usageLimit: Math.max(0, Math.floor(Number(body.usageLimit ?? 100))),
          usedCount: Math.max(0, Math.floor(Number(body.usedCount ?? 0))),
          isActive: body.isActive !== false,
          applicableCategoryIds: Array.isArray(body.applicableCategoryIds)
            ? body.applicableCategoryIds
            : [],
          applicableItemIds: Array.isArray(body.applicableItemIds) ? body.applicableItemIds : [],
        };
        const saved = await upsertCoupon(coupon);
        res.json({ coupon: saved });
      } catch {
        res.status(500).json({ error: 'تعذر حفظ كوبون الخصم.' });
      }
    }
  );

  app.delete(
    '/api/admin/coupons/:id',
    verifyAdminRequest,
    requirePermission('coupons'),
    async (req, res) => {
      try {
        const restaurantId = String(req.query.restaurantId || DEFAULT_RESTAURANT_ID);
        await deleteCoupon(restaurantId, req.params.id);
        res.json({ ok: true });
      } catch {
        res.status(500).json({ error: 'تعذر حذف الكوبون.' });
      }
    }
  );

  app.post(
    '/api/admin/employees',
    verifyAdminRequest,
    requirePermission('employees'),
    async (req, res) => {
      try {
        const body = req.body ?? {};
        if (!String(body.name || '').trim() || !String(body.email || '').trim()) {
          res.status(400).json({ error: 'اسم الموظف والبريد الإلكتروني مطلوبان.' });
          return;
        }
        const employee: Employee = {
          id: body.id || `emp_${Date.now()}`,
          restaurantId: body.restaurantId || DEFAULT_RESTAURANT_ID,
          name: String(body.name).trim(),
          email: String(body.email).trim(),
          phone: String(body.phone || '').trim(),
          role: ['owner', 'manager', 'cashier', 'kitchen'].includes(body.role)
            ? body.role
            : 'cashier',
          isActive: body.isActive !== false,
          createdAt: body.createdAt || new Date().toISOString(),
        };
        const saved = await upsertEmployee(employee);
        res.json({ employee: saved });
      } catch {
        res.status(500).json({ error: 'تعذر حفظ بيانات الموظف.' });
      }
    }
  );

  app.delete(
    '/api/admin/employees/:id',
    verifyAdminRequest,
    requirePermission('employees'),
    async (req, res) => {
      try {
        const restaurantId = String(req.query.restaurantId || DEFAULT_RESTAURANT_ID);
        await deleteEmployee(restaurantId, req.params.id);
        res.json({ ok: true });
      } catch {
        res.status(500).json({ error: 'تعذر حذف الموظف.' });
      }
    }
  );

  app.post('/api/admin/notifications/read', verifyAdminRequest, async (req, res) => {
    try {
      const restaurantId = String(req.body?.restaurantId || DEFAULT_RESTAURANT_ID);
      await markNotificationsRead(restaurantId);
      res.json({ ok: true });
    } catch {
      res.status(500).json({ error: 'تعذر تحديث الإشعارات.' });
    }
  });

  app.patch(
    '/api/admin/orders/:id/status',
    verifyAdminRequest,
    requirePermission('orders'),
    async (req, res) => {
      try {
        const { restaurantId = DEFAULT_RESTAURANT_ID, status } = req.body ?? {};
        const validStatuses: OrderStatus[] = [
          'received',
          'under_review',
          'accepted',
          'preparing',
          'out_for_delivery',
          'delivered',
          'cancelled',
        ];
        if (!validStatuses.includes(status)) {
          res.status(400).json({ error: 'حالة الطلب غير صالحة.' });
          return;
        }
        const actor = (req as AdminRequest).adminEmail || 'المدير';
        const updated = await updateOrderStatus(restaurantId, req.params.id, status, actor);
        if (!updated) {
          res.status(404).json({ error: 'الطلب غير موجود.' });
          return;
        }
        res.json({ order: updated });
      } catch {
        res.status(500).json({ error: 'تعذر تحديث حالة الطلب.' });
      }
    }
  );

  app.get(
    '/api/admin/orders/export',
    verifyAdminRequest,
    requirePermission('orders', 'analytics'),
    async (req, res) => {
      try {
        const restaurantId = String(req.query.restaurantId || DEFAULT_RESTAURANT_ID);
        const orders = await listOrders(restaurantId);
        const header = [
          'رقم الطلب',
          'اسم العميل',
          'رقم الهاتف',
          'نوع الطلب',
          'المنطقة / الفرع',
          'العنوان',
          'المجموع الفرعي',
          'الخصم',
          'التوصيل',
          'الإجمالي',
          'الحالة',
          'التقييم',
          'تاريخ الإنشاء',
        ].join(',');
        const escapeCsv = (val: unknown) => `"${String(val ?? '').replace(/"/g, '""')}"`;
        const rows = orders.map((o) =>
          [
            escapeCsv(o.orderNumber),
            escapeCsv(o.customerName),
            escapeCsv(o.customerPhone),
            escapeCsv(o.fulfillmentType === 'pickup' ? 'استلام من الفرع' : 'توصيل'),
            escapeCsv(o.deliveryZoneName || o.branchName || ''),
            escapeCsv(o.customerAddress),
            o.subtotal,
            o.discountAmount,
            o.deliveryFee,
            o.total,
            escapeCsv(o.status),
            o.rating ? `${o.rating}/5` : '',
            escapeCsv(o.createdAt),
          ].join(',')
        );
        const csv = '\uFEFF' + [header, ...rows].join('\n');
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', 'attachment; filename="orders-report.csv"');
        res.send(csv);
      } catch {
        res.status(500).json({ error: 'تعذر تصدير تقرير الطلبات.' });
      }
    }
  );

  app.post(
    '/api/admin/password',
    verifyAdminRequest,
    requirePermission('system'),
    (req, res) => {
      const { currentPassword, newPassword } = req.body ?? {};
      if (String(currentPassword || '') !== getLocalAdminPassword()) {
        res.status(400).json({ error: 'كلمة المرور الحالية غير صحيحة.' });
        return;
      }
      if (!newPassword || String(newPassword).length < 6) {
        res.status(400).json({ error: 'كلمة المرور الجديدة يجب أن تكون 6 أحرف على الأقل.' });
        return;
      }
      setLocalAdminPassword(String(newPassword));
      res.json({ ok: true });
    }
  );

  app.post('/api/admin/upload', verifyAdminRequest, async (req, res) => {
    try {
      const { filename = 'image.jpg', mimeType = 'image/jpeg', dataBase64 } = req.body ?? {};
      if (!dataBase64 || typeof dataBase64 !== 'string') {
        res.status(400).json({ error: 'لم يتم إرسال ملف الصورة.' });
        return;
      }
      const cleanBase64 = dataBase64.replace(/^data:image\/[a-zA-Z0-9+.-]+;base64,/, '');
      const buffer = Buffer.from(cleanBase64, 'base64');
      if (buffer.length > 5 * 1024 * 1024) {
        res.status(400).json({ error: 'حجم الصورة كبير جداً (الحد الأقصى 5 ميجابايت).' });
        return;
      }
      const url = await uploadImageAsset(String(filename), String(mimeType), buffer);
      res.json({ url });
    } catch {
      res.status(500).json({ error: 'تعذر رفع الصورة حالياً.' });
    }
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
