import { guestHtml, adminHtml } from './pages.js';

const ZODIACS = new Set(['aries','taurus','gemini','cancer','leo','virgo','libra','scorpio','sagittarius','capricorn','aquarius','pisces']);
const encoder=new TextEncoder();
const h={
  'X-Content-Type-Options':'nosniff',
  'Referrer-Policy':'no-referrer',
  'X-Frame-Options':'DENY',
  'Permissions-Policy':'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy':"default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  'Strict-Transport-Security':'max-age=31536000; includeSubDomains'
};
function res(body,status=200,extra={}){return new Response(body,{status,headers:{...h,...extra}})}
function json(payload,status=200){return res(JSON.stringify(payload),status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'})}
function page(body){return res(body,200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'})}
function failure(message,status=400){return json({error:message},status)}
function sameOrigin(r){return r.headers.get('Origin')===new URL(r.url).origin}
async function bodyJson(r){if(!r.headers.get('Content-Type')?.startsWith('application/json'))throw new Error('Требуется JSON');if(Number(r.headers.get('Content-Length')||0)>10000)throw new Error('Слишком большой запрос');const body=await r.text();if(body.length>10000)throw new Error('Слишком большой запрос');return JSON.parse(body)}
function toHex(buf){return Array.from(new Uint8Array(buf),b=>b.toString(16).padStart(2,'0')).join('')}
async function hash(s){return toHex(await crypto.subtle.digest('SHA-256',encoder.encode(s)))}
async function hmac(s,secret){const key=await crypto.subtle.importKey('raw',encoder.encode(secret),'HMAC',false,['sign']);return toHex(await crypto.subtle.sign('HMAC',key,encoder.encode(s)))}
function constantEqual(a,b){if(typeof a!=='string'||typeof b!=='string'||a.length!==b.length)return false;let x=0;for(let i=0;i<a.length;i++)x|=a.charCodeAt(i)^b.charCodeAt(i);return x===0}
async function authed(r,env){if(!env.SESSION_SECRET)return false;const raw=r.headers.get('Cookie')?.match(/(?:^|; )__Host-tr_session=([^;]+)/)?.[1];if(!raw)return false;const m=/^([0-9]{13})\.([a-f0-9]{64})$/.exec(raw);if(!m||Number(m[1])<=Date.now()||Number(m[1])>Date.now()+86400000)return false;return constantEqual(m[2],await hmac(m[1],env.SESSION_SECRET))}
async function rateAllowed(r,env,purpose,max,minutes){const ip=r.headers.get('CF-Connecting-IP')||'unknown';const window=Math.floor(Date.now()/(minutes*60000));const bucket=await hash(purpose+':'+window+':'+ip+':'+env.SESSION_SECRET);const write=await env.DB.prepare('INSERT INTO rate_limits(bucket,window_start,attempts) VALUES(?,?,1) ON CONFLICT(bucket) DO UPDATE SET attempts=attempts+1 WHERE attempts < ?').bind(bucket,window,max).run();if(Math.random()<.01)await env.DB.prepare('DELETE FROM rate_limits WHERE window_start < ?').bind(window-500).run();return (write.meta?.changes||0)>0}
function invalid(o){if(!o||typeof o!=='object')return 'Некорректная анкета';if(!['male','female'].includes(o.gender))return 'Выберите пол';if(!Number.isInteger(o.age)||o.age<1||o.age>110)return 'Укажите возраст';if(!ZODIACS.has(o.zodiac))return 'Выберите знак зодиака';if(typeof o.question!=='string'||o.question.trim().length<3||o.question.trim().length>1200)return 'Вопрос должен содержать от 3 до 1200 символов';if(!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(String(o.uid||'')))return 'Некорректный идентификатор запроса';return null}
async function snapshot(r,env){const meta=await env.DB.prepare('SELECT version FROM app_meta WHERE id=1').first();const version=meta?.version||1;const url=new URL(r.url);if(url.searchParams.get('version')===String(version))return res('',204,{'Cache-Control':'no-store'});
 const [rows,counters]=await Promise.all([env.DB.prepare('SELECT number,gender,age,zodiac,question,status,seen_at,resolved_at,created_at FROM submissions ORDER BY number ASC').all(),env.DB.prepare("SELECT COUNT(*) AS total, COALESCE(SUM(CASE WHEN status!='resolved' THEN 1 ELSE 0 END),0) AS active, COALESCE(SUM(CASE WHEN status='resolved' THEN 1 ELSE 0 END),0) AS resolved, COALESCE(SUM(CASE WHEN status='postponed' THEN 1 ELSE 0 END),0) AS postponed, COALESCE(SUM(CASE WHEN (status='new' AND seen_at IS NULL) OR status='postponed' THEN 1 ELSE 0 END),0) AS unseen FROM submissions").first()]);
 return json({version,items:rows.results||[],total:counters?.total||0,active:counters?.active||0,resolved:counters?.resolved||0,postponed:counters?.postponed||0,unseen:counters?.unseen||0})}
function numberFrom(p,prefix){const m=new RegExp('^'+prefix+'([1-9][0-9]{0,9})$').exec(p);return m?Number(m[1]):null}
export default {async fetch(r,env){try{
 const url=new URL(r.url),p=url.pathname,m=r.method;
 if(m==='GET'&&(p==='/'||p==='/index.html'))return page(guestHtml);
 if(m==='GET'&&(p==='/admin'||p==='/admin.html'))return page(adminHtml);
 if(m==='GET'&&p==='/api/health')return json({ok:true});
 if(m==='POST'&&p==='/api/submit'){
   if(!sameOrigin(r))return failure('Неверный источник запроса',403);
   const v=await bodyJson(r);const err=invalid(v);if(err)return failure(err);if(v.website)return json({ok:true});
   if(!await rateAllowed(r,env,'guest',20,15))return failure('Слишком много анкет. Попробуйте позже.',429);
   const row=await env.DB.prepare('INSERT OR IGNORE INTO submissions(uid,gender,age,zodiac,question) VALUES(?,?,?,?,?)').bind(v.uid,v.gender,v.age,v.zodiac,v.question.trim()).run();
   if(row.meta?.changes)await env.DB.prepare('UPDATE app_meta SET version=version+1 WHERE id=1').run();
   return json({ok:true},201)
 }
 if(m==='POST'&&p==='/api/admin/login'){
   if(!sameOrigin(r))return failure('Неверный источник',403);
   if(!env.ADMIN_PASSWORD||!env.SESSION_SECRET)return failure('Доступ не настроен',503);
   if(!await rateAllowed(r,env,'login',8,15))return failure('Слишком много попыток. Повторите через 15 минут.',429);
   const v=await bodyJson(r);const a=await hash(String(v.password||'')),b=await hash(env.ADMIN_PASSWORD);
   if(!constantEqual(a,b))return failure('Неверный пароль',401);
   const expiration=String(Date.now()+12*60*60*1000);
   const token=expiration+'.'+await hmac(expiration,env.SESSION_SECRET);
   return res(JSON.stringify({ok:true}),200,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','Set-Cookie':'__Host-tr_session='+token+'; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=43200'})
 }
 if(p.startsWith('/api/admin/')){
   if(!await authed(r,env))return failure('Требуется авторизация',401);
   if(m==='GET'&&p==='/api/admin/me')return json({ok:true});
   if(m==='POST'&&p==='/api/admin/logout'){if(!sameOrigin(r))return failure('Неверный источник',403);return res(JSON.stringify({ok:true}),200,{'Content-Type':'application/json','Cache-Control':'no-store','Set-Cookie':'__Host-tr_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0'})}
   if(m==='GET'&&p==='/api/admin/snapshot')return snapshot(r,env);
   const seen=numberFrom(p,'/api/admin/seen/');
   if(m==='POST'&&seen!==null){if(!sameOrigin(r))return failure('Неверный источник',403);const result=await env.DB.prepare("UPDATE submissions SET seen_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE number=? AND seen_at IS NULL AND status!='resolved'").bind(seen).run();if(result.meta?.changes)await env.DB.prepare('UPDATE app_meta SET version=version+1 WHERE id=1').run();return json({ok:true})}
   const number=numberFrom(p,'/api/admin/status/');
   if(m==='POST'&&number!==null){
     if(!sameOrigin(r))return failure('Неверный источник',403);
     const v=await bodyJson(r);if(!['postponed','resolved'].includes(v.status))return failure('Некорректный статус');
     const result=await env.DB.prepare("UPDATE submissions SET status=?,seen_at=COALESCE(seen_at,strftime('%Y-%m-%dT%H:%M:%fZ','now')),resolved_at=CASE WHEN ?='resolved' THEN strftime('%Y-%m-%dT%H:%M:%fZ','now') ELSE NULL END,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE number=? AND status!='resolved'").bind(v.status,v.status,number).run();
     if(!result.meta?.changes)return failure('Анкета уже разобрана или не существует',409);
     await env.DB.prepare('UPDATE app_meta SET version=version+1 WHERE id=1').run();
     return json({ok:true})
   }
 }
 return failure('Не найдено',404)
 }catch(e){if(e instanceof SyntaxError)return failure('Некорректный JSON');if(/Слишком большой запрос|Требуется JSON/.test(e.message))return failure(e.message,413);console.error('worker error',String(e));return failure('Временная ошибка сервера',500)}}};
