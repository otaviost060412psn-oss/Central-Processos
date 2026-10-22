import pg from 'pg';
import crypto from 'node:crypto';
const pool=new pg.Pool({connectionString:process.env.POSTGRES_URL,ssl:{rejectUnauthorized:false},max:3});
const hash=(s,salt)=>crypto.scryptSync(s,salt,64).toString('hex');
const pass=(s)=>{const salt=crypto.randomBytes(16).toString('hex');return `${salt}:${hash(s,salt)}`};
const check=(s,p)=>{if(!p||!p.includes(':'))return false;const [salt,h]=p.split(':');const a=Buffer.from(hash(s,salt),'hex'),b=Buffer.from(h,'hex');return a.length===b.length&&crypto.timingSafeEqual(a,b)};
const uid=()=>crypto.randomUUID();
const cookie=(req,name)=>(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(name+'='))?.slice(name.length+1);
const norm=s=>String(s||'').trim().toLowerCase();
const init=async()=>{
 await pool.query(`CREATE TABLE IF NOT EXISTS cp_users(id text PRIMARY KEY,nome text NOT NULL,usuario text UNIQUE NOT NULL,password_hash text NOT NULL,admin boolean NOT NULL DEFAULT false,criado bigint NOT NULL)`);
 await pool.query(`CREATE TABLE IF NOT EXISTS cp_sessions(token_hash text PRIMARY KEY,user_id text NOT NULL REFERENCES cp_users(id) ON DELETE CASCADE,expires timestamptz NOT NULL)`);
 await pool.query(`CREATE TABLE IF NOT EXISTS cp_weeks(id text PRIMARY KEY,data jsonb NOT NULL)`);
 await pool.query(`CREATE TABLE IF NOT EXISTS cp_settings(id int PRIMARY KEY DEFAULT 1,data jsonb NOT NULL)`);
};
const fail=(s,m)=>{throw Object.assign(new Error(m),{status:s})};
const requireAdmin=u=>{if(!u.admin)fail(403,'Apenas administradores podem realizar essa ação.')};
const publicUser=u=>({id:u.id,nome:u.nome,usuario:u.usuario,admin:u.admin,criado:Number(u.criado)});
const pathSet=(o,path,value)=>{const parts=path.split('.');if(parts.some(x=>!x||x==='__proto__'||x==='constructor'||x==='prototype'))fail(400,'Campo inválido');let t=o;for(const p of parts.slice(0,-1)){if(!t[p]||typeof t[p]!=='object'||Array.isArray(t[p]))t[p]={};t=t[p]}if(value===null)delete t[parts.at(-1)];else t[parts.at(-1)]=value};
export default async function handler(req,res){
 res.setHeader('Cache-Control','no-store');
 if(req.method!=='POST')return res.status(405).json({error:'Método inválido'});
 try{
  if(!process.env.POSTGRES_URL)fail(500,'POSTGRES_URL não configurada');
  await init();const b=req.body||{},action=b.action;
  if(action==='health')return res.json({ok:true});
  const token=cookie(req,'cp_session');let u=null;
  if(token){const q=await pool.query('SELECT u.* FROM cp_sessions s JOIN cp_users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires>now()',[crypto.createHash('sha256').update(token).digest('hex')]);u=q.rows[0]||null}
  if(action==='me')return res.json({user:u?publicUser(u):null});
  if(action==='login'){
   const q=await pool.query('SELECT * FROM cp_users WHERE usuario=$1',[norm(b.usuario)]);const account=q.rows[0];
   if(!account||!check(String(b.senha||''),account.password_hash))fail(401,'Usuário ou senha incorretos.');
   const secret=crypto.randomBytes(32).toString('hex'),days=b.keep?30:1;
   await pool.query('INSERT INTO cp_sessions(token_hash,user_id,expires) VALUES($1,$2,now()+($3 * interval \'1 day\'))',[crypto.createHash('sha256').update(secret).digest('hex'),account.id,days]);
   res.setHeader('Set-Cookie',`cp_session=${secret}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${days*86400}`);
   return res.json({user:publicUser(account)});
  }
  if(action==='logout'){if(token)await pool.query('DELETE FROM cp_sessions WHERE token_hash=$1',[crypto.createHash('sha256').update(token).digest('hex')]);res.setHeader('Set-Cookie','cp_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0');return res.json({ok:true})}
  if(!u)fail(401,'Sessão expirada. Entre novamente.');
  if(action==='snapshot'){
   const [weeks,settings,users]=await Promise.all([pool.query('SELECT * FROM cp_weeks'),pool.query('SELECT data FROM cp_settings WHERE id=1'),pool.query('SELECT id,nome,usuario,admin,criado FROM cp_users ORDER BY criado')]);
   return res.json({weeks:Object.fromEntries(weeks.rows.map(w=>[w.id,w.data])),settings:settings.rows[0]?.data||null,users:users.rows.map(publicUser)});
  }
  if(action==='createWeek'){if(!/^\d{4}-\d{2}-\d{2}$/.test(b.id))fail(400,'Data inválida');await pool.query('INSERT INTO cp_weeks(id,data) VALUES($1,$2) ON CONFLICT DO NOTHING',[b.id,JSON.stringify(b.data)]);return res.json({ok:true})}
  if(action==='update'){
   const client=await pool.connect();try{await client.query('BEGIN');const q=await client.query('SELECT data FROM cp_weeks WHERE id=$1 FOR UPDATE',[b.id]);if(!q.rows.length)fail(404,'Semana não encontrada');const w=q.rows[0].data;if(w.fechada&&!u.admin)fail(403,'Esta semana está fechada.');for(const [k,v] of Object.entries(b.patch||{}))pathSet(w,k,v===undefined?null:v);await client.query('UPDATE cp_weeks SET data=$2 WHERE id=$1',[b.id,JSON.stringify(w)]);await client.query('COMMIT')}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}return res.json({ok:true});
  }
  if(action==='setPassword'){
   if(b.id!==u.id)requireAdmin(u);else if(!check(String(b.atual||''),u.password_hash))fail(403,'Senha atual incorreta.');
   if(String(b.senha||'').length<8)fail(400,'A senha precisa ter pelo menos 8 caracteres.');await pool.query('UPDATE cp_users SET password_hash=$2 WHERE id=$1',[b.id,pass(b.senha)]);return res.json({ok:true});
  }
  requireAdmin(u);
  if(action==='deleteWeek')await pool.query('DELETE FROM cp_weeks WHERE id=$1',[b.id]);
  else if(action==='saveSettings')await pool.query('INSERT INTO cp_settings(id,data) VALUES(1,$1) ON CONFLICT(id) DO UPDATE SET data=$1',[JSON.stringify(b.settings)]);
  else if(action==='restore'){
   const backup=b.backup||{};if(backup.settings)await pool.query('INSERT INTO cp_settings(id,data) VALUES(1,$1) ON CONFLICT(id) DO UPDATE SET data=$1',[JSON.stringify(backup.settings)]);
   for(const [id,data] of Object.entries(backup.weeks||{}))await pool.query('INSERT INTO cp_weeks(id,data) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET data=$2',[id,JSON.stringify(data)]);
  }
  else if(action==='addUser'){
   const x=b.user||{};if(!x.nome||!x.usuario||String(x.senha||'').length<8)fail(400,'Informe nome, usuário e senha de pelo menos 8 caracteres.');
   await pool.query('INSERT INTO cp_users VALUES($1,$2,$3,$4,$5,$6)',[uid(),x.nome,norm(x.usuario),pass(x.senha),!!x.admin,Date.now()]);
  }
  else if(action==='updateUser'){
   const x=b.data||{};await pool.query('UPDATE cp_users SET nome=COALESCE($2,nome),usuario=COALESCE($3,usuario),admin=COALESCE($4,admin) WHERE id=$1',[b.id,x.nome??null,x.usuario?norm(x.usuario):null,x.admin??null]);
  }
  else if(action==='deleteUser'){if(b.id===u.id)fail(400,'Não é possível excluir sua própria conta.');await pool.query('DELETE FROM cp_users WHERE id=$1',[b.id])}
  else fail(400,'Operação desconhecida');
  return res.json({ok:true});
 }catch(e){console.error('API error',e.code||e.message);return res.status(e.status|| (e.code==='23505'?409:500)).json({error:e.code==='23505'?'Esse usuário já existe.':e.status?e.message:'Erro no servidor. Verifique a configuração do banco.'})}
}
