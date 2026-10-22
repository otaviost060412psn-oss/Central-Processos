import pg from 'pg';import crypto from 'node:crypto';
export default async function handler(req,res){res.setHeader('Cache-Control','no-store');if(req.method!=='POST')return res.status(405).end();
const {setupKey,usuario,senha}=req.body||{};
if(!process.env.SETUP_KEY||setupKey!==process.env.SETUP_KEY)return res.status(403).json({error:'Chave de configuração inválida'});
if(!usuario||String(senha||'').length<12)return res.status(400).json({error:'Informe usuário e senha com pelo menos 12 caracteres'});
const pool=new pg.Pool({connectionString:process.env.POSTGRES_URL,ssl:{rejectUnauthorized:false},max:1});
try{await pool.query('CREATE TABLE IF NOT EXISTS cp_users(id text PRIMARY KEY,nome text NOT NULL,usuario text UNIQUE NOT NULL,password_hash text NOT NULL,admin boolean NOT NULL DEFAULT false,criado bigint NOT NULL)');
const n=await pool.query('SELECT count(*)::int AS n FROM cp_users');if(n.rows[0].n)return res.status(409).json({error:'Já existe um usuário. Configuração inicial bloqueada.'});
const salt=crypto.randomBytes(16).toString('hex');const h=salt+':'+crypto.scryptSync(senha,salt,64).toString('hex');
await pool.query('INSERT INTO cp_users VALUES($1,$2,$3,$4,true,$5)',[crypto.randomUUID(),'Administrador',String(usuario).trim().toLowerCase(),h,Date.now()]);return res.json({ok:true});
}catch(e){console.error(e);return res.status(500).json({error:'Não foi possível criar administrador'})}finally{await pool.end()}}
