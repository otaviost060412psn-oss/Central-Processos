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
 await initAgenda();
 await initRegistros();
};
/* agenda: criada uma vez por instância (CREATE INDEX bloquearia escritas se rodasse em todo pedido);
   sem chave estrangeira para cp_users, para preservar os registros de contas excluídas */
let agPronto=null;
const initAgenda=()=>agPronto||(agPronto=(async()=>{
 await pool.query(`CREATE TABLE IF NOT EXISTS cp_agenda(id text PRIMARY KEY,user_id text NOT NULL,resp_nome text NOT NULL,resp_usuario text NOT NULL,titulo text NOT NULL,descricao text NOT NULL DEFAULT '',tipo text NOT NULL CHECK(tipo IN ('agenda','demanda')),status text CHECK(status IN ('planejada','andamento','concluida','cancelada')),dia text CHECK(dia ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'),hora_ini text CHECK(hora_ini ~ '^[0-9]{2}:[0-9]{2}$'),hora_fim text CHECK(hora_fim ~ '^[0-9]{2}:[0-9]{2}$'),criado bigint NOT NULL,criado_por text NOT NULL,atualizado bigint NOT NULL,atualizado_por text NOT NULL,encerrado bigint,CHECK(encerrado IS NULL OR (tipo='demanda' AND status IN ('concluida','cancelada'))),CHECK(dia IS NOT NULL OR (hora_ini IS NULL AND hora_fim IS NULL)),CHECK((tipo='agenda' AND dia IS NOT NULL AND status IS NULL) OR (tipo='demanda' AND status IS NOT NULL AND hora_ini IS NULL AND hora_fim IS NULL)))`);
 await pool.query('CREATE INDEX IF NOT EXISTS cp_agenda_user_dia ON cp_agenda(user_id,dia)');
 await pool.query('CREATE INDEX IF NOT EXISTS cp_agenda_dia ON cp_agenda(dia)');
})().catch(e=>{agPronto=null;if(e.code!=='23505'&&e.code!=='42P07')throw e}));
const fail=(s,m)=>{throw Object.assign(new Error(m),{status:s})};
const requireAdmin=u=>{if(!u.admin)fail(403,'Apenas administradores podem realizar essa ação.')};
const publicUser=u=>({id:u.id,nome:u.nome,usuario:u.usuario,admin:u.admin,criado:Number(u.criado)});
const pathSet=(o,path,value)=>{const parts=path.split('.');if(parts.some(x=>!x||x==='__proto__'||x==='constructor'||x==='prototype'))fail(400,'Campo inválido');let t=o;for(const p of parts.slice(0,-1)){if(!t[p]||typeof t[p]!=='object'||Array.isArray(t[p]))t[p]={};t=t[p]}if(value===null)delete t[parts.at(-1)];else t[parts.at(-1)]=value};
/* ---------- agenda ----------
   tipo 'agenda': item do calendário, data obrigatória, horário opcional, sem status;
   tipo 'demanda': o que a pessoa está fazendo, status obrigatório, prazo (dia) opcional, sem horário */
const AG_TIPOS=['agenda','demanda'],AG_STATUS=['planejada','andamento','concluida','cancelada'];
const AG_COLS=['id','user_id','resp_nome','resp_usuario','titulo','descricao','tipo','status','dia','hora_ini','hora_fim','criado','criado_por','atualizado','atualizado_por','encerrado'];
/* leitura com o nome atual do responsável; conta excluída mantém o nome gravado no registro */
const AG_SEL=`SELECT ${AG_COLS.map(c=>c==='resp_nome'?'COALESCE(u.nome,a.resp_nome) AS resp_nome':c==='resp_usuario'?'COALESCE(u.usuario,a.resp_usuario) AS resp_usuario':'a.'+c).join(',')},(u.id IS NULL) AS conta_excluida FROM cp_agenda a LEFT JOIN cp_users u ON u.id=a.user_id`;
const AG_INS=`INSERT INTO cp_agenda(${AG_COLS.join(',')}) VALUES(${AG_COLS.map((_,i)=>'$'+(i+1)).join(',')})`;
const agVals=r=>AG_COLS.map(c=>r[c]);
const agRow=r=>({...r,criado:Number(r.criado),atualizado:Number(r.atualizado),encerrado:r.encerrado==null?null:Number(r.encerrado)});
/* data de encerramento: gravada ao concluir/cancelar, mantida entre status encerrados, apagada ao reabrir */
const AG_FECHADO=['concluida','cancelada'];
const agEncerrado=(novo,antigo,encAntigo,agora)=>!AG_FECHADO.includes(novo)?null:AG_FECHADO.includes(antigo)&&encAntigo!=null?Number(encAntigo):agora;
const isDia=s=>typeof s==='string'&&/^\d{4}-\d{2}-\d{2}$/.test(s)&&!isNaN(Date.parse(s+'T00:00:00Z'))&&new Date(s+'T00:00:00Z').toISOString().slice(0,10)===s;
const isHora=s=>typeof s==='string'&&/^([01]\d|2[0-3]):[0-5]\d$/.test(s);
const isUuid=s=>typeof s==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);
/* campos que o navegador pode enviar; qualquer outro é ignorado */
const agCampos=x=>{
 if(!x||typeof x!=='object'||Array.isArray(x))fail(400,'Dados inválidos.');
 const titulo=typeof x.titulo==='string'?x.titulo.trim():'',descricao=x.descricao==null?'':x.descricao,vazio=v=>v==null||v==='';
 if(!titulo||titulo.length>120)fail(400,'Informe um título de até 120 caracteres.');
 if(typeof descricao!=='string'||descricao.length>2000)fail(400,'A descrição pode ter até 2000 caracteres.');
 if(!AG_TIPOS.includes(x.tipo))fail(400,'Tipo inválido.');
 const status=vazio(x.status)?null:x.status,dia=vazio(x.dia)?null:x.dia,hora_ini=vazio(x.hora_ini)?null:x.hora_ini,hora_fim=vazio(x.hora_fim)?null:x.hora_fim;
 if(x.tipo==='agenda'){if(status!==null)fail(400,'Itens da agenda não têm status.');if(dia===null)fail(400,'Informe a data.')}
 else{if(!AG_STATUS.includes(status))fail(400,'Status inválido.');if(hora_ini!==null||hora_fim!==null)fail(400,'Demandas não têm horário.')}
 if(dia!==null&&!isDia(dia))fail(400,'Data inválida.');
 if((hora_ini!==null&&!isHora(hora_ini))||(hora_fim!==null&&!isHora(hora_fim)))fail(400,'Horário inválido.');
 if(dia===null&&(hora_ini!==null||hora_fim!==null))fail(400,'Horários só podem ser informados junto com uma data.');
 if(hora_fim!==null&&hora_ini===null)fail(400,'Informe o horário de início.');
 if(hora_ini!==null&&hora_fim!==null&&hora_fim<hora_ini)fail(400,'O horário de fim não pode ser antes do início.');
 return {titulo,descricao,tipo:x.tipo,status,dia,hora_ini,hora_fim};
};
/* registro completo vindo de um backup */
const agRegistro=r=>{
 if(!r||typeof r!=='object'||Array.isArray(r))fail(400,'Formato inválido.');
 if(!isUuid(r.id))fail(400,'Identificador inválido.');
 /* nome e login podem estar vazios (conta salva sem nome); datas no futuro são recusadas */
 const id=(v)=>typeof v==='string'&&!!v.trim()&&v.length<=100,txt=(v,max)=>typeof v==='string'&&v.length<=max,ts=v=>Number.isSafeInteger(v)&&v>0&&v<=Date.now()+864e5;
 if(!id(r.user_id)||!txt(r.resp_nome,200)||!txt(r.resp_usuario,200)||!id(r.criado_por)||!id(r.atualizado_por))fail(400,'Responsável ou autor inválido.');
 if(!ts(r.criado)||!ts(r.atualizado)||r.criado>r.atualizado)fail(400,'Datas de criação ou atualização inválidas.');
 const c=agCampos(r);
 /* encerrado só existe em demanda encerrada; backup sem a data usa a da última alteração */
 if(r.encerrado!=null&&!ts(r.encerrado))fail(400,'Data de encerramento inválida.');
 const encerrado=AG_FECHADO.includes(c.status)?(r.encerrado??r.atualizado):null;
 return {...c,id:r.id,user_id:r.user_id,resp_nome:r.resp_nome,resp_usuario:r.resp_usuario,criado:r.criado,criado_por:r.criado_por,atualizado:r.atualizado,atualizado_por:r.atualizado_por,encerrado};
};
const agGet=async id=>{const r=(await pool.query(`${AG_SEL} WHERE a.id=$1`,[id])).rows[0];if(!r)fail(404,'Registro não encontrado.');return agRow(r)};
/* no restore, um registro existente mantém dono e autoria originais */
const AG_RESTORE_SET=['titulo','descricao','tipo','status','dia','hora_ini','hora_fim','atualizado','atualizado_por','encerrado'];
const AG_LIMITE=2000;
/* ---------- registros das áreas novas (Jornada, Diagnósticos, Projetos…) ----------
   uma tabela para todas; 'area' diz de que área é o registro e o servidor confere os campos de cada uma.
   só administradores leem ou alteram; 'ordem' guarda a posição quando a área tem ordem (etapas da jornada) */
let regPronto=null;
const initRegistros=()=>regPronto||(regPronto=(async()=>{
 await pool.query(`CREATE TABLE IF NOT EXISTS cp_registros(id text PRIMARY KEY,area text NOT NULL,data jsonb NOT NULL,ordem int,criado bigint NOT NULL,criado_por text NOT NULL,atualizado bigint NOT NULL,atualizado_por text NOT NULL)`);
 await pool.query('CREATE INDEX IF NOT EXISTS cp_registros_area ON cp_registros(area,ordem)');
})().catch(e=>{regPronto=null;if(e.code!=='23505'&&e.code!=='42P07')throw e}));
const regTxt=(v,max,nome,obrig)=>{const s=v==null?'':v;if(typeof s!=='string'||s.length>max)fail(400,`${nome}: até ${max} caracteres.`);const t=s.trim();if(obrig&&!t)fail(400,`Informe ${nome.toLowerCase()}.`);return obrig?t:s};
const regId=v=>typeof v==='string'&&!!v.trim()&&v.length<=100;
const REG_FLUXOS=['retorno','recorrencia','desvio'];
/* campos aceitos em cada área; qualquer outro é ignorado */
/* 'grupo': áreas que dependem umas das outras gravam uma de cada vez (etapas e caminhos da jornada) */
const REG_AREAS={
 jornada_etapa:{grupo:'jornada',ordenada:true,campos:x=>{
  const setores=x.setores==null?[]:x.setores;
  if(!Array.isArray(setores)||setores.length>50||!setores.every(regId))fail(400,'Setores inválidos.');
  return {nome:regTxt(x.nome,120,'O nome da etapa',true),descricao:regTxt(x.descricao,2000,'Descrição'),setores:[...new Set(setores)],
   processos:regTxt(x.processos,2000,'Processos'),motivos:regTxt(x.motivos,2000,'Motivos de contato'),riscos:regTxt(x.riscos,2000,'Problemas que podem surgir')}}},
 jornada_fluxo:{grupo:'jornada',ordenada:false,campos:x=>{
  if(!regId(x.de)||!regId(x.para))fail(400,'Escolha a etapa de origem e a de destino.');
  if(!REG_FLUXOS.includes(x.tipo))fail(400,'Tipo de caminho inválido.');
  return {de:x.de,para:x.para,tipo:x.tipo,descricao:regTxt(x.descricao,120,'Descrição')}}}};
/* registros que dependem de outros: um caminho só existe entre etapas que existem */
const regRefs=async(client,area,d)=>{
 if(area!=='jornada_fluxo')return;
 const q=await client.query("SELECT id FROM cp_registros WHERE area='jornada_etapa' AND id=ANY($1)",[[d.de,d.para]]);
 if(q.rows.length!==new Set([d.de,d.para]).size)fail(400,'Etapa de origem ou de destino não encontrada.');
};
const regArea=a=>{if(typeof a!=='string'||!Object.hasOwn(REG_AREAS,a))fail(400,'Área inválida.');return REG_AREAS[a]};
/* uma gravação por grupo de cada vez, até o fim da transação: evita travas cruzadas e ordem repetida */
const regTrava=(client,A)=>client.query('SELECT pg_advisory_xact_lock(hashtext($1))',['cp_registros:'+A.grupo]);
const regRow=r=>({id:r.id,area:r.area,data:r.data,ordem:r.ordem,criado:Number(r.criado),criado_por:r.criado_por,atualizado:Number(r.atualizado),atualizado_por:r.atualizado_por});
const REG_LIMITE=1000;
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
  /* agenda: o dono vem sempre da sessão; só administradores consultam ou alteram registros de outras pessoas */
  if(action==='agendaList'){
   const p=[],w=[],pessoa=u.admin?(b.pessoa??u.id):u.id;
   if(pessoa!=='*'){p.push(String(pessoa));w.push(`a.user_id=$${p.length}`)}
   /* quatro consultas: demandas abertas; concluídas num intervalo de encerramento (um mês);
      busca nas concluídas de todos os meses; ou, por padrão, agenda e prazos num período */
   let ordem='a.dia NULLS LAST,a.hora_ini NULLS FIRST,a.criado',lim=AG_LIMITE;
   if(b.demandas==='abertas'){w.push("a.tipo='demanda'","a.status IN ('planejada','andamento')");ordem="CASE a.status WHEN 'andamento' THEN 0 ELSE 1 END,a.dia NULLS LAST,a.criado"}
   else if(b.encerradas===true){if(!Number.isSafeInteger(b.desde)||!Number.isSafeInteger(b.ate)||b.desde>b.ate||b.ate-b.desde>32*864e5)fail(400,'Período inválido.');p.push(b.desde,b.ate);w.push("a.tipo='demanda'","a.status='concluida'",`a.encerrado BETWEEN $${p.length-1} AND $${p.length}`);ordem='a.encerrado DESC NULLS LAST'}
   else if(b.busca!=null){const s=typeof b.busca==='string'?b.busca.trim():'';if(s.length<2||s.length>100)fail(400,'Digite de 2 a 100 caracteres para buscar.');p.push('%'+s.replace(/[\\%_]/g,c=>'\\'+c)+'%');w.push("a.tipo='demanda'","a.status='concluida'",`(a.titulo ILIKE $${p.length} ESCAPE '\\' OR a.descricao ILIKE $${p.length} ESCAPE '\\')`);ordem='a.encerrado DESC NULLS LAST';lim=50}
   else{if(!isDia(b.de)||!isDia(b.ate)||b.de>b.ate)fail(400,'Período inválido.');if((Date.parse(b.ate)-Date.parse(b.de))/864e5>400)fail(400,'Consulte no máximo 400 dias por vez.');p.push(b.de,b.ate);w.push(`a.dia BETWEEN $${p.length-1} AND $${p.length}`)}
   const q=await pool.query(`${AG_SEL}${w.length?' WHERE '+w.join(' AND '):''} ORDER BY ${ordem} LIMIT ${lim+1}`,p);
   return res.json({itens:q.rows.slice(0,lim).map(agRow),limitado:q.rows.length>lim});
  }
  if(action==='agendaSave'){
   const x=agCampos(b.data),agora=Date.now();
   if(b.versao!=null&&!Number.isSafeInteger(b.versao))fail(400,'Dados inválidos.');
   if(!b.id){
    let dono=u;
    if(u.admin&&b.responsavel&&b.responsavel!==u.id){const q=await pool.query('SELECT id,nome,usuario FROM cp_users WHERE id=$1',[String(b.responsavel)]);if(!q.rows.length)fail(400,'Responsável inválido.');dono=q.rows[0]}
    const id=uid();
    await pool.query(AG_INS,agVals({...x,id,user_id:dono.id,resp_nome:dono.nome,resp_usuario:dono.usuario,criado:agora,criado_por:u.id,atualizado:agora,atualizado_por:u.id,encerrado:agEncerrado(x.status,null,null,agora)}));
    return res.json({item:await agGet(id)});
   }
   const client=await pool.connect();try{await client.query('BEGIN');
    const q=await client.query('SELECT user_id,tipo,status,atualizado,encerrado FROM cp_agenda WHERE id=$1 FOR UPDATE',[String(b.id)]),r=q.rows[0];
    if(!r||(!u.admin&&r.user_id!==u.id))fail(404,'Registro não encontrado.');
    if(b.versao!=null&&b.versao!==Number(r.atualizado))fail(409,'Este registro foi alterado por outra pessoa. Recarregue.');
    /* o tipo é fixo depois de criado: atividade continua atividade, demanda continua demanda */
    if(x.tipo!==r.tipo)fail(400,'O tipo do registro não pode ser alterado.');
    /* responsável não muda na edição; nome e login são atualizados se a conta ainda existir */
    await client.query('UPDATE cp_agenda SET titulo=$2,descricao=$3,tipo=$4,status=$5,dia=$6,hora_ini=$7,hora_fim=$8,atualizado=$9,atualizado_por=$10,encerrado=$11,resp_nome=COALESCE((SELECT nome FROM cp_users WHERE id=cp_agenda.user_id),resp_nome),resp_usuario=COALESCE((SELECT usuario FROM cp_users WHERE id=cp_agenda.user_id),resp_usuario) WHERE id=$1',[String(b.id),x.titulo,x.descricao,x.tipo,x.status,x.dia,x.hora_ini,x.hora_fim,Math.max(agora,Number(r.atualizado)+1),u.id,agEncerrado(x.status,r.status,r.encerrado,agora)]);
    await client.query('COMMIT')}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
   return res.json({item:await agGet(String(b.id))});
  }
  if(action==='agendaDelete'){
   const q=await pool.query('DELETE FROM cp_agenda WHERE id=$1 AND ($2 OR user_id=$3)',[String(b.id),!!u.admin,u.id]);
   if(!q.rowCount)fail(404,'Registro não encontrado.');
   return res.json({ok:true});
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
  else if(action==='agendaPessoas'){
   const [ativos,excluidos]=await Promise.all([pool.query('SELECT id,nome,usuario FROM cp_users ORDER BY nome'),pool.query('SELECT DISTINCT ON (a.user_id) a.user_id AS id,a.resp_nome AS nome,a.resp_usuario AS usuario FROM cp_agenda a LEFT JOIN cp_users u ON u.id=a.user_id WHERE u.id IS NULL ORDER BY a.user_id,a.atualizado DESC')]);
   return res.json({pessoas:[...ativos.rows.map(p=>({...p,contaExcluida:false})),...excluidos.rows.map(p=>({...p,contaExcluida:true}))]});
  }
  else if(action==='agendaBackup'){const q=await pool.query(`SELECT ${AG_COLS.join(',')} FROM cp_agenda ORDER BY criado`);return res.json({itens:q.rows.map(agRow)})}
  else if(action==='agendaRestore'){
   /* nunca apaga; registro existente só é substituído se o do arquivo for mais recente */
   const itens=b.itens;if(!Array.isArray(itens)||!itens.length||itens.length>100)fail(400,'Envie de 1 a 100 registros da agenda por vez.');
   const ids=new Set(),regs=itens.map((r,i)=>{try{const x=agRegistro(r);if(ids.has(x.id))fail(400,'Identificador repetido no arquivo.');ids.add(x.id);return x}catch(e){fail(400,`Registro ${i+1} da agenda: ${e.status?e.message:'formato inválido.'}`)}});
   if(b.validar===true)return res.json({ok:true,validos:regs.length});
   let novos=0,atualizados=0,ignorados=0;
   const client=await pool.connect();try{await client.query('BEGIN');
    for(const r of regs){const q=await client.query(`${AG_INS} ON CONFLICT(id) DO UPDATE SET ${AG_RESTORE_SET.map(c=>`${c}=EXCLUDED.${c}`).join(',')} WHERE cp_agenda.atualizado<EXCLUDED.atualizado RETURNING (xmax=0) AS novo`,agVals(r));if(!q.rows.length)ignorados++;else if(q.rows[0].novo)novos++;else atualizados++}
    await client.query('COMMIT')}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
   return res.json({ok:true,novos,atualizados,ignorados});
  }
  else if(action==='regList'){
   regArea(b.area);
   const q=await pool.query(`SELECT * FROM cp_registros WHERE area=$1 ORDER BY ordem NULLS LAST,criado,id LIMIT ${REG_LIMITE+1}`,[b.area]);
   return res.json({itens:q.rows.slice(0,REG_LIMITE).map(regRow),limitado:q.rows.length>REG_LIMITE});
  }
  else if(action==='regSave'){
   const A=regArea(b.area),d=A.campos(b.data&&typeof b.data==='object'&&!Array.isArray(b.data)?b.data:fail(400,'Dados inválidos.')),agora=Date.now();
   if(b.versao!=null&&!Number.isSafeInteger(b.versao))fail(400,'Dados inválidos.');
   if(b.id!=null&&!regId(b.id))fail(400,'Dados inválidos.');
   let item;
   const client=await pool.connect();try{await client.query('BEGIN');await regTrava(client,A);
    await regRefs(client,b.area,d);
    if(!b.id){
     const n=(await client.query('SELECT COUNT(*)::int AS n,COALESCE(MAX(ordem),0)+1 AS o FROM cp_registros WHERE area=$1',[b.area])).rows[0];
     if(n.n>=REG_LIMITE)fail(400,`Esta área já tem o máximo de ${REG_LIMITE} registros.`);
     /* nova etapa entra no fim da ordem */
     item=(await client.query('INSERT INTO cp_registros(id,area,data,ordem,criado,criado_por,atualizado,atualizado_por) VALUES($1,$2,$3,$4,$5,$6,$5,$6) RETURNING *',[uid(),b.area,JSON.stringify(d),A.ordenada?n.o:null,agora,u.id])).rows[0];
    }else{
     const r=(await client.query('SELECT area,atualizado FROM cp_registros WHERE id=$1',[b.id])).rows[0];
     if(!r||r.area!==b.area)fail(404,'Registro não encontrado.');
     if(b.versao!=null&&b.versao!==Number(r.atualizado))fail(409,'Este registro foi alterado por outra pessoa. Recarregue.');
     item=(await client.query('UPDATE cp_registros SET data=$2,atualizado=$3,atualizado_por=$4 WHERE id=$1 RETURNING *',[b.id,JSON.stringify(d),Math.max(agora,Number(r.atualizado)+1),u.id])).rows[0];
    }
    await client.query('COMMIT')}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
   return res.json({item:regRow(item)});
  }
  else if(action==='regDelete'){
   const A=regArea(b.area);if(!regId(b.id))fail(400,'Dados inválidos.');
   let removidos=0;
   const client=await pool.connect();try{await client.query('BEGIN');await regTrava(client,A);
    const r=(await client.query('SELECT area FROM cp_registros WHERE id=$1',[b.id])).rows[0];
    if(!r||r.area!==b.area)fail(404,'Registro não encontrado.');
    /* excluir uma etapa exclui junto os caminhos que saem dela ou chegam nela */
    if(r.area==='jornada_etapa')removidos=(await client.query("DELETE FROM cp_registros WHERE area='jornada_fluxo' AND (data->>'de'=$1 OR data->>'para'=$1)",[String(b.id)])).rowCount;
    await client.query('DELETE FROM cp_registros WHERE id=$1',[String(b.id)]);
    await client.query('COMMIT')}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
   return res.json({ok:true,removidos});
  }
  else if(action==='regOrdem'){
   /* recebe a lista completa na nova ordem; se alguém incluiu ou excluiu algo nesse meio tempo, pede para recarregar */
   const A=regArea(b.area);if(!A.ordenada)fail(400,'Esta área não tem ordem.');
   const ids=b.ids;if(!Array.isArray(ids)||!ids.length||ids.length>REG_LIMITE||!ids.every(regId)||new Set(ids).size!==ids.length)fail(400,'Ordem inválida.');
   const client=await pool.connect();try{await client.query('BEGIN');await regTrava(client,A);
    const q=await client.query('SELECT id FROM cp_registros WHERE area=$1',[b.area]),atuais=new Set(q.rows.map(x=>x.id));
    if(atuais.size!==ids.length||!ids.every(x=>atuais.has(x)))fail(409,'A lista mudou enquanto você reorganizava. Recarregue.');
    await client.query('UPDATE cp_registros r SET ordem=v.o FROM unnest($1::text[]) WITH ORDINALITY AS v(id,o) WHERE r.id=v.id',[ids]);
    await client.query('COMMIT')}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
   return res.json({ok:true});
  }
  else fail(400,'Operação desconhecida');
  return res.json({ok:true});
 }catch(e){console.error('API error',e.code||e.message);return res.status(e.status|| (e.code==='23505'?409:500)).json({error:e.code==='23505'?'Esse usuário já existe.':e.status?e.message:'Erro no servidor. Verifique a configuração do banco.'})}
}
