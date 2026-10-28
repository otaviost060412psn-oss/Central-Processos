import pg from 'pg';
import crypto from 'node:crypto';
const pool=new pg.Pool({connectionString:process.env.POSTGRES_URL,ssl:true,max:3});
const hash=(s,salt)=>crypto.scryptSync(s,salt,64).toString('hex');
const pass=(s)=>{const salt=crypto.randomBytes(16).toString('hex');return `${salt}:${hash(s,salt)}`};
const check=(s,p)=>{if(!p||!p.includes(':'))return false;const [salt,h]=p.split(':');const a=Buffer.from(hash(s,salt),'hex'),b=Buffer.from(h,'hex');return a.length===b.length&&crypto.timingSafeEqual(a,b)};
const uid=()=>crypto.randomUUID();
const cookie=(req,name)=>(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith(name+'='))?.slice(name.length+1);
const norm=s=>String(s||'').trim().toLowerCase();
/* limite de tentativas de login por IP: bloqueia o IP, não a conta, para não travar quem erra a própria senha mas dificultar varrer logins.
   x-vercel-forwarded-for é definido pela borda da Vercel e não pode ser forjado pelo cliente (ao contrário de x-forwarded-for, cujo primeiro valor
   vem do próprio requisitante); sem um IP confiável, não há como aplicar o limite com segurança, então a tentativa segue sem bloqueio */
const LOGIN_MAX=10,LOGIN_JANELA=15*60*1000,LOGIN_BLOQUEIO=15*60*1000,IP_RE=/^[0-9a-fA-F:.]{3,45}$/;
const ipDe=req=>{const v=req.headers['x-vercel-forwarded-for'];const ip=(Array.isArray(v)?v[0]:v)?.trim();return ip&&IP_RE.test(ip)?ip:null};
const init=async()=>{
 await pool.query(`CREATE TABLE IF NOT EXISTS cp_users(id text PRIMARY KEY,nome text NOT NULL,usuario text UNIQUE NOT NULL,password_hash text NOT NULL,admin boolean NOT NULL DEFAULT false,criado bigint NOT NULL)`);
 await pool.query(`CREATE TABLE IF NOT EXISTS cp_sessions(token_hash text PRIMARY KEY,user_id text NOT NULL REFERENCES cp_users(id) ON DELETE CASCADE,expires timestamptz NOT NULL)`);
 await pool.query(`CREATE TABLE IF NOT EXISTS cp_weeks(id text PRIMARY KEY,data jsonb NOT NULL)`);
 await pool.query(`CREATE TABLE IF NOT EXISTS cp_settings(id int PRIMARY KEY DEFAULT 1,data jsonb NOT NULL)`);
 await pool.query(`CREATE TABLE IF NOT EXISTS cp_login_bloqueios(ip text PRIMARY KEY,tentativas int NOT NULL,primeira timestamptz NOT NULL,bloqueado_ate timestamptz)`);
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
/* ---------- semanas: o que cada perfil pode gravar ----------
   o navegador só altera os campos que a tela usa; "quem lançou" vem da sessão; datas da semana não mudam por aqui */
const SEM_ID=/^[A-Za-z0-9_-]{1,60}$/,SEM_LIMITE=256*1024;
const semNum=(v,max)=>v===null||(typeof v==='number'&&Number.isFinite(v)&&v>=0&&(max==null||v<=max));
const semTxt=(v,n)=>v===null||(typeof v==='string'&&v.length<=n);
const SEM_CAMPOS={q:{monitorias:v=>semNum(v),qualidade:v=>semNum(v,100),zeradas:v=>semNum(v),agentes:v=>semNum(v),responsavel:v=>semTxt(v,500)},o:{tratados:v=>semNum(v),backlog:v=>semNum(v),tempo:v=>semNum(v)}};
const SEM_ROTULO={monitorias:'Monitorias',qualidade:'Qualidade',zeradas:'Zeradas',agentes:'Quantidade de agentes',responsavel:'Responsável',tratados:'Tickets tratados',backlog:'Backlog',tempo:'Tempo médio de backlog',erro:'Erro identificado',acao:'Ação proposta',objetivo:'Objetivo',palavra:'Palavra',nome:'Nome'};
/* objeto simples: chaves curtas (nunca nomes nativos como toString) e valores texto, número, sim/não ou vazio; preserva campos antigos sem aceitar estruturas */
const semObj=(v,max,qual)=>{if(!v||typeof v!=='object'||Array.isArray(v))fail(400,qual+' inválido.');const E=Object.entries(v);if(E.length>30)fail(400,qual+' inválido.');
 for(const[k,x]of E){if(!/^[A-Za-z][A-Za-z0-9_]{0,29}$/.test(k)||k in Object.prototype)fail(400,qual+' inválido.');
  if(typeof x==='string'){if(x.length>max)fail(400,`Texto muito longo em ${SEM_ROTULO[k]||k} (máximo de ${max.toLocaleString('pt-BR')} caracteres).`)}
  else if(!(x===null||typeof x==='boolean'||(typeof x==='number'&&Number.isFinite(x))))fail(400,qual+' inválido.')}};
const semPlanoValido=v=>{if(v===null)return;semObj(v,2000,'Plano de ação');if(!['q','o'].includes(v.frente)||typeof v.setor!=='string'||!SEM_ID.test(v.setor))fail(400,'Plano de ação inválido.');
 if(v.prazo!=null&&v.prazo!==''&&!isDia(v.prazo))fail(400,'Prazo do plano inválido.')};
const semPlano=(v,nome)=>{semPlanoValido(v);return v===null?null:{...v,by:nome,at:Date.now()}};
const semPalavraValida=v=>{if(v===null)return;semObj(v,200,'Palavra');if(typeof v.palavra!=='string'||!v.palavra.trim())fail(400,'Palavra inválida.')};
const semPalavra=(v,nome)=>{semPalavraValida(v);return v===null?null:{...v,by:nome,at:Date.now()}};
const semFoto=v=>{if(v===null)return null;if(!v||typeof v!=='object'||Array.isArray(v)||Object.keys(v).length>50)fail(400,'Números congelados inválidos.');
 for(const[k,x]of Object.entries(v))if(!SEM_ID.test(k)||!x||typeof x!=='object'||!['monitorias','qualidade','zeradas','agentes'].every(c=>semNum(x[c]??null,c==='qualidade'?100:null))||!semTxt(x.responsavel??null,2000))fail(400,'Números congelados inválidos.');
 return Object.fromEntries(Object.entries(v).map(([k,x])=>[k,{monitorias:x.monitorias??null,qualidade:x.qualidade??null,zeradas:x.zeradas??null,agentes:x.agentes??null,responsavel:x.responsavel??null}]))};
/* formato completo de uma semana (usado só no restore de backup; não reescreve nada, só valida) */
const SEM_TOPO=['inicio','fim','fechada','q','o','planos','palavras','criadaEm','sla','slaBy','slaAt','maCongelado'];
const SEM_GRUPO_MAX=200;
const semGrupo=(v,qual)=>{if(!v||typeof v!=='object'||Array.isArray(v))fail(400,qual+' inválido.');const E=Object.entries(v);if(E.length>SEM_GRUPO_MAX)fail(400,qual+' inválido.');for(const[setor,vals] of E){if(!SEM_ID.test(setor))fail(400,qual+' inválido.');semObj(vals,500,qual)}};
const semSemana=data=>{
 if(!data||typeof data!=='object'||Array.isArray(data))fail(400,'Semana malformada.');
 for(const k of Object.keys(data))if(!SEM_TOPO.includes(k))fail(400,'Campo desconhecido na semana: '+String(k).slice(0,60));
 if(!isDia(data.inicio)||!isDia(data.fim))fail(400,'Datas da semana inválidas.');
 if(typeof data.fechada!=='boolean')fail(400,'Campo "fechada" inválido.');
 if(data.criadaEm!=null&&!semNum(data.criadaEm))fail(400,'Campo "criadaEm" inválido.');
 if(data.sla!=null&&!semNum(data.sla))fail(400,'SLA inválido.');
 if(data.slaBy!=null&&typeof data.slaBy!=='string')fail(400,'Campo "slaBy" inválido.');
 if(data.slaAt!=null&&!semNum(data.slaAt))fail(400,'Campo "slaAt" inválido.');
 semGrupo(data.q||{},'Números de qualidade');
 semGrupo(data.o||{},'Números de operações');
 const planos=data.planos||{};if(typeof planos!=='object'||Array.isArray(planos))fail(400,'Planos inválidos.');
 const EP=Object.entries(planos);if(EP.length>SEM_GRUPO_MAX)fail(400,'Planos inválidos.');
 for(const[id,v] of EP){if(!SEM_ID.test(id))fail(400,'Identificador de plano inválido.');semPlanoValido(v)}
 const palavras=data.palavras||{};if(typeof palavras!=='object'||Array.isArray(palavras))fail(400,'Palavras inválidas.');
 const EW=Object.entries(palavras);if(EW.length>SEM_GRUPO_MAX)fail(400,'Palavras inválidas.');
 for(const[id,v] of EW){if(!SEM_ID.test(id))fail(400,'Identificador de palavra inválido.');semPalavraValida(v)}
 if(data.maCongelado!=null)semFoto(data.maCongelado);
};
/* devolve [caminho, valor] já conferido; recusa o que não for da tela */
function semCampo(k,v,u){const p=String(k).split('.'),nome=u.nome,agora=Date.now(),bad=()=>fail(400,'Campo inválido: '+String(k).slice(0,60));
 if(v===undefined)v=null;
 if(p.length===3&&(p[0]==='q'||p[0]==='o')&&SEM_ID.test(p[1])){const c=p[2];
  if(c==='by')return [k,v===null?null:nome];if(c==='at')return [k,v===null?null:agora];
  if(!Object.hasOwn(SEM_CAMPOS[p[0]],c))bad();if(!SEM_CAMPOS[p[0]][c](v))fail(400,`Valor inválido em ${SEM_ROTULO[c]}.`);return [k,v]}
 if(p.length===1){
  if(k==='sla'){if(!semNum(v))fail(400,'SLA inválido.');return [k,v]}
  if(k==='slaBy')return [k,v===null?null:nome];if(k==='slaAt')return [k,v===null?null:agora];
  if(u.admin&&k==='fechada'){if(typeof v!=='boolean')bad();return [k,v]}
  if(u.admin&&k==='maCongelado')return [k,semFoto(v)];
  if(u.admin&&k==='palavras'){if(!v||typeof v!=='object'||Array.isArray(v)||Object.keys(v).length)bad();return [k,{}]}
  if(k==='fechada'||k==='maCongelado')fail(403,'Apenas administradores podem fechar ou reabrir a semana.');
  bad()}
 if(p.length===2&&p[0]==='planos'&&SEM_ID.test(p[1]))return [k,semPlano(v,nome)];
 if(p.length===2&&p[0]==='palavras'&&SEM_ID.test(p[1]))return [k,semPalavra(v,nome)];
 bad()}
/* semana nova: montada aqui, nunca com o conteúdo enviado; segunda-feira válida */
const semDiaSP=()=>new Intl.DateTimeFormat('en-CA',{timeZone:'America/Sao_Paulo'}).format(new Date());
const semSoma=(s,n)=>{const d=new Date(s+'T00:00:00Z');d.setUTCDate(d.getUTCDate()+n);return d.toISOString().slice(0,10)};
const semSegunda=s=>{const d=new Date(s+'T00:00:00Z');return semSoma(s,-((d.getUTCDay()+6)%7))};
function semNova(id,u){if(!isDia(id)||new Date(id+'T00:00:00Z').getUTCDay()!==1)fail(400,'A semana precisa começar numa segunda-feira válida.');
 if(!u.admin){const s=semSegunda(semDiaSP());if(![semSoma(s,-7),s,semSoma(s,7)].includes(id))fail(403,'Apenas administradores podem criar semanas além da anterior, da atual e da próxima.')}
 return {inicio:id,fim:semSoma(id,4),fechada:false,q:{},o:{},planos:{},palavras:{},criadaEm:Date.now()}}
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
   só administradores leem ou alteram, exceto as áreas de monitoria (ver leitura/escrita em REG_AREAS); 'ordem' guarda a posição quando a área tem ordem (etapas da jornada) */
let regPronto=null;
const initRegistros=()=>regPronto||(regPronto=(async()=>{
 await pool.query(`CREATE TABLE IF NOT EXISTS cp_registros(id text PRIMARY KEY,area text NOT NULL,data jsonb NOT NULL,ordem int,criado bigint NOT NULL,criado_por text NOT NULL,atualizado bigint NOT NULL,atualizado_por text NOT NULL)`);
 await pool.query('CREATE INDEX IF NOT EXISTS cp_registros_area ON cp_registros(area,ordem)');
})().catch(e=>{regPronto=null;if(e.code!=='23505'&&e.code!=='42P07')throw e}));
const regTxt=(v,max,nome,obrig)=>{const s=v==null?'':v;if(typeof s!=='string'||s.length>max)fail(400,`${nome}: até ${max} caracteres.`);const t=s.trim();if(obrig&&!t)fail(400,`Informe ${nome.toLowerCase()}.`);return obrig?t:s};
const regId=v=>typeof v==='string'&&!!v.trim()&&v.length<=100;
const REG_FLUXOS=['retorno','recorrencia','desvio'];
const regLista=(v,nome,ok)=>{const L=v==null?[]:v;if(!Array.isArray(L)||L.length>50||!L.every(ok))fail(400,`${nome}: lista inválida.`);return L};
/* setores digitados: sem espaços nas pontas e sem repetir maiúsculas/minúsculas */
const regSetores=v=>{const vistos=new Set();return regLista(v,'Setores',s=>typeof s==='string'&&s.trim().length>0&&s.length<=100).map(s=>s.trim()).filter(s=>{const k=s.toLowerCase();if(vistos.has(k))return false;vistos.add(k);return true})};
const regOpcao=(v,L,nome,obrig)=>{if(v==null||v===''){if(obrig)fail(400,`Informe: ${nome}.`);return ''}if(!L.includes(v))fail(400,`${nome}: opção inválida.`);return v};
const regDia=(v,nome)=>{const d=v==null?'':v;if(d!==''&&!isDia(d))fail(400,`${nome}: data inválida.`);return d};
const REG_PJ_STATUS=['ideia','planejado','andamento','standby','aguardando','concluido','cancelado'];
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
  return {de:x.de,para:x.para,tipo:x.tipo,descricao:regTxt(x.descricao,120,'Descrição')}}},
 /* problema da experiência; etapas são ids da jornada (uma etapa excluída depois continua listada e aparece como "Etapa excluída") */
 diagnostico:{grupo:'diagnostico',ordenada:false,campos:x=>{
  const lista=(v,nome,ok)=>{const L=v==null?[]:v;if(!Array.isArray(L)||L.length>50||!L.every(ok))fail(400,`${nome}: lista inválida.`);return L};
  const etapas=[...new Set(lista(x.etapas,'Etapas',regId))];
  /* setores digitados: sem espaços nas pontas e sem repetir maiúsculas/minúsculas */
  const vistos=new Set(),setores=lista(x.setores,'Setores',s=>typeof s==='string'&&s.trim().length>0&&s.length<=100).map(s=>s.trim()).filter(s=>{const k=s.toLowerCase();if(vistos.has(k))return false;vistos.add(k);return true});
  const opcao=(v,L,nome,obrig)=>{if(v==null||v===''){if(obrig)fail(400,`Informe: ${nome}.`);return ''}if(!L.includes(v))fail(400,`${nome}: opção inválida.`);return v};
  const data=x.data==null||x.data===''?'':x.data;if(data&&!isDia(data))fail(400,'Data de registro inválida.');
  return {titulo:regTxt(x.titulo,150,'O título do problema',true),descricao:regTxt(x.descricao,4000,'Descrição'),etapas,setores,tema:regTxt(x.tema,100,'Tema').trim(),data,
   impacto:regTxt(x.impacto,4000,'Impacto para o cliente'),frequencia:opcao(x.frequencia,['diaria','semanal','quinzenal','mensal','pontual','nao_medida'],'Frequência'),
   gravidade:opcao(x.gravidade,['critica','alta','media','baixa'],'Gravidade',true),causaTipo:opcao(x.causaTipo,['hipotese','confirmada'],'Tipo de causa',true),
   causa:regTxt(x.causa,4000,'Causa'),evidencias:regTxt(x.evidencias,4000,'Evidências'),proxima:regTxt(x.proxima,1000,'Próxima ação'),
   situacao:opcao(x.situacao,['ativo','investigacao','reduzido','resolvido'],'Situação',true)}}},
 /* projeto ou iniciativa; etapas e problemas são ids da Jornada e dos Diagnósticos (um excluído depois continua listado) */
 projeto:{grupo:'projeto',ordenada:false,limite:500,campos:x=>{
  const prev=x.previsao==null?'':x.previsao;if(prev!==''&&!(typeof prev==='string'&&/^\d{4}-(0[1-9]|1[0-2])$/.test(prev)))fail(400,'Previsão de atuação inválida.');
  return {nome:regTxt(x.nome,150,'O nome do projeto',true),status:regOpcao(x.status,REG_PJ_STATUS,'Status',true),prioridade:regOpcao(x.prioridade,['critica','alta','media','baixa'],'Prioridade',true),
   responsavel:regTxt(x.responsavel,120,'Responsável').trim(),setores:regSetores(x.setores),etapas:[...new Set(regLista(x.etapas,'Etapas',regId))],problemas:[...new Set(regLista(x.problemas,'Problemas',regId))],
   objetivo:regTxt(x.objetivo,2000,'Objetivo'),acao:regTxt(x.acao,4000,'Ação proposta'),proxima:regTxt(x.proxima,1000,'Próxima ação'),
   inicio:regDia(x.inicio,'Início previsto'),prazo:regDia(x.prazo,'Prazo'),concluidoEm:regDia(x.concluidoEm,'Data de conclusão'),
   dependeDe:regTxt(x.dependeDe,1000,'Depende de'),impedimentos:regTxt(x.impedimentos,2000,'Impedimentos'),
   indicador:regTxt(x.indicador,500,'Indicador de sucesso'),linhaBase:regTxt(x.linhaBase,100,'Valor de antes'),meta:regTxt(x.meta,100,'Meta'),atual:regTxt(x.atual,100,'Valor atual'),
   resultado:regTxt(x.resultado,2000,'Resultado alcançado'),validacao:regOpcao(x.validacao,['nao_avaliado','aguardando','comprovada','parcial','sem_efeito','piorou'],'Validação')||'nao_avaliado',
   previsao:prev,reavaliar:regDia(x.reavaliar,'Data de reavaliação'),motivoAguardar:regTxt(x.motivoAguardar,2000,'Por que aguardar'),condicao:regTxt(x.condicao,1000,'Condição para reavaliar')}}},
 /* um registro no histórico de um projeto; mudanças de status são registradas pela tela */
 projeto_hist:{grupo:'projeto',ordenada:false,limite:2000,campos:x=>{
  if(!regId(x.projeto))fail(400,'Projeto inválido.');
  const tipo=regOpcao(x.tipo,['atualizacao','decisao','marco','status'],'Tipo',true),dia=regDia(x.dia,'Data');if(!dia)fail(400,'Informe a data.');
  return {projeto:x.projeto,tipo,dia,texto:regTxt(x.texto,1000,'O texto',true)}}},
 /* monitorias: todos os usuários leem; agentes e critérios só administradores alteram; monitorias todos registram, corrigem e excluem.
    'setor' é o id do setor em Configurações */
 monit_agente:{grupo:'monit_cfg',ordenada:false,leitura:true,campos:x=>{
  if(!regId(x.setor))fail(400,'Escolha o setor do agente.');
  /* equipe (gestão) é opcional: vazio = sem equipe; precisa ser uma equipe do mesmo setor (conferido em regRefs) */
  const equipe=x.equipe==null||x.equipe===''?'':x.equipe;if(equipe&&!regId(equipe))fail(400,'Equipe inválida.');
  return {nome:regTxt(x.nome,120,'O nome do agente',true),setor:x.setor,equipe,ativo:x.ativo!==false}}},
 /* equipe (gestão) de um setor das monitorias: os agentes apontam para ela pelo id */
 monit_equipe:{grupo:'monit_cfg',ordenada:false,leitura:true,limite:500,campos:x=>{
  if(!regId(x.setor))fail(400,'Setor inválido.');
  return {setor:x.setor,nome:regTxt(x.nome,80,'O nome da equipe',true).trim(),ativo:x.ativo!==false}}},
 /* gestor(a) de um setor das monitorias (um registro por setor), mostrado no relatório */
 monit_gestor:{grupo:'monit_cfg',ordenada:false,leitura:true,limite:500,campos:x=>{
  if(!regId(x.setor))fail(400,'Setor inválido.');
  return {setor:x.setor,nome:regTxt(x.nome,120,'O nome do gestor').trim()}}},
 /* critérios de um setor: o total de pontos e cada critério com o peso (pontos perdidos quando marcado) e se zera a monitoria */
 monit_setor:{grupo:'monit_cfg',ordenada:false,leitura:true,campos:x=>{
  if(!regId(x.setor))fail(400,'Setor inválido.');
  const total=x.total;if(typeof total!=='number'||!Number.isFinite(total)||total<=0||total>100000)fail(400,'Total de pontos inválido.');
  const L=x.criterios==null?[]:x.criterios;if(!Array.isArray(L)||L.length>100)fail(400,'Critérios: lista inválida.');
  const ids=new Set(),criterios=L.map(c=>{if(!c||typeof c!=='object'||!regId(c.id)||c.id.length>40||ids.has(c.id))fail(400,'Critério inválido.');ids.add(c.id);
   const peso=c.peso;if(typeof peso!=='number'||!Number.isFinite(peso)||peso<0||peso>100000)fail(400,'Peso inválido.');
   return {id:c.id,nome:regTxt(c.nome,200,'O nome do critério',true),descricao:regTxt(c.descricao,2000,'A descrição do critério'),peso,zera:c.zera===true,ativo:c.ativo!==false}});
  /* modo 'erros': o avaliador marca o que deu errado; 'acertos': os critérios começam marcados e desmarcar tira os pontos (os que zeram continuam sendo marcados).
     Nos dois, a monitoria guarda em 'erros' os critérios em falha */
  /* vagas de cada agente no mês: 'semanas' (N semanas × M monitorias) ou 'total' (M monitorias sem semanas) */
  const V=x.vagas==null?{}:x.vagas;if(typeof V!=='object'||Array.isArray(V))fail(400,'Vagas inválidas.');
  const vm=regOpcao(V.modo,['semanas','total'],'Vagas')||'semanas',vi=(v,max,pad)=>{const n=v==null?pad:v;if(!(Number.isInteger(n)&&n>=1&&n<=max))fail(400,'Quantidade de vagas inválida.');return n};
  const vagas=vm==='total'?{modo:'total',total:vi(V.total,100,15)}:{modo:'semanas',semanas:vi(V.semanas,6,4),porSemana:vi(V.porSemana,10,2)};
  return {setor:x.setor,total,modo:regOpcao(x.modo,['erros','acertos'],'Modo')||'erros',zerarManual:x.zerarManual===true,vagas,criterios}}},
 /* configuração geral das monitorias (um registro só): link da planilha de preenchimento */
 monit_geral:{grupo:'monit_cfg',ordenada:false,leitura:true,campos:x=>{
  const p=regTxt(x.planilha,1000,'O link da planilha').trim();if(p&&!/^https:\/\/[^\s<>"'\x00-\x1f\x7f]+$/i.test(p))fail(400,'Link inválido: use um endereço https:// sem espaços ou aspas.');
  return {planilha:p}}},
 /* uma monitoria: o servidor completa setor, nome do agente, critérios errados (com nome e peso do dia), total, pontos perdidos, nota e se foi zerada */
 monitoria:{grupo:'monitoria',ordenada:false,leitura:true,escrita:true,limite:50000,lista:2000,periodo:'data',campos:x=>{
  const data=regDia(x.data,'Data da monitoria');if(!data)fail(400,'Informe a data da monitoria.');
  if(!regId(x.agente))fail(400,'Escolha o agente monitorado.');
  const E=x.erros==null?[]:x.erros;if(!Array.isArray(E)||E.length>100||!E.every(c=>regId(c)&&c.length<=40))fail(400,'Critérios: lista inválida.');const erros=[...new Set(E)];
  let vaga=null;if(x.vaga!=null){const g=x.vaga;if(typeof g!=='object'||Array.isArray(g)||typeof g.mes!=='string'||!/^\d{4}-(0[1-9]|1[0-2])$/.test(g.mes)||!(g.semana===null||g.semana===undefined||(Number.isInteger(g.semana)&&g.semana>=1&&g.semana<=6))||!(Number.isInteger(g.numero)&&g.numero>=1&&g.numero<=100))fail(400,'Vaga inválida.');vaga={mes:g.mes,semana:g.semana==null?null:g.semana,numero:g.numero}}
  return {data,agente:x.agente,vaga,protocolo:regTxt(x.protocolo,100,'Protocolo').trim(),erros,zeradaManual:x.zeradaManual===true,observacao:regTxt(x.observacao,2000,'A observação',true)}}}};
/* registros que dependem de outros: um caminho só existe entre etapas que existem */
const regRefs=async(client,area,d,id)=>{
 /* um registro de critérios por setor */
 if(area==='monit_geral'){if((await client.query("SELECT 1 FROM cp_registros WHERE area='monit_geral' AND id<>$1",[String(id||'')])).rows.length)fail(400,'A configuração geral já existe.');return}
 if(area==='monit_gestor'){if((await client.query("SELECT 1 FROM cp_registros WHERE area='monit_gestor' AND data->>'setor'=$1 AND id<>$2",[d.setor,String(id||'')])).rows.length)fail(400,'Este setor já tem gestor cadastrado.');return}
 /* equipe: o setor não muda depois de criada (os agentes dela são daquele setor); nome sem repetir no setor */
 if(area==='monit_equipe'){
  if(id){const a=(await client.query("SELECT data FROM cp_registros WHERE area='monit_equipe' AND id=$1",[String(id)])).rows[0];if(a&&a.data.setor!==d.setor)fail(400,'O setor da equipe não pode ser trocado.')}
  if((await client.query("SELECT 1 FROM cp_registros WHERE area='monit_equipe' AND data->>'setor'=$1 AND lower(data->>'nome')=lower($2) AND id<>$3",[d.setor,d.nome,String(id||'')])).rows.length)fail(400,'Já existe uma equipe com este nome no setor.');
  return}
 if(area==='monit_agente'){if(d.equipe&&!(await client.query("SELECT 1 FROM cp_registros WHERE area='monit_equipe' AND id=$1 AND data->>'setor'=$2",[d.equipe,d.setor])).rows.length)fail(400,'Equipe não encontrada neste setor.');return}
 if(area==='monit_setor'){if((await client.query("SELECT 1 FROM cp_registros WHERE area='monit_setor' AND data->>'setor'=$1 AND id<>$2",[d.setor,String(id||'')])).rows.length)fail(400,'Este setor já tem critérios cadastrados.');return}
 if(area==='monitoria'){
  const ag=(await client.query("SELECT data FROM cp_registros WHERE area='monit_agente' AND id=$1",[d.agente])).rows[0];
  const antes=id?(await client.query("SELECT data FROM cp_registros WHERE area='monitoria' AND id=$1",[String(id)])).rows[0]:null;
  /* correção do mesmo agente: setor, total e critérios ficam como eram no dia (o agente pode ter mudado de setor ou sido excluído) */
  const mesmo=!!antes&&antes.data.agente===d.agente;
  if(!mesmo&&(!ag||ag.data.ativo===false))fail(400,'Agente não encontrado ou inativo.');
  d.setor=mesmo?antes.data.setor:ag.data.setor;d.agenteNome=ag?ag.data.nome:antes.data.agenteNome;
  const cfg=mesmo?null:(await client.query("SELECT data FROM cp_registros WHERE area='monit_setor' AND data->>'setor'=$1",[d.setor])).rows[0];
  if(!mesmo&&!cfg)fail(400,'Este setor ainda não tem critérios de monitoria.');
  const cfgM=mesmo?(await client.query("SELECT data FROM cp_registros WHERE area='monit_setor' AND data->>'setor'=$1",[d.setor])).rows[0]:cfg;
  /* critério já marcado vale como era; critério novo precisa existir e estar ativo nos critérios de hoje */
  const velhos=new Map((mesmo?antes.data.erros:[]).map(c=>[c.id,c])),atuais=new Map((cfgM?cfgM.data.criterios:[]).filter(c=>c.ativo!==false).map(c=>[c.id,c]));
  d.total=mesmo?antes.data.total:cfg.data.total;
  /* monitoria nova precisa de vaga; correção de uma antiga sem vaga pode continuar sem */
  if(!d.vaga&&!(mesmo&&!antes.data.vaga))fail(400,'Escolha a vaga da monitoria.');
  if(d.vaga){const V=(cfgM&&cfgM.data.vagas)||{modo:'semanas',semanas:4,porSemana:2},va=mesmo&&antes.data.vaga,igual=!!va&&va.mes===d.vaga.mes&&(va.semana??null)===d.vaga.semana&&va.numero===d.vaga.numero;
   {const[y,m]=d.vaga.mes.split('-').map(Number),ini=d.vaga.mes+'-01',fim=new Date(Date.UTC(y,m+1,0)).toISOString().slice(0,10);if(d.data<ini||d.data>fim)fail(400,'A data da monitoria precisa ficar entre o começo do mês da vaga e o fim do mês seguinte.')}
   if(!igual){if(V.modo==='total'?(d.vaga.semana!==null||d.vaga.numero>V.total):(d.vaga.semana===null||d.vaga.semana>V.semanas||d.vaga.numero>V.porSemana))fail(400,'Esta vaga não existe para o setor.')}
   if((await client.query("SELECT 1 FROM cp_registros WHERE area='monitoria' AND id<>$1 AND data->>'agente'=$2 AND data->'vaga'->>'mes'=$3 AND COALESCE(data->'vaga'->>'semana','')=$4 AND data->'vaga'->>'numero'=$5",[String(id||''),d.agente,d.vaga.mes,d.vaga.semana==null?'':String(d.vaga.semana),String(d.vaga.numero)])).rows.length)fail(400,'Esta vaga já tem uma monitoria registrada. Para refazer, edite ou exclua a monitoria no histórico.')}
  d.erros=d.erros.map(cid=>{const c=velhos.get(cid)||atuais.get(cid);if(!c)fail(400,'Critério não encontrado ou inativo.');return {id:c.id,nome:c.nome,peso:c.peso,zera:!!c.zera}});
  d.perdidos=d.erros.reduce((t,c)=>t+c.peso,0);
  if(d.zeradaManual&&!(cfgM&&cfgM.data.zerarManual)&&!(mesmo&&antes.data.zeradaManual))fail(400,'Este setor não permite zerar a monitoria manualmente.');
  d.zerada=d.zeradaManual||d.perdidos>=d.total||d.erros.some(c=>c.zera);
  d.nota=d.zerada?0:Math.round((d.total-d.perdidos)/d.total*10000)/100;
  return}
 if(area==='projeto_hist'){if(!(await client.query("SELECT 1 FROM cp_registros WHERE area='projeto' AND id=$1",[d.projeto])).rows.length)fail(400,'Projeto não encontrado.');return}
 if(area!=='jornada_fluxo')return;
 const q=await client.query("SELECT id FROM cp_registros WHERE area='jornada_etapa' AND id=ANY($1)",[[d.de,d.para]]);
 if(q.rows.length!==new Set([d.de,d.para]).size)fail(400,'Etapa de origem ou de destino não encontrada.');
};
const regArea=a=>{if(typeof a!=='string'||!Object.hasOwn(REG_AREAS,a))fail(400,'Área inválida.');return REG_AREAS[a]};
/* restauração de backup de monitoria: a área guarda, além dos campos digitados, o que regRefs calculou na hora (setor, critérios errados com nome/peso/zera do dia, total, agente). Diferente dessa, a nota, os pontos perdidos e se foi zerada NUNCA vêm do arquivo: são sempre recalculados aqui a partir dos critérios e do total, como no registro normal, para que um backup não possa gravar uma nota fabricada */
const regMonRestore=x=>{
 const data=regDia(x.data,'Data da monitoria');if(!data)fail(400,'Informe a data da monitoria.');
 if(!regId(x.agente))fail(400,'Escolha o agente monitorado.');
 if(!regId(x.setor))fail(400,'Setor inválido.');
 const total=x.total;if(typeof total!=='number'||!Number.isFinite(total)||total<=0||total>100000)fail(400,'Total de pontos inválido.');
 const E=x.erros==null?[]:x.erros;if(!Array.isArray(E)||E.length>100)fail(400,'Critérios: lista inválida.');
 const vistos=new Set(),erros=E.map(c=>{if(!c||typeof c!=='object'||!regId(c.id)||c.id.length>40||vistos.has(c.id))fail(400,'Critério inválido.');vistos.add(c.id);
  const peso=c.peso;if(typeof peso!=='number'||!Number.isFinite(peso)||peso<0||peso>100000)fail(400,'Peso inválido.');
  return {id:c.id,nome:regTxt(c.nome,200,'O nome do critério',true),peso,zera:c.zera===true}});
 let vaga=null;if(x.vaga!=null){const g=x.vaga;if(typeof g!=='object'||Array.isArray(g)||typeof g.mes!=='string'||!/^\d{4}-(0[1-9]|1[0-2])$/.test(g.mes)||!(g.semana===null||g.semana===undefined||(Number.isInteger(g.semana)&&g.semana>=1&&g.semana<=6))||!(Number.isInteger(g.numero)&&g.numero>=1&&g.numero<=100))fail(400,'Vaga inválida.');vaga={mes:g.mes,semana:g.semana==null?null:g.semana,numero:g.numero}}
 const zeradaManual=x.zeradaManual===true,perdidos=erros.reduce((t,c)=>t+c.peso,0),zerada=zeradaManual||perdidos>=total||erros.some(c=>c.zera),nota=zerada?0:Math.round((total-perdidos)/total*10000)/100;
 return {data,agente:x.agente,setor:x.setor,agenteNome:regTxt(x.agenteNome,120,'Nome do agente'),total,perdidos,nota,zerada,zeradaManual,vaga,protocolo:regTxt(x.protocolo,100,'Protocolo').trim(),erros,observacao:regTxt(x.observacao,2000,'A observação',true)};
};
const REG_RESTORE_LOTE=200;
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
   const ip=ipDe(req);let account;
   if(ip){
    const client=await pool.connect();
    try{
     await client.query('BEGIN');
     /* trava por hash do IP: serializa mesmo a 1ª tentativa de um IP ainda sem linha, antes de qualquer SELECT/INSERT */
     await client.query('SELECT pg_advisory_xact_lock(hashtext($1))',['cp_login_bloqueios:'+ip]);
     if(Math.random()<0.02)await client.query("DELETE FROM cp_login_bloqueios WHERE (bloqueado_ate IS NULL OR bloqueado_ate<now()) AND primeira<now()-interval '1 day'");
     const qb=await client.query('SELECT * FROM cp_login_bloqueios WHERE ip=$1',[ip]);
     const bloqueio=qb.rows[0],agora=new Date();
     if(bloqueio?.bloqueado_ate&&new Date(bloqueio.bloqueado_ate)>agora)fail(429,'Muitas tentativas de login. Tente novamente em alguns minutos.');
     const q=await client.query('SELECT * FROM cp_users WHERE usuario=$1',[norm(b.usuario)]);account=q.rows[0];
     if(!account||!check(String(b.senha||''),account.password_hash)){
      const janelaExpirada=!bloqueio||new Date(bloqueio.primeira).getTime()+LOGIN_JANELA<agora.getTime();
      const tentativas=janelaExpirada?1:bloqueio.tentativas+1;
      const bloqueadoAte=tentativas>=LOGIN_MAX?new Date(agora.getTime()+LOGIN_BLOQUEIO):null;
      await client.query('INSERT INTO cp_login_bloqueios(ip,tentativas,primeira,bloqueado_ate) VALUES($1,$2,$3,$4) ON CONFLICT(ip) DO UPDATE SET tentativas=$2,primeira=$3,bloqueado_ate=$4',[ip,tentativas,janelaExpirada?agora:bloqueio.primeira,bloqueadoAte]);
      await client.query('COMMIT');
      fail(401,'Usuário ou senha incorretos.');
     }
     if(bloqueio)await client.query('DELETE FROM cp_login_bloqueios WHERE ip=$1',[ip]);
     await client.query('COMMIT');
    }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
   }else{
    const q=await pool.query('SELECT * FROM cp_users WHERE usuario=$1',[norm(b.usuario)]);account=q.rows[0];
    if(!account||!check(String(b.senha||''),account.password_hash))fail(401,'Usuário ou senha incorretos.');
   }
   const secret=crypto.randomBytes(32).toString('hex'),days=b.keep?30:1;
   await pool.query('INSERT INTO cp_sessions(token_hash,user_id,expires) VALUES($1,$2,now()+($3 * interval \'1 day\'))',[crypto.createHash('sha256').update(secret).digest('hex'),account.id,days]);
   res.setHeader('Set-Cookie',`cp_session=${secret}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${days*86400}`);
   return res.json({user:publicUser(account)});
  }
  if(action==='logout'){if(token)await pool.query('DELETE FROM cp_sessions WHERE token_hash=$1',[crypto.createHash('sha256').update(token).digest('hex')]);res.setHeader('Set-Cookie','cp_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0');return res.json({ok:true})}
  if(!u)fail(401,'Sessão expirada. Entre novamente.');
  if(action==='snapshot'){
   const [weeks,settings,users]=await Promise.all([pool.query('SELECT * FROM cp_weeks'),pool.query('SELECT data FROM cp_settings WHERE id=1'),pool.query('SELECT id,nome,usuario,admin,criado FROM cp_users ORDER BY criado')]);
   return res.json({weeks:Object.fromEntries(weeks.rows.map(w=>[w.id,w.data])),settings:settings.rows[0]?.data||null,users:users.rows.map(x=>u.admin||x.id===u.id?publicUser(x):{id:x.id,nome:x.nome})});
  }
  if(action==='createWeek'){const d=semNova(b.id,u);await pool.query('INSERT INTO cp_weeks(id,data) VALUES($1,$2) ON CONFLICT DO NOTHING',[b.id,JSON.stringify(d)]);return res.json({ok:true})}
  if(action==='update'){
   const client=await pool.connect();try{await client.query('BEGIN');const q=await client.query('SELECT data FROM cp_weeks WHERE id=$1 FOR UPDATE',[b.id]);if(!q.rows.length)fail(404,'Semana não encontrada');const w=q.rows[0].data;if(w.fechada&&!u.admin)fail(403,'Esta semana está fechada.');const P=b.patch;if(!P||typeof P!=='object'||Array.isArray(P)||Object.keys(P).length>60)fail(400,'Alteração inválida.');const antes=Buffer.byteLength(JSON.stringify(w));for(const [k,v] of Object.entries(P).map(([k,v])=>semCampo(k,v,u)))pathSet(w,k,v);const j=JSON.stringify(w),depois=Buffer.byteLength(j);
   /* acima do limite só aceita o que não aumenta a semana (dá para apagar e encurtar) */
   if(depois>SEM_LIMITE&&depois>antes)fail(413,'A semana ficou grande demais. Encurte os textos.');await client.query('UPDATE cp_weeks SET data=$2 WHERE id=$1',[b.id,j]);await client.query('COMMIT')}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}return res.json({ok:true});
  }
  if(action==='setPassword'){
   const self=b.id===u.id;
   if(!self)requireAdmin(u);else if(!check(String(b.atual||''),u.password_hash))fail(403,'Senha atual incorreta.');
   if(String(b.senha||'').length<8)fail(400,'A senha precisa ter pelo menos 8 caracteres.');
   /* trocar a senha derruba as demais sessões: a própria pessoa mantém a sessão atual; o alvo de um admin perde todas. uma transação evita senha trocada com sessões antigas ainda válidas */
   const client=await pool.connect();try{await client.query('BEGIN');await client.query('UPDATE cp_users SET password_hash=$2 WHERE id=$1',[b.id,pass(b.senha)]);
   if(self)await client.query('DELETE FROM cp_sessions WHERE user_id=$1 AND token_hash<>$2',[b.id,crypto.createHash('sha256').update(token).digest('hex')]);
   else await client.query('DELETE FROM cp_sessions WHERE user_id=$1',[b.id]);
   await client.query('COMMIT')}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
   return res.json({ok:true});
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
  /* registros: colaboradores leem as áreas liberadas para leitura e gravam/excluem só as liberadas para escrita (monitorias); o resto é de administradores */
  const regLivre=()=>{if(!['regList','regSave','regDelete'].includes(action)||typeof b.area!=='string'||!Object.hasOwn(REG_AREAS,b.area))return false;const A=REG_AREAS[b.area];return action==='regList'?!!A.leitura:!!A.escrita};
  if(!regLivre())requireAdmin(u);
  if(action==='deleteWeek')await pool.query('DELETE FROM cp_weeks WHERE id=$1',[b.id]);
  else if(action==='saveSettings')await pool.query('INSERT INTO cp_settings(id,data) VALUES(1,$1) ON CONFLICT(id) DO UPDATE SET data=$1',[JSON.stringify(b.settings)]);
  else if(action==='restore'){
   const backup=b.backup||{};
   if(backup.settings!=null&&(typeof backup.settings!=='object'||Array.isArray(backup.settings)))fail(400,'Backup inválido: configurações malformadas.');
   const weeks=backup.weeks||{};
   if(typeof weeks!=='object'||Array.isArray(weeks))fail(400,'Backup inválido: semanas malformadas.');
   const entradas=Object.entries(weeks);
   if(entradas.length>5000)fail(400,'Backup inválido: excesso de semanas.');
   for(const [id,data] of entradas){
    if(!isDia(id)||new Date(id+'T00:00:00Z').getUTCDay()!==1)fail(400,'Backup inválido: semana "'+id+'" fora do formato esperado.');
    semSemana(data);
    if(Buffer.byteLength(JSON.stringify(data))>SEM_LIMITE)fail(400,'Backup inválido: semana "'+id+'" grande demais.');
   }
   const client=await pool.connect();
   try{
    await client.query('BEGIN');
    if(backup.settings)await client.query('INSERT INTO cp_settings(id,data) VALUES(1,$1) ON CONFLICT(id) DO UPDATE SET data=$1',[JSON.stringify(backup.settings)]);
    for(const [id,data] of entradas)await client.query('INSERT INTO cp_weeks(id,data) VALUES($1,$2) ON CONFLICT(id) DO UPDATE SET data=$2',[id,JSON.stringify(data)]);
    await client.query('COMMIT');
   }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
  }
  else if(action==='addUser'){
   const x=b.user||{};if(!x.nome||!x.usuario||String(x.senha||'').length<8)fail(400,'Informe nome, usuário e senha de pelo menos 8 caracteres.');
   await pool.query('INSERT INTO cp_users VALUES($1,$2,$3,$4,$5,$6)',[uid(),x.nome,norm(x.usuario),pass(x.senha),!!x.admin,Date.now()]);
  }
  else if(action==='updateUser'){
   const x=b.data||{};
   if(x.admin===false){
    const client=await pool.connect();
    try{await client.query('BEGIN');await client.query("SELECT pg_advisory_xact_lock(hashtext('cp_users:admin'))");
     const r=await client.query('SELECT admin FROM cp_users WHERE id=$1',[b.id]);
     if(r.rows[0]?.admin){const c=await client.query('SELECT count(*)::int AS n FROM cp_users WHERE admin');if(c.rows[0].n<=1)fail(400,'Não é possível remover o último administrador.')}
     await client.query('UPDATE cp_users SET nome=COALESCE($2,nome),usuario=COALESCE($3,usuario),admin=COALESCE($4,admin) WHERE id=$1',[b.id,x.nome??null,x.usuario?norm(x.usuario):null,x.admin??null]);
     await client.query('COMMIT');
    }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
   }else{
    await pool.query('UPDATE cp_users SET nome=COALESCE($2,nome),usuario=COALESCE($3,usuario),admin=COALESCE($4,admin) WHERE id=$1',[b.id,x.nome??null,x.usuario?norm(x.usuario):null,x.admin??null]);
   }
  }
  else if(action==='deleteUser'){
   if(b.id===u.id)fail(400,'Não é possível excluir sua própria conta.');
   const client=await pool.connect();
   try{await client.query('BEGIN');await client.query("SELECT pg_advisory_xact_lock(hashtext('cp_users:admin'))");
    const r=await client.query('SELECT admin FROM cp_users WHERE id=$1',[b.id]);
    if(r.rows[0]?.admin){const c=await client.query('SELECT count(*)::int AS n FROM cp_users WHERE admin');if(c.rows[0].n<=1)fail(400,'Não é possível excluir o último administrador.')}
    await client.query('DELETE FROM cp_users WHERE id=$1',[b.id]);
    await client.query('COMMIT');
   }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
  }
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
   const A=regArea(b.area),lim=A.lista||A.limite||REG_LIMITE;let q;
   if(A.periodo){if(!isDia(b.de)||!isDia(b.ate)||b.de>b.ate||(Date.parse(b.ate)-Date.parse(b.de))/864e5>400)fail(400,'Período inválido.');
    q=await pool.query(`SELECT * FROM cp_registros WHERE area=$1 AND data->>'${A.periodo}' BETWEEN $2 AND $3 ORDER BY data->>'${A.periodo}',criado,id LIMIT ${lim+1}`,[b.area,b.de,b.ate])}
   else q=await pool.query(`SELECT * FROM cp_registros WHERE area=$1 ORDER BY ordem NULLS LAST,criado,id LIMIT ${lim+1}`,[b.area]);
   return res.json({itens:q.rows.slice(0,lim).map(regRow),limitado:q.rows.length>lim});
  }
  else if(action==='regSave'){
   const A=regArea(b.area),d=A.campos(b.data&&typeof b.data==='object'&&!Array.isArray(b.data)?b.data:fail(400,'Dados inválidos.')),agora=Date.now();
   if(b.versao!=null&&!Number.isSafeInteger(b.versao))fail(400,'Dados inválidos.');
   if(b.id!=null&&!regId(b.id))fail(400,'Dados inválidos.');
   let item;
   const client=await pool.connect();try{await client.query('BEGIN');await regTrava(client,A);
    await regRefs(client,b.area,d,b.id);
    if(!b.id){
     const n=(await client.query('SELECT COUNT(*)::int AS n,COALESCE(MAX(ordem),0)+1 AS o FROM cp_registros WHERE area=$1',[b.area])).rows[0];
     const lim=A.limite||REG_LIMITE;if(n.n>=lim)fail(400,`Esta área já tem o máximo de ${lim} registros.`);
     /* nova etapa entra no fim da ordem */
     item=(await client.query('INSERT INTO cp_registros(id,area,data,ordem,criado,criado_por,atualizado,atualizado_por) VALUES($1,$2,$3,$4,$5,$6,$5,$6) RETURNING *',[uid(),b.area,JSON.stringify(d),A.ordenada?n.o:null,agora,u.id])).rows[0];
    }else{
     const r=(await client.query("SELECT area,atualizado,data->>'projeto' AS projeto FROM cp_registros WHERE id=$1",[b.id])).rows[0];
     if(!r||r.area!==b.area)fail(404,'Registro não encontrado.');
     if(b.area==='projeto_hist'&&r.projeto!==d.projeto)fail(400,'Um registro do histórico não pode mudar de projeto.');
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
    /* equipe com agentes não é excluída (os agentes ficariam apontando para uma equipe que não existe) */
    if(r.area==='monit_equipe'&&(await client.query("SELECT 1 FROM cp_registros WHERE area='monit_agente' AND data->>'equipe'=$1 LIMIT 1",[String(b.id)])).rows.length)fail(400,'Esta equipe ainda tem agentes. Troque a equipe deles antes de excluir.');
    /* excluir um projeto exclui junto o histórico dele */
    if(r.area==='projeto')removidos=(await client.query("DELETE FROM cp_registros WHERE area='projeto_hist' AND data->>'projeto'=$1",[String(b.id)])).rowCount;
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
  else if(action==='regBackup'){
   const q=await pool.query('SELECT * FROM cp_registros ORDER BY area,ordem NULLS LAST,criado');
   return res.json({itens:q.rows.map(regRow)});
  }
  else if(action==='regRestore'){
   /* nunca apaga; registro existente só é substituído se o do arquivo for mais recente. não reaplica regRefs inteiro (confia na estrutura, como o restore de semanas e de agenda),
      mas confere o que evitaria dado inconsistente ou duplicado: existência de referências (agente, etapas, projeto) e unicidade por setor/vaga, com trava por grupo igual à gravação normal */
   const itens=b.itens;if(!Array.isArray(itens)||!itens.length||itens.length>REG_RESTORE_LOTE)fail(400,`Envie de 1 a ${REG_RESTORE_LOTE} registros por vez.`);
   const ts=v=>Number.isSafeInteger(v)&&v>0&&v<=Date.now()+864e5;
   const ids=new Set(),vagas=new Set(),regs=itens.map((r,i)=>{try{
    if(!r||typeof r!=='object'||Array.isArray(r))fail(400,'Formato inválido.');
    if(!regId(r.id))fail(400,'Identificador inválido.');
    if(ids.has(r.id))fail(400,'Identificador repetido no arquivo.');ids.add(r.id);
    const A=regArea(r.area);
    if(r.ordem!=null&&!(Number.isInteger(r.ordem)&&r.ordem>=0))fail(400,'Ordem inválida.');
    if(A.ordenada&&r.ordem==null)fail(400,'Esta área exige ordem.');
    if(!A.ordenada&&r.ordem!=null)fail(400,'Esta área não tem ordem.');
    if(!regId(r.criado_por)||!regId(r.atualizado_por))fail(400,'Autor inválido.');
    if(!ts(r.criado)||!ts(r.atualizado)||r.criado>r.atualizado)fail(400,'Datas de criação ou atualização inválidas.');
    const x=r.data&&typeof r.data==='object'&&!Array.isArray(r.data)?r.data:fail(400,'Dados inválidos.');
    const data=r.area==='monitoria'?regMonRestore(x):A.campos(x);
    if(r.area==='monitoria'&&data.vaga){const chave=data.agente+':'+data.vaga.mes+':'+(data.vaga.semana??'')+':'+data.vaga.numero;if(vagas.has(chave))fail(400,'Vaga repetida no arquivo.');vagas.add(chave)}
    return {id:r.id,area:r.area,data,ordem:r.ordem??null,criado:r.criado,criado_por:r.criado_por,atualizado:r.atualizado,atualizado_por:r.atualizado_por};
   }catch(e){fail(400,`Registro ${i+1}: ${e.status?e.message:'formato inválido.'}`)}
   });
   if(b.validar===true)return res.json({ok:true,validos:regs.length});
   let novos=0,atualizados=0,ignorados=0;
   const client=await pool.connect();try{await client.query('BEGIN');
    for(const g of [...new Set(regs.map(r=>regArea(r.area).grupo))].sort())await regTrava(client,{grupo:g});
    for(const area of [...new Set(regs.map(r=>r.area))]){
     const A=regArea(area),lim=A.limite||REG_LIMITE,idsArea=regs.filter(r=>r.area===area).map(r=>r.id);
     const existentes=new Set((await client.query('SELECT id FROM cp_registros WHERE area=$1 AND id=ANY($2)',[area,idsArea])).rows.map(x=>x.id));
     const novosArea=idsArea.filter(id=>!existentes.has(id)).length;
     if(novosArea){const atual=(await client.query('SELECT COUNT(*)::int AS n FROM cp_registros WHERE area=$1',[area])).rows[0].n;if(atual+novosArea>lim)fail(400,`A área "${area}" ultrapassaria o limite de ${lim} registros.`)}
    }
    for(const r of regs){
     if(r.area==='monitoria'){
      if(!(await client.query("SELECT 1 FROM cp_registros WHERE area='monit_agente' AND id=$1",[r.data.agente])).rows.length)fail(400,'Agente monitorado não encontrado para o registro '+r.id+'.');
      if(r.data.vaga&&(await client.query("SELECT 1 FROM cp_registros WHERE area='monitoria' AND id<>$1 AND data->>'agente'=$2 AND data->'vaga'->>'mes'=$3 AND COALESCE(data->'vaga'->>'semana','')=$4 AND data->'vaga'->>'numero'=$5",[r.id,r.data.agente,r.data.vaga.mes,r.data.vaga.semana==null?'':String(r.data.vaga.semana),String(r.data.vaga.numero)])).rows.length)fail(400,'Esta vaga já tem outra monitoria registrada (registro '+r.id+').');
     }
     if(r.area==='jornada_fluxo'){
      const q=await client.query("SELECT id FROM cp_registros WHERE area='jornada_etapa' AND id=ANY($1)",[[r.data.de,r.data.para]]);
      if(q.rows.length!==new Set([r.data.de,r.data.para]).size)fail(400,'Etapa de origem ou de destino não encontrada para o caminho '+r.id+'.');
     }
     if(r.area==='projeto_hist'&&!(await client.query("SELECT 1 FROM cp_registros WHERE area='projeto' AND id=$1",[r.data.projeto])).rows.length)fail(400,'Projeto não encontrado para o histórico '+r.id+'.');
     if(r.area==='monit_setor'&&(await client.query("SELECT 1 FROM cp_registros WHERE area='monit_setor' AND data->>'setor'=$1 AND id<>$2",[r.data.setor,r.id])).rows.length)fail(400,'Este setor já tem critérios cadastrados (registro '+r.id+').');
     if(r.area==='monit_gestor'&&(await client.query("SELECT 1 FROM cp_registros WHERE area='monit_gestor' AND data->>'setor'=$1 AND id<>$2",[r.data.setor,r.id])).rows.length)fail(400,'Este setor já tem gestor cadastrado (registro '+r.id+').');
     if(r.area==='monit_geral'&&(await client.query("SELECT 1 FROM cp_registros WHERE area='monit_geral' AND id<>$1",[r.id])).rows.length)fail(400,'A configuração geral já existe (registro '+r.id+').');
     const q=await client.query('INSERT INTO cp_registros(id,area,data,ordem,criado,criado_por,atualizado,atualizado_por) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO UPDATE SET data=EXCLUDED.data,ordem=EXCLUDED.ordem,atualizado=EXCLUDED.atualizado,atualizado_por=EXCLUDED.atualizado_por WHERE cp_registros.area=EXCLUDED.area AND cp_registros.atualizado<EXCLUDED.atualizado RETURNING (xmax=0) AS novo',[r.id,r.area,JSON.stringify(r.data),r.ordem,r.criado,r.criado_por,r.atualizado,r.atualizado_por]);
     if(!q.rows.length)ignorados++;else if(q.rows[0].novo)novos++;else atualizados++;
    }
    await client.query('COMMIT')}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
   return res.json({ok:true,novos,atualizados,ignorados});
  }
  else fail(400,'Operação desconhecida');
  return res.json({ok:true});
 }catch(e){console.error('API error',e.code||e.message);return res.status(e.status|| (e.code==='23505'?409:500)).json({error:e.code==='23505'?'Esse usuário já existe.':e.status?e.message:'Erro no servidor. Verifique a configuração do banco.'})}
}
