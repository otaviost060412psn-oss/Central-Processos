# Auditoria técnica: resumo

Base: commit `bc969bd` (out/2026). Resumo para orientar a modularização sem refazer a análise. Detalhes de segurança foram reportados ao responsável fora do repositório.

## Estado atual
| Arquivo | Papel |
|---|---|
| `index.html` (~692 KB) | Toda a interface: CSS, markup, JavaScript e assets em base64 (11 fontes WOFF2 de Geist, Sora e Inter, foto do login, textura, logotipo) |
| `api/db.js` | API única `POST /api/db` com campo `action`: autenticação, sessão e dados |
| `api/setup.js` | Criação do primeiro administrador (só funciona sem usuários) |
| `package.json` | Dependência única: `pg` |

- Não há build, testes, lint, CI, lockfile nem `vercel.json`. A Vercel publica a raiz como site estático e trata `api/*.js` como funções.
- Variáveis de ambiente: configuradas na Vercel (ver README). Nunca registrar valores.
- No frontend, a camada de dados usada é `NeonDB` (`const DB=NeonDB`). `LocalDB` e `FireDB` são legado sem uso: não remover sem autorização.

## Dados (Neon)
| Tabela | Conteúdo |
|---|---|
| `cp_users` | usuários (senha com hash) |
| `cp_sessions` | sessões (token com hash) |
| `cp_weeks` | uma linha por semana (`id` = segunda-feira `AAAA-MM-DD`, `data` JSONB com `q`, `o`, `planos`, `palavras`, `sla`, `fechada`…) |
| `cp_settings` | linha única com setores, colaboradores e flags |

Ações da API: `health`, `me`, `login`, `logout`, `snapshot`, `createWeek`, `update` (patch por caminho), `setPassword`, `deleteWeek`, `saveSettings`, `restore`, `addUser`, `updateUser`, `deleteUser`. O frontend atualiza o snapshot completo a cada 10 s e após cada escrita.

## Funcionalidades a preservar
Login e sessão · semanas (criar, fechar, reabrir, excluir, seletor ano/mês/semana) · Qualidade e Operações (lançamento passo a passo, KPIs, tabela, status) · planos de ação · gráfico das últimas 8 semanas · Palavra da Semana · Configurações (usuários, setores com frente Q/O, semanas, colaboradores, backup JSON) · exportação Excel · apresentação em tela cheia · **download da apresentação em HTML offline**.

## Pontos de atenção na modularização
1. **Export HTML offline**: `downloadPres` copia o conteúdo de todas as tags `<style>` e o SVG da marca. Separar CSS ou fontes sem adaptar esse trecho quebra o arquivo baixado.
2. Existe uma rotina de migração sensível em `onData`; não alterar `settings` sem análise prévia e autorização.
3. **Formato JSONB**: campos como `q`, `o`, `frentes` (ausente = as duas frentes) devem permanecer.
4. **Estado e boot**: script IIFE com closures compartilhadas e propriedades em `render` (`render.pending`, `render.force`). Extrair primeiro as funções puras.
5. **Vercel**: todo `.js` em `api/` vira endpoint. Módulos auxiliares devem ficar em `api/_lib/` ou fora de `api/`.
6. **Preview × Produção**: confirmar se usam bancos separados antes de testar escritas.

## Estrutura proposta
```
index.html            casca com pontos de montagem
src/core/             utilitários, estado, eventos
src/domain/           cálculos (calcQ, calcO, status, agregações), semanas, planos
src/data/             cliente da API (mesma interface de NeonDB)
src/ui/               toast, confirmação, menu, seletor de semana, painel de edição
src/pages/            início, frente (Q/O), palavra, config/*
src/features/         apresentação (slides, player, download), exportar Excel
src/styles/           tokens, base, componentes, páginas, apresentação
assets/               fontes, imagens, logotipo
api/db.js             roteamento (mesmo contrato)
api/_lib/             pool, schema, auth, sessão, repositórios, validação
tests/                unit/, api/, e2e/
```

## Plano de migração (cada etapa aprovada separadamente)
0. Rede de segurança: branch `desenvolvimento` publicada, Preview com banco isolado, backup JSON, `.gitignore`, lockfile, `engines`.
1. Testes de caracterização do comportamento atual.
2. Vite com saída em HTML único, ainda com o código atual, validando o funcionamento atual e a exportação HTML offline.
3. Extração das funções puras (utils, domínio).
4. Extração de CSS e assets, mantendo o export offline.
5. Cliente da API e estado.
6. Páginas e recursos, um por vez.
7. Backend modular em `api/_lib/`, mesmo contrato.
8. Correções de segurança e remoção de legado: somente com autorização específica.

## Testes de referência
- **Unitários**: `calcQ`, `calcO`, `status`, `aggQ`/`aggO`, `parseDur`, `parseNum`, `mondayOf`, `temFrente`.
- **API**: login e sessão, bloqueio de ações de administrador, semana fechada, patch inválido, `createWeek` idempotente, `restore`.
- **E2E**: lançamentos, planos, palavras, fechar e reabrir semana, configurações, backup ida e volta, Excel, apresentação, HTML baixado abrindo offline, sincronização entre abas.
- **Regressão visual**: 5 páginas e slides antes e depois de cada etapa.
