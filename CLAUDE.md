# Central de Processos: instruções do projeto

Contexto técnico do sistema atual: [docs/AUDITORIA.md](docs/AUDITORIA.md). Consulte esse arquivo e o histórico do git antes de reanalisar o código.

## Arquitetura escolhida
- Frontend: **Vite + JavaScript puro**, com código-fonte modular e **build final em um único HTML**.
- Backend: funções da Vercel em `api/`, com o **mesmo contrato** de `POST /api/db` (campo `action`).
- Banco: Neon (PostgreSQL), sem mudanças de esquema ou formato durante a modularização.

## Protocolo obrigatório antes de qualquer alteração
1. Apresentar um plano objetivo: arquivos afetados, mudanças, riscos e testes.
2. Aguardar **aprovação explícita** do responsável. Nunca alterar arquivos antes dela.
3. Em decisões de preferência (design, navegação, arquitetura, implementação), apresentar **pelo menos 5 opções distintas**, com prós e contras, e aguardar a escolha.
4. Não ampliar o escopo aprovado. Se algo adicional for necessário, parar e pedir nova autorização.
5. Commit, push, deploy, instalação de dependências e comandos no banco exigem autorização específica.

## O que preservar
- Design, funcionalidades e dados existentes, salvo autorização específica.
- Integração com o Neon e o contrato atual da API.
- Formato dos dados armazenados (JSONB de semanas e configurações). Nenhuma migração sem aprovação específica.
- **Exportação da apresentação como HTML para uso offline.** Ela depende do CSS, das fontes e das imagens estarem embutidos na página.

## Proibido durante a modularização sem autorização específica
- Correções de segurança.
- Exclusão de código, inclusive código legado sem uso.
- Mudanças funcionais ou visuais.

## Fluxo de trabalho
- Mudanças pequenas, reversíveis e testáveis.
- Trabalhar na branch `desenvolvimento` e validar no ambiente Preview da Vercel antes de qualquer publicação em produção (`main`).
- Nunca expor segredos, credenciais ou valores de variáveis de ambiente.
- Este repositório é publicado como site estático: não registrar aqui nem em `docs/` informações sensíveis ou detalhes de vulnerabilidades.

## Eficiência
- Minimizar consumo de tokens: não repetir auditorias, contextos ou código já analisados. Usar este arquivo, `docs/AUDITORIA.md` e o histórico.

## Organização
- Estrutura profissional, clara e sustentável, com responsabilidades bem definidas por pasta (proposta em `docs/AUDITORIA.md`).
