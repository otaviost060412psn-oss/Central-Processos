# Central de Processos — Neon

## Publicação
1. Envie os arquivos desta pasta para a raiz do repositório GitHub vinculado à Vercel.
2. Confirme que `POSTGRES_URL` está disponível no ambiente Production.
3. Crie em Vercel → Settings → Environment Variables uma variável secreta `SETUP_KEY` com um valor longo e aleatório (não coloque no GitHub). Faça novo deploy.
4. Inicialize o administrador enviando POST a `/api/setup` com JSON `{"setupKey":"SUA_CHAVE","usuario":"processos","senha":"SENHA_FORTE_DE_12_OU_MAIS_CARACTERES"}` usando uma ferramenta HTTP de sua confiança. A configuração só funciona antes de existir qualquer usuário.
5. Acesse o site e faça login. Após criar o administrador, remova `SETUP_KEY` e faça novo deploy.

## Observações
- Dados começam vazios. A interface original foi preservada.
- Senhas são armazenadas como hashes scrypt e as sessões usam cookies HttpOnly.
- Atualizações de outros usuários aparecem automaticamente em até 10 segundos.
- O site exige internet; não utiliza mais o LocalDB para salvar.
- Não exponha valores de `POSTGRES_URL`, `PGPASSWORD` ou `SETUP_KEY`.
- Recomenda-se testar num deployment Preview antes de usar em produção.
