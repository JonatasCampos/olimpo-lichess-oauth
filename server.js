const express = require('express');
const crypto = require('crypto');

const app = express();

const PORT = process.env.PORT || 3000;
const BOT_SECRET = process.env.BOT_SECRET;

const LICHESS_CLIENT_ID = 'olimpo-chess-club';
const LICHESS_REDIRECT_URI = 'https://olimpo-lichess-oauth.onrender.com/lichess/callback';

const autenticacoes = {};
const vinculos = {};

app.use(express.json());

function verificarSecret(req, res, next) {
    if (req.headers.authorization !== `Bearer ${BOT_SECRET}`) {
        return res.status(401).json({
            erro: 'Não autorizado'
        });
    }

    next();
}

function gerarState() {
    return crypto.randomBytes(32).toString('hex');
}

function gerarCodeVerifier() {
    return crypto.randomBytes(32).toString('base64url');
}

function gerarCodeChallenge(codeVerifier) {
    return crypto
        .createHash('sha256')
        .update(codeVerifier)
        .digest('base64url');
}

function criarLinkLichess(state, codeChallenge) {
    const url = new URL('https://lichess.org/oauth');

    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', LICHESS_CLIENT_ID);
    url.searchParams.set('redirect_uri', LICHESS_REDIRECT_URI);
    url.searchParams.set('state', state);
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 'S256');

    return url.toString();
}

app.get('/', (req, res) => {
    res.send('Olimpo Chess Club - OAuth online!');
});

app.post('/auth/start', verificarSecret, (req, res) => {
    const { jid, grupo } = req.body;

    if (!jid || !grupo) {
        return res.status(400).json({
            erro: 'jid e grupo são obrigatórios'
        });
    }

    const state = gerarState();
    const codeVerifier = gerarCodeVerifier();
    const codeChallenge = gerarCodeChallenge(codeVerifier);

    autenticacoes[state] = {
        jid,
        grupo,
        codeVerifier,
        status: 'aguardando',
        criadoEm: Date.now()
    };

    const link = criarLinkLichess(
        state,
        codeChallenge
    );

    res.json({
        state,
        link
    });
});

app.get('/lichess/callback', async (req, res) => {
    const { code, state, error } = req.query;

    if (error) {
        return res.status(400).send(
            'Autorização cancelada.'
        );
    }

    if (!code || !state) {
        return res.status(400).send(
            'Código ou state ausente.'
        );
    }

    const autenticacao = autenticacoes[state];

    if (!autenticacao) {
        return res.status(400).send(
            'Solicitação inválida ou expirada.'
        );
    }

    if (autenticacao.status !== 'aguardando') {
        return res.status(400).send(
            'Essa solicitação já foi utilizada.'
        );
    }

    try {
        const respostaToken = await fetch(
            'https://lichess.org/api/token',
            {
                method: 'POST',

                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },

                body: new URLSearchParams({
                    grant_type: 'authorization_code',
                    client_id: LICHESS_CLIENT_ID,
                    code,
                    redirect_uri: LICHESS_REDIRECT_URI,
                    code_verifier: autenticacao.codeVerifier
                })
            }
        );

        const token = await respostaToken.json();

        if (!respostaToken.ok) {
            console.error(
                'Erro Lichess:',
                token
            );

            autenticacao.status = 'erro';

            return res.status(400).send(
                'Não foi possível concluir a autenticação.'
            );
        }

        const respostaConta = await fetch(
            'https://lichess.org/api/account',
            {
                headers: {
                    Authorization: `Bearer ${token.access_token}`
                }
            }
        );

        const conta = await respostaConta.json();

        if (!respostaConta.ok) {
            throw new Error(
                'Não foi possível obter a conta Lichess.'
            );
        }

        vinculos[autenticacao.grupo] ??= {};

        vinculos[autenticacao.grupo][autenticacao.jid] = {
            lichessId: conta.id,
            lichessUsername: conta.username
        };

        autenticacao.status = 'concluido';
        autenticacao.lichessId = conta.id;
        autenticacao.lichessUsername = conta.username;

        console.log(
            `${autenticacao.jid} vinculou ${conta.username}`
        );

        res.send(`
            <!DOCTYPE html>
            <html>
                <head>
                    <meta charset="UTF-8">
                    <title>Olimpo Chess Club</title>
                </head>

                <body>
                    <h1>✅ Conta vinculada!</h1>

                    <p>
                        Sua conta Lichess
                        <strong>${conta.username}</strong>
                        foi vinculada com sucesso.
                    </p>

                    <p>
                        Você pode voltar para o WhatsApp.
                    </p>
                </body>
            </html>
        `);
    } catch (erro) {
        console.error(
            'Erro no callback:',
            erro
        );

        autenticacao.status = 'erro';

        res.status(500).send(
            'Erro interno ao processar a autenticação.'
        );
    }
});

app.get('/vinculo', verificarSecret, (req, res) => {
    const jid = req.query.jid;
    const grupo = req.query.grupo;

    if (!jid || !grupo) {
        return res.status(400).json({
            erro: 'jid e grupo são obrigatórios'
        });
    }

    const vinculo = vinculos[grupo]?.[jid];

    if (!vinculo) {
        return res.json({
            vinculado: false
        });
    }

    res.json({
        vinculado: true,
        lichessId: vinculo.lichessId,
        lichessUsername: vinculo.lichessUsername
    });
});

app.post('/vinculo/remove', verificarSecret, (req, res) => {
    const { jid, grupo } = req.body;

    if (!jid || !grupo) {
        return res.status(400).json({
            erro: 'jid e grupo são obrigatórios'
        });
    }

    if (vinculos[grupo]?.[jid]) {
        delete vinculos[grupo][jid];

        console.log(
            `Vínculo removido: ${jid}`
        );
    }

    for (const state of Object.keys(autenticacoes)) {
        const autenticacao = autenticacoes[state];

        if (
            autenticacao.jid === jid &&
            autenticacao.grupo === grupo
        ) {
            delete autenticacoes[state];
        }
    }

    res.json({
        sucesso: true
    });
});

app.get('/auth/status/:state', verificarSecret, (req, res) => {
    const autenticacao = autenticacoes[
        req.params.state
    ];

    if (!autenticacao) {
        return res.status(404).json({
            erro: 'Solicitação não encontrada'
        });
    }

    res.json({
        status: autenticacao.status,
        jid: autenticacao.jid,
        grupo: autenticacao.grupo,
        lichessUsername: autenticacao.lichessUsername || null,
        lichessId: autenticacao.lichessId || null
    });

    if (autenticacao.status === 'concluido') {
        delete autenticacoes[req.params.state];
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(
        `Servidor rodando na porta ${PORT}`
    );
});
