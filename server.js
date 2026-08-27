const express = require('express');

const app = express();

const PORT = process.env.PORT || 3000;

app.get('/', (req, res) => {
    res.send('Olimpo Chess Club - servidor OAuth online!');
});

app.get('/lichess/callback', (req, res) => {
    console.log('Callback recebido:', req.query);

    res.send('Callback da Lichess recebido!');
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
