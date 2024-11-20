import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';

const app = express();
const port = 3030;

app.use(cors());
app.use(express.json());

app.post('/proxy-scan', async (req, res) => {
    try {
        const response = await fetch('http://127.0.0.1:7070/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(req.body)
        });

        const data = await response.json();
        res.json(data);
    } catch (error) {
        console.error('Proxy error:', error);
        res.status(500).json({ error: 'Proxy server error' });
    }
});

app.listen(port, () => {
    console.log(`Proxy server running at http://localhost:${port}`);
}); 