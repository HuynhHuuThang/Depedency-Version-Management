import express from 'express';
const app = express();
const port = 8080;

app.use(express.static('.'));

app.listen(port, () => {
    console.log(`HTML server running at http://localhost:${port}`);
}); 