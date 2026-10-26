// Local entry point. On Vercel, vercel.json routes /api/* to app.js.
const app = require('./app');

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`zkID backend running on http://localhost:${PORT}`);
});
