// Local entry point. On Vercel, api/index.js exports the same app.
const app = require('./app');

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`zkID backend running on http://localhost:${PORT}`);
});
