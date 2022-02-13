const dotenv = require('dotenv').config();
const app = require('./app');
require('./redis/blacklist');
const port = 3000;

const routes = require('./rotas');
routes(app);

app.listen(port, () => console.log(`App listening on port ${port}`));
