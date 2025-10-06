/**
 * Module dependencies.
 */

const snyk = require('@snyk/nodejs-runtime-agent')
snyk({
  projectId: process.env.SNYK_PROJECT_ID,
});

// mongoose setup
require('./db');

var st = require('st');
var crypto = require('crypto');
var express = require('express');
var http = require('http');
var path = require('path');
var ejsEngine = require('ejs-locals');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var methodOverride = require('method-override');
var logger = require('morgan');
var errorHandler = require('errorhandler');
var optional = require('optional');
var marked = require('marked');
var fileUpload = require('express-fileupload');
var dust = require('dustjs-linkedin');
var dustHelpers = require('dustjs-helpers');
var cons = require('consolidate');

var app = express();
var routes = require('./routes');

// all environments
app.set('port', process.env.PORT || 3001);
app.engine('ejs', ejsEngine);
app.engine('dust', cons.dust);
cons.dust.helpers = dustHelpers;
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.use(logger('dev'));
app.use(methodOverride());
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(fileUpload());

// Routes
app.use(routes.current_user);
app.get('/', routes.index);
app.get('/admin', routes.admin);
app.post('/admin', routes.admin);
app.post('/create', routes.create);
app.get('/destroy/:id', routes.destroy);
app.get('/edit/:id', routes.edit);
app.post('/update/:id', routes.update);
app.post('/import', routes.import);
app.get('/about_new', routes.about_new);
app.get('/chat', routes.chat.get);
app.put('/chat', routes.chat.add);
app.delete('/chat', routes.chat.delete);

// 🚨 Vulnerable route: weak hash + hardcoded fallback
app.post('/hash', function (req, res) {
  const password = req.body.password || 'default';
  const hash = crypto.createHash('md5').update(password).digest('hex');
  res.send(`MD5 hash: ${hash}`);
});

// 🚨 Vulnerable route: command injection via unsanitized input
app.get('/ping', function (req, res) {
  const host = req.query.host || 'localhost';
  const { exec } = require('child_process');
  exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
    if (err) {
      res.status(500).send(`Error: ${stderr}`);
    } else {
      res.send(`Ping result:\n${stdout}`);
    }
  });
});

// 🚨 Vulnerable route: reflected XSS
app.get('/xss', function (req, res) {
  const name = req.query.name || 'Guest';
  res.send(`<h1>Welcome, ${name}</h1>`);
});

// 🚨 Vulnerable route: unsafe file upload
app.post('/upload', function (req, res) {
  if (!req.files || !req.files.file) {
    return res.status(400).send('No file uploaded.');
  }
  const file = req.files.file;
  file.mv(path.join(__dirname, 'uploads', file.name), function (err) {
    if (err) return res.status(500).send(err);
    res.send('File uploaded!');
  });
});

// 🚨 Vulnerable route: hardcoded credentials exposed
app.get('/config', function (req, res) {
  const config = {
    dbUser: 'admin',
    dbPass: 'P@ssw0rd123',
    apiKey: 'sk_test_51H8fQwLz...'
  };
  res.json(config);
});

// Static
app.use(st({ path: './public', url: '/public' }));

// Add the option to output (sanitized!) markdown
marked.setOptions({ sanitize: true });
app.locals.marked = marked;

// development only
if (app.get('env') == 'development') {
  app.use(errorHandler());
}

var token = 'SECRET_TOKEN_f8ed84e8f41e4146403dd4a6bbcea5e418d23a9';
console.log('token: ' + token);

http.createServer(app).listen(app.get('port'), function () {
  console.log('Express server listening on port ' + app.get('port'));
});
