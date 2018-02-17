
var express = require('express');
var app = express();
var bodyParser = require('body-parser');
var morgan = require('morgan');

var jwt = require('jsonwebtoken'); // used to create, sign, and verify tokens
var config = require('./config'); // get our config file

var port = process.env.PORT || 55310; 
app.set('SEC_KEY', config.secret); // secret variable used to create, sign, and verify tokens 

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// use morgan to log requests to the console
app.use(morgan('dev'));

// routes
// basic route (http://localhost:8080)
app.get('/', function (req, res) {
	res.send('The login API is at http://localhost:' + port + '/api/login');
});

var apiRoutes = express.Router();
var homeRoutes = express.Router();

// login end-point
apiRoutes.post('/login', function (req, res) {

	// console.log('Password: ' + req.body.password);
	// check if password matches

	if ("1" != req.body.password) {
		res.json({ success: false, message: 'Authentication failed. Wrong password.' });
	} else {

		// if user is found and password is right
		// create a token
		var payload = {
			user: req.body.username
		}
		var token = jwt.sign(payload, app.get('SEC_KEY'), {
			expiresIn: 86400 * 7 // expires in 7 days
		});

		res.json({
			auth_token: token
		});

	}
});

function parseBearerToken(req) {
	var auth;
	if (!req.headers || !(auth = req.headers.authorization)) {
		return null;
	}
	var parts = auth.split(' ');
	if (2 > parts.length) return null;
	var schema = parts.shift().toLowerCase();
	var token = parts.join(' ');
	if ('bearer' != schema) return null;
	return token;
}

var middleware = {
	requireTokenAuth: function (req, res, next) {

		//var token = req.body.token || req.param('authorization') || req.param('token') || req.headers['x-access-token'];
		var token = parseBearerToken(req);
	
		if (token) {
	
			jwt.verify(token, app.get('SEC_KEY'), function (err, decoded) {
				if (err) {
					return res.json({ success: false, message: 'Authentication failed for token!' });
				} else {
					req.user = decoded.user;
					next();
				}
			});
	
		} else {
			return res.status(401).send({
				success: false,
				message: 'No token provided.'
			});
		}
	}
}

// route middleware to authenticate and check token
apiRoutes.use(middleware.requireTokenAuth);
homeRoutes.use(middleware.requireTokenAuth);

apiRoutes.get('/', function (req, res) {
	res.json({ message: 'Intellutions login API' });
});

homeRoutes.get('/getuserdetails', function (req, res) {
	console.log("authentication successfull.");
	var userdetails = {
		username: req.user
	}
	res.json(userdetails);
});

apiRoutes.get('/check', function (req, res) {
	console.log("authentication successfull.");
	res.json(req.user);
});

app.use('/api', apiRoutes);
app.use('/home', homeRoutes);

// start the server 
app.listen(port);
console.log('Server started at http://localhost:' + port);
