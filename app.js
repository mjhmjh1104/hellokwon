var express     = require('express');
var app         = express();
var path        = require('path');
var mongoose    = require('mongoose');
var passport    = require('passport');
var session     = require('express-session');
var flash       = require ('connect-flash');
var async       = require('async');
var bodyParser  = require('body-parser');

mongoose.connect('mongodb://' + process.env.MONGO_DB + "@ds155714.mlab.com:55714/hellokwon", {useNewUrlParser: true});

var db = mongoose.connection;
db.once('open', function() {
  console.log('Database is connected');
});
db.on('error', function() {
  console.log('Database ERROR: ', err);
});

var bcrypt = require('bcrypt-nodejs');
var userSchema = mongoose.Schema({
  name: {type: String, required: true, unique: true},
  password: {type: String, required: true},
  createdAt: {type: Date, default: Date.now}
});
userSchema.pre('save', function(next) {
  if (this.isModified('password')) this.password = bcrypt.hashSync(this.password);
  return next();
});
userSchema.methods.authenticate = function(password) {
  return bcrypt.compareSync(password, this.password);
};
var User = mongoose.model('user', userSchema);

app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
app.use(flash());
app.use(session({
  secret: 'FourthSiliconValleyCampSecretHashValue%!@^#&)*$_(',
  resave: true,
  saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

var LocalStrategy = require('passport-local').Strategy;
passport.use('local-login', new LocalStrategy({
  usernameField: 'name',
  passwordField: 'password',
  passReqToCallback: true
}, function(req, name, password, done) {
  User.findOne({'name': name}, function(err, user) {
    if (err) return done(err);
    if (!user || !user.authenticate(password)) {
      req.flash('name', req.body.name);
      return done(null, false, req.flash('loginError', '이름 또는 비밀번호가 다릅니다'));
    }
    return done(null, user);
  });
}));

app.get('/', function(req, res) {
  res.render('main', {user: req.user});
});

app.get('/login', function(req, res) {
  res.render('login/login', {
    name: req.flash('name')[0],
    loginError: req.flash('loginError')[0]
  });
});

app.post('/login', function(req, res, next) {
  req.flash('name');
  if (req.body.name.length === 0 || req.body.password.length === 0) {
    req.flash('name', req.body.name);
    req.flash('loginError', '이름 또는 비밀번호가 다릅니다');
    res.redirect('/login');
  } else next();
}, passport.authenticate('local-login', {
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: true
}));

app.get('/logout', function(req, res) {
  req.logout();
  res.redirect('/');
});

app.get('/users/new', function(req, res) {
  res.render('users/new', {
    formData: req.flash('formData')[0],
    registerError: req.flash('registerError')[0]
  });
});

app.post('/users', function (req, res, next) {
  if (!req.body.user.name) {
    req.flash('registerError', '이름을 입력해주세요');
    req.flash('formData', req.body.user);
    res.redirect('back');
  } else if (!req.body.user.password || !req.body.user.passwordConfirmation) {
    req.flash('registerError', '비밀번호를 입력해주세요');
    req.flash('formData', req.body.user);
    res.redirect('back');
  } else if (req.body.user.password !== req.body.user.passwordConfirmation) {
    req.flash('registerError', '비밀번호가 일치하지 않습니다');
    req.flash('formData', req.body.user);
    res.redirect('back');
  } else next();
}, checkUserRegValidation, function(req, res) {
  User.create(req.body.user, function(err, user) {
    if (err) return res.json({success: false, message: err});
    res.redirect('/login');
  });
});

/*app.get('/users', function(req, res) {
  res.render('/users/user', {user: req.user});
});*/

app.listen(process.env.PORT || 3000, function() {
  console.log('Server is now ON!');
});

function checkUserRegValidation(req, res, next) {
  var isValid = true;

  async.waterfall([
    function(callback) {
      User.findOne({name: req.body.user.name, _id: {$ne: mongoose.Types.ObjectId(req.params.id)}}, function(err, user) {
        if (user) {
          isValid = false;
          req.flash('registerError', '이미 가입되었습니다');
        }
        callback(null, isValid);
      });
    }], function(err, isValid) {
      if (err) return res.json({success: 'false', message: err});
      if (isValid) return next();
      else {
        req.flash('formData', req.body.user);
        res.redirect('back');
      }
    });
};

app.get('*', function(req, res) {
  res.render('404');
});
